package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

const notifyToken = "123456:" + "abcdefghijklmnopqrstuvwxyz_ABCD1234"
const notifyToken2 = "654321:" + "abcdefghijklmnopqrstuvwxyz_EFGH5678"

type telegramMessage struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func setupNotify(t *testing.T, receiver http.Handler) *fixture {
	t.Helper()
	f := setup(t)
	server, client := testutil.NewServer(t, receiver)
	c, err := alert.NewChannels(f.s, alert.Telegram{BaseURL: server.URL + "/proxy", Client: client, Instance: "测试望楼"}, alert.Webhook{})
	if err != nil {
		t.Fatal(err)
	}
	f.h.Config.Channels = c
	return f
}
func (f *fixture) notifyForm(token, chat string) url.Values {
	return url.Values{"csrf": {f.csrf}, "token": {token}, "chat_id": {chat}, "totp": {totp(f.secret, f.now.Unix()/30, 6)}}
}
func TestNotifyLifecycleAndRuntimeDispatch(t *testing.T) {
	messages := make(chan telegramMessage, 20)
	f := setupNotify(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message telegramMessage
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/proxy/bot"+notifyToken+"/sendMessage" {
			t.Error("unexpected Telegram API path")
		}
		messages <- message
	}))
	c := f.h.Config.Channels
	var logs bytes.Buffer
	f.h.Logf = log.New(&logs, "", 0).Printf
	d := &alert.Dispatcher{Store: f.s, Notifiers: c.Notifiers}
	deliver := func(kind string) {
		t.Helper()
		result, err := f.s.DB.Exec(`INSERT INTO events(ts,node,kind,detail,targets) VALUES(?,'node',?,'运行时提醒','telegram')`, time.Now().Unix(), kind)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		if err := d.Deliver(context.Background(), store.Event{ID: id, Node: "node", Time: time.Now().Unix(), Kind: kind, Detail: "运行时提醒", Targets: "telegram"}); err != nil {
			t.Fatal(err)
		}
	}
	deliver("offline")
	for _, path := range []string{"/", "/billing?edit=node", "/notify"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 || strings.Contains(w.Body.String(), `value="telegram"`) {
			t.Fatal("unexpected initial channels", path, w.Code)
		}
	}
	w := f.request("POST", "/notify/telegram", f.notifyForm(notifyToken, "-123"), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已保存，确认消息已发出") {
		t.Fatal(w.Code, w.Body)
	}
	if message := <-messages; message.ChatID != "-123" || message.Text != "测试望楼 · 已开始向这里发送告警通知" {
		t.Fatal("missing confirmation")
	}
	raw, err := f.s.KV("notify.telegram")
	var saved alert.TelegramSettings
	if err != nil || json.Unmarshal([]byte(raw), &saved) != nil || saved.Token != notifyToken || saved.ChatID != "-123" || saved.UpdatedBy != "admin" || saved.UpdatedAt != f.now.Unix() {
		t.Fatal("incorrect persisted settings", err)
	}
	for _, path := range []string{"/", "/billing?edit=node", "/notify"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Telegram") || strings.Contains(w.Body.String(), notifyToken) {
			t.Fatal("missing or unsafe runtime channels", path, w.Code)
		}
		if path == "/notify" && (input(t, w.Body.String(), "token") != "" || !strings.Contains(w.Body.String(), "…1234")) {
			t.Fatal("token disclosure")
		}
	}
	for _, kind := range []string{"offline", "billing", "traffic"} {
		deliver(kind)
		if message := <-messages; message.ChatID != "-123" || !strings.HasPrefix(message.Text, "测试望楼 · node · ") || !strings.Contains(message.Text, "运行时提醒") {
			t.Fatal("runtime dispatcher did not use saved channel")
		}
	}
	form := f.notifyForm(notifyToken2, "999")
	w = f.request("POST", "/notify/telegram/test", form, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if message := <-messages; message.ChatID != "-123" || message.Text != "测试望楼 · 测试通知：收到这条消息说明配置正确" {
		t.Fatal("test used unsaved settings")
	}
	if w := f.request("POST", "/notify/telegram/test", form, true); w.Code != 429 {
		t.Fatal("test limit", w.Code)
	}
	f.now = f.now.Add(10 * time.Second)
	if w := f.request("POST", "/notify/telegram/test", form, true); w.Code != 200 {
		t.Fatal("test limit did not expire", w.Code)
	}
	<-messages
	f.now = f.now.Add(30 * time.Second)
	w = f.request("POST", "/notify/telegram/disable", f.notifyForm("", ""), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已停用") {
		t.Fatal(w.Code, w.Body)
	}
	if message := <-messages; message.ChatID != "-123" || !strings.Contains(message.Text, "Telegram 通知已被 admin 从 192.0.2.1 停用") {
		t.Fatal("old channel did not receive disable notice")
	}
	if raw, err := f.s.KV("notify.telegram"); err != nil || raw != "" || len(c.Notifiers()) != 0 {
		t.Fatal("disable did not delete configuration", err)
	}
	deliver("billing")
	if len(messages) != 0 {
		t.Fatal("disabled channel received notifications or historical events replayed")
	}
	for _, path := range []string{"/", "/billing?edit=node"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "未配置") || strings.Contains(w.Body.String(), `value="telegram"`) {
			t.Fatal("channels did not update after disable", path)
		}
	}
	for _, action := range []string{"notify_telegram_set", "notify_telegram_disable", "notify_telegram_test"} {
		var detail string
		if err := f.s.DB.QueryRow(`SELECT detail FROM audit_log WHERE action=? LIMIT 1`, action).Scan(&detail); err != nil || !strings.Contains(detail, "chat_id=-123 token=…1234 old_notified=") || strings.Contains(detail, notifyToken) {
			t.Fatal("missing or unsafe audit", action, err)
		}
	}
	if strings.Contains(logs.String(), notifyToken) || strings.Contains(logs.String(), notifyToken2) {
		t.Fatal("token in logs")
	}
}

func TestNotifyOldChannelBeforeSaveAndFailures(t *testing.T) {
	type delivery struct {
		telegramMessage
		before string
	}
	messages := make(chan delivery, 10)
	var f *fixture
	f = setupNotify(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message telegramMessage
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Error(err)
		}
		raw, err := f.s.KV("notify.telegram")
		if err != nil {
			t.Error(err)
		}
		var saved alert.TelegramSettings
		if raw != "" && json.Unmarshal([]byte(raw), &saved) != nil {
			t.Error("invalid saved settings")
		}
		if saved.ChatID != f.h.Config.Channels.Settings().ChatID {
			t.Error("configuration snapshot differs from database during send")
		}
		messages <- delivery{message, saved.ChatID}
		if strings.Contains(message.Text, "修改") || message.ChatID == "789" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(notifyToken2))
		}
	}))
	if w := f.request("POST", "/notify/telegram", f.notifyForm(notifyToken, "123"), true); w.Code != 200 {
		t.Fatal(w.Code)
	}
	<-messages
	f.now = f.now.Add(30 * time.Second)
	w := f.request("POST", "/notify/telegram", f.notifyForm("", "456"), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已保存，确认消息已发出") || !strings.Contains(w.Body.String(), "旧渠道通知发送失败") {
		t.Fatal(w.Code, w.Body)
	}
	old, confirmation := <-messages, <-messages
	if old.ChatID != "123" || old.before != "123" || !strings.Contains(old.Text, "通知渠道已被 admin 从 192.0.2.1 修改，新的 chat id 为 456") || confirmation.ChatID != "456" || confirmation.before != "456" {
		t.Fatal("old notification must precede activation and confirmation")
	}
	if f.h.Config.Channels.Settings().Token != notifyToken {
		t.Fatal("blank token did not preserve old token")
	}
	var detail string
	if err := f.s.DB.QueryRow(`SELECT detail FROM audit_log WHERE action='notify_telegram_set' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil || !strings.Contains(detail, "old_notified=false") {
		t.Fatal("old send failure not audited", err)
	}
	f.now = f.now.Add(30 * time.Second)
	w = f.request("POST", "/notify/telegram", f.notifyForm(notifyToken2, "789"), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已保存，但确认消息发送失败：notification status 401") || strings.Contains(w.Body.String(), notifyToken) || strings.Contains(w.Body.String(), notifyToken2) {
		t.Fatal("unsafe or missing confirmation error", w.Code)
	}
	<-messages
	<-messages
	if f.h.Config.Channels.Settings().Token != notifyToken2 {
		t.Fatal("new token not applied")
	}
	if err := f.s.DB.QueryRow(`SELECT detail FROM audit_log WHERE action='notify_telegram_set' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil || strings.Contains(detail, notifyToken2) || !strings.Contains(detail, "…5678") {
		t.Fatal("unsafe new token audit", err)
	}
}

func TestNotifyTOTPValidationReplayAndLock(t *testing.T) {
	f := setupNotify(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	form := f.notifyForm(notifyToken, "123")
	form.Del("totp")
	if w := f.request("POST", "/notify/telegram", form, true); w.Code != 400 || !strings.Contains(w.Body.String(), "验证码错误") {
		t.Fatal("TOTP required", w.Code)
	}
	form.Set("totp", "wrong")
	if w := f.request("POST", "/notify/telegram/disable", form, true); w.Code != 400 {
		t.Fatal("disable must require TOTP", w.Code)
	}
	form = f.notifyForm(notifyToken, "123")
	if w := f.request("POST", "/notify/telegram", form, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var last int64
	if err := f.s.DB.QueryRow(`SELECT totp_last_step FROM admins WHERE user='admin'`).Scan(&last); err != nil || last != f.now.Unix()/30 {
		t.Fatal("TOTP step not consumed", err)
	}
	if w := f.request("POST", "/notify/telegram/disable", form, true); w.Code != 400 || !strings.Contains(w.Body.String(), "这个验证码已经用过，请等下一个") {
		t.Fatal("replay accepted", w.Code)
	}
	form.Set("totp", "wrong")
	for range 2 {
		if w := f.request("POST", "/notify/telegram", form, true); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	f.now = f.now.Add(30 * time.Second)
	form = f.notifyForm(notifyToken, "123")
	for _, path := range []string{"/notify/telegram", "/notify/telegram/disable"} {
		if w := f.request("POST", path, form, true); w.Code != 429 || !strings.Contains(w.Body.String(), "稍后再试") {
			t.Fatal("five failed codes must lock both mutations", path, w.Code)
		}
	}
	f.now = f.now.Add(870 * time.Second)
	if w := f.request("POST", "/notify/telegram", f.notifyForm("", "456"), true); w.Code != 200 {
		t.Fatal("lock did not expire at 15 minutes", w.Code, w.Body)
	}
	// A login consumes the same administrator counter used by notification changes.
	f.now = f.now.Add(30 * time.Second)
	form, cookie := f.loginForm(t)
	if w := f.submitLogin(form, cookie, "192.0.2.10", nil); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := f.request("POST", "/notify/telegram/disable", f.notifyForm("", ""), true); w.Code != 400 || !strings.Contains(w.Body.String(), "已经用过") {
		t.Fatal("login code reused", w.Code)
	}
}

func TestNotifyFormatsAndMiddleware(t *testing.T) {
	f := setupNotify(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, values := range [][2]string{{"", "123"}, {"12345:short", "123"}, {"1234:" + strings.Repeat("a", 30), "123"}, {"12345678901234567:" + strings.Repeat("a", 30), "123"}, {"12345:" + strings.Repeat("a", 65), "123"}, {"12345:" + strings.Repeat("a", 29), "123"}, {notifyToken + "<", "123"}, {notifyToken, ""}, {notifyToken, "1.2"}, {notifyToken, "123456789012345678901"}, {notifyToken, "@abcd"}, {notifyToken, "@" + strings.Repeat("a", 33)}, {notifyToken, "<script>"}} {
		w := f.request("POST", "/notify/telegram", f.notifyForm(values[0], values[1]), true)
		if w.Code != 400 || strings.Contains(w.Body.String(), notifyToken) {
			t.Fatal("invalid configuration accepted or token reflected", w.Code)
		}
		if raw, _ := f.s.KV("notify.telegram"); raw != "" {
			t.Fatal("invalid configuration persisted")
		}
	}
	for _, path := range []string{"/notify/telegram", "/notify/telegram/disable", "/notify/telegram/test"} {
		for _, check := range []struct{ csrf, origin string }{{"wrong", "https://panel.example.com"}, {f.csrf, "https://evil.example.com"}, {f.csrf, ""}} {
			form := f.notifyForm(notifyToken, "123")
			form.Set("csrf", check.csrf)
			r := httptest.NewRequest("POST", "https://panel.example.com"+path, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", check.origin)
			r.AddCookie(f.cookie)
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("notification route skipped middleware", path, w.Code)
			}
			checkHeaders(t, w)
		}
	}
	if w := f.request("POST", "/notify/telegram/test", f.notifyForm(notifyToken, "123"), true); w.Code != 400 {
		t.Fatal("test must require saved configuration", w.Code)
	}
	for _, values := range [][2]string{{"12345:" + strings.Repeat("A_", 32), "-12345678901234567890"}, {"1234567890123456:" + strings.Repeat("a-", 15), "@" + strings.Repeat("a", 32)}} {
		f.now = f.now.Add(30 * time.Second)
		if w := f.request("POST", "/notify/telegram", f.notifyForm(values[0], values[1]), true); w.Code != 200 {
			t.Fatal("valid boundary rejected", w.Code, w.Body)
		}
	}
}

func TestNotifyFileConfigurationReadOnly(t *testing.T) {
	f := setup(t)
	if err := f.s.SetKV("notify.telegram", "malformed and ignored"); err != nil {
		t.Fatal(err)
	}
	c, err := alert.NewChannels(f.s, alert.Telegram{Token: notifyToken, ChatID: "123", BaseURL: "https://proxy.example.invalid"}, alert.Webhook{URL: "https://hook.example.invalid"})
	if err != nil {
		t.Fatal("file configuration must ignore KV", err)
	}
	f.h.Config.Channels = c
	w := f.request("GET", "/notify", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "由服务器配置文件设置，面板不能修改") || strings.Contains(w.Body.String(), `name="token"`) || strings.Contains(w.Body.String(), notifyToken) || !strings.Contains(w.Body.String(), "https://proxy.example.invalid") || !strings.Contains(w.Body.String(), "Webhook") {
		t.Fatal("incorrect readonly page", w.Code)
	}
	for _, path := range []string{"/notify/telegram", "/notify/telegram/disable", "/notify/telegram/test"} {
		if w := f.request("POST", path, f.notifyForm(notifyToken2, "456"), true); w.Code != 403 {
			t.Fatal("readonly POST accepted", path, w.Code)
		}
	}
	if raw, _ := f.s.KV("notify.telegram"); raw != "malformed and ignored" || c.Settings().ChatID != "123" {
		t.Fatal("readonly config modified")
	}
}

func TestNotifySaveTimeoutBudget(t *testing.T) {
	f := setup(t)
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message telegramMessage
		_ = json.NewDecoder(r.Body).Decode(&message)
		<-r.Context().Done()
	}))
	c, err := alert.NewChannels(f.s, alert.Telegram{BaseURL: server.URL, Client: client}, alert.Webhook{})
	if err != nil {
		t.Fatal(err)
	}
	f.h.Config.Channels = c
	old, _ := json.Marshal(alert.TelegramSettings{Token: notifyToken, ChatID: "123"})
	if err := f.s.SetKV("notify.telegram", string(old)); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	w := f.request("POST", "/notify/telegram", f.notifyForm(notifyToken2, "456"), true)
	elapsed := time.Since(started)
	if w.Code != 200 || elapsed >= 15*time.Second || elapsed < 9*time.Second || c.Settings().ChatID != "456" || !strings.Contains(w.Body.String(), "旧渠道通知发送失败") || !strings.Contains(w.Body.String(), "确认消息发送失败") || strings.Contains(w.Body.String(), notifyToken) || strings.Contains(w.Body.String(), notifyToken2) {
		t.Fatal("save timeout budget or error handling", w.Code, elapsed)
	}
}
