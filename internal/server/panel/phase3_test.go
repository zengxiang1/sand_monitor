package panel

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func TestBillingValidationSaveRenewAndOverview(t *testing.T) {
	f := setup(t)
	f.s.Location = time.UTC
	f.now = time.Date(2026, 1, 28, 12, 0, 0, 0, time.UTC)
	if _, err := f.s.DB.Exec(`UPDATE sessions SET created_at=?,last_seen=?`, f.now.Unix(), f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	form := billingForm(store.DefaultBilling("node"))
	form.Set("csrf", f.csrf)
	form.Set("expiry", "2026-01-31")
	form.Set("price", "58.00")
	form.Set("provider", "Example provider")
	form.Set("quota_gb", "1000")
	form.Set("calibrate", "930")
	form["notify"] = []string{"telegram", "webhook"}
	for _, tc := range []struct{ k, v string }{{"expiry", "2026-02-31"}, {"price", "-1"}, {"price", "1e2"}, {"price", "12345678"}, {"quota_gb", "1.5"}, {"quota_gb", "10000001"}, {"reset_day", "29"}, {"cycle", "weekly"}, {"currency", "JPY"}, {"direction", "unknown"}, {"remind_days", "2"}, {"remind_pct", "81"}, {"notify", "email"}, {"provider", strings.Repeat("字", 65)}, {"calibrate", "NaN"}} {
		values := append([]string(nil), form[tc.k]...)
		form.Set(tc.k, tc.v)
		w := f.request("POST", "/billing/node", form, true)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "role=\"alert\"") {
			t.Fatal(tc, w.Code, w.Body)
		}
		if tc.k == "provider" && !strings.Contains(w.Body.String(), tc.v) {
			t.Fatal("form values lost")
		}
		form[tc.k] = values
	}
	w := f.request("POST", "/billing/node", form, true)
	if w.Code != 303 || w.Header().Get("Location") != "/billing?edit=node&saved=1" {
		t.Fatal(w.Code, w.Body)
	}
	b, err := f.s.Billing("node")
	if err != nil || b.Price != "58.00" || b.Notify != "telegram,webhook" || b.AnchorDay != 31 {
		t.Fatal(b, err)
	}
	tr, err := f.s.Traffic("node")
	if err != nil || store.Counted(tr, b.Direction) != 930000000000 {
		t.Fatal(tr, err)
	}
	for _, path := range []string{"/billing?edit=node&saved=1", "/"} {
		w = f.request("GET", path, nil, true)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body)
		}
		for _, text := range []string{"续费与流量", "93%", "3 天后到期"} {
			if !strings.Contains(w.Body.String(), text) {
				t.Fatal("missing", path, text)
			}
		}
		checkHeaders(t, w)
	}
	if w = f.request("POST", "/billing/node/renewed", url.Values{"csrf": {f.csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	b, _ = f.s.Billing("node")
	if b.Expiry != "2026-02-28" || b.AnchorDay != 31 {
		t.Fatal(b.Expiry)
	}
	form.Set("cycle", "once")
	if w = f.request("POST", "/billing/node", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	w = f.request("GET", "/billing?edit=node", nil, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), "已续费一期") {
		t.Fatal(w.Code, w.Body)
	}
	if w = f.request("POST", "/billing/node/renewed", url.Values{"csrf": {f.csrf}}, true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	f.h.Config.Channels = nil
	form["notify"] = []string{"telegram"}
	if w = f.request("POST", "/billing/node", form, true); w.Code != 400 {
		t.Fatal("unconfigured channel accepted", w.Code)
	}
	w = f.request("GET", "/billing?edit=node", nil, true)
	if !strings.Contains(w.Body.String(), "未配置任何通知渠道") {
		t.Fatal(w.Body)
	}
	for _, action := range []string{"billing_save", "billing_renewed", "traffic_calibrate"} {
		var n int
		if err = f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil || n == 0 {
			t.Fatal(action, n, err)
		}
	}
}
func publicForm(f *fixture) url.Values {
	return url.Values{"csrf": {f.csrf}, "title": {"服务器状态"}, "interval": {"30"}, "access": {"public"}, "public_node": {"true"}, "name_node": {"公开一号"}, "specs": {"true"}, "usage": {"true"}, "net": {"true"}, "uptime": {"true"}, "availability": {"true"}, "reason": {"true"}}
}
func TestPublicDraftPublishedPreviewAndToken(t *testing.T) {
	f := setup(t)
	dir := t.TempDir()
	f.h.Config.PublicDir = dir
	f.h.Config.PublicURL = "https://status.example.com"
	f.h.Config.Exporter = &status.Exporter{Store: f.s, Dir: dir}
	form := publicForm(f)
	for _, tc := range []struct{ k, v string }{{"name_node", ""}, {"name_node", strings.Repeat("字", 33)}, {"title", strings.Repeat("字", 41)}, {"interval", "1"}, {"access", "password"}} {
		values := append([]string(nil), form[tc.k]...)
		form.Set(tc.k, tc.v)
		w := f.request("POST", "/public", form, true)
		if w.Code != 400 {
			t.Fatal(tc, w.Code, w.Body)
		}
		form[tc.k] = values
	}
	if w := f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	draft, err := f.s.KV("public.draft")
	if err != nil || draft == "" {
		t.Fatal(err)
	}
	published, _ := f.s.KV("public.published")
	if published != "" {
		t.Fatal("draft auto-published")
	}
	if _, err = os.Stat(filepath.Join(dir, "index.html")); !os.IsNotExist(err) {
		t.Fatal("draft exported", err)
	}
	w := f.request("GET", "/public", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "有未发布的修改") || !strings.Contains(w.Body.String(), "公开一号") {
		t.Fatal(w.Code, w.Body)
	}
	w = f.request("GET", "/public/preview", nil, true)
	checkHeaders(t, w)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "预览 · 未发布") || !strings.Contains(w.Body.String(), `href="/static/status.css"`) || !strings.Contains(w.Body.String(), "公开一号") {
		t.Fatal(w.Code, w.Body)
	}
	w = f.request("GET", "/static/status.css", nil, false)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/css") {
		t.Fatal(w.Code)
	}
	form.Set("publish", "1")
	if w = f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	draft, _ = f.s.KV("public.draft")
	published, _ = f.s.KV("public.published")
	if draft != published {
		t.Fatal("published differs")
	}
	if _, err = os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatal("publish did not export immediately", err)
	}
	form.Set("access", "token")
	if w = f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c, err := status.Load(f.s, "public.published")
	if err != nil {
		t.Fatal(err)
	}
	old := c.Token
	if _, err = os.Stat(filepath.Join(dir, old, "index.html")); err != nil {
		t.Fatal(err)
	}
	if w = f.request("POST", "/public/token", url.Values{"csrf": {f.csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c, _ = status.Load(f.s, "public.draft")
	if len(c.Token) != 22 || c.Token == old {
		t.Fatal("token unchanged")
	}
	live, _ := status.Load(f.s, "public.published")
	if live.Token != old {
		t.Fatal("token changed before publish")
	}
	w = f.request("GET", "/public", nil, true)
	if !strings.Contains(w.Body.String(), "https://status.example.com/"+c.Token+"/") {
		t.Fatal("token link missing")
	}
	if w = f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	if _, err = os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Fatal("old token retained", err)
	}
	if _, err = os.Stat(filepath.Join(dir, c.Token, "index.html")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/index.html", "/status.json", "/status.css", "/" + c.Token + "/"} {
		for _, handler := range []http.Handler{f.h, f.h.Ingest} {
			r := httptest.NewRequest("GET", path, nil)
			r.AddCookie(f.cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 404 {
				t.Fatal("public HTTP route exists", path, w.Code)
			}
		}
	}
}
func TestAnnouncementsCRUDLimitAndAudit(t *testing.T) {
	f := setup(t)
	form := publicForm(f)
	if w := f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	a := url.Values{"csrf": {f.csrf}, "title": {"事件"}, "body": {"排查中"}, "node": {"node"}, "status": {"investigating"}, "time": {f.now.In(f.s.Location).Format("2006-01-02T15:04")}}
	for _, tc := range []struct{ k, v string }{{"title", ""}, {"body", ""}, {"title", strings.Repeat("字", 81)}, {"body", strings.Repeat("字", 1001)}, {"node", "missing"}, {"time", "invalid"}, {"status", "unknown"}, {"id", "999"}} {
		values := append([]string(nil), a[tc.k]...)
		a.Set(tc.k, tc.v)
		w := f.request("POST", "/public/announcements", a, true)
		if w.Code != 400 {
			t.Fatal(tc, w.Code, w.Body)
		}
		if values == nil {
			a.Del(tc.k)
		} else {
			a[tc.k] = values
		}
	}
	if w := f.request("POST", "/public/announcements", a, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c, _ := status.Load(f.s, "public.draft")
	if len(c.Announcements) != 1 {
		t.Fatal(c)
	}
	id := strconv.FormatInt(c.Announcements[0].ID, 10)
	w := f.request("GET", "/public?edit_ann="+id, nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `value="事件"`) {
		t.Fatal(w.Code, w.Body)
	}
	a.Set("id", id)
	a.Set("title", "已恢复")
	a.Set("status", "resolved")
	if w = f.request("POST", "/public/announcements", a, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c, _ = status.Load(f.s, "public.draft")
	if len(c.Announcements) != 1 || c.Announcements[0].Title != "已恢复" {
		t.Fatal(c)
	}
	if w = f.request("POST", "/public/announcements/"+id+"/delete", url.Values{"csrf": {f.csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c, _ = status.Load(f.s, "public.draft")
	if len(c.Announcements) != 0 {
		t.Fatal(c)
	}
	for i := range 100 {
		c.Announcements = append(c.Announcements, status.Announcement{ID: int64(i + 1), Title: fmt.Sprint(i), Body: "内容", Status: "resolved", Time: f.now.Format(time.RFC3339)})
	}
	if err := status.Save(f.s, c, false, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	a.Del("id")
	if w = f.request("POST", "/public/announcements", a, true); w.Code != 400 || !strings.Contains(w.Body.String(), "最多 100 条公告") {
		t.Fatal(w.Code, w.Body)
	}
	for _, action := range []string{"public_draft", "public_announcement_add", "public_announcement_edit", "public_announcement_delete"} {
		var n int
		if err := f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil || n == 0 {
			t.Fatal(action, n, err)
		}
	}
}
func TestPhaseThreeAllPostsRequireCSRFAndOrigin(t *testing.T) {
	f := setup(t)
	for _, entry := range routes {
		if !strings.HasPrefix(entry.pattern, "POST /billing") && !strings.HasPrefix(entry.pattern, "POST /public") {
			continue
		}
		_, path, _ := strings.Cut(entry.pattern, " ")
		path = strings.NewReplacer("{name}", "node", "{id}", "1").Replace(path)
		if w := f.request("POST", path, url.Values{}, true); w.Code != 403 {
			t.Fatal(path, w.Code)
		}
		r := httptest.NewRequest("POST", "https://panel.example.com"+path, strings.NewReader(url.Values{"csrf": {f.csrf}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(f.cookie)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("origin", path, w.Code)
		}
	}
}

func TestBillingScheduleAndHeartbeatOverview(t *testing.T) {
	f := setup(t)
	f.s.Location = time.UTC
	f.now = f.now.Truncate(24 * time.Hour).Add(10 * time.Hour)
	if _, err := f.s.DB.Exec(`UPDATE sessions SET created_at=?,last_seen=?`, f.now.Unix(), f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	b := store.DefaultBilling("node")
	b.Expiry = f.now.AddDate(0, 0, 3).Format("2006-01-02")
	b.QuotaGB = 1000
	b.Notify = "telegram,webhook"
	calibration := uint64(960000000000)
	if err := f.s.SaveBilling(b, &calibration, f.now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.s.CheckReminders(f.now); err != nil {
		t.Fatal(err)
	}
	w := f.request("GET", "/billing", nil, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, text := range []string{"还有 3 天到期，需要手动续费", "本周期流量用到 95%", "已发送 · Telegram、Webhook"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatal("missing", text)
		}
	}
	if strings.Count(w.Body.String(), "本周期流量用到 95%") != 1 || strings.Contains(w.Body.String(), "本周期流量用到 80%") {
		t.Fatal("threshold history not collapsed", w.Body)
	}
	overview := f.request("GET", "/", nil, true)
	if overview.Code != 200 {
		t.Fatal(overview.Code, overview.Body)
	}
	row := regexp.MustCompile(`(?s)<div class="traffic-summary-row">.*?</div>`).FindString(overview.Body.String())
	if !strings.Contains(row, `<svg class="traffic-bar danger"`) || !strings.Contains(row, `width="96"`) || !strings.Contains(row, "96%") {
		t.Fatal("overview traffic progress missing", row)
	}
	f.h.Config.HeartbeatURL = "https://example.invalid/heartbeat-marker"
	f.h.Config.HeartbeatStatus = func(time.Time) string { return "失败（3 分钟前成功过）" }
	w = f.request("GET", "/", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "外部心跳") || !strings.Contains(w.Body.String(), "失败（3 分钟前成功过）") || strings.Contains(w.Body.String(), "heartbeat-marker") {
		t.Fatal(w.Code, w.Body)
	}
}

func TestBillingCalibrationGETIsEmpty(t *testing.T) {
	f := setup(t)
	f.report(t, "node", sampleReport(), 204)
	form := billingForm(store.DefaultBilling("node"))
	form.Set("csrf", f.csrf)
	form.Set("calibrate", "930")
	w := f.request("POST", "/billing/node", form, true)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	for _, path := range []string{w.Header().Get("Location"), "/billing?edit=node&calibrate=930"} {
		w = f.request("GET", path, nil, true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		match := regexp.MustCompile(`<input name="calibrate"[^>]*>`).FindString(w.Body.String())
		if !strings.Contains(match, `value=""`) || !strings.Contains(match, `placeholder="930.000"`) {
			t.Fatal("calibration should be an empty input with current usage as placeholder", match)
		}
	}
	f.now = f.now.Add(5 * time.Second)
	report := sampleReport()
	report.Up += 5
	report.NetTotal = [2]uint64{1000000000, 2000000000}
	f.report(t, "node", report, 204)
	form.Set("calibrate", "")
	if w = f.request("POST", "/billing/node", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	tr, err := f.s.Traffic("node")
	if err != nil || store.Counted(tr, "both") != 933000000000 {
		t.Fatal("empty calibration discarded new usage", tr, err)
	}
	form.Set("calibrate", "940")
	form.Set("expiry", "invalid")
	w = f.request("POST", "/billing/node", form, true)
	if w.Code != 400 || !strings.Contains(regexp.MustCompile(`<input name="calibrate"[^>]*>`).FindString(w.Body.String()), `value="940"`) {
		t.Fatal("validation error lost typed calibration", w.Code, w.Body)
	}
}

func TestBillingUnsetAndSelectOrder(t *testing.T) {
	f := setup(t)
	w := f.request("GET", "/billing?edit=node", nil, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	row := regexp.MustCompile(`(?s)<tbody><tr>.*?</tr>`).FindString(w.Body.String())
	if !strings.Contains(row, "0 GB") || !strings.Contains(row, "未设置账单 · 只记录用量") {
		t.Fatal(row)
	}
	for _, text := range []string{"不统计额度", "每月 1 日重置", "上下行合计", "节点失联，统计暂停"} {
		if strings.Contains(row, text) {
			t.Fatal("unconfigured billing showed", text, row)
		}
	}
	for _, tc := range []struct {
		name string
		want []string
	}{{"direction", []string{"both", "out", "in", "max"}}, {"currency", []string{"CNY", "USD", "EUR"}}} {
		selectHTML := regexp.MustCompile(`(?s)<select name="` + tc.name + `"[^>]*>(.*?)</select>`).FindString(w.Body.String())
		options := regexp.MustCompile(`<option value="([^"]+)"`).FindAllStringSubmatch(selectHTML, -1)
		got := []string{}
		for _, option := range options {
			got = append(got, option[1])
		}
		if !slices.Equal(got, tc.want) {
			t.Fatal(tc.name, got)
		}
	}
	for _, label := range []string{"上行 + 下行合计", "只算上行（出站）", "只算下行（入站）", "取两者中较大的", "¥", "$", "€"} {
		if !strings.Contains(html.UnescapeString(w.Body.String()), ">"+label+"</option>") {
			t.Fatal("missing select label", label)
		}
	}
	w = f.request("GET", "/public", nil, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, tc := range []struct {
		name string
		want []string
	}{{"status", []string{"investigating", "monitoring", "resolved", "scheduled", "done"}}, {"interval", []string{"30", "60", "300"}}} {
		selectHTML := regexp.MustCompile(`(?s)<select[^>]*name="` + tc.name + `"[^>]*>(.*?)</select>`).FindString(w.Body.String())
		options := regexp.MustCompile(`<option value="([^"]+)"`).FindAllStringSubmatch(selectHTML, -1)
		got := []string{}
		for _, option := range options {
			got = append(got, option[1])
		}
		if !slices.Equal(got, tc.want) {
			t.Fatal(tc.name, got)
		}
	}
}

func TestPublicPublishFeedback(t *testing.T) {
	f := setup(t)
	form := publicForm(f)
	w := f.request("POST", "/public", form, true)
	if w.Code != 303 || w.Header().Get("Location") != "/public?saved=1" {
		t.Fatal(w.Code, w.Header(), w.Body)
	}
	form.Set("publish", "1")
	for _, interval := range []string{"30", "60", "300"} {
		form.Set("interval", interval)
		w = f.request("POST", "/public", form, true)
		if w.Code != 303 || w.Header().Get("Location") != "/public?published=1" {
			t.Fatal(w.Code, w.Header(), w.Body)
		}
		w = f.request("GET", w.Header().Get("Location"), nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "已发布。公开页会在 "+interval+" 秒内更新。") || strings.Contains(w.Body.String(), "有未发布的修改") {
			t.Fatal(w.Code, w.Body)
		}
	}
}
