package alert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func TestCooldownKeysAndExemptEvents(t *testing.T) {
	engine, now := setupEngine(t)
	node, err := engine.Store.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Store.AddNode("other", node.Pubkey, now); err != nil {
		t.Fatal(err)
	}
	var sent []store.Event
	notifier := notifyFunc(func(_ context.Context, e store.Event) error { sent = append(sent, e); return nil })
	d := &Dispatcher{Store: engine.Store, Cooldown: 30 * time.Minute, Now: func() time.Time { return now }, Notifiers: staticNotifiers(notifier)}
	emit := func(node, kind, detail string) int64 {
		t.Helper()
		result, err := d.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,?,?,?)`, now.Unix(), node, kind, detail)
		if err != nil {
			t.Fatal(err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		if err = d.Deliver(context.Background(), store.Event{ID: id, Time: now.Unix(), Node: node, Kind: kind, Detail: detail}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for _, item := range []struct{ kind, detail string }{
		{"login_new_ip", "root 从 192.0.2.1 登录（首次出现的 IP）"},
		{"login_new_ip", "user 从 192.0.2.1 登录（首次出现的 IP）"},
		{"login_new_ip", "user 从 192.0.2.2 登录（首次出现的 IP）"},
		{"resource", "内存超过 90%，已持续 5 分钟"},
		{"resource", "磁盘超过 90%，已持续 5 分钟"},
		{"resource", "内存超过 90%，已持续 5 分钟"},
		{"resource", "磁盘超过 90%，已持续 5 分钟"},
	} {
		emit("node", item.kind, item.detail)
	}
	if len(sent) != 4 {
		t.Fatal("keys not independent", sent)
	}
	emit("other", "resource", "memory")
	if len(sent) != 5 {
		t.Fatal("node key not independent", sent)
	}
	for _, kind := range []string{"bin_changed", "billing", "traffic"} {
		emit("node", kind, "one")
		emit("node", kind, "two")
	}
	if len(sent) != 11 {
		t.Fatal("exempt events cooled", sent)
	}
	var suppressed, pending int
	if err = d.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE suppressed=1 AND notified=1`).Scan(&suppressed); err != nil || suppressed != 3 {
		t.Fatal(suppressed, err)
	}
	if err = d.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE notified=0`).Scan(&pending); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	// A new dispatcher and reopened database must retain decisions and counts.
	var number int
	var name, path string
	if err = d.Store.DB.QueryRow(`PRAGMA database_list`).Scan(&number, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err = d.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	d = &Dispatcher{Store: reopened, Cooldown: 30 * time.Minute, Now: func() time.Time { return now }, Notifiers: staticNotifiers(notifier)}
	emit("node", "resource", "memory")
	if len(sent) != 11 {
		t.Fatal("restart lost cooldown")
	}
	now = now.Add(30 * time.Minute)
	if err = d.Store.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	var keys int
	if err = d.Store.DB.QueryRow(`SELECT count(*) FROM notify_cooldowns`).Scan(&keys); err != nil || keys != 0 {
		t.Fatal("expired keys retained", keys, err)
	}
	emit("node", "resource", "memory")
	if len(sent) != 12 || !strings.Contains(sent[11].Detail, "（过去 30 分钟内另有 2 次，已合并）") {
		t.Fatal(sent)
	}
	now = now.Add(30 * time.Minute)
	emit("node", "resource", "memory")
	if strings.Contains(sent[len(sent)-1].Detail, "已合并") {
		t.Fatal("count repeated", sent)
	}
	d.Cooldown = 0
	emit("node", "resource", "memory")
	emit("node", "resource", "memory")
	if len(sent) != 15 {
		t.Fatal("zero cooldown", sent)
	}
}

func TestCooldownConnectivityPairAndWarnings(t *testing.T) {
	engine, now := setupEngine(t)
	var sent []store.Event
	d := &Dispatcher{Store: engine.Store, Cooldown: 30 * time.Minute, Now: func() time.Time { return now }, Notifiers: staticNotifiers(notifyFunc(func(_ context.Context, e store.Event) error { sent = append(sent, e); return nil }))}
	emit := func(kind string) int64 {
		t.Helper()
		result, err := d.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node',?,'original')`, now.Unix(), kind)
		if err != nil {
			t.Fatal(err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		if err = d.Deliver(context.Background(), store.Event{ID: id, Time: now.Unix(), Node: "node", Kind: kind, Detail: "original"}); err != nil {
			t.Fatal(err)
		}
		pending, err := d.Store.Pending(100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range pending {
			if err = d.Deliver(context.Background(), e); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	emit("offline")
	emit("recovered")
	if len(sent) != 2 || sent[0].Kind != "offline" || sent[1].Kind != "recovered" {
		t.Fatal("a single outage must send both offline and recovered", sent)
	}
	emit("offline")
	if len(sent) != 3 || sent[2].Kind != "flapping" || sent[2].Detail != "频繁掉线，30 分钟内不再推送上下线通知，面板照常记录" {
		t.Fatal(sent)
	}
	// Even after the live key has been deleted, a suppressed offline cannot produce a lone recovery.
	now = now.Add(31 * time.Minute)
	if err := d.Store.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	recovered := emit("recovered")
	var suppressed, notified bool
	if err := d.Store.DB.QueryRow(`SELECT suppressed,notified FROM events WHERE id=?`, recovered).Scan(&suppressed, &notified); err != nil || !suppressed || !notified {
		t.Fatal(suppressed, notified, err)
	}
	if len(sent) != 3 {
		t.Fatal(sent)
	}
	emit("offline")
	if len(sent) != 4 || sent[3].Kind != "offline" || !strings.Contains(sent[3].Detail, "另有 1 次，已合并") {
		t.Fatal(sent)
	}
	emit("recovered")
	if len(sent) != 5 || sent[4].Kind != "recovered" || strings.Contains(sent[4].Detail, "已合并") {
		t.Fatal(sent)
	}
	emit("offline")
	emit("recovered")
	emit("offline")
	emit("recovered")
	if len(sent) != 6 || sent[5].Kind != "flapping" {
		t.Fatal("warning missing or repeated in one window", sent)
	}
	var original int
	if err := d.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE kind IN ('offline','recovered') AND detail='original'`).Scan(&original); err != nil || original != 10 {
		t.Fatal(original, err)
	}
}

func TestCooldownMuteAndRetry(t *testing.T) {
	engine, now := setupEngine(t)
	var sent []store.Event
	fail := true
	d := &Dispatcher{Store: engine.Store, Cooldown: 30 * time.Minute, Now: func() time.Time { return now }, Notifiers: staticNotifiers(notifyFunc(func(_ context.Context, e store.Event) error {
		if fail {
			return errors.New("unavailable")
		}
		sent = append(sent, e)
		return nil
	}))}
	if _, err := d.Store.DB.Exec(`UPDATE nodes SET muted_until=?; INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,'node','login_new_ip','first','login:192.0.2.1')`, now.Add(time.Hour).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	pending, err := d.Store.Pending(100)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Deliver(context.Background(), pending[0]); err != nil {
		t.Fatal(err)
	}
	var keys int
	if err = d.Store.DB.QueryRow(`SELECT count(*) FROM notify_cooldowns`).Scan(&keys); err != nil || keys != 0 {
		t.Fatal("mute counted", keys, err)
	}
	if _, err = d.Store.DB.Exec(`UPDATE nodes SET muted_until=0; INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,'node','login_new_ip','second','login:192.0.2.1')`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pending, err = d.Store.Pending(100)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Deliver(context.Background(), pending[0]); err == nil {
		t.Fatal("expected send failure")
	}
	fail = false
	// Restart clears memory backoff, while the saved decision prevents self-suppression.
	d = &Dispatcher{Store: engine.Store, Cooldown: 30 * time.Minute, Now: func() time.Time { return now }, Notifiers: d.Notifiers}
	if err = d.Deliver(context.Background(), pending[0]); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].Detail != "second" {
		t.Fatal(sent)
	}
	if _, err = d.Store.DB.Exec(`UPDATE nodes SET muted_until=?;INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,'node','login_new_ip','third','login:192.0.2.1')`, now.Add(time.Hour).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	pending, err = d.Store.Pending(100)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Deliver(context.Background(), pending[0]); err != nil {
		t.Fatal(err)
	}
	var suppressed int
	if err = d.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE suppressed=1`).Scan(&suppressed); err != nil || suppressed != 0 {
		t.Fatal("muted event counted", suppressed, err)
	}
}

func TestDisplayNameNotificationFormats(t *testing.T) {
	engine, now := setupEngine(t)
	if _, err := engine.Store.DB.Exec(`UPDATE nodes SET display_name='东京一号';INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','bin_changed','changed')`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var texts []string
	var hooks []store.Event
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/hook" {
			var e store.Event
			if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
				t.Error(err)
			}
			hooks = append(hooks, e)
		} else {
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			texts = append(texts, payload["text"])
		}
		w.WriteHeader(204)
	}))
	d := &Dispatcher{Store: engine.Store, Notifiers: staticNotifiers(Telegram{Token: "token", ChatID: "123", BaseURL: server.URL, Client: client}, Webhook{URL: server.URL + "/hook", Client: client})}
	pending, err := d.Store.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Deliver(context.Background(), pending[0]); err != nil {
		t.Fatal(err)
	}
	if len(texts) != 1 || texts[0] != "望楼 · 东京一号 · 二进制变化：changed" || len(hooks) != 1 || hooks[0].Node != "node" || hooks[0].DisplayName != "东京一号" {
		t.Fatal(texts, hooks)
	}
	if err := (Telegram{Token: "token", ChatID: "123", BaseURL: server.URL, Client: client}).Notify(context.Background(), store.Event{Node: "node", DisplayName: "东京一号", Kind: "flapping", Detail: "频繁掉线，30 分钟内不再推送上下线通知，面板照常记录"}); err != nil {
		t.Fatal(err)
	}
	if texts[1] != "望楼 · 东京一号 频繁掉线，30 分钟内不再推送上下线通知，面板照常记录" {
		t.Fatal(texts)
	}
}

func TestEnginePersistsCooldownKeys(t *testing.T) {
	engine, now := setupEngine(t)
	engine.Config.Sustain = 5 * time.Second
	r := sampleReport()
	r.Mem = [2]float64{95, 100}
	r.Disk = [2]float64{95, 100}
	send(t, engine, now, r)
	r.Login = []proto.Login{{User: "root 从 假IP 登录", From: "192.0.2.5", Time: now.Add(5 * time.Second).Unix()}}
	send(t, engine, now.Add(5*time.Second), r)
	rows, err := engine.Store.DB.Query(`SELECT kind,cooldown_key FROM events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	keys := map[string]bool{}
	for rows.Next() {
		var kind, key string
		if err := rows.Scan(&kind, &key); err != nil {
			t.Fatal(err)
		}
		keys[kind+":"+key] = true
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"login_new_ip:login:192.0.2.5", "resource:resource:memory", "resource:resource:disk"} {
		if !keys[key] {
			t.Fatal(keys)
		}
	}
}

func TestCooldownQueuePreservesEventOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		engine, now := setupEngine(t)
		for i := 0; i < 40; i++ {
			kind := "offline"
			if i%2 == 1 {
				kind = "recovered"
			}
			if _, err := engine.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node',?,'queued')`, now.Unix(), kind); err != nil {
				t.Fatal(err)
			}
		}
		var mu sync.Mutex
		var sent []store.Event
		d := &Dispatcher{Store: engine.Store, Cooldown: 30 * time.Minute, Notifiers: staticNotifiers(notifyFunc(func(_ context.Context, e store.Event) error {
			mu.Lock()
			defer mu.Unlock()
			sent = append(sent, e)
			return nil
		}))}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { d.Run(ctx); close(done) }()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		if len(sent) != 3 {
			t.Fatal(sent)
		}
		warnings := 0
		for _, event := range sent {
			if event.Kind == "flapping" {
				warnings++
			} else if !(event.Kind == "offline" && event.ID == 1 || event.Kind == "recovered" && event.ID == 2) {
				t.Fatal("out of order decision", event)
			}
		}
		if warnings != 1 {
			t.Fatal(sent)
		}
		var suppressed int
		if err := engine.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE suppressed=1 AND notified=1`).Scan(&suppressed); err != nil || suppressed != 38 {
			t.Fatal(suppressed, err)
		}
	})
}
