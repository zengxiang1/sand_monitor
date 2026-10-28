package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

const channelToken = "123456:abcdefghijklmnopqrstuvwxyz_ABCD1234"

func TestChannelsReloadCacheAndFilePrecedence(t *testing.T) {
	e, _ := setupEngine(t)
	c, err := NewChannels(e.Store, Telegram{}, Webhook{URL: "https://hook.example.invalid"})
	if err != nil || len(c.Notifiers()) != 1 || c.Settings().Token != "" || c.ReadOnly() || c.APIBase() != "https://api.telegram.org" {
		t.Fatal("initial channels", err)
	}
	settings := TelegramSettings{Token: channelToken, ChatID: "123", UpdatedBy: "admin", UpdatedAt: time.Now().Unix()}
	raw, _ := json.Marshal(settings)
	if err := e.Store.SetKV("notify.telegram", string(raw)); err != nil {
		t.Fatal(err)
	}
	if len(c.Notifiers()) != 1 {
		t.Fatal("settings changed without explicit reload")
	}
	if err := c.Reload(); err != nil || c.Settings() != settings || strings.Join(c.Names(), ",") != "Telegram,Webhook" {
		t.Fatal("reload did not apply settings", err)
	}
	firstID := c.Notifiers()[0].ID()
	notifiers := c.Notifiers()
	notifiers[0] = nil
	if c.Notifiers()[0] == nil {
		t.Fatal("caller mutated cached channels")
	}
	restarted, err := NewChannels(e.Store, Telegram{}, Webhook{})
	if err != nil || restarted.Settings() != settings {
		t.Fatal("panel configuration did not survive restart", err)
	}
	for _, raw := range []string{"{", `{"token":123}`, `{"token":"` + channelToken + `","chat_id":"invalid"}`} {
		if err := e.Store.SetKV("notify.telegram", raw); err != nil {
			t.Fatal(err)
		}
		if c.Settings() != settings || len(c.Notifiers()) != 2 {
			t.Fatal("reading cached channels accessed KV")
		}
		if err := c.Reload(); err == nil || strings.Contains(err.Error(), channelToken) || c.Settings() != settings {
			t.Fatal("reload must safely reject invalid KV and preserve snapshot")
		}
	}
	damaged, err := NewChannels(e.Store, Telegram{}, Webhook{URL: "https://hook.example.invalid"})
	if err != nil || damaged.Settings().Token != "" || len(damaged.Notifiers()) != 1 || damaged.Notifiers()[0].Kind() != "webhook" {
		t.Fatal("invalid stored settings must not stop startup or other channels", err)
	}
	file, err := NewChannels(e.Store, Telegram{Token: channelToken, ChatID: "456", BaseURL: "https://proxy.example.invalid"}, Webhook{})
	if err != nil || !file.ReadOnly() || file.Settings().ChatID != "456" || file.Notifiers()[0].Kind() != "telegram" {
		t.Fatal("file configuration did not ignore invalid KV", err)
	}
	if err := file.Reload(); err != nil {
		t.Fatal(err)
	}
	if firstID == file.Notifiers()[0].ID() || firstID == c.Telegram(TelegramSettings{Token: channelToken, ChatID: "456"}).ID() || firstID == c.Telegram(TelegramSettings{Token: channelToken + "x", ChatID: "123"}).ID() {
		t.Fatal("Telegram identity did not change with configuration")
	}
}

func TestChannelsConcurrentReadsAndReload(t *testing.T) {
	e, _ := setupEngine(t)
	c, err := NewChannels(e.Store, Telegram{}, Webhook{})
	if err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 100 {
				_ = c.Notifiers()
				_ = c.Settings()
				_ = c.Names()
			}
		})
	}
	for i := range 20 {
		if i%2 == 0 {
			raw, _ := json.Marshal(TelegramSettings{Token: channelToken, ChatID: "123"})
			err = e.Store.SetKV("notify.telegram", string(raw))
		} else {
			_, err = e.Store.DB.Exec(`DELETE FROM kv WHERE key='notify.telegram'`)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}

func TestDispatcherRunObservesChannelReload(t *testing.T) {
	e, now := setupEngine(t)
	var calls atomic.Int32
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	c, err := NewChannels(e.Store, Telegram{BaseURL: server.URL, Client: client}, Webhook{})
	if err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Store: e.Store, Notifiers: c.Notifiers}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	defer func() { cancel(); <-done }()
	queue := func(kind string) {
		t.Helper()
		if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,targets) VALUES(?,'node',?,'runtime','telegram')`, now.Unix(), kind); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(3 * time.Second)
		for {
			pending, err := e.Store.Pending(1)
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) == 0 {
				return
			}
			select {
			case <-deadline:
				t.Fatal("dispatcher did not drain queue")
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	queue("offline")
	raw, _ := json.Marshal(TelegramSettings{Token: channelToken, ChatID: "123"})
	if err := e.Store.SetKV("notify.telegram", string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	queue("billing")
	if calls.Load() != 1 {
		t.Fatal("reload failed or historical event replayed", calls.Load())
	}
	if _, err := e.Store.DB.Exec(`DELETE FROM kv WHERE key='notify.telegram'`); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	queue("traffic")
	if calls.Load() != 1 {
		t.Fatal("disabled channel received a notification")
	}
}

func TestTelegramErrorsNeverExposeToken(t *testing.T) {
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/truncated/") {
			w.Header().Set("Content-Length", "8192")
		} else {
			w.WriteHeader(401)
		}
		_, _ = w.Write([]byte(channelToken))
	}))
	for _, base := range []string{server.URL, server.URL + "/truncated", "http://[invalid", "invalid://"} {
		err := (Telegram{Token: channelToken, ChatID: "123", BaseURL: base, Client: client}).Notify(context.Background(), store.Event{Kind: "offline"})
		if err == nil || strings.Contains(err.Error(), channelToken) {
			t.Fatal("unsafe Telegram error")
		}
	}
}
