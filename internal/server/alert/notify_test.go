package alert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func TestWebhookAndTelegram(t *testing.T) {
	var calls atomic.Int32
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("request format")
		}
		var payload map[string]any
		if e := json.NewDecoder(r.Body).Decode(&payload); e != nil {
			t.Error(e)
		}
		switch r.URL.Path {
		case "/hook":
			if payload["node"] != "node" || payload["kind"] != "offline" {
				t.Error(payload)
			}
		case "/bottoken/sendMessage":
			if payload["chat_id"] != "123" || payload["text"] == "" {
				t.Error(payload)
			}
		default:
			t.Error(r.URL.Path)
		}
		calls.Add(1)
		w.WriteHeader(204)
	}))
	event := store.Event{Node: "node", Kind: "offline"}
	if e := (Webhook{URL: server.URL + "/hook", Client: client}).Notify(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	if e := (Telegram{Token: "token", ChatID: "123", BaseURL: server.URL, Client: client}).Notify(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}

type notifyFunc func(context.Context, store.Event) error

func (f notifyFunc) ID() string                                    { return "test" }
func (f notifyFunc) Notify(c context.Context, e store.Event) error { return f(c, e) }
func TestRetryThreeTimesAndMark(t *testing.T) {
	e, now := setupEngine(t)
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err := e.Store.Pending(10)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	var calls int
	d := Dispatcher{Store: e.Store, RetryDelay: time.Nanosecond, Notifiers: []Notifier{notifyFunc(func(context.Context, store.Event) error {
		calls++
		if calls < 4 {
			return errors.New("temporary")
		}
		return nil
	})}}
	if err = d.Deliver(context.Background(), events[0]); err != nil || calls != 4 {
		t.Fatal(calls, err)
	}
	pending, err := e.Store.Pending(10)
	if err != nil || len(pending) != 0 {
		t.Fatal(pending, err)
	}
}
func TestFailedNotificationRemainsPendingAndCancellation(t *testing.T) {
	e, now := setupEngine(t)
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	events, _ := e.Store.Pending(1)
	calls := 0
	d := Dispatcher{Store: e.Store, RetryDelay: time.Nanosecond, Notifiers: []Notifier{notifyFunc(func(context.Context, store.Event) error { calls++; return errors.New("failed") })}}
	if err := d.Deliver(context.Background(), events[0]); err == nil || calls != 4 {
		t.Fatal(calls, err)
	}
	pending, _ := e.Store.Pending(1)
	if len(pending) != 1 {
		t.Fatal("failed delivery lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Deliver(ctx, events[0]); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestNotificationsDoNotBlockReports(t *testing.T) {
	e, now := setupEngine(t)
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := Dispatcher{Store: e.Store, Notifiers: []Notifier{notifyFunc(func(ctx context.Context, _ store.Event) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return ctx.Err()
	})}}
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher did not start")
	}
	send(t, e, now.Add(17*time.Second), sampleReport())
	if count(t, e, "recovered") != 1 {
		t.Fatal("report blocked")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop")
	}
}
func TestWebhookFailure(t *testing.T) {
	s, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	if e := (Webhook{URL: s.URL, Client: client}).Notify(context.Background(), store.Event{}); e == nil {
		t.Fatal("ignored failure")
	}
}

type namedNotifier struct {
	name string
	notifyFunc
}

func (n namedNotifier) ID() string { return n.name }
func TestPerNotifierDeliveryPersistsAcrossRetryAndRestart(t *testing.T) {
	e, now := setupEngine(t)
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err := e.Store.Pending(1)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	first, second := 0, 0
	fail := true
	a := namedNotifier{"first", func(context.Context, store.Event) error { first++; return nil }}
	b := namedNotifier{"second", func(context.Context, store.Event) error {
		second++
		if fail {
			return errors.New("failed")
		}
		return nil
	}}
	d := Dispatcher{Store: e.Store, Notifiers: []Notifier{a, b}, RetryDelay: time.Nanosecond}
	if err = d.Deliver(context.Background(), events[0]); err == nil || first != 1 || second != 4 {
		t.Fatal(first, second, err)
	}
	// Reopen SQLite and recreate the dispatcher in reversed order: receipts
	// survive a process restart and configuration order changes.
	var databaseNumber int
	var databaseName, databasePath string
	if err = e.Store.DB.QueryRow(`PRAGMA database_list`).Scan(&databaseNumber, &databaseName, &databasePath); err != nil {
		t.Fatal(err)
	}
	if err = e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	e.Store = reopened
	d = Dispatcher{Store: e.Store, Notifiers: []Notifier{b, a}, RetryDelay: time.Nanosecond}
	fail = false
	if err = d.Deliver(context.Background(), events[0]); err != nil || first != 1 || second != 5 {
		t.Fatal(first, second, err)
	}
	if err = d.Deliver(context.Background(), events[0]); err != nil || first != 1 || second != 5 {
		t.Fatal("redelivered completed event", first, second, err)
	}
	pending, err := e.Store.Pending(1)
	if err != nil || len(pending) != 0 {
		t.Fatal(pending, err)
	}
	var receipts int
	if err = e.Store.DB.QueryRow(`SELECT count(*) FROM event_deliveries`).Scan(&receipts); err != nil || receipts != 2 {
		t.Fatal(receipts, err)
	}
	if err = e.Store.Cleanup(now.Add(8 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = e.Store.DB.QueryRow(`SELECT count(*) FROM event_deliveries`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("orphan receipts", receipts, err)
	}
}

func TestMutedEventsAreRecordedAndProcessed(t *testing.T) {
	e, now := setupEngine(t)
	if _, err := e.Store.DB.Exec(`UPDATE nodes SET muted_until=? WHERE name='node'`, now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err := e.Store.Pending(10)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	calls := 0
	d := Dispatcher{Store: e.Store, Notifiers: []Notifier{notifyFunc(func(context.Context, store.Event) error { calls++; return nil })}}
	if err = d.Deliver(context.Background(), events[0]); err != nil || calls != 0 {
		t.Fatal(calls, err)
	}
	pending, err := e.Store.Pending(10)
	if err != nil || len(pending) != 0 {
		t.Fatal(pending, err)
	}
	var count int
	if err = e.Store.DB.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil || count != 1 {
		t.Fatal("muted event lost", count, err)
	}
	if _, err = e.Store.DB.Exec(`UPDATE nodes SET muted_until=0 WHERE name='node'`); err != nil {
		t.Fatal(err)
	}
	send(t, e, now.Add(17*time.Second), sampleReport())
	pending, err = e.Store.Pending(10)
	if err != nil || len(pending) != 1 {
		t.Fatal(pending, err)
	}
	if err = d.Deliver(context.Background(), pending[0]); err != nil || calls != 1 {
		t.Fatal(calls, err)
	}
}
