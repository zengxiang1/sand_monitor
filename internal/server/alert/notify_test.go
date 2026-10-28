package alert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
			if payload["chat_id"] != "123" || payload["text"] != "望楼 · node · 失联：从未上报" {
				t.Error(payload)
			}
		default:
			t.Error(r.URL.Path)
		}
		calls.Add(1)
		w.WriteHeader(204)
	}))
	event := store.Event{Node: "node", Kind: "offline", Detail: "从未上报"}
	if e := (Webhook{URL: server.URL + "/hook", Client: client}).Notify(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	if e := (Telegram{Token: "token", ChatID: "123", BaseURL: server.URL, Client: client}).Notify(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
	var text string
	late, lateClient := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		text = payload["text"]
		w.WriteHeader(204)
	}))
	loc := time.FixedZone("CST", 8*3600)
	event.Time = time.Date(2026, 1, 2, 3, 4, 0, 0, loc).Unix()
	if e := (Telegram{Token: "token", ChatID: "123", BaseURL: late.URL, Client: lateClient, Location: loc}).Notify(context.Background(), event); e != nil || text != "望楼 · node · 失联：从未上报（发生于 01-02 03:04）" {
		t.Fatal(text, e)
	}
}

type notifyFunc func(context.Context, store.Event) error

func (f notifyFunc) Kind() string                                  { return "webhook" }
func (f notifyFunc) ID() string                                    { return "test" }
func (f notifyFunc) Notify(c context.Context, e store.Event) error { return f(c, e) }
func TestSingleAttemptAndMarkAfterRetry(t *testing.T) {
	e, now := setupEngine(t)
	send(t, e, now, sampleReport())
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err := e.Store.Pending(10)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	var calls int
	d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(notifyFunc(func(context.Context, store.Event) error {
		calls++
		if calls < 4 {
			return errors.New("temporary")
		}
		return nil
	}))}
	for attempt := 1; attempt <= 4; attempt++ {
		if attempt > 1 {
			d.mu.Lock()
			d.retries[deliveryKey{events[0].ID, "test"}] = deliveryRetry{}
			d.mu.Unlock()
		}
		err = d.Deliver(context.Background(), events[0])
		if calls != attempt || (err == nil) != (attempt == 4) {
			t.Fatal(calls, err)
		}
	}
	pending, err := e.Store.Pending(10)
	if err != nil || len(pending) != 0 {
		t.Fatal(pending, err)
	}
}
func TestFailedNotificationRemainsPendingAndCancellation(t *testing.T) {
	e, now := setupEngine(t)
	send(t, e, now, sampleReport())
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	events, _ := e.Store.Pending(1)
	calls := 0
	d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(notifyFunc(func(context.Context, store.Event) error { calls++; return errors.New("failed") }))}
	if err := d.Deliver(context.Background(), events[0]); err == nil || calls != 1 {
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
	send(t, e, now, sampleReport())
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(notifyFunc(func(ctx context.Context, _ store.Event) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return ctx.Err()
	}))}
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
	send(t, e, now, sampleReport())
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
	d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(a, b)}
	if err = d.Deliver(context.Background(), events[0]); err == nil || first != 1 || second != 1 {
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
	d = Dispatcher{Store: e.Store, Notifiers: staticNotifiers(b, a)}
	fail = false
	if err = d.Deliver(context.Background(), events[0]); err != nil || first != 1 || second != 2 {
		t.Fatal(first, second, err)
	}
	if err = d.Deliver(context.Background(), events[0]); err != nil || first != 1 || second != 2 {
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
	e.Store.RetentionDays = 7
	if err = e.Store.Cleanup(now.Add(8 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = e.Store.DB.QueryRow(`SELECT count(*) FROM event_deliveries`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("orphan receipts", receipts, err)
	}
}

func TestMutedEventsAreRecordedAndProcessed(t *testing.T) {
	e, now := setupEngine(t)
	send(t, e, now, sampleReport())
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
	d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(notifyFunc(func(context.Context, store.Event) error { calls++; return nil }))}
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

type channelNotifier struct {
	channel string
	notifyFunc
}

func (n channelNotifier) Kind() string { return n.channel }
func (n channelNotifier) ID() string   { return n.channel }
func TestBillingTrafficTargetsAndMute(t *testing.T) {
	e, now := setupEngine(t)
	send(t, e, now, sampleReport())
	if _, err := e.Store.DB.Exec(`UPDATE nodes SET muted_until=?`, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	var mu sync.Mutex
	d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(channelNotifier{"telegram", func(context.Context, store.Event) error { mu.Lock(); calls["telegram"]++; mu.Unlock(); return nil }}, channelNotifier{"webhook", func(context.Context, store.Event) error { mu.Lock(); calls["webhook"]++; mu.Unlock(); return nil }})}
	for _, kind := range []string{"billing", "traffic"} {
		result, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,targets) VALUES(?,'node',?,'','telegram')`, now.Unix(), kind)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		if err = d.Deliver(context.Background(), store.Event{ID: id, Time: now.Unix(), Node: "node", Kind: kind, Targets: "telegram"}); err != nil {
			t.Fatal(err)
		}
	}
	if calls["telegram"] != 2 || calls["webhook"] != 0 {
		t.Fatal(calls)
	}
	result, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,notified) VALUES(?,'node','billing','',1)`, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	if err = d.Deliver(context.Background(), store.Event{ID: id, Node: "node", Kind: "billing", Notified: true}); err != nil || calls["telegram"] != 2 {
		t.Fatal(calls, err)
	}
	if _, err = e.Store.DB.Exec(`UPDATE nodes SET muted_until=0`); err != nil {
		t.Fatal(err)
	}
	result, err = e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','offline','legacy')`, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	id, _ = result.LastInsertId()
	if err = d.Deliver(context.Background(), store.Event{ID: id, Node: "node", Time: now.Unix(), Kind: "offline"}); err != nil || calls["telegram"] != 3 || calls["webhook"] != 1 {
		t.Fatal(calls, err)
	}
}

func TestDispatcherBackoffDoesNotStarveNewEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _ := setupEngine(t)
		var failed, healthy atomic.Int32
		d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(
			namedNotifier{"broken", func(context.Context, store.Event) error { failed.Add(1); return errors.New("always fails") }},
			namedNotifier{"healthy", func(context.Context, store.Event) error { healthy.Add(1); return nil }},
		)}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); d.Run(ctx) }()
		defer func() { cancel(); <-done }()
		for i := range 40 {
			if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','offline','test')`, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if healthy.Load() != int32(i+1) {
				t.Fatal("new event starved", i, healthy.Load())
			}
		}
		if failed.Load() != 50 {
			t.Fatal("expected 40 first attempts and 10 retries", failed.Load())
		}
		for range 20 {
			time.Sleep(time.Second)
			synctest.Wait()
		}
		if failed.Load() != 70 || healthy.Load() != 40 {
			t.Fatal("backoff or duplicate healthy delivery", failed.Load(), healthy.Load())
		}
		for range 30 {
			time.Sleep(time.Second)
			synctest.Wait()
		}
		if failed.Load() != 81 {
			t.Fatal("retry should double to 60 seconds", failed.Load())
		}
		pending, err := e.Store.Pending(100)
		if err != nil || len(pending) != 40 {
			t.Fatal(pending, err)
		}
	})
}
func TestDispatcherSlowChannelDoesNotDelayOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _ := setupEngine(t)
		var healthy atomic.Int32
		d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(
			namedNotifier{"slow", func(ctx context.Context, _ store.Event) error { <-ctx.Done(); return ctx.Err() }},
			namedNotifier{"healthy", func(context.Context, store.Event) error { healthy.Add(1); return nil }},
		)}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); d.Run(ctx) }()
		defer func() { cancel(); <-done }()
		for range 40 {
			if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','offline','slow')`, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Second)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if healthy.Load() != 40 {
			t.Fatal("slow channel blocked new events", healthy.Load())
		}
	})
}
func TestDispatcherBackoffCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _ := setupEngine(t)
		if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','offline','test')`, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
		events, err := e.Store.Pending(1)
		if err != nil || len(events) != 1 {
			t.Fatal(events, err)
		}
		calls := 0
		d := Dispatcher{Store: e.Store, Notifiers: staticNotifiers(notifyFunc(func(context.Context, store.Event) error { calls++; return errors.New("failed") }))}
		for i, delay := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute} {
			if err = d.Deliver(context.Background(), events[0]); err == nil || calls != i+1 {
				t.Fatal(calls, err)
			}
			for range 3 {
				_ = d.Deliver(context.Background(), events[0])
			}
			if calls != i+1 {
				t.Fatal("retried during backoff", calls)
			}
			time.Sleep(delay - time.Nanosecond)
			_ = d.Deliver(context.Background(), events[0])
			if calls != i+1 {
				t.Fatal("retried early", calls)
			}
			time.Sleep(time.Nanosecond)
		}
	})
}
func TestDispatcherExpiresAndProcessesWithoutChannels(t *testing.T) {
	for _, noChannels := range []bool{false, true} {
		e, _ := setupEngine(t)
		at := time.Now()
		if !noChannels {
			at = at.Add(-24*time.Hour - time.Second)
		}
		result, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','offline','retained')`, at.Unix())
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		var calls atomic.Int32
		d := Dispatcher{Store: e.Store}
		if !noChannels {
			d.Notifiers = staticNotifiers(notifyFunc(func(context.Context, store.Event) error { calls.Add(1); return nil }))
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); d.Run(ctx) }()
		deadline := time.After(2 * time.Second)
		for {
			pending, err := e.Store.Pending(1)
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) == 0 {
				break
			}
			select {
			case <-deadline:
				cancel()
				<-done
				t.Fatal("event not processed")
			case <-time.After(time.Millisecond):
			}
		}
		cancel()
		<-done
		var detail string
		if err = e.Store.DB.QueryRow(`SELECT detail FROM events WHERE id=?`, id).Scan(&detail); err != nil || detail != "retained" || calls.Load() != 0 {
			t.Fatal(detail, calls.Load(), err)
		}
	}
}

func staticNotifiers(notifiers ...Notifier) func() []Notifier {
	return func() []Notifier { return notifiers }
}
