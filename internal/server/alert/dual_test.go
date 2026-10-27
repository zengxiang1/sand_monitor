package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func TestSecurityScope(t *testing.T) {
	e, now := setupEngine(t)
	calls := []string{}
	d := Dispatcher{Store: e.Store, Scope: "security", Notifiers: []Notifier{notifyFunc(func(_ context.Context, event store.Event) error { calls = append(calls, event.Kind); return nil })}}
	for _, kind := range []string{"offline", "recovered", "login_new_ip", "bin_changed", "resource", "billing", "traffic", "future-kind"} {
		result, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node',?,'test')`, now.Unix(), kind)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		if err = d.Deliver(context.Background(), store.Event{ID: id, Node: "node", Time: now.Unix(), Kind: kind}); err != nil {
			t.Fatal(err)
		}
	}
	if len(calls) != 4 {
		t.Fatal(calls)
	}
	pending, err := e.Store.Pending(20)
	if err != nil || len(pending) != 0 {
		t.Fatal(pending, err)
	}
	var count int
	if err = e.Store.DB.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil || count != 8 {
		t.Fatal(count, err)
	}
}
func TestInstanceNotifications(t *testing.T) {
	var calls int
	s, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct{ Instance, Node, Kind, Text string }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if r.URL.Path == "/hook" {
			if payload.Instance != "望楼·备" || payload.Node != "node" || payload.Kind != "offline" {
				t.Error(payload)
			}
		} else if payload.Text != "望楼·备 · node · 失联：从未上报" && payload.Text != "望楼·备 · 对端接收端 primary.example.com 不可达" {
			t.Error(payload)
		}
		calls++
		w.WriteHeader(204)
	}))
	event := store.Event{Node: "node", Kind: "offline", Detail: "从未上报"}
	for _, n := range []Notifier{Webhook{URL: s.URL + "/hook", Client: client, Instance: "望楼·备"}, Telegram{BaseURL: s.URL, Client: client, Instance: "望楼·备"}} {
		if err := n.Notify(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if err := (Telegram{BaseURL: s.URL, Client: client, Instance: "望楼·备"}).Notify(context.Background(), store.Event{Kind: "peer", Detail: "对端接收端 primary.example.com 不可达"}); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}
