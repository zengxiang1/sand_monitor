package alert

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func TestProbeGroupingAndRecovery(t *testing.T) {
	for _, muted := range []bool{false, true} {
		t.Run(map[bool]string{false: "majority", true: "muted-member"}[muted], func(t *testing.T) {
			e, now := setupEngine(t)
			n, _ := e.Store.Node("node")
			for _, name := range []string{"second", "healthy"} {
				if err := e.Store.AddNode(name, n.Pubkey, now); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.Store.DB.Exec(`UPDATE nodes SET display_name=CASE name WHEN 'node' THEN '东京' WHEN 'second' THEN '大阪' ELSE '正常' END`); err != nil {
				t.Fatal(err)
			}
			if muted {
				if _, err := e.Store.DB.Exec(`UPDATE nodes SET muted_until=? WHERE name='second'`, now.Add(24*time.Hour).Unix()); err != nil {
					t.Fatal(err)
				}
			}
			report := func(name string, at time.Time, failed bool) {
				t.Helper()
				r := sampleReport()
				p := proto.Probe{Target: "https://example.com/", Time: at.Unix(), Status: 200}
				if failed {
					p.Error, p.Status = "timeout", 0
				}
				r.Probes = []proto.Probe{p}
				n, err := e.Store.Node(name)
				if err != nil {
					t.Fatal(err)
				}
				if err = e.Store.Accept(name, n.LastSeq+1, at, "192.0.2.1", &r, func() error { return nil }, func(tx *sql.Tx, n store.Node) error { return e.Report(tx, n, r, at) }); err != nil {
					t.Fatal(err)
				}
			}
			for i := range 3 {
				at := now.Add(time.Duration(i) * proto.ProbeInterval)
				report("node", at, true)
				report("second", at, true)
				report("healthy", at, false)
			}
			var sent []store.Event
			notify := notifyFunc(func(_ context.Context, ev store.Event) error { sent = append(sent, ev); return nil })
			clock := now.Add(2*proto.ProbeInterval + 20*time.Second)
			d := &Dispatcher{Store: e.Store, Cooldown: time.Hour, Scope: "security", Now: func() time.Time { return clock }, Notifiers: staticNotifiers(notify)}
			events, err := e.Store.Pending(10)
			if err != nil || len(events) != 2 {
				t.Fatal(events, err)
			}
			if err = d.Deliver(context.Background(), events[0]); err != nil || len(sent) != 0 {
				t.Fatal("did not wait for peers", sent, err)
			}
			clock = now.Add(2*proto.ProbeInterval + 31*time.Second)
			// Cached reports keep nodes online while notifications wait.
			if _, err = e.Store.DB.Exec(`UPDATE nodes SET last_seen=?`, clock.Unix()); err != nil {
				t.Fatal(err)
			}
			for _, ev := range events {
				if err = d.Deliver(context.Background(), ev); err != nil {
					t.Fatal(err)
				}
			}
			if len(sent) != 1 || sent[0].Kind != "probe_down" {
				t.Fatal(sent)
			}
			if !muted && (!strings.Contains(sent[0].Detail, "东京、大阪") || !strings.Contains(sent[0].Detail, "疑似目标站或共同路径异常")) {
				t.Fatal("missing grouped evidence", sent)
			}
			if muted && strings.Contains(sent[0].Detail, "大阪") {
				t.Fatal("muted member leaked into group", sent)
			}
			report("node", now.Add(3*proto.ProbeInterval), false)
			report("second", now.Add(3*proto.ProbeInterval), false)
			clock = now.Add(3*proto.ProbeInterval + 30*time.Second)
			if _, err = e.Store.DB.Exec(`UPDATE nodes SET last_seen=?`, clock.Unix()); err != nil {
				t.Fatal(err)
			}
			events, err = e.Store.Pending(10)
			if err != nil || len(events) != 2 {
				t.Fatal("missing retained per-node recoveries", events, err)
			}
			for _, ev := range events {
				if err = d.Deliver(context.Background(), ev); err != nil {
					t.Fatal(err)
				}
			}
			if len(sent) != 2 || sent[1].Kind != "probe_up" || !muted && !strings.Contains(sent[1].Detail, "东京、大阪") {
				t.Fatal("grouped down suppressed recovery", sent)
			}
		})
	}
}

func TestProbeCooldownScopeAndTargets(t *testing.T) {
	e, now := setupEngine(t)
	clock := now.Add(time.Minute)
	var sent []store.Event
	notify := notifyFunc(func(_ context.Context, ev store.Event) error { sent = append(sent, ev); return nil })
	d := &Dispatcher{Store: e.Store, Cooldown: time.Hour, Scope: "security", Now: func() time.Time { return clock }, Notifiers: staticNotifiers(notify)}
	for _, item := range []struct{ kind, target string }{{"probe_down", "one"}, {"probe_up", "one"}, {"probe_down", "one"}, {"probe_up", "one"}, {"probe_down", "two"}} {
		result, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,'node',?,'test',?)`, now.Unix(), item.kind, "probe:"+item.target)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		if err = d.Deliver(context.Background(), store.Event{ID: id, Time: now.Unix(), Node: "node", Kind: item.kind, Detail: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sent) != 3 || sent[0].Kind != "probe_down" || sent[1].Kind != "probe_up" || sent[2].Kind != "probe_down" {
		t.Fatal("target cooldown or security scope", sent)
	}
}

func TestProbeGroupedDetailSurvivesRetryAndPartialDelivery(t *testing.T) {
	e, now := setupEngine(t)
	n, _ := e.Store.Node("node")
	if err := e.Store.AddNode("second", n.Pubkey, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "second"} {
		if _, err := e.Store.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name=?`, now.Unix(), name); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Store.DB.Exec(`INSERT INTO probe_alerts VALUES(?,'https://example.com/',?,3,1)`, name, now.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,?,'probe_down','individual','probe:https://example.com/')`, now.Add(-30*time.Second).Unix(), name); err != nil {
			t.Fatal(err)
		}
	}
	events, err := e.Store.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Store: e.Store, Now: func() time.Time { return now }}
	notifier := notifyFunc(func(context.Context, store.Event) error { return errors.New("offline") })
	prepared, err := d.prepare(events[0], []Notifier{notifier})
	if err != nil || !strings.Contains(prepared.Detail, "node、second") {
		t.Fatal(prepared, err)
	}
	if err = e.Store.AddNode("late", n.Pubkey, now); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Store.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name='late'`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Store.DB.Exec(`INSERT INTO probe_alerts VALUES('late','https://example.com/',?,3,1)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,'late','probe_down','late individual','probe:https://example.com/')`, now.Add(-29*time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	frozen, err := d.prepare(events[0], []Notifier{notifier})
	if err != nil || frozen.Detail != prepared.Detail {
		t.Fatal("later candidate changed frozen payload", frozen, err)
	}
	var lateNotified bool
	if err = e.Store.DB.QueryRow(`SELECT notified FROM events WHERE node='late'`).Scan(&lateNotified); err != nil || lateNotified {
		t.Fatal("late event silently merged on retry", lateNotified, err)
	}
	if err = e.Store.MarkDelivered(prepared.ID, "already-sent"); err != nil {
		t.Fatal(err)
	}
	// Recreate dispatcher after the group is no longer fresh. Its representative
	// must retain the exact group text and its channel receipt.
	now = now.Add(proto.ProbeMaxAge + time.Minute)
	d = &Dispatcher{Store: e.Store, Now: func() time.Time { return now }}
	retried, err := d.prepare(events[0], []Notifier{notifier})
	if err != nil || retried.Detail != prepared.Detail || retried.Notified {
		t.Fatal("group text lost", retried, err)
	}
	if delivered, err := e.Store.Delivered(retried.ID, "already-sent"); err != nil || !delivered {
		t.Fatal("receipt lost", delivered, err)
	}
	merged, err := d.prepare(events[1], []Notifier{notifier})
	if err != nil || !merged.Notified {
		t.Fatal("merged node event reopened", merged, err)
	}
}

func TestProbeGroupExcludesDifferentRecipientsAndDeliveredEvents(t *testing.T) {
	for _, reason := range []string{"different-targets", "second-delivered", "current-delivered", "current-recovered"} {
		t.Run(reason, func(t *testing.T) {
			e, now := setupEngine(t)
			n, _ := e.Store.Node("node")
			for _, name := range []string{"second", "third"} {
				if err := e.Store.AddNode(name, n.Pubkey, now); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"node", "second", "third"} {
				if _, err := e.Store.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name=?`, now.Unix(), name); err != nil {
					t.Fatal(err)
				}
				if _, err := e.Store.DB.Exec(`INSERT INTO probe_alerts VALUES(?,'https://example.com/',?,3,1)`, name, now.Unix()); err != nil {
					t.Fatal(err)
				}
				if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,?,'probe_down','individual','probe:https://example.com/')`, now.Add(-31*time.Second).Unix(), name); err != nil {
					t.Fatal(err)
				}
			}
			events, err := e.Store.Pending(10)
			if err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "different-targets":
				_, err = e.Store.DB.Exec(`UPDATE events SET targets='telegram' WHERE node<>'node'`)
			case "second-delivered":
				_, err = e.Store.DB.Exec(`INSERT INTO event_deliveries SELECT id,'sent' FROM events WHERE node<>'node'`)
			case "current-delivered":
				err = e.Store.MarkDelivered(events[0].ID, "sent")
			case "current-recovered":
				_, err = e.Store.DB.Exec(`UPDATE probe_alerts SET active=0 WHERE node='node'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			d := &Dispatcher{Store: e.Store, Now: func() time.Time { return now }}
			notifier := notifyFunc(func(context.Context, store.Event) error { return nil })
			prepared, err := d.prepare(events[0], []Notifier{notifier})
			if err != nil || prepared.Detail != "individual" || prepared.Notified {
				t.Fatal(prepared, err)
			}
			var grouped int
			if err = e.Store.DB.QueryRow(`SELECT count(*) FROM probe_groups`).Scan(&grouped); err != nil || grouped != 0 {
				t.Fatal("unsafe group selected", grouped, err)
			}
			var pending int
			if err = e.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE notified=0`).Scan(&pending); err != nil || pending != 3 {
				t.Fatal("another group changed without current event", pending, err)
			}
		})
	}
}

func TestProbeGroupingCountsFreshHourlyHealthyNodes(t *testing.T) {
	e, now := setupEngine(t)
	n, _ := e.Store.Node("node")
	for _, name := range []string{"second", "healthy-one", "healthy-two"} {
		if err := e.Store.AddNode(name, n.Pubkey, now); err != nil {
			t.Fatal(err)
		}
	}
	clock := now.Add(2 * proto.ProbeInterval)
	for _, name := range []string{"node", "second", "healthy-one", "healthy-two"} {
		failed := name == "node" || name == "second"
		observed := clock
		if !failed {
			observed = clock.Add(-proto.ProbeInterval)
		}
		if _, err := e.Store.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name=?`, clock.Unix(), name); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Store.DB.Exec(`INSERT INTO probe_alerts VALUES(?,'https://example.com/',?,3,?)`, name, observed.Unix(), failed); err != nil {
			t.Fatal(err)
		}
		if failed {
			if _, err := e.Store.DB.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,?,'probe_down','individual','probe:https://example.com/')`, clock.Add(-31*time.Second).Unix(), name); err != nil {
				t.Fatal(err)
			}
		}
	}
	events, err := e.Store.Pending(10)
	if err != nil || len(events) != 2 {
		t.Fatal(events, err)
	}
	d := &Dispatcher{Store: e.Store, Now: func() time.Time { return clock }}
	notifier := notifyFunc(func(context.Context, store.Event) error { return nil })
	prepared, err := d.prepare(events[0], []Notifier{notifier})
	if err != nil || prepared.Detail != "individual" {
		t.Fatal("healthy hourly observations were excluded from majority", prepared, err)
	}
	var groups int
	if err = e.Store.DB.QueryRow(`SELECT count(*) FROM probe_groups`).Scan(&groups); err != nil || groups != 0 {
		t.Fatal("half of fresh hourly nodes treated as majority", groups, err)
	}
}
