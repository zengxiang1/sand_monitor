package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/eventtext"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func outageEngine(t *testing.T, total int) (*Engine, time.Time) {
	t.Helper()
	e, now := setupEngine(t)
	n, err := e.Store.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < total; i++ {
		if err = e.Store.AddNode(fmt.Sprintf("node%d", i), n.Pubkey, now); err != nil {
			t.Fatal(err)
		}
	}
	nodes, err := e.Store.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		reportNode(t, e, n.Name, now, sampleReport())
	}
	return e, now
}

func reportNode(t *testing.T, e *Engine, name string, now time.Time, r proto.Report) {
	t.Helper()
	n, err := e.Store.Node(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Store.Accept(name, n.LastSeq+1, now, "203.0.113.1", &r, func() error { return nil }, func(tx *sql.Tx, n store.Node) error { return e.Report(tx, n, r, now) }); err != nil {
		t.Fatal(err)
	}
}

func checkOffline(t *testing.T, e *Engine, now time.Time) {
	t.Helper()
	if err := e.CheckOffline(now); err != nil {
		t.Fatal(err)
	}
}

func eventDetail(t *testing.T, e *Engine, kind string) string {
	t.Helper()
	var detail string
	if err := e.Store.DB.QueryRow(`SELECT detail FROM events WHERE kind=? ORDER BY id DESC LIMIT 1`, kind).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

func TestReceiverOutageQuorum(t *testing.T) {
	for _, tc := range []struct {
		total, stopped, offline int
	}{{6, 5, 0}, {6, 4, 0}, {6, 1, 1}, {6, 3, 3}, {2, 2, 2}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			e, now := outageEngine(t, tc.total)
			nodes, err := e.Store.Nodes()
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range nodes[tc.stopped:] {
				reportNode(t, e, n.Name, now.Add(16*time.Second), sampleReport())
			}
			checkOffline(t, e, now.Add(15*time.Second))
			if count(t, e, "offline") != 0 {
				t.Fatal("threshold must be strict")
			}
			checkOffline(t, e, now.Add(16*time.Second))
			checkOffline(t, e, now.Add(17*time.Second))
			if got := count(t, e, "offline"); got != tc.offline {
				t.Fatal(got, tc.offline)
			}
			if tc.offline != 0 {
				return
			}
			r := sampleReport()
			r.Outage = &proto.Outage{Since: now.Unix(), Failures: 3}
			for _, n := range nodes[:tc.stopped] {
				reportNode(t, e, n.Name, now.Add(27*time.Second), r)
			}
			for _, n := range nodes[tc.stopped:] {
				reportNode(t, e, n.Name, now.Add(27*time.Second), sampleReport())
			}
			checkOffline(t, e, now.Add(28*time.Second))
			checkOffline(t, e, now.Add(29*time.Second))
			if count(t, e, "receiver_up") != 1 || count(t, e, "receiver_down") != 0 || count(t, e, "recovered") != 0 || count(t, e, "offline") != 0 {
				t.Fatal("unexpected outage events")
			}
			detail := eventDetail(t, e, "receiver_up")
			for _, want := range []string{"主控网络中断 27 秒", now.In(e.Store.Location).Format("15:04:05") + "–" + now.Add(27*time.Second).In(e.Store.Location).Format("15:04:05"), fmt.Sprintf("受影响 %d 个节点，已恢复 %d 个", tc.stopped, tc.stopped), fmt.Sprintf("其中 %d 个节点的 agent 报告期间持续运行、上报失败", tc.stopped)} {
				if !strings.Contains(detail, want) {
					t.Fatal(detail, want)
				}
			}
			var remaining int
			if err = e.Store.DB.QueryRow(`SELECT count(*) FROM kv WHERE key='receiver.outage'`).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatal(remaining, err)
			}
		})
	}
}

func TestReceiverOutageStaggeredAndExcludedNodes(t *testing.T) {
	e, now := outageEngine(t, 6)
	node, err := e.Store.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"offline", "never", "old", "revoked"} {
		if err = e.Store.AddNode(name, node.Pubkey, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = e.Store.DB.Exec(`UPDATE nodes SET last_seen=?1 WHERE name IN ('offline','revoked'); UPDATE nodes SET last_seen=?2 WHERE name='old'; UPDATE nodes SET revoked_at=1 WHERE name='revoked'; INSERT INTO events(ts,node,kind,detail) VALUES(?3,'offline','offline','already offline')`, now.Unix(), now.Add(-11*time.Minute).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	reportNode(t, e, "node4", now.Add(5*time.Second), sampleReport())
	reportNode(t, e, "node5", now.Add(16*time.Second), sampleReport())
	checkOffline(t, e, now.Add(16*time.Second))
	// The stale node is handled normally; the already offline node is not repeated.
	if count(t, e, "offline") != 2 {
		var events string
		_ = e.Store.DB.QueryRow(`SELECT group_concat(node) FROM events WHERE kind='offline'`).Scan(&events)
		t.Fatal("staggered members went offline, or excluded node repeated", events)
	}
	if err = e.Store.Transaction(func(tx *sql.Tx) error {
		o, err := loadOutage(tx)
		if err != nil {
			return err
		}
		if o == nil || len(o.Members) != 5 || o.Since != now.Add(5*time.Second).Unix() {
			t.Fatalf("wrong outage: %+v", o)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	checkOffline(t, e, now.Add(17*time.Second))
	if count(t, e, "offline") != 2 {
		t.Fatal("duplicate offline")
	}
}

func TestReceiverOutageLongRestartAndPartialRecovery(t *testing.T) {
	e, now := outageEngine(t, 6)
	poll := func(seconds int) {
		t.Helper()
		at := now.Add(time.Duration(seconds) * time.Second)
		reportNode(t, e, "node5", at, sampleReport())
		checkOffline(t, e, at)
	}
	poll(16)
	poll(135)
	if count(t, e, "receiver_down") != 0 {
		t.Fatal("early receiver_down")
	}
	poll(136)
	poll(140)
	if count(t, e, "receiver_down") != 1 || count(t, e, "offline") != 0 {
		t.Fatal("missing or duplicate receiver_down")
	}
	r := sampleReport()
	r.Outage = &proto.Outage{Since: now.Unix(), Failures: 8}
	reportNode(t, e, "node", now.Add(150*time.Second), r)
	// Recreate after one recovery to verify both notification and member state persist.
	e = New(e.Store, DefaultConfig())
	e.StartedAt = now.Add(150 * time.Second)
	for _, name := range []string{"node1", "node2", "node3"} {
		reportNode(t, e, name, now.Add(155*time.Second), sampleReport())
	}
	for _, seconds := range []int{220, 225, 226} {
		for _, name := range []string{"node", "node1", "node2", "node3"} {
			reportNode(t, e, name, now.Add(time.Duration(seconds)*time.Second), sampleReport())
		}
		poll(seconds)
		want := 0
		if seconds > 225 {
			want = 1
		}
		if count(t, e, "receiver_up") != want || count(t, e, "offline") != want {
			t.Fatal("wrong partial recovery deadline", seconds)
		}
	}
	detail := eventDetail(t, e, "receiver_up")
	for _, want := range []string{"主控网络中断 2 分 30 秒", "受影响 5 个节点，已恢复 4 个", "其中 1 个节点的 agent", "另有 1 个仍失联，已单独告警"} {
		if !strings.Contains(detail, want) {
			t.Fatal(detail, want)
		}
	}
	if got := eventDetail(t, e, "offline"); got != eventtext.Offline(now.Unix(), e.Store.Location) {
		t.Fatal(got)
	}
	if count(t, e, "receiver_down") != 1 || count(t, e, "recovered") != 0 {
		t.Fatal("restart repeated events")
	}
}

func TestRecoveredOutageText(t *testing.T) {
	for _, tc := range []struct {
		outage *proto.Outage
		up     float64
		want   string
	}{{&proto.Outage{Since: 1, Failures: 4}, 2, "；agent 期间持续运行，自 08:00:01 起上报失败 4 次"}, {nil, 2, "；节点期间重启过（已运行 2 秒）"}, {nil, 30, ""}} {
		t.Run(tc.want, func(t *testing.T) {
			e, now := setupEngine(t)
			e.Store.Location = time.FixedZone("test", 8*3600)
			send(t, e, now, sampleReport())
			checkOffline(t, e, now.Add(16*time.Second))
			r := sampleReport()
			r.Up, r.Outage = tc.up, tc.outage
			send(t, e, now.Add(30*time.Second), r)
			if got := eventDetail(t, e, "recovered"); got != "重新开始上报，离线 30 秒"+tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestReceiverSystemDispatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, now := setupEngine(t)
		if _, err := e.Store.DB.Exec(`UPDATE nodes SET muted_until=?1; INSERT INTO notify_cooldowns VALUES('node','connectivity',?2,1)`, now.Add(time.Hour).Unix(), now.Add(time.Hour).UnixNano()); err != nil {
			t.Fatal(err)
		}
		var messages []string
		attempts := 0
		server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			messages = append(messages, payload["text"])
			attempts++
			if attempts == 1 {
				w.WriteHeader(503)
			}
		}))
		telegram := Telegram{Instance: "测试", BaseURL: server.URL, Client: client}
		d := &Dispatcher{Store: e.Store, Scope: "security", Cooldown: time.Hour, Notifiers: staticNotifiers(telegram)}
		for _, kind := range []string{"receiver_up", "receiver_down", "receiver_up"} {
			if err := e.Store.Transaction(func(tx *sql.Tx) error { return store.AddEvent(tx, now, "", kind, "内容") }); err != nil {
				t.Fatal(err)
			}
		}
		pending, err := e.Store.Pending(10)
		if err != nil || len(pending) != 3 {
			t.Fatal(pending, err)
		}
		if err = d.Deliver(context.Background(), pending[0]); err == nil {
			t.Fatal("expected failed attempt")
		}
		if err = d.Deliver(context.Background(), pending[1]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		for _, event := range []store.Event{pending[0], pending[2]} {
			if err = d.Deliver(context.Background(), event); err != nil {
				t.Fatal(err)
			}
		}
		if len(messages) != 4 || messages[0] != "测试 · 主控 · 主控恢复：内容" || messages[1] != "测试 · 主控 · 主控中断：内容" {
			t.Fatal(messages)
		}
		pending, err = e.Store.Pending(10)
		if err != nil || len(pending) != 0 {
			t.Fatal(pending, err)
		}
	})
}

func TestReceiverMemberRecoveryTransaction(t *testing.T) {
	e, now := outageEngine(t, 3)
	checkOffline(t, e, now.Add(16*time.Second))
	r := sampleReport()
	n, err := e.Store.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback")
	err = e.Store.Transaction(func(tx *sql.Tx) error {
		if err := e.Report(tx, n, r, now.Add(20*time.Second)); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if err = e.Store.Transaction(func(tx *sql.Tx) error {
		o, err := loadOutage(tx)
		if err == nil && o.Members["node"].Recovered != 0 {
			t.Fatal("recovery escaped transaction")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverOutageNewMemberAndDeadline(t *testing.T) {
	e, now := outageEngine(t, 6)
	reportNode(t, e, "node4", now.Add(16*time.Second), sampleReport())
	reportNode(t, e, "node5", now.Add(16*time.Second), sampleReport())
	checkOffline(t, e, now.Add(16*time.Second))
	// node4 becomes silent during the outage and joins the original four.
	reportNode(t, e, "node5", now.Add(27*time.Second), sampleReport())
	checkOffline(t, e, now.Add(27*time.Second))
	if err := e.Store.Transaction(func(tx *sql.Tx) error {
		o, err := loadOutage(tx)
		if err != nil {
			return err
		}
		if len(o.Members) != 5 || o.Members["node4"].LastSeen != now.Add(16*time.Second).Unix() {
			t.Fatal("silent member not added", o)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "node1"} {
		reportNode(t, e, name, now.Add(30*time.Second), sampleReport())
	}
	// Recovered members end the outage after the straggler allowance, even if
	// most of the others never come back.
	for _, name := range []string{"node", "node1", "node5"} {
		reportNode(t, e, name, now.Add(104*time.Second), sampleReport())
	}
	checkOffline(t, e, now.Add(104*time.Second))
	if count(t, e, "receiver_up") != 0 || count(t, e, "offline") != 0 {
		t.Fatal("ended before the straggler allowance")
	}
	for _, name := range []string{"node", "node1", "node5"} {
		reportNode(t, e, name, now.Add(106*time.Second), sampleReport())
	}
	checkOffline(t, e, now.Add(106*time.Second))
	if count(t, e, "receiver_up") != 1 || count(t, e, "offline") != 3 {
		t.Fatal("allowance did not end outage")
	}
	if got := eventDetail(t, e, "offline"); got != eventtext.Offline(now.Add(16*time.Second).Unix(), e.Store.Location) {
		t.Fatal("joined member lost its own last report", got)
	}
}
