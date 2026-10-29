package alert

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func setupEngine(t *testing.T) (*Engine, time.Time) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Truncate(time.Second)
	if e = s.AddNode("node", pub, now); e != nil {
		t.Fatal(e)
	}
	engine := New(s, DefaultConfig())
	engine.StartedAt = now.Add(-time.Hour)
	return engine, now
}
func sampleReport() proto.Report {
	return proto.Report{Version: 1, Up: 864000, Bin: "sha256:" + strings.Repeat("a", 64), OS: "linux", Arch: "amd64", Mem: [2]float64{10, 100}, Disk: [2]float64{10, 100}, Login: []proto.Login{}}
}
func send(t *testing.T, e *Engine, now time.Time, r proto.Report) {
	t.Helper()
	n, err := e.Store.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	err = e.Store.Accept("node", n.LastSeq+1, now, "203.0.113.1", &r, func() error { return nil }, func(tx *sql.Tx, n store.Node) error { return e.Report(tx, n, r, now) })
	if err != nil {
		t.Fatal(err)
	}
}
func count(t *testing.T, e *Engine, kind string) int {
	t.Helper()
	var n int
	if err := e.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE kind=?`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOfflineStartupGrace(t *testing.T) {
	for _, interval := range []time.Duration{time.Second, 5 * time.Second, 20 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			e, now := setupEngine(t)
			send(t, e, now, sampleReport())
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Store.AddNode("never-reported", pub, now); err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			e = New(e.Store, DefaultConfig())
			if e.StartedAt.Before(before) || e.StartedAt.After(time.Now()) {
				t.Fatal("missing process start time", e.StartedAt)
			}
			e.Config.Interval = interval
			e.StartedAt = now.Add(time.Hour)
			grace := 3*interval + time.Minute
			for _, elapsed := range []time.Duration{0, 3 * interval, grace - time.Nanosecond} {
				if err := e.CheckOffline(e.StartedAt.Add(elapsed)); err != nil {
					t.Fatal(err)
				}
				if got := count(t, e, "offline"); got != 0 {
					t.Fatal("offline during startup grace", elapsed, got)
				}
			}
			for _, elapsed := range []time.Duration{grace, grace + time.Second} {
				if err := e.CheckOffline(e.StartedAt.Add(elapsed)); err != nil {
					t.Fatal(err)
				}
				if got := count(t, e, "offline"); got != 2 {
					t.Fatal("missing or duplicate offline after grace", elapsed, got)
				}
			}
		})
	}
}

func TestReportDuringStartupGrace(t *testing.T) {
	e, now := setupEngine(t)
	send(t, e, now, sampleReport())
	e = New(e.Store, DefaultConfig())
	e.StartedAt = now.Add(time.Hour)
	if err := e.CheckOffline(e.StartedAt); err != nil {
		t.Fatal(err)
	}
	send(t, e, e.StartedAt.Add(time.Minute), sampleReport())
	if err := e.CheckOffline(e.StartedAt.Add(3*e.Config.Interval + time.Minute)); err != nil {
		t.Fatal(err)
	}
	if count(t, e, "offline") != 0 || count(t, e, "recovered") != 0 {
		t.Fatal("server restart created an offline/recovered pair")
	}
}

func TestOfflineRecovered(t *testing.T) {
	e, now := setupEngine(t)
	r := sampleReport()
	send(t, e, now, r)
	for _, seconds := range []int{15, 16, 20} {
		if err := e.CheckOffline(now.Add(time.Duration(seconds) * time.Second)); err != nil {
			t.Fatal(err)
		}
		want := 0
		if seconds > 15 {
			want = 1
		}
		if count(t, e, "offline") != want {
			t.Fatal(seconds)
		}
	}
	// Engine recreation uses persisted state and does not repeat an event.
	e = New(e.Store, DefaultConfig())
	e.StartedAt = now.Add(21 * time.Second)
	if err := e.CheckOffline(now.Add(21 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if count(t, e, "offline") != 1 {
		t.Fatal("duplicate offline")
	}
	if state, err := e.Store.Node("node"); err != nil || state.LastSeen != now.Unix() {
		t.Fatal("startup grace changed the node", state, err)
	}
	send(t, e, now.Add(22*time.Second), r)
	send(t, e, now.Add(23*time.Second), r)
	if count(t, e, "recovered") != 1 {
		t.Fatal("recovery")
	}
	if err := e.Store.Revoke("node", now.Add(24*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := e.CheckOffline(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if count(t, e, "offline") != 1 {
		t.Fatal("revoked offline")
	}
}
func TestNeverReportedOffline(t *testing.T) {
	e, now := setupEngine(t)
	for _, elapsed := range []time.Duration{16 * time.Second, 10 * time.Minute, 10*time.Minute + time.Second, 11 * time.Minute} {
		if err := e.CheckOffline(now.Add(elapsed)); err != nil {
			t.Fatal(err)
		}
		want := 0
		if elapsed > 10*time.Minute {
			want = 1
		}
		if count(t, e, "offline") != want {
			t.Fatal(elapsed, "missing or duplicate never-seen event")
		}
	}
	send(t, e, now.Add(12*time.Minute), sampleReport())
	if count(t, e, "recovered") != 1 {
		t.Fatal("recovered")
	}
}
func TestReenabledNodeOfflineGrace(t *testing.T) {
	e, now := setupEngine(t)
	send(t, e, now, sampleReport())
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.Revoke("node", now); err != nil {
		t.Fatal(err)
	}
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enabledAt := now.Add(24 * time.Hour)
	if err = e.Store.ConfirmEnrollment("node", "new", proto.PublicKeyLine(key, "node"), "", enabledAt, "admin", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	node, err := e.Store.Node("node")
	if err != nil || node.LastSeen != 0 || node.CreatedAt != enabledAt.Unix() || node.LastSeq != 1 {
		t.Fatal(node, err)
	}
	for _, elapsed := range []time.Duration{16 * time.Second, 10 * time.Minute, 10*time.Minute + time.Second, 11 * time.Minute} {
		if err = e.CheckOffline(enabledAt.Add(elapsed)); err != nil {
			t.Fatal(err)
		}
		want := 1
		if elapsed > 10*time.Minute {
			want = 2
		}
		if count(t, e, "offline") != want {
			t.Fatal(elapsed, "reenabled grace")
		}
	}
}
func TestLoginBaselineNewIPAndBinary(t *testing.T) {
	e, now := setupEngine(t)
	r := sampleReport()
	r.Login = []proto.Login{{User: "root", From: "203.0.113.7", Time: now.Unix() - 1}, {User: "alice", From: "2001:db8::1", Time: now.Unix() - 1}}
	send(t, e, now, r)
	if count(t, e, "login_new_ip") != 0 {
		t.Fatal("baseline alerted")
	}
	r.Login = []proto.Login{{User: "root", From: "203.0.113.7", Time: now.Unix() + 1}, {User: "root", From: "203.0.113.8", Time: now.Unix() + 1}, {User: "alice", From: "203.0.113.8", Time: now.Unix() + 1}}
	r.Bin = "sha256:" + strings.Repeat("b", 64)
	send(t, e, now.Add(time.Second), r)
	send(t, e, now.Add(2*time.Second), r)
	if count(t, e, "login_new_ip") != 2 || count(t, e, "bin_changed") != 1 {
		t.Fatal("login or hash event count")
	}
	var records int
	if err := e.Store.DB.QueryRow(`SELECT count(*) FROM logins`).Scan(&records); err != nil || records != 5 {
		t.Fatal(records, err)
	}
	if _, err := e.Store.DB.Exec(`INSERT INTO known_ips VALUES(?,?)`, "node", "203.0.113.8"); err != nil {
		t.Fatal(err)
	}
	e.Store.RetentionDays = 7
	if err := e.Store.Cleanup(now.Add(8 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.Login = []proto.Login{{User: "root", From: "203.0.113.8", Time: now.Add(8 * 24 * time.Hour).Unix()}}
	send(t, e, now.Add(8*24*time.Hour), r)
	if count(t, e, "login_new_ip") != 0 {
		t.Fatal("known IP lost on retention")
	}
}
func TestSustainedResource(t *testing.T) {
	e, now := setupEngine(t)
	r := sampleReport()
	r.Mem = [2]float64{90, 100}
	r.Disk = [2]float64{90, 100}
	for seconds := 0; seconds <= 1200; seconds += 5 {
		send(t, e, now.Add(time.Duration(seconds)*time.Second), r)
		want := 0
		if seconds >= 300 {
			want = 2
		}
		if count(t, e, "resource") != want {
			t.Fatalf("at %ds got %d want %d", seconds, count(t, e, "resource"), want)
		}
	}
	r.Mem[0] = 89
	send(t, e, now.Add(1205*time.Second), r)
	r.Mem[0] = 90
	for seconds := 1210; seconds <= 1510; seconds += 5 {
		send(t, e, now.Add(time.Duration(seconds)*time.Second), r)
	}
	if count(t, e, "resource") != 3 {
		t.Fatal("resource reset")
	}
}
func TestResourceGapAndThreshold(t *testing.T) {
	e, now := setupEngine(t)
	e.Config.MemoryThreshold = 95
	r := sampleReport()
	r.Mem = [2]float64{94, 100}
	for seconds := 0; seconds <= 300; seconds += 5 {
		send(t, e, now.Add(time.Duration(seconds)*time.Second), r)
	}
	if count(t, e, "resource") != 0 {
		t.Fatal("threshold")
	}
	r.Mem[0] = 95
	send(t, e, now.Add(305*time.Second), r)
	send(t, e, now.Add(610*time.Second), r)
	if count(t, e, "resource") != 0 {
		t.Fatal("gap treated as sustained")
	}
}

func TestResourceQueryExcludesOldHistory(t *testing.T) {
	e, now := setupEngine(t)
	// SQLite's dynamic typing lets an old malformed sample prove that the
	// resource query never visits history outside its indexed time window.
	if _, err := e.Store.DB.Exec(`INSERT INTO metrics(node,ts,mem_used,mem_total,disk_used,disk_total) VALUES(?,?,'old-invalid-value',100,'old-invalid-value',100)`, "node", now.Add(-24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	r := sampleReport()
	r.Mem = [2]float64{90, 100}
	r.Disk = [2]float64{90, 100}
	for seconds := 0; seconds <= 300; seconds += 5 {
		send(t, e, now.Add(time.Duration(seconds)*time.Second), r)
	}
	if count(t, e, "resource") != 2 {
		t.Fatal("bounded query failed to detect sustained usage")
	}
}

func TestChineseEventDetails(t *testing.T) {
	e, now := setupEngine(t)
	now = now.Add(10 * time.Minute)
	e.Store.Location = time.FixedZone("test", 8*3600)
	assertDetail := func(kind, want string) {
		t.Helper()
		var got string
		if err := e.Store.DB.QueryRow(`SELECT detail FROM events WHERE kind=? ORDER BY id DESC LIMIT 1`, kind).Scan(&got); err != nil || got != want {
			t.Fatal(kind, got, want, err)
		}
	}
	if err := e.CheckOffline(now.Add(16 * time.Second)); err != nil {
		t.Fatal(err)
	}
	assertDetail("offline", "从未上报")
	r := sampleReport()
	send(t, e, now.Add(17*time.Second), r)
	assertDetail("recovered", "首次开始上报")
	send(t, e, now.Add(22*time.Second), r)
	if err := e.CheckOffline(now.Add(40 * time.Second)); err != nil {
		t.Fatal(err)
	}
	assertDetail("offline", "最近一次上报 "+now.Add(22*time.Second).In(e.Store.Location).Format("2006-01-02 15:04:05"))
	r.Login = []proto.Login{{User: "admin", From: "192.0.2.3", Time: now.Add(92 * time.Second).Unix()}}
	old := r.Bin
	r.Bin = "sha256:" + strings.Repeat("b", 64)
	send(t, e, now.Add(92*time.Second), r)
	assertDetail("recovered", "重新开始上报，离线 1 分 10 秒")
	assertDetail("bin_changed", "agent 二进制变化："+old+" → "+r.Bin)
	assertDetail("login_new_ip", "admin 从 192.0.2.3 登录（首次出现的 IP）")
	e.Config.MemoryThreshold = 95
	e.Config.DiskThreshold = 96
	e.Config.Sustain = time.Minute
	r.Mem = [2]float64{95, 100}
	r.Disk = [2]float64{96, 100}
	for seconds := 100; seconds <= 160; seconds += 5 {
		send(t, e, now.Add(time.Duration(seconds)*time.Second), r)
	}
	var detail string
	if err := e.Store.DB.QueryRow(`SELECT detail FROM events WHERE kind='resource' ORDER BY id LIMIT 1`).Scan(&detail); err != nil || detail != "内存超过 95%，已持续 1 分钟" {
		t.Fatal(detail, err)
	}
	assertDetail("resource", "磁盘超过 96%，已持续 1 分钟")
}

func TestReenabledReportIgnoresOldOffline(t *testing.T) {
	e, now := setupEngine(t)
	if err := e.CheckOffline(now.Add(11 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if count(t, e, "offline") != 1 {
		t.Fatal("missing old offline")
	}
	if err := e.Store.Revoke("node", now.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enabledAt := now.Add(time.Hour)
	if err = e.Store.ConfirmEnrollment("node", "", proto.PublicKeyLine(key, "node"), "", enabledAt, "admin", ""); err != nil {
		t.Fatal(err)
	}
	send(t, e, enabledAt.Add(time.Second), sampleReport())
	if count(t, e, "recovered") != 0 {
		t.Fatal("recovered from previous registration")
	}
}
