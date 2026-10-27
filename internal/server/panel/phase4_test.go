package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"html"
	"net/url"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestHistorySourcesTailRangesAndPerformance(t *testing.T) {
	f := setup(t)
	now := f.now.Unix()
	minute := now/60*60 - 120
	hour := now / 3600 * 3600
	if _, err := f.s.DB.Exec(`INSERT INTO kv VALUES('rollup.1m',?),('rollup.1h',?)`, minute, hour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DB.Exec(`INSERT INTO metrics(node,ts,cpu,mem_used,mem_total,disk_used,disk_total,net_tx,net_rx) VALUES('node',?,99,50,100,25,100,1,2),('node',?,10,50,100,25,100,1,2)`, now-3600, now); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		table string
		ts    int64
		cpu   int
	}{{"metrics_1m", minute - 12*3600, 20}, {"metrics_1h", hour - 10*86400, 30}} {
		if _, err := f.s.DB.Exec(`INSERT INTO `+item.table+`(node,ts,samples,cpu,mem_used,mem_total,disk_used,disk_total,net_tx,net_rx) VALUES('node',?,12,?,50,100,25,100,1,2)`, item.ts, item.cpu); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		duration time.Duration
		cpu      float64
	}{{time.Hour, 99}, {24 * time.Hour, 20}, {7 * 24 * time.Hour, 20}, {30 * 24 * time.Hour, 30}, {90 * 24 * time.Hour, 30}} {
		points, err := f.h.history("node", tc.duration)
		if err != nil || len(points) != 2 || points[0].CPU != tc.cpu || points[1].CPU != 10 {
			t.Fatal(tc, points, err)
		}
		if points[len(points)-1].Time != now {
			t.Fatal("missing raw tail", points)
		}
	}
	f.s.RetentionDays = 7
	for _, value := range []string{"30d", "90d"} {
		w := f.request("GET", "/nodes/node?range="+value, nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `href="?range=24h" aria-current="page"`) || strings.Contains(w.Body.String(), `href="?range=30d"`) || strings.Contains(w.Body.String(), `href="?range=90d"`) || !strings.Contains(w.Body.String(), "数据精度：1 分钟") {
			t.Fatal(w.Code, w.Body)
		}
	}
	f.s.RetentionDays = 90
	for _, tc := range []struct {
		table, value, precision string
		step, rows              int
	}{{"metrics_1m", "7d", "1 分钟", 60, 7 * 1440}, {"metrics_1h", "90d", "1 小时", 3600, 90 * 24}} {
		if _, err := f.s.DB.Exec(`DELETE FROM metrics;DELETE FROM metrics_1m;DELETE FROM metrics_1h`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.DB.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO `+tc.table+`(node,ts,samples,cpu,mem_used,mem_total,disk_used,disk_total,net_tx,net_rx) SELECT 'node',?-i*?,12,i%100,50,100,25,100,1,2 FROM n`, tc.rows, now, tc.step); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.DB.Exec(`UPDATE kv SET value=? WHERE key LIKE 'rollup.%'`, now); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		points, err := f.h.history("node", time.Duration(tc.rows*tc.step)*time.Second)
		if err != nil || len(points) > 360 || len(points) < 350 {
			t.Fatal(tc, len(points), err)
		}
		w := f.request("GET", "/nodes/node?range="+tc.value, nil, true)
		elapsed := time.Since(start)
		if w.Code != 200 || elapsed >= 200*time.Millisecond || !strings.Contains(w.Body.String(), "数据精度："+tc.precision) {
			t.Fatal(tc.value, w.Code, elapsed, w.Body)
		}
		t.Logf("%s: %d source rows, %d points, query + page render %s", tc.value, tc.rows, len(points), elapsed)
	}
}

func TestDescribeOldEventsAndEscaping(t *testing.T) {
	f := setup(t)
	f.s.Location = time.FixedZone("test", 8*3600)
	for _, tc := range []struct{ kind, detail, want string }{
		{"offline", "last seen 0", "从未上报"},
		{"offline", "last seen 1", "最近一次上报 1970-01-01 08:00:01"},
		{"login_new_ip", "admin from 192.0.2.1", "admin 从 192.0.2.1 登录（首次出现的 IP）"},
		{"resource", "memory", "内存超过 90%，已持续 5 分钟"},
		{"resource", "disk", "磁盘超过 90%，已持续 5 分钟"},
		{"bin_changed", "old -> new", "agent 二进制变化：old → new"},
		{"recovered", "重新开始上报，离线 5 秒", "重新开始上报，离线 5 秒"},
		{"recovered", "", "重新开始上报"},
		{"offline", "last seen invalid", "last seen invalid"},
		{"offline", "last seen -1", "last seen -1"},
		{"bin_changed", " -> ", " -> "},
		{"unknown", `<script>alert(1)</script>`, `<script>alert(1)</script>`},
	} {
		if got := f.h.describeEvent(tc.kind, tc.detail); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	for _, kind := range []string{"unknown", "offline", "login_new_ip", "bin_changed"} {
		detail := `<script>alert(1)</script>`
		if kind == "login_new_ip" {
			detail += " from 192.0.2.1"
		}
		if kind == "bin_changed" {
			detail += " -> new"
		}
		if _, err := f.s.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node',?,?)`, f.now.Unix(), kind, detail); err != nil {
			t.Fatal(err)
		}
	}
	w := f.request("GET", "/", nil, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>alert(1)</script>") || !strings.Contains(w.Body.String(), html.EscapeString(`<script>alert(1)</script>`)) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestRevokedEnrollmentCodeAndPaste(t *testing.T) {
	for _, method := range []string{"codes", "paste"} {
		t.Run(method, func(t *testing.T) {
			f := setup(t)
			f.report(t, "node", sampleReport(), 204)
			original, err := f.s.Node("node")
			if err != nil {
				t.Fatal(err)
			}
			oldKey := f.key
			if err = f.s.Revoke("node", f.now); err != nil {
				t.Fatal(err)
			}
			warning := "这个名称之前被吊销过。启用后会换成新公钥，历史数据保留，旧公钥永远不能再用。"
			w := f.request("GET", "/enroll?name=node", nil, true)
			if w.Code != 200 || strings.Count(w.Body.String(), warning) != 2 {
				t.Fatal(w.Code, w.Body)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			line := proto.PublicKeyLine(pub, "node")
			if method == "codes" {
				state, location := f.pendingCode(t, "node")
				f.submitCode(t, state.Code, line, 204)
				w = f.request("GET", location, nil, true)
			} else {
				w = f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {"node"}, "note": {"new note"}, "pubkey": {line}}, true)
				if w.Code != 303 {
					t.Fatal(w.Code, w.Body)
				}
				w = f.request("GET", w.Header().Get("Location"), nil, true)
			}
			if w.Code != 200 || strings.Count(w.Body.String(), warning) != 2 {
				t.Fatal(w.Code, w.Body)
			}
			form := url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {line}, "matched": {"yes"}}
			if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 303 {
				t.Fatal(w.Code, w.Body)
			}
			enabled, err := f.s.Node("node")
			if err != nil || enabled.RevokedAt != 0 || enabled.Fingerprint != proto.Fingerprint(pub) || enabled.CreatedAt != original.CreatedAt || enabled.LastSeq != original.LastSeq || enabled.Note == original.Note {
				t.Fatal(enabled, original, err)
			}
			f.key = key
			f.now = f.now.Add(5 * time.Second)
			f.report(t, "node", sampleReport(), 204)
			f.key = oldKey
			f.report(t, "node", sampleReport(), 401)
			var count int
			if err = f.s.DB.QueryRow(`SELECT count(*) FROM metrics WHERE node='node'`).Scan(&count); err != nil || count != 2 {
				t.Fatal("history lost", count, err)
			}
			if err = f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='node_reenable' AND detail='node'`).Scan(&count); err != nil || count != 1 {
				t.Fatal(count, err)
			}
			// Active names and CLI enrollment continue to reject replacement.
			for _, path := range []string{"/enroll/codes", "/enroll/preview"} {
				w = f.request("POST", path, url.Values{"csrf": {f.csrf}, "name": {"node"}, "pubkey": {line}}, true)
				if w.Code != 409 {
					t.Fatal(path, w.Code, w.Body)
				}
			}
			if err = f.s.AddNode("node", pub, f.now); err == nil {
				t.Fatal("CLI replaced existing name")
			}
		})
	}
}

func TestRevokedOldKeyRejected(t *testing.T) {
	f := setup(t)
	if err := f.s.Revoke("node", f.now); err != nil {
		t.Fatal(err)
	}
	line := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "node")
	w := f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {"node"}, "pubkey": {line}}, true)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "不能复用已吊销的公钥") {
		t.Fatal(w.Code, w.Body)
	}
	state, _ := f.pendingCode(t, "node")
	f.submitCode(t, state.Code, line, 400)
	var retained string
	var used int64
	if err := f.s.DB.QueryRow(`SELECT pubkey,used_at FROM enroll_codes WHERE code_hash=?`, state.Hash).Scan(&retained, &used); err != nil || retained != "" || used != 0 {
		t.Fatal("rejected key consumed code", retained, used, err)
	}
	// A paste preview made while unused must also be checked in the confirmation transaction.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pasted := proto.PublicKeyLine(pub, "fresh")
	w = f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {"fresh"}, "pubkey": {pasted}}, true)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	w = f.request("GET", w.Header().Get("Location"), nil, true)
	form := url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {pasted}, "matched": {"yes"}}
	if err := f.s.AddNode("fresh", pub, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Revoke("fresh", f.now); err != nil {
		t.Fatal(err)
	}
	w = f.request("POST", "/enroll/confirm", form, true)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "不能复用已吊销的公钥") {
		t.Fatal(w.Code, w.Body)
	}
}

func TestLegacyResourceUsesConfiguredThresholds(t *testing.T) {
	f := setup(t)
	h := New(f.s, f.h.Ingest, Config{CookieSecure: true, MemoryThreshold: 85, DiskThreshold: 95, Sustain: 2 * time.Minute})
	h.Now = f.h.Now
	for _, item := range []struct{ detail, want string }{{"memory", "内存超过 85%，已持续 2 分钟"}, {"disk", "磁盘超过 95%，已持续 2 分钟"}} {
		if got := h.describeEvent("resource", item.detail); got != item.want {
			t.Fatal(got)
		}
		if _, err := f.s.DB.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,'node','resource',?)`, f.now.Unix(), item.detail); err != nil {
			t.Fatal(err)
		}
	}
	f.h = h
	w := f.request("GET", "/", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "内存超过 85%，已持续 2 分钟") || !strings.Contains(w.Body.String(), "磁盘超过 95%，已持续 2 分钟") {
		t.Fatal(w.Code, w.Body)
	}
}

func TestGlobalRevokedKeyRejectedByPanelAndIngest(t *testing.T) {
	f := setup(t)
	original := f.key.Public().(ed25519.PublicKey)
	replacement, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := f.s.Revoke("node", f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.s.ConfirmEnrollment("node", "", proto.PublicKeyLine(replacement, "node"), "", f.now, "admin", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Revoke("node", f.now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "fresh"} {
		line := proto.PublicKeyLine(original, name)
		w := f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {name}, "pubkey": {line}}, true)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "不能复用已吊销的公钥") {
			t.Fatal(name, w.Code, w.Body)
		}
		state, _ := f.pendingCode(t, name)
		f.submitCode(t, state.Code, line, 400)
	}
}

func TestConfirmationRejectsKeyRevokedAfterSubmission(t *testing.T) {
	for _, method := range []string{"codes", "paste"} {
		t.Run(method, func(t *testing.T) {
			f := setup(t)
			line := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "fresh")
			location := ""
			if method == "codes" {
				state, url := f.pendingCode(t, "fresh")
				f.submitCode(t, state.Code, line, 204)
				location = url
			} else {
				w := f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {"fresh"}, "pubkey": {line}}, true)
				if w.Code != 303 {
					t.Fatal(w.Code, w.Body)
				}
				location = w.Header().Get("Location")
			}
			w := f.request("GET", location, nil, true)
			form := url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {line}, "matched": {"yes"}}
			if err := f.s.Revoke("node", f.now); err != nil {
				t.Fatal(err)
			}
			w = f.request("POST", "/enroll/confirm", form, true)
			if w.Code != 400 || !strings.Contains(w.Body.String(), "不能复用已吊销的公钥") {
				t.Fatal(w.Code, w.Body)
			}
			var count int
			if err := f.s.DB.QueryRow(`SELECT count(*) FROM nodes WHERE name='fresh'`).Scan(&count); err != nil || count != 0 {
				t.Fatal(count, err)
			}
		})
	}
}
