package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func publicFixture(t *testing.T) (*store.Store, PublicConfig, time.Time) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.Location = time.UTC
	now := time.Date(2026, 10, 27, 14, 32, 19, 0, time.UTC)
	c := DefaultConfig()
	for _, name := range []string{"leak_node_51", "unselected_node_52", "revoked_node_53"} {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		if err = s.AddNode(name, pub, now); err != nil {
			t.Fatal(err)
		}
		r := proto.Report{CPU: 13.6, Mem: [2]float64{812, 2048}, Disk: [2]float64{18.2, 40}, Net: [2]float64{1532123, 8841234}, Up: 12*86400 + 1, Bin: "leak_bin_54", OS: "leak_os_55", Arch: "leak_arch_56", Login: []proto.Login{{User: "leak_user_57", From: "192.0.2.77", Time: now.Unix()}}}
		if err = s.Accept(name, 1, now, "192.0.2.78", &r, func() error { return nil }, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.DB.Exec(`UPDATE nodes SET note='leak_note_58',fingerprint='leak_fingerprint_59'`); err != nil {
		t.Fatal(err)
	}
	b := store.DefaultBilling("leak_node_51")
	b.Provider = "leak_provider_60"
	if err = s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO logins VALUES('leak_node_51',?,'leak_user_57','192.0.2.77',1)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err = s.Revoke("revoked_node_53", now); err != nil {
		t.Fatal(err)
	}
	c.Nodes = []Selection{{Node: "leak_node_51", Public: true, Name: "香港 · 01"}, {Node: "unselected_node_52", Name: "not public"}, {Node: "revoked_node_53", Public: true, Name: "revoked display"}}
	c.Announcements = []Announcement{{ID: 1, Time: now.Format(time.RFC3339), Title: "维护", Body: "正常", Node: "leak_node_51", Status: "resolved"}, {ID: 2, Time: now.Format(time.RFC3339), Title: "已结束", Body: "正常", Node: "unselected_node_52", Status: "done"}}
	return s, c, now
}
func TestExportWhitelistAndDisabledFields(t *testing.T) {
	s, c, now := publicFixture(t)
	dir := t.TempDir()
	e := Exporter{Store: s, Dir: dir}
	if err := Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if err := e.Export(now); err != nil {
		t.Fatal(err)
	}
	markers := []string{"leak_node_51", "unselected_node_52", "revoked_node_53", "leak_bin_54", "leak_os_55", "leak_arch_56", "leak_user_57", "leak_note_58", "leak_fingerprint_59", "leak_provider_60", "192.0.2.77", "192.0.2.78", "not public", "revoked display"}
	files := 0
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range markers {
			if strings.Contains(string(data), marker) {
				t.Errorf("leaked %q in %s", marker, entry.Name())
			}
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0644 {
			t.Error(info.Mode())
		}
		return nil
	})
	if err != nil || files != 3 {
		t.Fatal(files, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	if err = json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.V != 1 || len(d.Nodes) != 1 || d.Summary.OK != 1 || d.Generated != "2026-10-27T14:32:00Z" || d.Nodes[0].Name != "香港 · 01" || d.Nodes[0].Specs.MemGB != 2 || d.Nodes[0].Usage.CPU != 14 || d.Nodes[0].Net.TX != 1500000 || *d.Nodes[0].UptimeDays != 12 || d.Nodes[0].Availability == nil {
		t.Fatalf("%+v %+v", d, d.Nodes)
	}
	if d.Announcements[0].Node != "香港 · 01" || d.Announcements[1].Node != "" {
		t.Fatal(d.Announcements)
	}
	c.Fields = Fields{}
	if err = Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if err = e.Export(now); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "status.json"))
	html, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	for _, field := range []string{`"specs"`, `"usage"`, `"net"`, `"uptime_days"`, `"offline_since"`, `"availability"`} {
		if strings.Contains(string(raw), field) {
			t.Fatal("disabled JSON field", field)
		}
	}
	for _, field := range []string{"内存 2 GB", "CPU 14%", "↑ ", "已运行 12 天", "45 天前", "可用率", "day-ok"} {
		if strings.Contains(string(html), field) {
			t.Fatal("disabled HTML field", field)
		}
	}
	if strings.Contains(string(html), "<script") || strings.Contains(string(html), "style=") || !strings.Contains(string(html), `http-equiv="refresh" content="30"`) {
		t.Fatal("unsafe assets")
	}
}
func TestTokenCleanupIsLimited(t *testing.T) {
	s, c, now := publicFixture(t)
	dir := t.TempDir()
	e := Exporter{Store: s, Dir: dir}
	publish := func() {
		t.Helper()
		if err := Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
			t.Fatal(err)
		}
		if err := e.Export(now); err != nil {
			t.Fatal(err)
		}
	}
	publish()
	c.Access = "token"
	old := c.Token
	publish()
	for _, name := range []string{"index.html", "status.json", "status.css"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("root retained", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, old, "keep.txt"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	unmatched := "not-a-token"
	if err := os.Mkdir(filepath.Join(dir, unmatched), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, unmatched, "index.html"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	c.Token = Token()
	publish()
	for _, name := range []string{"index.html", "status.json", "status.css"} {
		if _, err := os.Stat(filepath.Join(dir, old, name)); !os.IsNotExist(err) {
			t.Fatal("old token retained", name, err)
		}
	}
	for _, path := range []string{filepath.Join(old, "keep.txt"), filepath.Join(unmatched, "index.html"), "other.txt"} {
		if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
			t.Fatal("unrelated file removed", path, err)
		}
	}
	current := c.Token
	c.Access = "public"
	publish()
	if _, err := os.Stat(filepath.Join(dir, current)); !os.IsNotExist(err) {
		t.Fatal("empty old token not removed", err)
	}
}
func TestAtomicFailureAndEscaping(t *testing.T) {
	s, c, now := publicFixture(t)
	dir := t.TempDir()
	e := Exporter{Store: s, Dir: dir}
	payload := `<script>alert("x")</script>`
	c.Nodes[0].Name = payload
	c.Announcements[0].Title = payload
	c.Announcements[0].Body = payload
	if err := Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if err := e.Export(now); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>") || !strings.Contains(string(html), "&lt;script&gt;") {
		t.Fatal("unescaped", string(html))
	}
	old := string(html)
	if err = os.Remove(filepath.Join(dir, "status.json")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, "status.json"), 0755); err != nil {
		t.Fatal(err)
	}
	c.Title = "changed"
	if err = Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if err = e.Export(now); err == nil {
		t.Fatal("expected rename failure")
	}
	html, _ = os.ReadFile(filepath.Join(dir, "index.html"))
	if string(html) != old {
		t.Fatal("index partially replaced")
	}
	files, err := filepath.Glob(filepath.Join(dir, ".wanglou-*"))
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
}
func TestOfflineRoundingAndPreview(t *testing.T) {
	s, c, now := publicFixture(t)
	if _, err := s.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name='leak_node_51'`, now.Add(-91*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	d, err := Build(s, c, now)
	if err != nil || d.Summary.Offline != 1 || d.Nodes[0].Status != "offline" || d.Nodes[0].Usage != nil || d.Nodes[0].Net != nil || d.Nodes[0].UptimeDays != nil || d.Nodes[0].OfflineSince == "" {
		t.Fatal(d, err)
	}
	html, err := Render(d, true)
	if err != nil || !strings.Contains(string(html), "预览 · 未发布") || !strings.Contains(string(html), `href="/static/status.css"`) || !strings.Contains(string(html), "离线 1 小时") {
		t.Fatal(string(html), err)
	}
	c.Fields.Reason = false
	d, err = Build(s, c, now)
	if err != nil || d.Nodes[0].OfflineSince != "" {
		t.Fatal(d, err)
	}
	html, _ = Render(d, false)
	if strings.Contains(string(html), "起没有响应") || strings.Contains(string(html), "离线 1 小时") {
		t.Fatal(string(html))
	}
}

func TestFieldSwitchesIndependentlyAndDisplayOrder(t *testing.T) {
	s, c, now := publicFixture(t)
	if _, err := s.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name='leak_node_51'`, now.Add(-10*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	c.Fields.Uptime = false
	d, err := Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	html, err := Render(d, false)
	if err != nil || strings.Contains(string(html), "离线 10 分钟") || !strings.Contains(string(html), "起无响应") {
		t.Fatal(string(html), err)
	}
	c.Fields.Uptime = true
	c.Fields.Reason = false
	d, err = Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	html, _ = Render(d, false)
	if strings.Contains(string(html), "离线 10 分钟") || strings.Contains(string(html), "起无响应") {
		t.Fatal(string(html))
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET last_seen=? WHERE name='leak_node_51';INSERT INTO resource_alerts VALUES('leak_node_51','memory',1,?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	c.Nodes[1].Public = true
	c.Nodes[1].Name = "A public name"
	d, err = Build(s, c, now)
	if err != nil || len(d.Nodes) != 2 || d.Nodes[0].Name != "A public name" || d.Nodes[1].Status != "ok" {
		t.Fatal(d, err)
	}
	for _, field := range []string{"specs", "usage", "net", "uptime", "availability"} {
		cfg := c
		switch field {
		case "specs":
			cfg.Fields.Specs = false
		case "usage":
			cfg.Fields.Usage = false
		case "net":
			cfg.Fields.Net = false
		case "uptime":
			cfg.Fields.Uptime = false
		case "availability":
			cfg.Fields.Availability = false
		}
		d, err := Build(s, cfg, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(d)
		key := field
		if field == "uptime" {
			key = "uptime_days"
		}
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatal(field, string(raw))
		}
	}
}

func TestPublicRateAndShortUptime(t *testing.T) {
	s, c, now := publicFixture(t)
	for _, tc := range []struct {
		tx, rx float64
		up     int
		want   []string
	}{
		{440, 999, 0, []string{"440 B/s", "999 B/s", "已运行不到 1 天"}},
		{13 * 1024, 1.2 * 1024 * 1024, 86400, []string{"13 KB/s", "1.2 MB/s", "已运行 1 天"}},
	} {
		if _, err := s.DB.Exec(`UPDATE metrics SET net_tx=?,net_rx=?,uptime=?`, tc.tx, tc.rx, tc.up); err != nil {
			t.Fatal(err)
		}
		d, err := Build(s, c, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := Render(d, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range tc.want {
			if !strings.Contains(string(raw), want) {
				t.Fatal("missing", want, string(raw))
			}
		}
		data, err := json.Marshal(d)
		if err != nil || !strings.Contains(string(data), `"uptime_days":`) {
			t.Fatal(string(data), err)
		}
	}
}
