package public

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wanglou/internal/server/store"
)

func TestPublicProbeConfigDefaultsAndLegacyOptIn(t *testing.T) {
	s, c, now := publicFixture(t)
	if !c.Fields.Probes {
		t.Fatal("new configurations should show domestic inbound access")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(raw), `,"Probes":true`, "", 1)
	for _, key := range []string{"public.draft", "public.published"} {
		if err := s.SetKV(key, legacy); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(s, key)
		if err != nil || loaded.Fields.Probes {
			t.Fatal("existing configuration opted in automatically", loaded, err)
		}
	}
	for _, on := range []bool{false, true} {
		c.Fields.Probes = on
		d, err := Build(s, c, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		html, err := Render(d, RenderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"mainland_probes"`) != on || strings.Contains(string(html), "国内访问") != on || (d.Nodes[0].MainlandProbes != nil) != on {
			t.Fatal("field toggle did not control inbound HTML and JSON", on, string(raw), string(html))
		}
	}
}

func TestOutgoingProbesNeverReachPublicRendererOrJSON(t *testing.T) {
	s, c, now := publicFixture(t)
	for _, target := range []string{"https://www.baidu.com/robots.txt?token=private-secret", "https://cloud.tencent.com/robots.txt", "https://www.aliyun.com/robots.txt"} {
		if _, err := s.DB.Exec(`INSERT INTO probe_samples VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "leak_node_51", target, now.Unix(), "192.0.2.222", 7, 12, 20, 45, 60, 200, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetMainlandProbes("leak_node_51", []store.MainlandProbe{{Carrier: "中国联通", City: "Shanghai", ASN: 4837, Time: now.Unix(), Status: "ok", TCPMS: 68.7, Sent: 3, Received: 3}}); err != nil {
		t.Fatal(err)
	}
	d, err := Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{string(raw)}
	for _, options := range []RenderOptions{{}, {Preview: true}, {Login: true}} {
		html, err := Render(d, options)
		if err != nil || !strings.Contains(string(html), "国内访问") || !strings.Contains(string(html), "68.7 ms") {
			t.Fatal("inbound results removed with outgoing probes", string(html), err)
		}
		outputs = append(outputs, string(html))
	}
	dir := t.TempDir()
	if err := Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if err := (&Exporter{Store: s, Dir: dir}).Export(now); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"index.html", "status.json"} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(b))
	}
	for _, output := range outputs {
		for _, retired := range []string{`"probes"`, "ttfb_ms", "baidu.com", "tencent.com", "aliyun.com", "private-secret", "192.0.2.222", "国内连接", "节点 → 站点", "TTFB"} {
			if strings.Contains(output, retired) {
				t.Error("retired outgoing probe still public", retired)
			}
		}
	}
	stored, err := s.LatestProbes("leak_node_51")
	if err != nil || len(stored) != 3 {
		t.Fatal("hiding probes changed historical storage", stored, err)
	}
	if _, err := s.DB.Exec(`ALTER TABLE probe_samples RENAME TO retained_probe_samples`); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(s, c, now); err != nil {
		t.Fatal("public routes still query retired outgoing samples", err)
	}
}
