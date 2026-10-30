package public

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func TestPublicMainlandWhitelistDirectionsAndToggle(t *testing.T) {
	s, c, now := publicFixture(t)
	samples := []store.MainlandProbe{{Carrier: "中国联通", City: "Shanghai <source>", Network: "private-network 192.0.2.231:443", Country: "CN", ASN: 4837, MeasurementID: "measurement-private", Time: now.Unix(), TCPMS: 58.36, Sent: 3, Received: 2, Status: "ok"}, {Carrier: "中国电信", City: "Beijing", Country: "CN", ASN: 4134, Time: now.Unix(), TCPMS: 73.2, Sent: 3, Received: 2, Status: "ok"}, {Carrier: "中国移动", Time: now.Unix(), Sent: 3, Received: 0, Status: "failed"}}
	if err := s.SetMainlandProbes("leak_node_51", samples); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"unselected_node_52", "revoked_node_53"} {
		if err := s.SetMainlandProbes(node, []store.MainlandProbe{{Carrier: "中国联通", City: "private-hidden-city", ASN: 4837, Time: now.Unix(), TCPMS: 999, Sent: 3, Received: 3, Status: "ok"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET last_seen=0 WHERE name='leak_node_51'`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetKV("receiver.outage", `{"members":{"leak_node_51":true}}`); err != nil {
		t.Fatal(err)
	}
	d, err := Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Nodes) != 1 || d.Nodes[0].Status != "offline" || d.Nodes[0].MainlandProbes == nil {
		t.Fatal(d.Nodes)
	}
	probes := *d.Nodes[0].MainlandProbes
	if len(probes) != 1 || probes[0].Status != "partial" || *probes[0].TCPMS != 58.4 || probes[0].Rate != "66.7%" || *probes[0].Received != 2 {
		t.Fatal("independent single-probe projection incorrect", probes)
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var whitelist struct {
		Nodes []struct {
			Mainland []map[string]json.RawMessage `json:"mainland_probes"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(encoded, &whitelist); err != nil {
		t.Fatal(err)
	}
	for _, p := range whitelist.Nodes[0].Mainland {
		for key := range p {
			if key != "carrier" && key != "city" && key != "status" && key != "age" && key != "tcp_ms" && key != "success_rate" && key != "sent" && key != "received" {
				t.Error("unapproved public mainland field", key)
			}
		}
	}
	outputs := []string{string(encoded)}
	for _, options := range []RenderOptions{{}, {Preview: true}, {Login: true}} {
		html, err := Render(d, options)
		if err != nil {
			t.Fatal(err)
		}
		body := string(html)
		for _, marker := range []string{"国内访问", "国内 → 节点", "Globalping", "每小时", "58.4 ms", "66.7%", "成功 2/3", "Shanghai &lt;source&gt;"} {
			if !strings.Contains(body, marker) {
				t.Error("missing public mainland information", marker)
			}
		}
		outputs = append(outputs, body)
	}
	dir := t.TempDir()
	if err := Save(s, c, true, now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if err := (&Exporter{Store: s, Dir: dir}).Export(now); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"index.html", "status.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(raw))
	}
	for _, output := range outputs {
		for _, private := range []string{"measurement-private", "measurement_id", "192.0.2.231", ":443", "private-network", "network", "target", "private-hidden-city", "unselected_node_52", "revoked_node_53", "revoked display", "not public", "中国电信", "中国移动", "Beijing"} {
			if strings.Contains(output, private) {
				t.Error("public mainland output leaked", private)
			}
		}
	}
	c.Fields.Probes = false
	d, err = Build(s, c, now)
	if err != nil || d.Nodes[0].MainlandProbes != nil {
		t.Fatal("disabled field still included external data", d, err)
	}
	raw, _ := json.Marshal(d)
	html, err := Render(d, RenderOptions{})
	if err != nil || strings.Contains(string(raw), "mainland_probes") || strings.Contains(string(html), "国内访问") || strings.Contains(string(html), "Globalping") {
		t.Fatal("disabled public mainland output remains", string(raw), string(html), err)
	}
}

func TestPublicMainlandEmptyUnavailableAndFreshness(t *testing.T) {
	s, c, now := publicFixture(t)
	d, err := Build(s, c, now)
	if err != nil || d.Nodes[0].MainlandProbes == nil || len(*d.Nodes[0].MainlandProbes) != 1 {
		t.Fatal(d, err)
	}
	for _, p := range *d.Nodes[0].MainlandProbes {
		if p.Status != "empty" || p.TCPMS != nil || p.Rate != "" || p.Sent != nil || p.Received != nil {
			t.Fatal("missing result turned into failure", p)
		}
	}
	for _, tc := range []struct {
		name, status, want, rate string
		age                      time.Duration
		received, asn            int
	}{{"unavailable", "unavailable", "unavailable", "", 0, 0, 0}, {"failed", "failed", "failed", "0%", 0, 0, 4837}, {"partial", "ok", "partial", "66.7%", 0, 2, 4837}, {"boundary", "ok", "ok", "100%", proto.ProbeMaxAge, 3, 4837}, {"old", "ok", "stale", "", proto.ProbeMaxAge + time.Second, 3, 4837}} {
		t.Run(tc.name, func(t *testing.T) {
			sample := store.MainlandProbe{Carrier: "中国联通", ASN: tc.asn, City: "Shanghai", Time: now.Add(-tc.age).Unix(), Status: tc.status, TCPMS: 0, Sent: 3, Received: tc.received}
			if err := s.SetMainlandProbes("leak_node_51", []store.MainlandProbe{sample}); err != nil {
				t.Fatal(err)
			}
			d, err := Build(s, c, now.Add(900*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			probes := *d.Nodes[0].MainlandProbes
			if len(probes) != 1 || probes[0].Status != tc.want || probes[0].Rate != tc.rate {
				t.Fatal("single probe status or rate incorrect", probes)
			}
			p := probes[0]
			if (tc.want == "ok" || tc.want == "partial") && (p.TCPMS == nil || *p.TCPMS != 0) || tc.want == "failed" && (p.TCPMS != nil || p.Received == nil || *p.Received != 0) || (tc.want == "stale" || tc.want == "unavailable") && (p.TCPMS != nil || p.Sent != nil || p.Received != nil) {
				t.Fatal("single probe measurement misleading", p)
			}
		})
	}
}

func TestPublicMainlandDoesNotRelabelOldTelecomResult(t *testing.T) {
	s, c, now := publicFixture(t)
	if err := s.SetMainlandProbes("leak_node_51", []store.MainlandProbe{{Carrier: "中国电信", ASN: 4134, City: "old-telecom-city", Country: "CN", Time: now.Unix(), Status: "ok", TCPMS: 987.6, Sent: 3, Received: 3}}); err != nil {
		t.Fatal(err)
	}
	d, err := Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	probes := *d.Nodes[0].MainlandProbes
	if len(probes) != 1 || probes[0].Carrier != "中国联通" || probes[0].Status != "empty" || probes[0].City != "" || probes[0].TCPMS != nil || probes[0].Rate != "" {
		t.Fatal("old Telecom result relabeled as Unicom", probes)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	html, err := Render(d, RenderOptions{})
	if err != nil || !strings.Contains(string(html), "中国联通") || !strings.Contains(string(html), "暂无数据") {
		t.Fatal(string(html), err)
	}
	for _, output := range []string{string(raw), string(html)} {
		for _, old := range []string{"中国电信", "old-telecom-city", "987.6"} {
			if strings.Contains(output, old) {
				t.Error("previous carrier result still exposed", old)
			}
		}
	}
}

func TestPublicMainlandConfiguredCarrier(t *testing.T) {
	s, c, now := publicFixture(t)
	samples := []store.MainlandProbe{
		{Carrier: "中国联通", ASN: 4837, City: "unselected-unicom-city", Country: "CN", Time: now.Unix(), Status: "ok", TCPMS: 987.6, Sent: 3, Received: 3},
		{Carrier: "中国电信", ASN: 4134, City: "Shanghai", Country: "CN", Network: "private-tcp-target 192.0.2.231:443", MeasurementID: "private-telecom-measurement", Time: now.Unix(), Status: "ok", TCPMS: 12.3, Sent: 3, Received: 3},
		{Carrier: "中国移动", ASN: 9808, City: "Guangzhou", Country: "CN", Network: "private-tcp-target 192.0.2.231:443", MeasurementID: "private-mobile-measurement", Time: now.Unix(), Status: "ok", TCPMS: 45.6, Sent: 3, Received: 3},
	}
	for _, tc := range []struct {
		asn           int
		carrier, city string
		tcp           float64
	}{{4134, "中国电信", "Shanghai", 12.3}, {9808, "中国移动", "Guangzhou", 45.6}} {
		t.Run(tc.carrier, func(t *testing.T) {
			if err := s.SetMainlandSource(store.MainlandSource{ASN: tc.asn}); err != nil {
				t.Fatal(err)
			}
			if err := s.SetMainlandProbes("leak_node_51", samples); err != nil {
				t.Fatal(err)
			}
			d, err := Build(s, c, now)
			if err != nil {
				t.Fatal(err)
			}
			probes := *d.Nodes[0].MainlandProbes
			if len(probes) != 1 || probes[0].Carrier != tc.carrier || probes[0].City != tc.city || probes[0].Status != "ok" || probes[0].TCPMS == nil || *probes[0].TCPMS != tc.tcp {
				t.Fatal("configured carrier not projected", probes)
			}
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			html, err := Render(d, RenderOptions{})
			if err != nil || !strings.Contains(string(html), tc.carrier) || !strings.Contains(string(html), tc.city) {
				t.Fatal(string(html), err)
			}
			for _, output := range []string{string(raw), string(html)} {
				for _, private := range []string{"中国联通", "unselected-unicom-city", "987.6", "private-tcp-target", "192.0.2.231", ":443", "private-telecom-measurement", "private-mobile-measurement", "measurement_id", "network", "target", "asn"} {
					if strings.Contains(output, private) {
						t.Error("configured public source leaked private or unselected data", private)
					}
				}
			}
			if err := s.SetMainlandProbes("leak_node_51", []store.MainlandProbe{}); err != nil {
				t.Fatal(err)
			}
			d, err = Build(s, c, now)
			if err != nil {
				t.Fatal(err)
			}
			probes = *d.Nodes[0].MainlandProbes
			if len(probes) != 1 || probes[0].Carrier != tc.carrier || probes[0].Status != "empty" || probes[0].TCPMS != nil {
				t.Fatal("missing result did not retain selected carrier", probes)
			}
		})
	}
}

func TestPublicMainlandCitySelectionDoesNotReuseOldResult(t *testing.T) {
	s, c, now := publicFixture(t)
	old := store.MainlandProbe{Carrier: "中国电信", ASN: 4134, City: "Shanghai", Country: "CN", Time: now.Unix(), Status: "ok", TCPMS: 987.6, Sent: 3, Received: 3}
	if err := s.SetMainlandSource(store.MainlandSource{ASN: 4134, City: "Shanghai"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMainlandProbes("leak_node_51", []store.MainlandProbe{old}); err != nil {
		t.Fatal(err)
	}
	d, err := Build(s, c, now)
	if err != nil || (*d.Nodes[0].MainlandProbes)[0].Status != "ok" {
		t.Fatal(d, err)
	}
	if err := s.SetMainlandSource(store.MainlandSource{ASN: 4134, City: "Beijing"}); err != nil {
		t.Fatal(err)
	}
	d, err = Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	probes := *d.Nodes[0].MainlandProbes
	if len(probes) != 1 || probes[0].Carrier != "中国电信" || probes[0].City != "Beijing" || probes[0].Status != "empty" || probes[0].TCPMS != nil || probes[0].Sent != nil || probes[0].Rate != "" || probes[0].Age != "" {
		t.Fatal("city change reused old measurements", probes)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	html, err := Render(d, RenderOptions{})
	if err != nil || !strings.Contains(string(html), "中国电信") || !strings.Contains(string(html), "暂无数据") {
		t.Fatal(string(html), err)
	}
	for _, output := range []string{string(raw), string(html)} {
		if strings.Contains(output, "Shanghai") || strings.Contains(output, "987.6") {
			t.Error("old city remains in public output", output)
		}
	}
	current := old
	current.City, current.TCPMS = "Beijing", 12.3
	if err := s.SetMainlandProbes("leak_node_51", []store.MainlandProbe{old, current}); err != nil {
		t.Fatal(err)
	}
	d, err = Build(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	probes = *d.Nodes[0].MainlandProbes
	if len(probes) != 1 || probes[0].City != "Beijing" || probes[0].Status != "ok" || probes[0].TCPMS == nil || *probes[0].TCPMS != 12.3 {
		t.Fatal("matching current city not selected", probes)
	}
}
