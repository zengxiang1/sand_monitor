package panel

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func TestMainlandViewsSelectedProbeStatusesAndOldBatchFilter(t *testing.T) {
	now := time.Unix(2_000_000_000, 900_000_000)
	empty := mainlandViews(nil, store.MainlandSource{ASN: 4837}, now)
	if len(empty) != 1 || empty[0].Carrier != "中国联通" || empty[0].State != "暂无数据" || empty[0].Rate != "—" {
		t.Fatal(empty)
	}
	legacy := []store.MainlandProbe{{Carrier: "中国电信", ASN: 4134, City: "old-telecom-city", Time: now.Unix(), Status: "ok", TCPMS: 999, Sent: 3, Received: 3}, {Carrier: "中国移动", ASN: 9808, City: "old-mobile-city", Time: now.Unix(), Status: "ok", TCPMS: 999, Sent: 3, Received: 3}, {Carrier: "中国联通", ASN: 9999, City: "wrong-source-city", Time: now.Unix(), Status: "ok", TCPMS: 999, Sent: 3, Received: 3}}
	for _, tc := range []struct {
		status, state, tone, rate string
		received, asn             int
	}{{"ok", "成功", "ok", "100%", 3, 4837}, {"ok", "部分成功", "warn", "66.7%", 2, 4837}, {"failed", "连接失败", "danger", "0%", 0, 4837}, {"unavailable", "探针不可用", "muted", "—", 0, 0}} {
		selected := store.MainlandProbe{Carrier: "中国联通", ASN: tc.asn, City: "Shanghai", Time: now.Unix(), Status: tc.status, TCPMS: 45.25, Sent: 3, Received: tc.received}
		got := mainlandViews(append(legacy, selected), store.MainlandSource{ASN: 4837}, now)
		if len(got) != 1 || got[0].CityText != "Shanghai" || got[0].State != tc.state || got[0].Tone != tc.tone || got[0].Rate != tc.rate {
			t.Fatal("selected probe state or old-batch filtering failed", got)
		}
		if tc.received > 0 && got[0].TCP != "45.2 ms" || tc.received == 0 && got[0].TCP != "—" {
			t.Fatal("latency shown for unsuccessful measurement", got)
		}
	}
	if p := mainlandViews(legacy, store.MainlandSource{ASN: 4837}, now); len(p) != 1 || p[0].State != "暂无数据" {
		t.Fatal("unselected legacy carrier used as fallback", p)
	}
	for _, age := range []time.Duration{proto.ProbeMaxAge, proto.ProbeMaxAge + time.Second} {
		p := mainlandViews([]store.MainlandProbe{{Carrier: "中国联通", ASN: 4837, Time: now.Add(-age).Unix(), Status: "ok", Sent: 3, Received: 3, TCPMS: 12}}, store.MainlandSource{ASN: 4837}, now)[0]
		if age == proto.ProbeMaxAge && p.State != "成功" || age > proto.ProbeMaxAge && (p.State != "暂无新数据" || p.Rate != "—" || p.TCP != "—") {
			t.Fatal("incorrect selected probe freshness", age, p)
		}
	}
}

func TestMainlandPagesIgnoreDestinationHeartbeatAndOutage(t *testing.T) {
	f := setup(t)
	samples := []store.MainlandProbe{{Carrier: "中国联通", City: "Shanghai", Network: "China Unicom <source>", Country: "CN", ASN: 4837, MeasurementID: "private-measurement", Time: f.now.Unix(), Status: "ok", TCPMS: 52.4, Sent: 3, Received: 2}, {Carrier: "中国电信", City: "Beijing", Network: "CHINANET", Country: "CN", ASN: 4134, Time: f.now.Unix(), Status: "ok", TCPMS: 78.3, Sent: 3, Received: 2}, {Carrier: "中国移动", Time: f.now.Unix(), Status: "unavailable"}}
	if err := f.s.SetMainlandProbes("node", samples); err != nil {
		t.Fatal(err)
	}
	for _, outage := range []bool{false, true} {
		if outage {
			if err := f.s.SetKV("receiver.outage", `{"members":{"node":true}}`); err != nil {
				t.Fatal(err)
			}
		}
		// This node has never sent a heartbeat. Independent external tests
		// should still be visible as current successful measurements.
		for _, path := range []string{"/", "/nodes/node"} {
			w := f.request("GET", path, nil, true)
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, "国内访问 · 国内 → 节点") || !strings.Contains(body, "52.4 ms") || !strings.Contains(body, "66.7%") || !strings.Contains(body, "Globalping") {
				t.Fatal("external direction followed destination heartbeat", path, w.Code, body)
			}
			if strings.Contains(body, "中国电信") || strings.Contains(body, "中国移动") || !strings.Contains(body, "TCP 往返建连延迟") {
				t.Fatal("multiple legacy sources or ambiguous latency rendered", body)
			}
			if path == "/nodes/node" && (!strings.Contains(body, "AS4837") || !strings.Contains(body, "China Unicom &lt;source&gt;") || !strings.Contains(body, "Shanghai · CN")) {
				t.Fatal("source details missing or unescaped", body)
			}
			if path == "/" {
				servers := regexp.MustCompile(`(?s)<table class="servers">.*?</table>`).FindString(body)
				if strings.Count(servers, "<th>") != 7 || strings.Contains(servers, "52.4") {
					t.Fatal("inbound probes crowded resource table", servers)
				}
			}
		}
	}
	f.now = f.now.Add(proto.ProbeMaxAge + time.Second)
	w := f.request("GET", "/", nil, true)
	block := regexp.MustCompile(`(?s)<section class="card flush" id="mainland-overview">.*?</section>`).FindString(w.Body.String())
	if !strings.Contains(block, "暂无新数据") || strings.Contains(block, "52.4 ms") || strings.Contains(block, "66.7%") {
		t.Fatal("old external measurements still shown as current", block)
	}
}
