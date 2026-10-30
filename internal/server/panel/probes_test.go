package panel

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func TestProbeStatisticsUseRawSuccessfulTTFB(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	var history []proto.Probe
	for i := range 100 {
		history = append(history, proto.Probe{Target: "https://www.baidu.com/robots.txt", Time: now.Unix() - int64(100-i)*60, TCPMS: 10, TTFBMS: float64(i + 1), Status: 200})
	}
	history[99].Error = "timeout"
	view := probeViews(history[99:], history, now, true, 24*time.Hour)[0]
	if view.Samples != 100 || view.Successes != 99 || view.Rate != "99.0%" || view.P50 != "50.0 ms" || view.P95 != "95.0 ms" {
		t.Fatalf("raw statistics: %+v", view)
	}
	if view.State != "请求超时" || view.Tone != "danger" {
		t.Fatalf("failure status: %+v", view)
	}
	view = probeViews(history[99:], nil, now, true, 24*time.Hour)[0]
	if view.Samples != 0 || view.Rate != "—" || view.P50 != "—" || view.Chart.TCP != "" {
		t.Fatalf("empty history: %+v", view)
	}
}

func TestProbeFreshnessAndFailureStages(t *testing.T) {
	now := time.Unix(2_000_000_000, 900_000_000)
	for _, tc := range []struct {
		error, state string
	}{{"", "成功"}, {"dns", "DNS 失败"}, {"connect", "TCP 失败"}, {"tls", "TLS 失败"}, {"timeout", "请求超时"}, {"http", "HTTP 失败"}, {"request", "请求失败"}, {"read", "读取失败"}} {
		t.Run(tc.error, func(t *testing.T) {
			p := proto.Probe{Target: "https://www.baidu.com/robots.txt", Time: now.Add(-proto.ProbeMaxAge).Unix(), Status: 200, Error: tc.error}
			view := probeViews([]proto.Probe{p}, nil, now, true, 24*time.Hour)[0]
			if view.State != tc.state {
				t.Fatal(view.State)
			}
			for _, fresh := range []bool{false, true} {
				p.Time = now.Add(-proto.ProbeMaxAge - time.Second).Unix()
				view = probeViews([]proto.Probe{p}, nil, now, fresh, 24*time.Hour)[0]
				if view.State != "暂无新数据" || view.Tone != "muted" {
					t.Fatalf("old sample still indicates success/failure: %+v", view)
				}
			}
			p.Time = now.Unix()
			if got := probeViews([]proto.Probe{p}, nil, now, false, 24*time.Hour)[0]; got.State != "暂无新数据" {
				t.Fatalf("stale node with fresh sample: %+v", got)
			}
		})
	}
}

func TestProbeChartBucketsPreserveFailuresAndMissingIntervals(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	target := "https://www.baidu.com/robots.txt"
	var history []proto.Probe
	for i := range 10080 {
		p := proto.Probe{Target: target, Time: now.Add(-7*24*time.Hour).Unix() + int64(i)*60, TCPMS: 10, TTFBMS: 30, Status: 200}
		if i == 100 || i == 200 {
			p.Error = "timeout"
		}
		if i >= 400 && i <= 500 {
			continue
		}
		history = append(history, p)
	}
	view := probeViews(history[len(history)-1:], history, now, true, 7*24*time.Hour)[0]
	commands := regexp.MustCompile(`[ML]`).FindAllString(view.Chart.TCP, -1)
	if len(commands) > 240 || strings.Count(view.Chart.TCP, "M") < 4 || view.Samples != len(history) {
		t.Fatalf("bounded/gapped chart: %d commands, %d gaps, %d samples", len(commands), strings.Count(view.Chart.TCP, "M"), view.Samples)
	}
	// Empty display buckets between hourly observations are expected; only
	// a gap beyond the shared maximum age should split the successful line.
	var hourly []proto.Probe
	for i := range 24 {
		hourly = append(hourly, proto.Probe{Target: target, Time: now.Add(-time.Duration(24-i) * proto.ProbeInterval).Unix(), TCPMS: 10, TTFBMS: 30, Status: 200})
	}
	connected := probeViews(hourly[23:], hourly, now, true, 24*time.Hour)[0].Chart.TCP
	if strings.Count(connected, "M") != 1 || strings.Count(connected, "L") != 23 {
		t.Fatal("hourly samples were split by empty chart buckets:", connected)
	}
	hourly = append(hourly[:10], hourly[11:]...)
	gapped := probeViews(hourly[len(hourly)-1:], hourly, now, true, 24*time.Hour)[0].Chart.TCP
	if strings.Count(gapped, "M") != 2 {
		t.Fatal("missing hourly sample was bridged:", gapped)
	}
}

func TestOutgoingProbesStayStoredButLeavePrivatePages(t *testing.T) {
	f := setup(t)
	r := sampleReport()
	r.Probes = []proto.Probe{{Target: "https://www.baidu.com/robots.txt", Time: f.now.Unix(), TCPMS: 32.5, TTFBMS: 60, Status: 200}, {Target: "https://cloud.tencent.com/robots.txt", Time: f.now.Unix(), Error: "dns"}, {Target: "https://www.aliyun.com/robots.txt", Time: f.now.Unix(), Status: 200}}
	f.report(t, "node", r, 204)
	if err := f.s.SetMainlandProbes("node", []store.MainlandProbe{{Carrier: "中国联通", City: "Shanghai", ASN: 4837, Time: f.now.Unix(), TCPMS: 68.7, Sent: 3, Received: 3, Status: "ok"}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/nodes/node?range=7d&probe_range=7d"} {
		w := f.request("GET", path, nil, true)
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "国内访问") || !strings.Contains(body, "68.7 ms") {
			t.Fatal("inbound monitoring removed with old site probes", path, w.Code, body)
		}
		for _, removed := range []string{"www.baidu.com", "cloud.tencent.com", "www.aliyun.com", "节点 → 站点", "国内连接", `id="probe-overview"`, `id="domestic-connection"`, "probe_range=", "P50", "TTFB"} {
			if strings.Contains(body, removed) {
				t.Error("retired outgoing probe still rendered", path, removed)
			}
		}
	}
	stored, err := f.s.LatestProbes("node")
	if err != nil || len(stored) != 3 {
		t.Fatal("hiding outgoing probes changed their stored history", stored, err)
	}
	if _, err := f.s.DB.Exec(`ALTER TABLE probe_samples RENAME TO retained_probe_samples`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/nodes/node?probe_range=7d"} {
		if w := f.request("GET", path, nil, true); w.Code != 200 {
			t.Fatal("private routes still query retired outgoing probes", path, w.Code, w.Body)
		}
	}
}
