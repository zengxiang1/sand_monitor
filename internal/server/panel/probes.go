package panel

import (
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"
	"wanglou/internal/proto"
)

type probeView struct {
	proto.Probe
	Host, State, Tone, IPText, TCP, TTFB, DNS, TLS, Total string
	Rate, P50, P95                                        string
	Samples, Successes                                    int
	Chart                                                 probeChart
}

type probeChart struct {
	TCP, TTFB, Top, Mid, Start, End string
}

// probeViews keeps statistics over raw samples; only the rendered chart is bucketed.
func probeViews(latest, history []proto.Probe, now time.Time, freshNode bool, duration time.Duration) []probeView {
	byTarget := make(map[string][]proto.Probe)
	start := now.Add(-duration).Unix()
	for _, p := range history {
		if p.Time >= start && p.Time <= now.Unix() {
			byTarget[p.Target] = append(byTarget[p.Target], p)
		}
	}
	var out []probeView
	for _, p := range latest {
		target, _ := url.Parse(p.Target)
		v := probeView{Probe: p, Host: target.Hostname(), State: "成功", Tone: "ok", IPText: p.IP, Rate: "—", P50: "—", P95: "—"}
		if v.IPText == "" {
			v.IPText = "—"
		}
		if p.Error != "" {
			v.Tone = "danger"
			v.State = map[string]string{"dns": "DNS 失败", "connect": "TCP 失败", "tls": "TLS 失败", "timeout": "请求超时", "http": "HTTP 失败", "request": "请求失败", "read": "读取失败"}[p.Error]
		}
		if !freshNode || now.Unix()-p.Time > int64(proto.ProbeMaxAge/time.Second) {
			v.State, v.Tone = "暂无新数据", "muted"
		}
		values := []*string{&v.TCP, &v.TTFB, &v.DNS, &v.TLS, &v.Total}
		for i, value := range []float64{p.TCPMS, p.TTFBMS, p.DNSMS, p.TLSMS, p.TotalMS} {
			*values[i] = fmt.Sprintf("%.1f ms", value)
			if p.Error != "" && value == 0 {
				*values[i] = "—"
			}
		}
		samples := byTarget[p.Target]
		v.Samples = len(samples)
		var successful []float64
		for _, sample := range samples {
			if sample.Error == "" {
				successful = append(successful, sample.TTFBMS)
			}
		}
		v.Successes = len(successful)
		if len(samples) > 0 {
			v.Rate = fmt.Sprintf("%.1f%%", float64(v.Successes)*100/float64(len(samples)))
		}
		if len(successful) > 0 {
			slices.Sort(successful)
			v.P50 = fmt.Sprintf("%.1f ms", successful[int(math.Ceil(float64(len(successful))*.50))-1])
			v.P95 = fmt.Sprintf("%.1f ms", successful[int(math.Ceil(float64(len(successful))*.95))-1])
		}
		// Failure buckets stay blank. Missing intervals break the line while
		// preserving the next observation after a gap.
		type bucket struct {
			first, last      int64
			tcp, ttfb        float64
			count            int
			gap, breakBefore bool
		}
		var buckets [240]bucket
		previous := int64(0)
		for _, sample := range samples {
			index := min(239, int(float64(sample.Time-start)/duration.Seconds()*240))
			b := &buckets[index]
			if b.first == 0 {
				b.first = sample.Time
			}
			b.last = sample.Time
			if sample.Error != "" {
				b.gap = true
			}
			if previous != 0 && time.Duration(sample.Time-previous)*time.Second > proto.ProbeMaxAge {
				b.breakBefore = true
			}
			b.tcp += sample.TCPMS
			b.ttfb += sample.TTFBMS
			b.count++
			previous = sample.Time
		}
		ceiling := 1.0
		for _, b := range buckets {
			if b.count > 0 && !b.gap {
				ceiling = max(ceiling, b.tcp/float64(b.count), b.ttfb/float64(b.count))
			}
		}
		var tcp, ttfb strings.Builder
		command := "M"
		for _, b := range buckets {
			if b.count == 0 {
				continue
			}
			if b.gap {
				command = "M"
				continue
			}
			if b.breakBefore {
				command = "M"
			}
			x := 84 + float64((b.first+b.last)/2-start)/duration.Seconds()*508
			fmt.Fprintf(&tcp, "%s%.2f,%.2f ", command, x, 160-b.tcp/float64(b.count)/ceiling*146)
			fmt.Fprintf(&ttfb, "%s%.2f,%.2f ", command, x, 160-b.ttfb/float64(b.count)/ceiling*146)
			if command == "M" {
				tcp.WriteString("l0,0 ")
				ttfb.WriteString("l0,0 ")
			}
			command = "L"
		}
		v.Chart = probeChart{TCP: tcp.String(), TTFB: ttfb.String(), Top: fmt.Sprintf("%.0f ms", ceiling), Mid: fmt.Sprintf("%.0f ms", ceiling/2), Start: time.Unix(start, 0).Format("01-02 15:04"), End: now.Format("01-02 15:04")}
		out = append(out, v)
	}
	return out
}
