package proto

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestProbeValidation(t *testing.T) {
	valid := Probe{Target: "https://example.com/robots.txt", Time: 1, IP: "2001:db8::1", Status: 200, DNSMS: 1, TCPMS: 2, TLSMS: 3, TTFBMS: 8, TotalMS: 9}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Probe){
		func(p *Probe) { p.Time = 0 }, func(p *Probe) { p.IP = "invalid" },
		func(p *Probe) { p.DNSMS = math.NaN() }, func(p *Probe) { p.TCPMS = math.Inf(1) },
		func(p *Probe) { p.TLSMS = -1 }, func(p *Probe) { p.TTFBMS = 60001 }, func(p *Probe) { p.TotalMS = 60001 },
		func(p *Probe) { p.Status = 0 }, func(p *Probe) { p.Status = 199 }, func(p *Probe) { p.Status = 400 },
		func(p *Probe) { p.Error = "arbitrary message" }, func(p *Probe) { p.Status = 600; p.Error = "http" },
	} {
		bad := valid
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted invalid probe", bad)
		}
	}
	for _, code := range []string{"dns", "connect", "tls", "timeout", "http", "request", "read"} {
		p := valid
		p.Error, p.Status, p.IP = code, 0, ""
		if err := p.Validate(); err != nil {
			t.Fatal(p, err)
		}
	}
	for _, target := range []string{"http://example.com/", "https://", "https://user:pass@example.com/", "https://example.com/#", "https://example.com/#fragment", "https://example.com/" + strings.Repeat("a", 512), "https://example.com:invalid/"} {
		if ValidateProbeTargets([]string{target}) == nil {
			t.Fatal("accepted", target)
		}
	}
	for _, targets := range [][]string{{valid.Target, valid.Target}, make([]string, 9)} {
		if ValidateProbeTargets(targets) == nil {
			t.Fatal("accepted targets", targets)
		}
	}
	if err := ValidateProbeTargets([]string{"https://example.com/path?a=1,b=2"}); err != nil {
		t.Fatal(err)
	}
	r := Report{Version: 1, Bin: "sha256:" + strings.Repeat("a", 64), OS: "linux", Arch: "amd64"}
	body, err := json.Marshal(r)
	if err != nil || strings.Contains(string(body), `"probes"`) {
		t.Fatal(string(body), err)
	}
	r.Probes = []Probe{valid}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Probes = append(r.Probes, valid)
	if r.Validate() == nil {
		t.Fatal("duplicate report targets")
	}
	r.Probes = make([]Probe, 9)
	if r.Validate() == nil {
		t.Fatal("too many report probes")
	}
}
