package alert

import (
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestProbeEpisodesDeduplicateAndPersist(t *testing.T) {
	e, now := setupEngine(t)
	r := sampleReport()
	p := proto.Probe{Target: "https://example.com/", Error: "timeout"}
	for i := range 3 {
		at := now.Add(time.Duration(i) * proto.ProbeInterval)
		p.Time = at.Unix()
		r.Probes = []proto.Probe{p}
		for repeat := range 5 {
			send(t, e, at.Add(time.Duration(repeat)*10*time.Minute), r)
		}
		want := 0
		if i == 2 {
			want = 1
		}
		if got := count(t, e, "probe_down"); got != want {
			t.Fatal(i, got)
		}
	}
	e = New(e.Store, DefaultConfig())
	send(t, e, now.Add(2*proto.ProbeInterval+45*time.Minute), r)
	p.Time = now.Add(2*proto.ProbeInterval - time.Minute).Unix()
	p.Error, p.Status = "", 200
	r.Probes = []proto.Probe{p}
	send(t, e, now.Add(2*proto.ProbeInterval+46*time.Minute), r)
	if count(t, e, "probe_up") != 0 {
		t.Fatal("out of order recovered")
	}
	p.Time = now.Add(3 * proto.ProbeInterval).Unix()
	r.Probes = []proto.Probe{p}
	send(t, e, now.Add(3*proto.ProbeInterval), r)
	send(t, e, now.Add(3*proto.ProbeInterval+5*time.Minute), r)
	if count(t, e, "probe_down") != 1 || count(t, e, "probe_up") != 1 {
		t.Fatal("episode repeated or missing recovery")
	}
}

func TestProbeStaleGapAndIndependentTargets(t *testing.T) {
	e, now := setupEngine(t)
	r := sampleReport()
	last := now.Add(proto.ProbeInterval + proto.ProbeMaxAge + time.Second + proto.ProbeInterval)
	for _, at := range []time.Time{now, now.Add(proto.ProbeInterval), last.Add(-proto.ProbeInterval), last} {
		r.Probes = []proto.Probe{{Target: "https://example.com/", Time: at.Unix(), Error: "dns"}, {Target: "https://other.example/", Time: at.Unix(), Status: 200}}
		send(t, e, at, r)
	}
	if count(t, e, "probe_down") != 0 {
		t.Fatal("missed hourly observation counted as consecutive")
	}
	// A new timestamp that arrives more than 75 minutes late cannot complete
	// the two-observation failure streak.
	r.Probes[0].Time = last.Add(time.Minute).Unix()
	send(t, e, last.Add(proto.ProbeMaxAge+2*time.Minute), r)
	if count(t, e, "probe_down") != 0 {
		t.Fatal("stale failure alerted")
	}
	var processed int64
	if err := e.Store.DB.QueryRow(`SELECT last_ts FROM probe_alerts WHERE node='node' AND target='https://example.com/'`).Scan(&processed); err != nil || processed != last.Unix() {
		t.Fatal("stale failure changed current health", processed, err)
	}
	for i := range 3 {
		at := last.Add(time.Duration(i+2) * proto.ProbeInterval)
		r.Probes[0].Time = at.Unix()
		r.Probes[1].Time = at.Unix()
		send(t, e, at, r)
		want := 0
		if i == 2 {
			want = 1
		}
		if count(t, e, "probe_down") != want {
			t.Fatal("fresh hourly streak after stale reports", i)
		}
	}
	// A stale success cannot recover an active failure episode.
	r.Probes[0].Error, r.Probes[0].Status = "", 200
	last = last.Add(4*proto.ProbeInterval + time.Minute)
	r.Probes[0].Time = last.Unix()
	send(t, e, last.Add(proto.ProbeMaxAge+time.Second), r)
	if count(t, e, "probe_up") != 0 {
		t.Fatal("stale success recovered")
	}
	// A fresh success still recovers the persisted episode after a long gap.
	at := last.Add(proto.ProbeMaxAge + time.Minute)
	r.Probes[0].Time = at.Unix()
	send(t, e, at, r)
	if count(t, e, "probe_up") != 1 {
		t.Fatal("fresh recovery missing after missed hourly probes")
	}
}

func TestProbeFreshnessBoundary(t *testing.T) {
	e, now := setupEngine(t)
	r := sampleReport()
	r.Probes = []proto.Probe{{Target: "https://example.com/", Time: now.Unix(), Error: "dns"}}
	send(t, e, now.Add(proto.ProbeMaxAge), r)
	var last int64
	if err := e.Store.DB.QueryRow(`SELECT last_ts FROM probe_alerts WHERE node='node' AND target='https://example.com/'`).Scan(&last); err != nil || last != now.Unix() {
		t.Fatal("75 minute boundary rejected", last, err)
	}
}

func TestProbeConsecutiveGapBoundary(t *testing.T) {
	for _, gap := range []time.Duration{proto.ProbeMaxAge, proto.ProbeMaxAge + time.Second} {
		t.Run(gap.String(), func(t *testing.T) {
			e, now := setupEngine(t)
			r := sampleReport()
			for _, at := range []time.Time{now, now.Add(proto.ProbeInterval), now.Add(proto.ProbeInterval + gap)} {
				r.Probes = []proto.Probe{{Target: "https://example.com/", Time: at.Unix(), Error: "timeout"}}
				send(t, e, at, r)
			}
			want := 0
			if gap == proto.ProbeMaxAge {
				want = 1
			}
			if got := count(t, e, "probe_down"); got != want {
				t.Fatal("75 minute consecutive gap boundary", gap, got)
			}
		})
	}
}
