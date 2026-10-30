package ingest_test

import (
	"encoding/json"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestSignedProbeTimeBoundary(t *testing.T) {
	x := newSetup(t)
	r := sample()
	r.Probes = []proto.Probe{{Target: "https://example.com/", Time: x.now.Add(61 * time.Second).Unix(), Error: "timeout"}}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	check(t, x.h, signed(x.key, "node", 1, x.now.Unix(), body), 400)
	n, err := x.s.Node("node")
	if err != nil || n.LastSeq != 0 || n.LastSeen != 0 {
		t.Fatal("invalid probe advanced report", n, err)
	}
	r.Probes[0].Time = x.now.Add(time.Minute).Unix()
	body, _ = json.Marshal(r)
	check(t, x.h, signed(x.key, "node", 1, x.now.Unix(), body), 204)
	check(t, x.h, signed(x.key, "node", 2, x.now.Unix(), body), 204)
	probes, err := x.s.LatestProbes("node")
	if err != nil || len(probes) != 1 || probes[0].Time != r.Probes[0].Time {
		t.Fatal("future boundary or cached report", probes, err)
	}
	r.Probes[0].Time = x.now.Add(-8 * 24 * time.Hour).Unix()
	body, _ = json.Marshal(r)
	check(t, x.h, signed(x.key, "node", 3, x.now.Unix(), body), 204)
	n, err = x.s.Node("node")
	if err != nil || n.LastSeq != 3 {
		t.Fatal("stale probe blocked core report", n, err)
	}
}
