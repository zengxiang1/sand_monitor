package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestProbePersistenceAndRetention(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for range 2 { // Two independent receivers accept the same samples.
		s, err := Open(filepath.Join(t.TempDir(), "db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		if err = s.AddNode("node", pub, now.Add(-10*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		p := proto.Probe{Target: "https://example.com/", Time: now.Unix(), IP: "192.0.2.1", DNSMS: 1, TCPMS: 2, TLSMS: 3, TTFBMS: 4, TotalMS: 5, Status: 200}
		r := proto.Report{Probes: []proto.Probe{p}}
		accept := func(seq uint64, at time.Time, evaluate func(*sql.Tx, Node) error) error {
			return s.Accept("node", seq, at, "192.0.2.1", &r, func() error { return nil }, evaluate)
		}
		for seq := uint64(1); seq <= 10; seq++ {
			if err = accept(seq, now.Add(time.Duration(seq)*time.Second), nil); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.ProbeHistory("node", now.Add(-time.Hour))
		if err != nil || !reflect.DeepEqual(got, []proto.Probe{p}) {
			t.Fatal(got, err)
		}
		r.Probes[0].Time = now.Add(-time.Minute).Unix()
		r.Probes[0].Error = "timeout"
		r.Probes[0].Status = 0
		if err = accept(11, now, nil); err != nil {
			t.Fatal(err)
		}
		got, err = s.LatestProbes("node")
		if err != nil || !reflect.DeepEqual(got, []proto.Probe{p}) {
			t.Fatal("out of order changed latest", got, err)
		}
		r.Probes = append(r.Probes, proto.Probe{Target: "https://another.example/", Time: now.Unix(), Error: "dns"})
		if err = accept(12, now, nil); err != nil {
			t.Fatal(err)
		}
		got, err = s.ProbeHistory("node", now.Add(-time.Hour))
		if err != nil || len(got) != 3 || got[0].Target != "https://another.example/" || got[1].Time >= got[2].Time {
			t.Fatal("history ordering", got, err)
		}
		r.Probes = []proto.Probe{p}
		r.Probes[0].Time = now.Add(time.Minute + time.Second).Unix()
		if err = accept(13, now, nil); !errors.Is(err, ErrProbeTime) {
			t.Fatal("future accepted", err)
		}
		n, err := s.Node("node")
		if err != nil || n.LastSeq != 12 {
			t.Fatal("future advanced report", n, err)
		}
		r.Probes[0].Time = now.Add(-8 * 24 * time.Hour).Unix()
		if err = accept(13, now, nil); err != nil {
			t.Fatal("stale report rejected", err)
		}
		got, err = s.ProbeHistory("node", time.Time{})
		if err != nil || len(got) != 3 {
			t.Fatal("stale inserted", got, err)
		}
		r.Probes[0].Time = now.Add(time.Second).Unix()
		failure := errors.New("alert failed")
		if err = accept(14, now, func(*sql.Tx, Node) error { return failure }); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		got, err = s.LatestProbes("node")
		if err != nil || got[1].Time != now.Unix() {
			t.Fatal("failed transaction persisted sample", got, err)
		}
		if err = s.Cleanup(now.Add(7*24*time.Hour + time.Second)); err != nil {
			t.Fatal(err)
		}
		got, err = s.LatestProbes("node")
		if err != nil || len(got) != 0 {
			t.Fatal("seven day retention", got, err)
		}
	}
}

func TestV8ProbeMigrationPreservesEventsAndDeliveries(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = s.AddNode("node", pub, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO events(id,ts,node,kind,detail,notification_detail,targets) VALUES(7,1,'node','offline','retained','prepared','telegram'); INSERT INTO event_deliveries VALUES(7,'channel');DROP TABLE probe_samples; DROP TABLE probe_alerts; PRAGMA user_version=8;`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Migrate(); err != nil {
			t.Fatal(err)
		}
	}
	var detail, prepared, targets, notifier string
	if err = s.DB.QueryRow(`SELECT detail,notification_detail,targets,notifier FROM events JOIN event_deliveries ON events.id=event_id WHERE id=7`).Scan(&detail, &prepared, &targets, &notifier); err != nil || detail != "retained" || prepared != "prepared" || targets != "telegram" || notifier != "channel" {
		t.Fatal(detail, prepared, targets, notifier, err)
	}
}
