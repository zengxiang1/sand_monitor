package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestWALSchemaRetentionAndAtomicity(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var mode string
	if e = s.DB.QueryRow(`PRAGMA journal_mode`).Scan(&mode); e != nil || mode != "wal" {
		t.Fatal(mode, e)
	}
	if e = s.Migrate(); e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1700000000, 0)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if e = s.AddNode("node", pub, now); e != nil {
		t.Fatal(e)
	}
	if e = s.AddNode("node", pub, now); e == nil {
		t.Fatal("duplicate node")
	}
	r := proto.Report{NetTotal: [2]uint64{^uint64(0), ^uint64(0)}}
	fail := errors.New("rollback")
	e = s.Accept("node", 1, now, "ip", &r, func() error { return nil }, func(tx *sql.Tx, _ Node) error {
		if e := AddEvent(tx, now, "node", "test", ""); e != nil {
			t.Fatal(e)
		}
		return fail
	})
	if !errors.Is(e, fail) {
		t.Fatal(e)
	}
	n, _ := s.Node("node")
	if n.LastSeq != 0 {
		t.Fatal("sequence survived rollback")
	}
	for _, table := range []string{"metrics", "events"} {
		var count int
		if e = s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal(table, count, e)
		}
	}
	for i, at := range []time.Time{now.Add(-7*24*time.Hour - time.Second), now.Add(-7 * 24 * time.Hour), now} {
		if e = s.Accept("node", uint64(i+1), at, "ip", &r, func() error { return nil }, func(tx *sql.Tx, _ Node) error {
			if _, e := tx.Exec(`INSERT INTO logins VALUES(?,?,?,?,?)`, "node", at.Unix(), "root", "ip", 1); e != nil {
				return e
			}
			return AddEvent(tx, at, "node", "test", "")
		}); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Cleanup(now); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"metrics", "logins", "events"} {
		var count int
		if e = s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 2 {
			t.Fatal(table, count, e)
		}
	}
	var total string
	if e = s.DB.QueryRow(`SELECT net_total_tx FROM metrics LIMIT 1`).Scan(&total); e != nil || total != "18446744073709551615" {
		t.Fatal(total, e)
	}
	if e = s.Revoke("absent", now); !errors.Is(e, ErrNode) {
		t.Fatal(e)
	}
	if e = s.Revoke("node", now); e != nil {
		t.Fatal(e)
	}
	if e = s.Accept("node", 4, now, "ip", &r, func() error { return nil }, nil); !errors.Is(e, ErrNode) {
		t.Fatal(e)
	}
}
