package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestPhaseOneMigration(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`CREATE TABLE nodes(name TEXT PRIMARY KEY,pubkey BLOB NOT NULL,fingerprint TEXT NOT NULL,created_at INTEGER NOT NULL,revoked_at INTEGER NOT NULL DEFAULT 0,last_seq TEXT NOT NULL DEFAULT '0',last_seen INTEGER NOT NULL DEFAULT 0,last_ip TEXT NOT NULL DEFAULT '',bin_hash TEXT NOT NULL DEFAULT '');
 CREATE TABLE metrics(node TEXT NOT NULL REFERENCES nodes(name),ts INTEGER NOT NULL,cpu REAL,load1 REAL,load5 REAL,load15 REAL,mem_used REAL,mem_total REAL,swap_used REAL,swap_total REAL,disk_used REAL,disk_total REAL,net_tx REAL,net_rx REAL,net_total_tx TEXT,net_total_rx TEXT,tcp INTEGER,udp INTEGER,uptime REAL);
 CREATE TABLE logins(node TEXT NOT NULL REFERENCES nodes(name),ts INTEGER NOT NULL,user TEXT,from_ip TEXT,known INTEGER NOT NULL);
 CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,node TEXT NOT NULL REFERENCES nodes(name),kind TEXT NOT NULL,detail TEXT NOT NULL,notified INTEGER NOT NULL DEFAULT 0);`)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`PRAGMA user_version=` + string(rune('0'+version))); err != nil {
				t.Fatal(err)
			}
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			if _, err = db.Exec(`INSERT INTO nodes(name,pubkey,fingerprint,created_at,last_seq) VALUES('old',?,?,100,'18446744073709551615')`, []byte(pub), proto.Fingerprint(pub)); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`INSERT INTO metrics(node,ts,cpu) VALUES('old',100,42);INSERT INTO logins VALUES('old',100,'root','192.0.2.1',1);INSERT INTO events(ts,node,kind,detail) VALUES(100,'old','offline','retained');`); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var got int
			if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&got); err != nil || got != 6 {
				t.Fatal(got, err)
			}
			n, err := s.Node("old")
			if err != nil || n.LastSeq != ^uint64(0) || n.Fingerprint != proto.Fingerprint(pub) || n.Note != "" || n.OS != "" || n.Arch != "" || n.MutedUntil != 0 {
				t.Fatal(n, err)
			}
			var ack int64
			var detail string
			if err = s.DB.QueryRow(`SELECT detail,acked_at FROM events`).Scan(&detail, &ack); err != nil || detail != "retained" || ack != 0 {
				t.Fatal(detail, ack, err)
			}
			for _, table := range []string{"nodes", "metrics", "logins", "events"} {
				if err = s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&got); err != nil || got != 1 {
					t.Fatal(table, got, err)
				}
			}
			if err = s.Migrate(); err != nil {
				t.Fatal("not idempotent", err)
			}
		})
	}
}
func TestPanelRetentionAndMetadata(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Unix(2000000000, 0)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = s.AddNode("node", pub, now); err != nil {
		t.Fatal(err)
	}
	report := proto.Report{OS: strings.Repeat("o", 64), Arch: strings.Repeat("a", 64)}
	if err = s.Accept("node", 1, now, "192.0.2.1", &report, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	n, err := s.Node("node")
	if err != nil || len(n.OS) != 32 || len(n.Arch) != 32 {
		t.Fatal(n, err)
	}
	if _, err = s.DB.Exec(`INSERT INTO admins(user,pw_hash,totp_secret,created_at) VALUES('admin','test','test',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		token         string
		created, last time.Time
	}{{"idle", now, now.Add(-12 * time.Hour)}, {"absolute", now.Add(-7 * 24 * time.Hour), now}, {"live", now, now}} {
		if _, err = s.DB.Exec(`INSERT INTO sessions VALUES(?,?,?,?,?,?)`, TokenHash(item.token), "admin", "csrf", item.created.Unix(), item.last.Unix(), "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	for i, age := range []time.Duration{25 * time.Hour, time.Hour} {
		if _, err = s.DB.Exec(`INSERT INTO enroll_codes(code_hash,name,note,created_at,expires_at) VALUES(?,'fresh','',?,?)`, i, now.Add(-age).Unix(), now.Add(-age+10*time.Minute).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	for _, age := range []time.Duration{91 * 24 * time.Hour, time.Hour} {
		if _, err = s.DB.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,'admin','192.0.2.1','test','')`, now.Add(-age).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "enroll_codes", "audit_log"} {
		var count int
		if err = s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 1 {
			t.Fatal(table, count, err)
		}
	}
}

func TestRevokedKeysMigration(t *testing.T) {
	for _, version := range []int{4, 5} {
		s := billingStore(t)
		node, err := s.Node("node")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.Exec(`UPDATE nodes SET revoked_at=100 WHERE name='node'; DROP TABLE revoked_keys;ALTER TABLE billing DROP COLUMN anchor_day;PRAGMA user_version=5`); err != nil {
			t.Fatal(err)
		}
		if version == 4 {
			if _, err = s.DB.Exec(`DROP TABLE metrics_1m;DROP TABLE metrics_1h;PRAGMA user_version=4`); err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			if err = s.Migrate(); err != nil {
				t.Fatal(version, err)
			}
			var fingerprint, name string
			var at int64
			if err = s.DB.QueryRow(`SELECT fingerprint,node,revoked_at FROM revoked_keys`).Scan(&fingerprint, &name, &at); err != nil || fingerprint != node.Fingerprint || name != "node" || at != 100 {
				t.Fatal(version, fingerprint, name, at, err)
			}
			var got int
			if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&got); err != nil || got != 6 {
				t.Fatal(version, got, err)
			}
		}
	}
}

func TestV5AnchorDayMigration(t *testing.T) {
	s := billingStore(t)
	b := DefaultBilling("node")
	b.Expiry = "2026-01-31"
	if err := s.SaveBilling(b, nil, time.Now(), "admin", ""); err != nil {
		t.Fatal(err)
	}
	node, err := s.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	for name, expiry := range map[string]string{"blank": "", "leap": "2024-02-29"} {
		if err = s.AddNode(name, node.Pubkey, time.Now()); err != nil {
			t.Fatal(err)
		}
		bill := DefaultBilling(name)
		bill.Expiry = expiry
		if err = s.SaveBilling(bill, nil, time.Now(), "admin", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`ALTER TABLE billing DROP COLUMN anchor_day; PRAGMA user_version=5`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Migrate(); err != nil {
			t.Fatal(err)
		}
		got, err := s.Billing("node")
		if err != nil || got.AnchorDay != 31 || got.Expiry != b.Expiry {
			t.Fatal(got, err)
		}
		for name, anchor := range map[string]int{"blank": 1, "leap": 29} {
			got, err := s.Billing(name)
			if err != nil || got.AnchorDay != anchor {
				t.Fatal(got, err)
			}
		}
	}
	if _, err := s.DB.Exec(`UPDATE billing SET expiry='2026-02-28'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	got, err := s.Billing("node")
	if err != nil || got.AnchorDay != 31 {
		t.Fatal("migration rewrote anchor", got, err)
	}
	got.Expiry = "2026-03-15"
	if err = s.SaveBilling(got, nil, time.Now(), "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err = s.Billing("node")
	if err != nil || got.AnchorDay != 15 {
		t.Fatal("save failed to reset anchor", got, err)
	}
	got.Expiry = ""
	if err = s.SaveBilling(got, nil, time.Now(), "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err = s.Billing("node")
	if err != nil || got.AnchorDay != 1 {
		t.Fatal(got, err)
	}
}
