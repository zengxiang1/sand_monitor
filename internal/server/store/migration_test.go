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

const downgradeV7 = `DROP TABLE notify_cooldowns; DROP INDEX events_cooldown; ALTER TABLE nodes DROP COLUMN display_name; ALTER TABLE events DROP COLUMN cooldown_key; ALTER TABLE events DROP COLUMN cooldown_decided; ALTER TABLE events DROP COLUMN suppressed; ALTER TABLE events DROP COLUMN notification_detail; `

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
			if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&got); err != nil || got != 8 {
				t.Fatal(got, err)
			}
			n, err := s.Node("old")
			if err != nil || n.LastSeq != ^uint64(0) || n.Fingerprint != proto.Fingerprint(pub) || n.DisplayName != "" || n.Note != "" || n.OS != "" || n.Arch != "" || n.MutedUntil != 0 {
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
		if _, err = s.DB.Exec(downgradeV7 + `UPDATE nodes SET revoked_at=100 WHERE name='node'; DROP TABLE revoked_keys;ALTER TABLE billing DROP COLUMN anchor_day;PRAGMA user_version=5`); err != nil {
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
			if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&got); err != nil || got != 8 {
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
	if _, err := s.DB.Exec(downgradeV7 + `ALTER TABLE billing DROP COLUMN anchor_day; PRAGMA user_version=5`); err != nil {
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

func TestV6DisplayNameAndCooldownMigration(t *testing.T) {
	s := billingStore(t)
	if _, err := s.DB.Exec(downgradeV7 + `PRAGMA user_version=6; INSERT INTO events(ts,node,kind,detail) VALUES(100,'node','offline','retained')`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Migrate(); err != nil {
			t.Fatal(err)
		}
		var version int
		if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 8 {
			t.Fatal(version, err)
		}
		n, err := s.Node("node")
		if err != nil || n.DisplayName != "" {
			t.Fatal(n, err)
		}
		var key, detail string
		var decided, suppressed bool
		if err := s.DB.QueryRow(`SELECT cooldown_key,cooldown_decided,suppressed,detail FROM events`).Scan(&key, &decided, &suppressed, &detail); err != nil || key != "" || decided || suppressed || detail != "retained" {
			t.Fatal(key, decided, suppressed, detail, err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET display_name='东京一号';INSERT INTO notify_cooldowns VALUES('node','connectivity',1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	n, err := s.Node("node")
	if err != nil || n.DisplayName != "东京一号" {
		t.Fatal(n, err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM notify_cooldowns WHERE warned=1`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestV7SystemEventsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = s.AddNode("node", pub, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`DROP TABLE event_deliveries;
 DROP TABLE events;
 CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,node TEXT NOT NULL REFERENCES nodes(name),kind TEXT NOT NULL,detail TEXT NOT NULL,notified INTEGER NOT NULL DEFAULT 0,acked_at INTEGER NOT NULL DEFAULT 0,targets TEXT NOT NULL DEFAULT '',cooldown_key TEXT NOT NULL DEFAULT '',cooldown_decided INTEGER NOT NULL DEFAULT 0,suppressed INTEGER NOT NULL DEFAULT 0,notification_detail TEXT NOT NULL DEFAULT '');
 CREATE INDEX events_node_ts ON events(node,ts);
 CREATE INDEX events_cooldown ON events(node,cooldown_key,id);
 CREATE TABLE event_deliveries(event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,notifier TEXT NOT NULL,PRIMARY KEY(event_id,notifier));
 INSERT INTO events VALUES(41,100,'node','offline','retained delivered',1,110,'telegram','connectivity',1,0,'notification retained');
 INSERT INTO events VALUES(73,120,'node','recovered','retained pending',0,0,'','connectivity',1,1,'merged');
 INSERT INTO event_deliveries VALUES(41,'telegram:one'),(41,'webhook:two'),(73,'telegram:one');
 PRAGMA user_version=7;`); err != nil {
		t.Fatal(err)
	}
	queries := []string{
		`SELECT json_group_array(json_array(id,ts,node,kind,detail,notified,acked_at,targets,cooldown_key,cooldown_decided,suppressed,notification_detail)) FROM (SELECT * FROM events ORDER BY id)`,
		`SELECT json_group_array(json_array(event_id,notifier)) FROM (SELECT * FROM event_deliveries ORDER BY event_id,notifier)`,
		`SELECT json_group_array(json_array(name,sql)) FROM (SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='events' ORDER BY name)`,
	}
	before := make([]string, len(queries))
	for i, query := range queries {
		if err = s.DB.QueryRow(query).Scan(&before[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i, query := range queries {
		var after string
		if err = s.DB.QueryRow(query).Scan(&after); err != nil || after != before[i] {
			t.Fatal("migration changed data or indexes", before[i], after, err)
		}
	}
	var version int
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 8 {
		t.Fatal(version, err)
	}
	if pending, err := s.Pending(10); err != nil || len(pending) != 1 || pending[0].ID != 73 {
		t.Fatal("delivered event requeued", pending, err)
	}
	if delivered, err := s.Delivered(73, "telegram:one"); err != nil || !delivered {
		t.Fatal("partial delivery receipt lost", delivered, err)
	}
	if err = s.Transaction(func(tx *sql.Tx) error { return AddEvent(tx, time.Now(), "", "receiver_up", "system event") }); err != nil {
		t.Fatal(err)
	}
	var node, kind string
	var notified, acked, decided, suppressed int
	var targets, key, detail string
	if err = s.DB.QueryRow(`SELECT node,kind,notified,acked_at,targets,cooldown_key,cooldown_decided,suppressed,notification_detail FROM events WHERE id=74`).Scan(&node, &kind, &notified, &acked, &targets, &key, &decided, &suppressed, &detail); err != nil || node != "" || kind != "receiver_up" || notified != 0 || acked != 0 || targets != "" || key != "" || decided != 0 || suppressed != 0 || detail != "" {
		t.Fatal("system event or defaults changed", err)
	}
	rows, err := s.DB.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() || rows.Err() != nil {
		t.Fatal("foreign key violation", rows.Err())
	}
	rows.Close()
	// The delivery table must keep its original cascading foreign key.
	if _, err = s.DB.Exec(`DELETE FROM events WHERE id=73`); err != nil {
		t.Fatal(err)
	}
	if delivered, err := s.Delivered(73, "telegram:one"); err != nil || delivered {
		t.Fatal("delivery cascade changed", delivered, err)
	}
	if err = s.Migrate(); err != nil {
		t.Fatal(err)
	}
}
