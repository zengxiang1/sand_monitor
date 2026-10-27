// Package store owns SQLite migrations and atomic report persistence.
package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"strconv"
	"sync"
	"time"
	"wanglou/internal/proto"
)

var ErrReplay = errors.New("sequence replay")
var ErrNode = errors.New("unknown or revoked node")

type Store struct {
	DB *sql.DB
	mu sync.Mutex
}
type Node struct {
	Name                           string
	Pubkey                         ed25519.PublicKey
	Fingerprint                    string
	CreatedAt, RevokedAt, LastSeen int64
	LastSeq                        uint64
	LastIP, BinHash                string
}
type Event struct {
	ID       int64  `json:"id"`
	Time     int64  `json:"ts"`
	Node     string `json:"node"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Notified bool   `json:"notified"`
}

func Open(path string) (*Store, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if _, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); e == nil {
		e = s.Migrate()
	}
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Migrate() error {
	_, e := s.DB.Exec(`
 CREATE TABLE IF NOT EXISTS nodes(name TEXT PRIMARY KEY, pubkey BLOB NOT NULL, fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0, last_seq TEXT NOT NULL DEFAULT '0', last_seen INTEGER NOT NULL DEFAULT 0, last_ip TEXT NOT NULL DEFAULT '', bin_hash TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS metrics(node TEXT NOT NULL REFERENCES nodes(name),ts INTEGER NOT NULL,cpu REAL,load1 REAL,load5 REAL,load15 REAL,mem_used REAL,mem_total REAL,swap_used REAL,swap_total REAL,disk_used REAL,disk_total REAL,net_tx REAL,net_rx REAL,net_total_tx TEXT,net_total_rx TEXT,tcp INTEGER,udp INTEGER,uptime REAL);
 CREATE INDEX IF NOT EXISTS metrics_node_ts ON metrics(node,ts);
 CREATE TABLE IF NOT EXISTS logins(node TEXT NOT NULL REFERENCES nodes(name),ts INTEGER NOT NULL,user TEXT,from_ip TEXT,known INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS logins_node_ts ON logins(node,ts);
 CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,node TEXT NOT NULL REFERENCES nodes(name),kind TEXT NOT NULL,detail TEXT NOT NULL,notified INTEGER NOT NULL DEFAULT 0);
 CREATE INDEX IF NOT EXISTS events_node_ts ON events(node,ts);
 CREATE TABLE IF NOT EXISTS known_ips(node TEXT NOT NULL REFERENCES nodes(name),from_ip TEXT NOT NULL,PRIMARY KEY(node,from_ip));
 CREATE TABLE IF NOT EXISTS resource_alerts(node TEXT NOT NULL REFERENCES nodes(name),resource TEXT NOT NULL,active INTEGER NOT NULL,last_seen INTEGER NOT NULL,PRIMARY KEY(node,resource));
 CREATE TABLE IF NOT EXISTS event_deliveries(event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,notifier TEXT NOT NULL,PRIMARY KEY(event_id,notifier));
 PRAGMA user_version=2;`)
	return e
}
func (s *Store) AddNode(name string, key ed25519.PublicKey, now time.Time) error {
	if !proto.ValidNode(name) || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid node")
	}
	_, e := s.DB.Exec(`INSERT INTO nodes(name,pubkey,fingerprint,created_at) VALUES(?,?,?,?)`, name, []byte(key), proto.Fingerprint(key), now.Unix())
	return e
}

type scanner interface{ Scan(...any) error }

func scanNode(row scanner) (n Node, e error) {
	var seq string
	e = row.Scan(&n.Name, &n.Pubkey, &n.Fingerprint, &n.CreatedAt, &n.RevokedAt, &seq, &n.LastSeen, &n.LastIP, &n.BinHash)
	if e == nil {
		n.LastSeq, e = strconv.ParseUint(seq, 10, 64)
	}
	return
}

const columns = `name,pubkey,fingerprint,created_at,revoked_at,last_seq,last_seen,last_ip,bin_hash`

func (s *Store) Node(name string) (Node, error) {
	return scanNode(s.DB.QueryRow(`SELECT `+columns+` FROM nodes WHERE name=?`, name))
}
func (s *Store) Nodes() ([]Node, error) {
	rows, e := s.DB.Query(`SELECT ` + columns + ` FROM nodes ORDER BY name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) Revoke(name string, now time.Time) error {
	return s.Transaction(func(tx *sql.Tx) error {
		r, e := tx.Exec(`UPDATE nodes SET revoked_at=? WHERE name=?`, now.Unix(), name)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e == nil && n == 0 {
			return ErrNode
		}
		return e
	})
}
func (s *Store) Transaction(fn func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}

// Accept rechecks revocation and sequence inside the transaction. The admission
// callback runs after those checks and before any state is persisted.
func (s *Store) Accept(name string, seq uint64, now time.Time, ip string, r *proto.Report, admit func() error, evaluate func(*sql.Tx, Node) error) error {
	return s.Transaction(func(tx *sql.Tx) error {
		n, e := scanNode(tx.QueryRow(`SELECT `+columns+` FROM nodes WHERE name=?`, name))
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNode
		}
		if e != nil {
			return e
		}
		if n.RevokedAt != 0 {
			return ErrNode
		}
		if seq <= n.LastSeq {
			return ErrReplay
		}
		if e = admit(); e != nil {
			return e
		}
		if _, e = tx.Exec(`INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, name, now.Unix(), r.CPU, r.Load[0], r.Load[1], r.Load[2], r.Mem[0], r.Mem[1], r.Swap[0], r.Swap[1], r.Disk[0], r.Disk[1], r.Net[0], r.Net[1], strconv.FormatUint(r.NetTotal[0], 10), strconv.FormatUint(r.NetTotal[1], 10), r.Conn[0], r.Conn[1], r.Up); e != nil {
			return e
		}
		if evaluate != nil {
			if e = evaluate(tx, n); e != nil {
				return e
			}
		}
		_, e = tx.Exec(`UPDATE nodes SET last_seq=?,last_seen=?,last_ip=?,bin_hash=? WHERE name=?`, strconv.FormatUint(seq, 10), now.Unix(), ip, r.Bin, name)
		return e
	})
}
func AddEvent(tx *sql.Tx, now time.Time, node, kind, detail string) error {
	_, e := tx.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,?,?,?)`, now.Unix(), node, kind, detail)
	return e
}
func (s *Store) Pending(limit int) ([]Event, error) {
	rows, e := s.DB.Query(`SELECT id,ts,node,kind,detail,notified FROM events WHERE notified=0 ORDER BY id LIMIT ?`, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var v Event
		if e = rows.Scan(&v.ID, &v.Time, &v.Node, &v.Kind, &v.Detail, &v.Notified); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) MarkNotified(id int64) error {
	_, e := s.DB.Exec(`UPDATE events SET notified=1 WHERE id=?`, id)
	return e
}
func (s *Store) Cleanup(now time.Time) error {
	return s.Transaction(func(tx *sql.Tx) error {
		for _, table := range []string{"metrics", "logins", "events"} {
			if _, e := tx.Exec(`DELETE FROM `+table+` WHERE ts<?`, now.Add(-7*24*time.Hour).Unix()); e != nil {
				return e
			}
		}
		return nil
	})
}
func (s *Store) RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if e := s.Cleanup(time.Now()); e != nil {
			fmt.Printf("retention cleanup: %v\n", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Store) Delivered(id int64, notifier string) (bool, error) {
	var count int
	err := s.DB.QueryRow(`SELECT count(*) FROM event_deliveries WHERE event_id=? AND notifier=?`, id, notifier).Scan(&count)
	return count > 0, err
}
func (s *Store) MarkDelivered(id int64, notifier string) error {
	_, err := s.DB.Exec(`INSERT OR IGNORE INTO event_deliveries(event_id,notifier) VALUES(?,?)`, id, notifier)
	return err
}
