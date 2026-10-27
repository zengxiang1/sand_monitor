// Package alert evaluates report and heartbeat events within SQLite transactions.
package alert

import (
	"database/sql"
	"fmt"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

type Config struct {
	Interval                       time.Duration
	MemoryThreshold, DiskThreshold float64
	Sustain                        time.Duration
}

func DefaultConfig() Config {
	return Config{Interval: 5 * time.Second, MemoryThreshold: 90, DiskThreshold: 90, Sustain: 5 * time.Minute}
}

type Engine struct {
	Store  *store.Store
	Config Config
}

func New(s *store.Store, c Config) *Engine { return &Engine{Store: s, Config: c} }
func lastState(tx *sql.Tx, node string) (string, error) {
	var kind string
	e := tx.QueryRow(`SELECT kind FROM events WHERE node=? AND kind IN ('offline','recovered') ORDER BY id DESC LIMIT 1`, node).Scan(&kind)
	if e == sql.ErrNoRows {
		return "", nil
	}
	return kind, e
}
func (e *Engine) Report(tx *sql.Tx, n store.Node, r proto.Report, now time.Time) error {
	state, err := lastState(tx, n.Name)
	if err != nil {
		return err
	}
	if state == "offline" {
		if err = store.AddEvent(tx, now, n.Name, "recovered", ""); err != nil {
			return err
		}
	}
	if n.BinHash != "" && n.BinHash != r.Bin {
		if err = store.AddEvent(tx, now, n.Name, "bin_changed", n.BinHash+" -> "+r.Bin); err != nil {
			return err
		}
	}
	// The complete first report is the baseline, even if multiple login records
	// share an IP or timestamp. Known addresses persist independently of retention.
	for _, l := range r.Login {
		var known int
		err = tx.QueryRow(`SELECT count(*) FROM known_ips WHERE node=? AND from_ip=?`, n.Name, l.From).Scan(&known)
		if err != nil {
			return err
		}
		if n.LastSeen == 0 {
			known = 1
		}
		var duplicate int
		if err = tx.QueryRow(`SELECT count(*) FROM logins WHERE node=? AND ts=? AND user=? AND from_ip=?`, n.Name, l.Time, l.User, l.From).Scan(&duplicate); err != nil {
			return err
		}
		if duplicate > 0 {
			continue
		}
		if _, err = tx.Exec(`INSERT INTO logins VALUES(?,?,?,?,?)`, n.Name, l.Time, l.User, l.From, known); err != nil {
			return err
		}
		if known == 0 {
			if err = store.AddEvent(tx, now, n.Name, "login_new_ip", l.User+" from "+l.From); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO known_ips VALUES(?,?)`, n.Name, l.From); err != nil {
			return err
		}
	}
	for _, resource := range []struct {
		name, used, total string
		threshold         float64
	}{{"memory", "mem_used", "mem_total", e.Config.MemoryThreshold}, {"disk", "disk_used", "disk_total", e.Config.DiskThreshold}} {
		var active bool
		var lastSeen int64
		err := tx.QueryRow(`SELECT active,last_seen FROM resource_alerts WHERE node=? AND resource=?`, n.Name, resource.name).Scan(&active, &lastSeen)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if now.Sub(time.Unix(lastSeen, 0)) > 3*e.Config.Interval {
			active = false
		}
		rows, err := tx.Query(`SELECT ts,`+resource.used+`,`+resource.total+` FROM metrics WHERE node=? AND ts>=? ORDER BY ts DESC,rowid DESC`, n.Name, now.Add(-e.Config.Sustain-3*e.Config.Interval).Unix())
		if err != nil {
			return err
		}
		start := now.Unix()
		previous := now.Unix()
		high := true
		for rows.Next() {
			var ts int64
			var used, total float64
			if err = rows.Scan(&ts, &used, &total); err != nil {
				break
			}
			if total <= 0 || used/total*100 < resource.threshold || time.Duration(previous-ts)*time.Second > 3*e.Config.Interval {
				break
			}
			start = ts
			previous = ts
		}
		if rows.Err() != nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		high = now.Sub(time.Unix(start, 0)) >= e.Config.Sustain
		// A persisted active flag prevents a bounded sliding window from emitting
		// the same continuous episode again as its oldest sample ages out.
		used, total := r.Mem[0], r.Mem[1]
		if resource.name == "disk" {
			used, total = r.Disk[0], r.Disk[1]
		}
		if total <= 0 || used/total*100 < resource.threshold {
			active = false
		}
		if high && !active {
			if err = store.AddEvent(tx, now, n.Name, "resource", resource.name); err != nil {
				return err
			}
			active = true
		}
		if _, err = tx.Exec(`INSERT INTO resource_alerts(node,resource,active,last_seen) VALUES(?,?,?,?) ON CONFLICT(node,resource) DO UPDATE SET active=excluded.active,last_seen=excluded.last_seen`, n.Name, resource.name, active, now.Unix()); err != nil {
			return err
		}

	}
	return nil
}
func (e *Engine) CheckOffline(now time.Time) error {
	return e.Store.Transaction(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT name,created_at,last_seen FROM nodes WHERE revoked_at=0`)
		if err != nil {
			return err
		}
		type item struct {
			name          string
			created, last int64
		}
		var nodes []item
		for rows.Next() {
			var n item
			if err = rows.Scan(&n.name, &n.created, &n.last); err != nil {
				break
			}
			nodes = append(nodes, n)
		}
		if rows.Err() != nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		for _, n := range nodes {
			last := n.last
			if last == 0 {
				last = n.created
			}
			if now.Sub(time.Unix(last, 0)) <= 3*e.Config.Interval {
				continue
			}
			state, err := lastState(tx, n.name)
			if err != nil {
				return err
			}
			if state != "offline" {
				if err = store.AddEvent(tx, now, n.name, "offline", fmt.Sprintf("last seen %d", n.last)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
