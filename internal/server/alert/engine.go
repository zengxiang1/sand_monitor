// Package alert evaluates report and heartbeat events within SQLite transactions.
package alert

import (
	"database/sql"
	"fmt"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/eventtext"
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
	Store     *store.Store
	Config    Config
	StartedAt time.Time
}

func New(s *store.Store, c Config) *Engine {
	return &Engine{Store: s, Config: c, StartedAt: time.Now()}
}
func lastState(tx *sql.Tx, node string, since int64) (string, error) {
	var kind string
	e := tx.QueryRow(`SELECT kind FROM events WHERE node=? AND ts>=? AND kind IN ('offline','recovered') ORDER BY id DESC LIMIT 1`, node, since).Scan(&kind)
	if e == sql.ErrNoRows {
		return "", nil
	}
	return kind, e
}
func (e *Engine) Report(tx *sql.Tx, n store.Node, r proto.Report, now time.Time) error {
	outage, err := loadOutage(tx)
	if err != nil {
		return err
	}
	if outage != nil {
		if member, ok := outage.Members[n.Name]; ok && member.Recovered == 0 {
			member.Recovered, member.Outage = now.Unix(), r.Outage != nil
			outage.Members[n.Name] = member
			if err = saveOutage(tx, outage); err != nil {
				return err
			}
		}
	}
	state, err := lastState(tx, n.Name, n.CreatedAt)
	if err != nil {
		return err
	}
	if state == "offline" {
		detail := "首次开始上报"
		if n.LastSeen != 0 {
			detail = "重新开始上报，离线 " + eventtext.Duration(now.Unix()-n.LastSeen)
		}
		if r.Outage != nil {
			detail += fmt.Sprintf("；agent 期间持续运行，自 %s 起上报失败 %d 次", time.Unix(r.Outage.Since, 0).In(e.Store.Location).Format("15:04:05"), r.Outage.Failures)
		} else if n.LastSeen != 0 && r.Up < float64(now.Unix()-n.LastSeen) {
			detail += "；节点期间重启过（已运行 " + eventtext.Duration(int64(r.Up)) + "）"
		}
		if err = store.AddEvent(tx, now, n.Name, "recovered", detail); err != nil {
			return err
		}
	}
	if n.BinHash != "" && n.BinHash != r.Bin {
		if err = store.AddEvent(tx, now, n.Name, "bin_changed", "agent 二进制变化："+n.BinHash+" → "+r.Bin); err != nil {
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
			if _, err = tx.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,?,'login_new_ip',?,?)`, now.Unix(), n.Name, l.User+" 从 "+l.From+" 登录（首次出现的 IP）", "login:"+l.From); err != nil {
				return err
			}
		}
		if known != 0 {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO known_ips VALUES(?,?)`, n.Name, l.From); err != nil {
				return err
			}
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
			if _, err = tx.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,?,'resource',?,?)`, now.Unix(), n.Name, eventtext.Resource(resource.name, resource.threshold, e.Config.Sustain), "resource:"+resource.name); err != nil {
				return err
			}
			active = true
		}
		if _, err = tx.Exec(`INSERT INTO resource_alerts(node,resource,active,last_seen) VALUES(?,?,?,?) ON CONFLICT(node,resource) DO UPDATE SET active=excluded.active,last_seen=excluded.last_seen`, n.Name, resource.name, active, now.Unix()); err != nil {
			return err
		}

	}
	return e.probes(tx, n, r.Probes, now)
}
func (e *Engine) CheckOffline(now time.Time) error {
	if now.Sub(e.StartedAt) < 3*e.Config.Interval+time.Minute {
		return nil
	}
	return e.Store.Transaction(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT name,created_at,last_seen FROM nodes WHERE revoked_at=0`)
		if err != nil {
			return err
		}
		type item struct {
			name, state   string
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
		outage, err := loadOutage(tx)
		if err != nil {
			return err
		}
		active, silent := 0, map[string]outageMember{}
		overdue := false
		for i := range nodes {
			n := &nodes[i]
			n.state, err = lastState(tx, n.name, n.created)
			if err != nil {
				return err
			}
			if n.last == 0 || n.last < now.Add(-10*time.Minute).Unix() || n.state == "offline" {
				continue
			}
			active++
			gap := now.Sub(time.Unix(n.last, 0))
			if gap > 2*e.Config.Interval {
				silent[n.name] = outageMember{LastSeen: n.last}
			}
			overdue = overdue || gap > 3*e.Config.Interval
		}
		if outage == nil && overdue && active >= 3 && len(silent) >= 2 && len(silent)*3 >= active*2 {
			outage = &receiverOutage{Detected: now.Unix(), Members: silent}
			for _, member := range silent {
				outage.Since = max(outage.Since, member.LastSeen)
			}
		}
		if outage != nil {
			for name, member := range silent {
				if _, ok := outage.Members[name]; !ok {
					outage.Members[name] = member
				}
			}
			recovered, failures := 0, 0
			var first int64
			for _, member := range outage.Members {
				if member.Recovered != 0 {
					recovered++
					if first == 0 || member.Recovered < first {
						first = member.Recovered
					}
					if member.Outage {
						failures++
					}
				}
			}
			total := len(outage.Members)
			if recovered == total || recovered > 0 && now.Sub(time.Unix(first, 0)) > 3*e.Config.Interval+time.Minute {
				detail := fmt.Sprintf("主控网络中断 %s（%s–%s）；受影响 %d 个节点，已恢复 %d 个", eventtext.Duration(first-outage.Since), time.Unix(outage.Since, 0).In(e.Store.Location).Format("15:04:05"), time.Unix(first, 0).In(e.Store.Location).Format("15:04:05"), total, recovered)
				if failures > 0 {
					detail += fmt.Sprintf("；其中 %d 个节点的 agent 报告期间持续运行、上报失败", failures)
				}
				if recovered < total {
					detail += fmt.Sprintf("；另有 %d 个仍失联，已单独告警", total-recovered)
				}
				if err = store.AddEvent(tx, now, "", "receiver_up", detail); err != nil {
					return err
				}
				if _, err = tx.Exec(`DELETE FROM kv WHERE key='receiver.outage'`); err != nil {
					return err
				}
				outage = nil
			} else {
				if !outage.Notified && now.Unix()-outage.Detected >= 120 {
					if err = store.AddEvent(tx, now, "", "receiver_down", fmt.Sprintf("%d 个节点同时中断上报，疑似主控网络或接收服务中断，已持续 %s", total, eventtext.Duration(now.Unix()-outage.Detected))); err != nil {
						return err
					}
					outage.Notified = true
				}
				if err = saveOutage(tx, outage); err != nil {
					return err
				}
			}
		}
		for _, n := range nodes {
			if outage != nil {
				if _, ok := outage.Members[n.name]; ok {
					continue
				}
			}
			last := n.last
			grace := 3 * e.Config.Interval
			if last == 0 {
				last = n.created
				grace = 10 * time.Minute
			}
			if now.Sub(time.Unix(last, 0)) <= grace {
				continue
			}
			if n.state != "offline" {
				if err = store.AddEvent(tx, now, n.name, "offline", eventtext.Offline(n.last, e.Store.Location)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
