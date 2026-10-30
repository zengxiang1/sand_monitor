package alert

import (
	"database/sql"
	"fmt"
	"net/url"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func (e *Engine) probes(tx *sql.Tx, n store.Node, probes []proto.Probe, now time.Time) error {
	for _, p := range probes {
		if p.Time < now.Add(-proto.ProbeMaxAge).Unix() || p.Time > now.Add(time.Minute).Unix() || p.Time < n.CreatedAt {
			continue
		}
		var last int64
		var failures int
		var active bool
		err := tx.QueryRow(`SELECT last_ts,failures,active FROM probe_alerts WHERE node=? AND target=?`, n.Name, p.Target).Scan(&last, &failures, &active)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if p.Time <= last {
			continue
		}
		if last < n.CreatedAt {
			active = false
		}
		if time.Duration(p.Time-last)*time.Second > proto.ProbeMaxAge {
			failures = 0
		}
		kind := ""
		if p.Error == "" {
			failures = 0
			if active {
				kind, active = "probe_up", false
			}
		} else {
			failures = min(3, failures+1)
			if failures == 3 && !active {
				kind, active = "probe_down", true
			}
		}
		if _, err = tx.Exec(`INSERT INTO probe_alerts(node,target,last_ts,failures,active) VALUES(?,?,?,?,?) ON CONFLICT(node,target) DO UPDATE SET last_ts=excluded.last_ts,failures=excluded.failures,active=excluded.active`, n.Name, p.Target, p.Time, failures, active); err != nil {
			return err
		}
		if kind != "" {
			u, err := url.Parse(p.Target)
			if err != nil {
				return err
			}
			detail := fmt.Sprintf("到 %s 的 HTTPS 路径连续 3 次探测失败（%s）；目标 %s", u.Hostname(), p.Error, p.Target)
			if kind == "probe_up" {
				detail = fmt.Sprintf("到 %s 的 HTTPS 路径探测恢复（HTTP %d，%.0f 毫秒）；目标 %s", u.Hostname(), p.Status, p.TotalMS, p.Target)
			}
			if _, err = tx.Exec(`INSERT INTO events(ts,node,kind,detail,cooldown_key) VALUES(?,?,?,?,?)`, now.Unix(), n.Name, kind, detail, "probe:"+p.Target); err != nil {
				return err
			}
		}
	}
	return nil
}
