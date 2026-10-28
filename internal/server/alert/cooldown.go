package alert

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
	"wanglou/internal/server/store"
)

func (d *Dispatcher) prepare(event store.Event, notifiers []Notifier) (store.Event, error) {
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	if len(notifiers) == 0 || d.Scope == "security" && event.Kind != "offline" && event.Kind != "recovered" && event.Kind != "login_new_ip" && event.Kind != "bin_changed" && event.Kind != "flapping" {
		event.Notified = true
		return event, d.Store.MarkNotified(event.ID)
	}
	node, err := d.Store.Node(event.Node)
	if err != nil {
		return event, err
	}
	event.DisplayName = node.DisplayName
	if event.Kind != "billing" && event.Kind != "traffic" && (node.MutedUntil > event.Time || node.MutedUntil > now.Unix()) {
		event.Notified = true
		return event, d.Store.MarkNotified(event.ID)
	}
	if d.Cooldown == 0 {
		return event, nil
	}
	err = d.Store.Transaction(func(tx *sql.Tx) error {
		var key, detail string
		var decided bool
		if err := tx.QueryRow(`SELECT cooldown_key,cooldown_decided,suppressed,notification_detail,notified FROM events WHERE id=?`, event.ID).Scan(&key, &decided, &event.Suppressed, &detail, &event.Notified); err != nil {
			return err
		}
		if decided || event.Notified {
			if detail != "" {
				event.Detail = detail
			}
			return nil
		}
		switch event.Kind {
		case "offline", "recovered":
			key = "connectivity"
		case "login_new_ip":
			if key == "" {
				if _, rest, ok := strings.Cut(event.Detail, " 从 "); ok {
					ip, _, _ := strings.Cut(rest, " 登录")
					key = "login:" + ip
				} else if _, ip, ok := strings.Cut(event.Detail, " from "); ok {
					key = "login:" + ip
				}
			}
		case "resource":
			if key == "" {
				if event.Detail == "memory" || strings.HasPrefix(event.Detail, "内存") {
					key = "resource:memory"
				}
				if event.Detail == "disk" || strings.HasPrefix(event.Detail, "磁盘") {
					key = "resource:disk"
				}
			}
		default:
			return nil
		}
		if key == "" {
			return nil
		}
		var expires int64
		var warned bool
		err := tx.QueryRow(`SELECT expires_at,warned FROM notify_cooldowns WHERE node=? AND key=?`, event.Node, key).Scan(&expires, &warned)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		event.Suppressed = expires > now.UnixNano()
		if event.Kind == "recovered" {
			// A recovery follows its offline event: sent when that was sent, merged when it was merged.
			var paired bool
			if err := tx.QueryRow(`SELECT coalesce((SELECT suppressed FROM events WHERE node=? AND kind='offline' AND id<? ORDER BY id DESC LIMIT 1),0)`, event.Node, event.ID).Scan(&paired); err != nil {
				return err
			}
			event.Suppressed, event.Notified = paired, paired
			_, err := tx.Exec(`UPDATE events SET cooldown_key=?,cooldown_decided=1,suppressed=?,notification_detail=?,notified=? WHERE id=?`, key, event.Suppressed, event.Detail, event.Notified, event.ID)
			return err
		}
		duration := fmt.Sprintf("%g 秒", d.Cooldown.Seconds())
		if d.Cooldown%time.Minute == 0 {
			duration = fmt.Sprintf("%g 分钟", d.Cooldown.Minutes())
		}
		if event.Suppressed {
			event.Notified = true
			if key == "connectivity" && expires > now.UnixNano() && !warned {
				if _, err := tx.Exec(`INSERT INTO events(ts,node,kind,detail) VALUES(?,?,'flapping',?)`, now.Unix(), event.Node, "频繁掉线，"+duration+"内不再推送上下线通知，面板照常记录"); err != nil {
					return err
				}
				if _, err := tx.Exec(`UPDATE notify_cooldowns SET warned=1 WHERE node=? AND key=?`, event.Node, key); err != nil {
					return err
				}
			}
		} else {
			var count int
			if err := tx.QueryRow(`SELECT count(*) FROM events WHERE node=? AND cooldown_key=? AND kind<>'recovered' AND suppressed=1 AND id<? AND id>coalesce((SELECT max(id) FROM events WHERE node=? AND cooldown_key=? AND kind<>'recovered' AND cooldown_decided=1 AND suppressed=0 AND id<?),0)`, event.Node, key, event.ID, event.Node, key, event.ID).Scan(&count); err != nil {
				return err
			}
			if count > 0 {
				event.Detail += fmt.Sprintf("（过去 %s内另有 %d 次，已合并）", duration, count)
			}
			if _, err := tx.Exec(`INSERT INTO notify_cooldowns(node,key,expires_at,warned) VALUES(?,?,?,0) ON CONFLICT(node,key) DO UPDATE SET expires_at=excluded.expires_at,warned=0`, event.Node, key, now.Add(d.Cooldown).UnixNano()); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`UPDATE events SET cooldown_key=?,cooldown_decided=1,suppressed=?,notification_detail=?,notified=? WHERE id=?`, key, event.Suppressed, event.Detail, event.Notified, event.ID)
		return err
	})
	return event, err
}
