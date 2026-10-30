package alert

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

// Give jittered probes and five-second reports thirty seconds to join a target alert.
func (d *Dispatcher) prepare(event store.Event, notifiers []Notifier) (store.Event, error) {
	probe := event.Kind == "probe_down" || event.Kind == "probe_up"
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	if probe && event.Time > now.Add(-30*time.Second).Unix() {
		event.Deferred = true
		return event, nil
	}
	event.Deferred = false
	event, err := d.prepareIndividual(event, notifiers)
	if err != nil || event.Notified || !probe {
		return event, err
	}
	var key, prepared string
	var grouped bool
	if err = d.Store.DB.QueryRow(`SELECT cooldown_key,notified,notification_detail,EXISTS(SELECT 1 FROM probe_groups WHERE event_id=events.id) FROM events WHERE id=?`, event.ID).Scan(&key, &event.Notified, &prepared, &grouped); err != nil {
		return event, err
	}
	if prepared != "" {
		event.Detail = prepared
	}
	if event.Notified || grouped {
		return event, nil
	}
	target := strings.TrimPrefix(key, "probe:")
	if event.Kind == "probe_down" {
		var fresh, failed int
		if err = d.Store.DB.QueryRow(`SELECT count(*),coalesce(sum(p.active),0) FROM probe_alerts p JOIN nodes n ON n.name=p.node WHERE p.target=? AND p.last_ts>=? AND n.last_seen>=? AND n.revoked_at=0`, target, now.Add(-proto.ProbeMaxAge).Unix(), now.Add(-3*d.Store.Interval).Unix()).Scan(&fresh, &failed); err != nil {
			return event, err
		}
		if failed < 2 || failed*2 <= fresh {
			return event, nil
		}
	}
	rows, err := d.Store.DB.Query(`SELECT e.id,e.ts,e.node,e.kind,e.detail,e.targets FROM events e JOIN nodes n ON n.name=e.node JOIN probe_alerts p ON p.node=e.node AND p.target=? WHERE e.kind=? AND e.cooldown_key=? AND e.notified=0 AND e.ts>=? AND e.ts<=? AND e.targets=? AND NOT EXISTS(SELECT 1 FROM event_deliveries WHERE event_id=e.id) AND NOT EXISTS(SELECT 1 FROM probe_groups WHERE event_id=e.id) AND p.last_ts>=? AND p.active=? AND n.revoked_at=0 AND n.last_seen>=? ORDER BY e.id`, target, event.Kind, key, max(event.Time-30, now.Add(-proto.ProbeMaxAge).Unix()), event.Time+30, event.Targets, now.Add(-proto.ProbeMaxAge).Unix(), event.Kind == "probe_down", now.Add(-3*d.Store.Interval).Unix())
	if err != nil {
		return event, err
	}
	candidates := []store.Event{}
	for rows.Next() {
		var candidate store.Event
		if err = rows.Scan(&candidate.ID, &candidate.Time, &candidate.Node, &candidate.Kind, &candidate.Detail, &candidate.Targets); err != nil {
			break
		}
		candidates = append(candidates, candidate)
	}
	if rows.Err() != nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return event, err
	}
	eligible := []store.Event{}
	for _, candidate := range candidates {
		candidate, err = d.prepareIndividual(candidate, notifiers)
		if err != nil {
			return event, err
		}
		if !candidate.Notified {
			eligible = append(eligible, candidate)
		}
	}
	err = d.Store.Transaction(func(tx *sql.Tx) error {
		var detail string
		if err := tx.QueryRow(`SELECT notified,notification_detail,EXISTS(SELECT 1 FROM probe_groups WHERE event_id=events.id) FROM events WHERE id=?`, event.ID).Scan(&event.Notified, &detail, &grouped); err != nil {
			return err
		}
		if detail != "" {
			event.Detail = detail
		}
		if event.Notified || grouped {
			return nil
		}
		// Another worker may already have merged a candidate while its node
		// cooldown was being prepared. Never reopen that durable queue item.
		live := []store.Event{}
		for _, candidate := range eligible {
			var notified, delivered, frozen bool
			if err := tx.QueryRow(`SELECT notified,EXISTS(SELECT 1 FROM event_deliveries WHERE event_id=events.id),EXISTS(SELECT 1 FROM probe_groups WHERE event_id=events.id) FROM events WHERE id=?`, candidate.ID).Scan(&notified, &delivered, &frozen); err != nil {
				return err
			}
			if !notified && !delivered && !frozen {
				live = append(live, candidate)
			}
		}
		current := false
		for _, candidate := range live {
			current = current || candidate.ID == event.ID
		}
		if len(live) < 2 || !current {
			return nil
		}
		if _, err := tx.Exec(`INSERT INTO probe_groups(event_id) VALUES(?)`, live[0].ID); err != nil {
			return err
		}
		labels := make([]string, 0, len(live))
		for _, candidate := range live {
			labels = append(labels, candidate.Label())
		}
		detail = fmt.Sprintf("%d 个节点到 %s 的 HTTPS 探测同时失败：%s；疑似目标站或共同路径异常", len(live), target, strings.Join(labels, "、"))
		if event.Kind == "probe_up" {
			detail = fmt.Sprintf("%d 个节点到 %s 的 HTTPS 探测恢复：%s", len(live), target, strings.Join(labels, "、"))
		}
		for i, candidate := range live {
			if _, err := tx.Exec(`UPDATE events SET notified=?,notification_detail=? WHERE id=?`, i != 0, detail, candidate.ID); err != nil {
				return err
			}
			if event.ID == candidate.ID {
				event.Notified = i != 0
				event.Detail = detail
			}
		}
		return nil
	})
	return event, err
}
