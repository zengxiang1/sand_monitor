package store

import (
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type Reminder struct {
	Key, Kind, Detail string
	Keys              []string
	Advance           string
}

func Remaining(expiry string, now time.Time) (int, bool) {
	e, err := time.Parse("2006-01-02", expiry)
	if err != nil {
		return 0, false
	}
	today, _ := time.Parse("2006-01-02", now.Format("2006-01-02"))
	return int(e.Sub(today) / (24 * time.Hour)), true
}
func Bytes(value uint64) string {
	if value >= 1000000000000 {
		return fmt.Sprintf("%.3g TB", float64(value)/1e12)
	}
	return fmt.Sprintf("%.3g GB", float64(value)/1e9)
}
func Prediction(b Billing, t Traffic, days []Daily, now time.Time) (time.Time, float64) {
	if b.QuotaGB == 0 {
		return time.Time{}, 0
	}
	today := now.Format("2006-01-02")
	since := now.AddDate(0, 0, -3).Format("2006-01-02")
	sum := float64(0)
	count := 0
	for _, d := range days {
		if d.Day >= since && d.Day < today {
			sum += float64(RawCount(d.TX, d.RX, b.Direction))
			count++
		}
	}
	if count == 0 || sum <= 0 {
		return time.Time{}, 0
	}
	speed := sum / float64(count)
	used := float64(Counted(t, b.Direction))
	quota := float64(b.QuotaGB) * 1e9
	reset := NextReset(now, &b)
	pct := (used + speed*reset.Sub(now).Hours()/24) / quota * 100
	seconds := (quota - used) / speed * 86400
	if seconds <= 0 || seconds > float64(math.MaxInt64/int64(time.Second)) {
		return time.Time{}, pct
	}
	return now.Add(time.Duration(seconds) * time.Second), pct
}
func PredictionText(b Billing, t Traffic, days []Daily, now time.Time, offline bool) string {
	if offline {
		return "节点失联，统计暂停"
	}
	end, pct := Prediction(b, t, days, now)
	if pct == 0 {
		return ""
	}
	if !end.IsZero() && end.Before(NextReset(now, &b)) {
		return "按现在的速度 " + end.Format("01-02") + " 用完"
	}
	return fmt.Sprintf("预计重置前用到 %.0f%%", pct)
}
func DecideReminders(b Billing, t Traffic, days []Daily, seen map[string]bool, now time.Time) []Reminder {
	out := []Reminder{}
	remaining, hasExpiry := Remaining(b.Expiry, now)
	if hasExpiry && b.AutoRenew && b.Cycle != "once" && remaining <= -2 {
		expiry := Advance(b.Expiry, b.Cycle, now.Location())
		out = append(out, Reminder{Key: "advance:" + b.Expiry, Kind: "billing", Detail: "已按自动续费顺延到 " + expiry, Advance: expiry})
	}
	if hasExpiry && now.Hour() >= 9 {
		key, detail := "", ""
		if b.AutoRenew {
			if remaining == 3 {
				key = "auto:" + b.Expiry
				detail = "3 天后自动扣费"
				if cost := b.Cost(); cost != "" {
					detail += "（" + cost + "）"
				}
				detail += "，确认余额"
			}
		} else {
			match := remaining == 0 || remaining == -1
			for _, v := range strings.Split(b.RemindDays, ",") {
				if v != "" && v == strconv.Itoa(remaining) {
					match = true
				}
			}
			if match {
				key = fmt.Sprintf("exp:%s:%d", b.Expiry, remaining)
				switch {
				case remaining == 0:
					detail = "今天到期"
				case remaining == -1:
					detail = "已过期 1 天，记得续费"
				default:
					detail = fmt.Sprintf("还有 %d 天到期，需要手动续费", remaining)
				}
			}
		}
		if key != "" && !seen[key] {
			out = append(out, Reminder{Key: key, Kind: "billing", Detail: detail})
		}
	}
	if b.QuotaGB > 0 {
		used := Counted(t, b.Direction)
		pct := float64(used) / (float64(b.QuotaGB) * 1e9) * 100
		highest := 0
		keys := []string{}
		for _, v := range strings.Split(b.RemindPct, ",") {
			n, _ := strconv.Atoi(v)
			key := "pct:" + t.CycleStart + ":" + v
			if n > 0 && pct >= float64(n) && !seen[key] {
				keys = append(keys, key)
				highest = max(highest, n)
			}
		}
		if highest > 0 {
			out = append(out, Reminder{Key: fmt.Sprintf("pct:%s:%d", t.CycleStart, highest), Keys: keys, Kind: "traffic", Detail: fmt.Sprintf("本周期流量用到 %d%%（%s / %s）", highest, Bytes(used), Bytes(uint64(b.QuotaGB)*1000000000))})
		}
		key := "pred:" + t.CycleStart
		end, _ := Prediction(b, t, days, now)
		if b.Predict && used < uint64(b.QuotaGB)*1000000000 && !end.IsZero() && end.Before(NextReset(now, &b)) && !seen[key] {
			out = append(out, Reminder{Key: key, Kind: "traffic", Detail: "按现在的速度 " + end.Format("01-02") + " 用完，" + NextReset(now, &b).Format("01-02") + " 才重置"})
		}
	}
	return out
}
func (s *Store) CheckReminders(now time.Time) error {
	now = now.In(s.Location)
	return s.Transaction(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT ` + trafficColumns + ` FROM traffic WHERE node IN (SELECT name FROM nodes WHERE revoked_at=0) AND node NOT IN (SELECT node FROM billing)`)
		if err != nil {
			return err
		}
		unbilled := []Traffic{}
		for rows.Next() {
			t, e := scanTraffic(rows)
			if e != nil {
				rows.Close()
				return e
			}
			unbilled = append(unbilled, t)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, t := range unbilled {
			if err = RollCycle(tx, &t, nil, now); err != nil {
				return err
			}
			if err = saveTraffic(tx, t); err != nil {
				return err
			}
		}
		rows, err = tx.Query(`SELECT ` + billColumns + ` FROM billing WHERE node IN (SELECT name FROM nodes WHERE revoked_at=0)`)
		if err != nil {
			return err
		}
		bills := []Billing{}
		for rows.Next() {
			b, e := scanBilling(rows)
			if e != nil {
				rows.Close()
				return e
			}
			bills = append(bills, b)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, b := range bills {
			t, err := scanTraffic(tx.QueryRow(`SELECT `+trafficColumns+` FROM traffic WHERE node=?`, b.Node))
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if err == sql.ErrNoRows {
				t = Traffic{Node: b.Node, Adjust: "0"}
			}
			if err = RollCycle(tx, &t, &b, now); err != nil {
				return err
			}
			if err = saveTraffic(tx, t); err != nil {
				return err
			}
			rows, err := tx.Query(`SELECT day,tx,rx,online FROM daily WHERE node=? AND day>=?`, b.Node, now.AddDate(0, 0, -3).Format("2006-01-02"))
			if err != nil {
				return err
			}
			days := []Daily{}
			for rows.Next() {
				var d Daily
				if err = rows.Scan(&d.Day, &d.TX, &d.RX, &d.Online); err != nil {
					rows.Close()
					return err
				}
				days = append(days, d)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			rows, err = tx.Query(`SELECT key FROM reminders WHERE node=?`, b.Node)
			if err != nil {
				return err
			}
			seen := map[string]bool{}
			for rows.Next() {
				var key string
				if err = rows.Scan(&key); err != nil {
					rows.Close()
					return err
				}
				seen[key] = true
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, r := range DecideReminders(b, t, days, seen, now) {
				recorded := b.Notify == "" || r.Advance != ""
				if _, err = tx.Exec(`INSERT INTO events(ts,node,kind,detail,notified,targets) VALUES(?,?,?,?,?,?)`, now.Unix(), b.Node, r.Kind, r.Detail, recorded, b.Notify); err != nil {
					return err
				}
				keys := r.Keys
				if len(keys) == 0 {
					keys = []string{r.Key}
				}
				channels := b.Notify
				if r.Advance != "" {
					channels = ""
				}
				for _, key := range keys {
					if _, err = tx.Exec(`INSERT OR IGNORE INTO reminders VALUES(?,?,?,?)`, b.Node, key, now.Unix(), channels); err != nil {
						return err
					}
				}
				if r.Advance != "" {
					if _, err = tx.Exec(`UPDATE billing SET expiry=?,updated_at=? WHERE node=?`, r.Advance, now.Unix(), b.Node); err != nil {
						return err
					}
					if _, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,'system','','billing_auto_advance',?)`, now.Unix(), b.Node+" "+r.Advance); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}
