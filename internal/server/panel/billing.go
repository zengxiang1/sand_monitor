package panel

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"wanglou/internal/server/requestip"
	"wanglou/internal/server/store"
)

type billingRow struct {
	DisplayName                                                                                          string
	Name, Provider, Expiry, ExpiryShort, Due, DueTone, Cost, Auto, Used, Quota, Period, Prediction, Tone string
	Days, Pct, Bar                                                                                       int
	HasBill, HasExpiry                                                                                   bool
	Bill                                                                                                 store.Billing
	Traffic                                                                                              store.Traffic
	Daily                                                                                                []store.Daily
}
type billingEditor struct {
	Name, DisplayName, Current, Calibrate string
	Form                                  url.Values
}
type billingStat struct {
	Label, Sub string
	Count      int
}
type scheduleRow struct {
	Time                                 int64
	Date, Node, Text, State, DisplayName string
}
type billingPage struct {
	Budget    store.Budget
	Today     string
	Rows      []billingRow
	Editor    *billingEditor
	Stats     []billingStat
	Schedule  []scheduleRow
	HasBills  bool
	Due, High []billingRow
}

var cycleLabels = map[string]string{"month": "月付", "quarter": "季付", "half": "半年付", "year": "年付", "three_year": "三年付", "once": "一次性"}
var directionLabels = map[string]string{"both": "上下行合计", "out": "只算上行", "in": "只算下行", "max": "取两者中较大的"}

func (h *Handler) billingData() (billingPage, error) {
	now := h.Now().In(h.Store.Location)
	out := billingPage{Today: now.Format("2006-01-02"), Stats: []billingStat{{Label: "7 天内到期"}, {Label: "流量超过 80%"}, {Label: "30 天内要续费"}, {Label: "未来 7 天提醒"}}}
	nodes, err := h.Store.Nodes()
	if err != nil {
		return out, err
	}
	out.Budget, err = h.Store.Budget(now)
	if err != nil {
		return out, err
	}
	auto := 0
	for _, n := range nodes {
		if n.RevokedAt != 0 {
			continue
		}
		b, err := h.Store.Billing(n.Name)
		has := err == nil
		if err != nil && err != sql.ErrNoRows {
			return out, err
		}
		if !has {
			b = store.DefaultBilling(n.Name)
		}
		t, err := h.Store.Traffic(n.Name)
		if err != nil {
			return out, err
		}
		days, err := h.Store.Days(n.Name, now.AddDate(0, 0, -3).Format("2006-01-02"))
		if err != nil {
			return out, err
		}
		r := billingRow{Name: n.Name, DisplayName: n.DisplayName, Provider: b.Provider, Expiry: b.Expiry, HasBill: has, Used: store.Bytes(store.Counted(t, b.Direction)), Bill: b, Traffic: t, Daily: days, Cost: "未设置", Auto: "手动续费", DueTone: "muted", Tone: "normal"}
		if has {
			out.HasBills = true
			r.Cost = cycleLabels[b.Cycle]
			if b.Price != "" {
				r.Cost += " " + b.Cost()
			}
			if b.AutoRenew {
				r.Auto = "自动续费"
			}
		}
		r.Days, r.HasExpiry = store.Remaining(b.Expiry, now)
		if r.HasExpiry {
			r.ExpiryShort = r.Expiry[5:]
			switch {
			case r.Days < 0:
				r.Due = fmt.Sprintf("已过期 %d 天", -r.Days)
				r.DueTone = "danger"
			case r.Days == 0:
				r.Due = "今天到期"
				r.DueTone = "danger"
			case r.Days <= 3:
				r.Due = fmt.Sprintf("%d 天后到期", r.Days)
				r.DueTone = "danger"
			case r.Days <= 7:
				r.Due = fmt.Sprintf("%d 天后到期", r.Days)
				r.DueTone = "warn"
			default:
				r.Due = fmt.Sprintf("还剩 %d 天", r.Days)
			}
			if r.Days >= 0 && r.Days <= 7 {
				out.Stats[0].Count++
				if out.Stats[0].Count <= 2 {
					if out.Stats[0].Sub != "" {
						out.Stats[0].Sub += " · "
					}
					out.Stats[0].Sub += fmt.Sprintf("%s 还剩 %d 天", n.Label(), r.Days)
				}
			}
			if r.Days >= 0 && r.Days <= 30 {
				out.Stats[2].Count++
				if b.AutoRenew {
					auto++
				}
			}
		}
		if b.QuotaGB > 0 {
			r.Quota = store.Bytes(uint64(b.QuotaGB) * 1000000000)
			r.Pct = int(float64(store.Counted(t, b.Direction)) / (float64(b.QuotaGB) * 1e9) * 100)
			r.Bar = min(100, r.Pct)
			if r.Pct >= 95 {
				r.Tone = "danger"
			} else if r.Pct >= 80 {
				r.Tone = "warn"
			}
			if r.Pct >= 80 {
				out.Stats[1].Count++
				if out.Stats[1].Count <= 2 {
					if out.Stats[1].Sub != "" {
						out.Stats[1].Sub += " · "
					}
					out.Stats[1].Sub += fmt.Sprintf("%s %d%%", n.Label(), r.Pct)
				}
			}
		}
		var bill *store.Billing
		if has {
			bill = &b
		}
		r.Period = fmt.Sprintf("每月 %d 日重置 · %s", store.ResetDay(bill), directionLabels[b.Direction])
		r.Prediction = store.PredictionText(b, t, days, now, n.LastSeen == 0 || now.Unix()-n.LastSeen > int64(3*h.Config.Interval/time.Second))
		out.Rows = append(out.Rows, r)
	}
	sort.SliceStable(out.Rows, func(i, j int) bool {
		a, b := out.Rows[i], out.Rows[j]
		if a.Expiry == "" || b.Expiry == "" {
			return a.Expiry != "" && b.Expiry == ""
		}
		return a.Expiry < b.Expiry
	})
	out.Stats[2].Sub = fmt.Sprintf("其中 %d 台已开自动续费", auto)
	for _, r := range out.Rows {
		if r.HasExpiry && r.Days <= 7 && len(out.Due) < 5 {
			out.Due = append(out.Due, r)
		}
		if r.Pct >= 80 && len(out.High) < 5 {
			out.High = append(out.High, r)
		}
	}
	past := map[string]bool{}
	rows, err := h.Store.DB.Query(`SELECT r.node,r.key,r.ts,r.channels,coalesce((SELECT detail FROM events e WHERE e.node=r.node AND e.ts=r.ts AND e.kind=CASE WHEN r.key LIKE 'pct:%' OR r.key LIKE 'pred:%' THEN 'traffic' ELSE 'billing' END AND e.detail LIKE CASE WHEN r.key LIKE 'pct:%' THEN '本周期流量用到 %' WHEN r.key LIKE 'pred:%' THEN '按现在的速度 %' ELSE '%' END ORDER BY e.id DESC LIMIT 1),'') FROM reminders r WHERE r.ts>=? ORDER BY r.ts,r.key`, now.Add(-24*time.Hour).Unix())
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var node, key, channels, detail string
		var ts int64
		if err = rows.Scan(&node, &key, &ts, &channels, &detail); err != nil {
			rows.Close()
			return out, err
		}
		state := "已记录 · 未选择渠道"
		if channels != "" {
			state = "已发送 · " + channelNames(channels)
		}
		if detail == "" {
			detail = reminderText(key)
		}
		id := fmt.Sprintf("%s:%d:%s", node, ts, detail)
		if !past[id] {
			out.Schedule = append(out.Schedule, scheduleRow{Time: ts, Node: node, Text: detail, State: state})
			past[id] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for _, r := range out.Rows {
		if !r.HasBill {
			continue
		}
		seen := map[string]bool{}
		rows, err := h.Store.DB.Query(`SELECT key FROM reminders WHERE node=?`, r.Name)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var key string
			if err = rows.Scan(&key); err != nil {
				rows.Close()
				return out, err
			}
			seen[key] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		for i := 0; i <= 14; i++ {
			at := time.Date(now.Year(), now.Month(), now.Day()+i, 9, 0, 0, 0, now.Location())
			if at.Before(now) {
				if i > 0 {
					continue
				}
				at = now
			}
			for _, d := range store.DecideReminders(r.Bill, r.Traffic, r.Daily, seen, at) {
				if d.Kind != "billing" || d.Advance != "" {
					continue
				}
				out.Schedule = append(out.Schedule, scheduleRow{Time: at.Unix(), Node: r.Name, Text: d.Detail, State: "待提醒"})
			}
		}
		reset := store.NextReset(now, &r.Bill)
		if reset.Before(now.AddDate(0, 0, 15)) {
			out.Schedule = append(out.Schedule, scheduleRow{Time: reset.Unix(), Node: r.Name, Text: "流量周期重置，用量清零 · 只记录，不发送", State: "只记录"})
		}
		for _, d := range store.DecideReminders(r.Bill, r.Traffic, r.Daily, seen, now) {
			if strings.HasPrefix(d.Key, "pred:") {
				out.Schedule = append(out.Schedule, scheduleRow{Time: now.Unix(), Node: r.Name, Text: d.Detail + " · 预测提醒", State: "待提醒"})
			}
		}
	}
	sort.SliceStable(out.Schedule, func(i, j int) bool { return out.Schedule[i].Time < out.Schedule[j].Time })
	for i := range out.Schedule {
		r := &out.Schedule[i]
		for _, n := range nodes {
			if n.Name == r.Node {
				r.DisplayName = n.DisplayName
				break
			}
		}
		r.Date = time.Unix(r.Time, 0).In(h.Store.Location).Format("01-02 15:04")
		if r.Time >= now.Unix() && r.Time < now.AddDate(0, 0, 7).Unix() && r.State == "待提醒" {
			out.Stats[3].Count++
			if out.Stats[3].Sub == "" {
				label := r.Node
				if r.DisplayName != "" {
					label = r.DisplayName
				}
				out.Stats[3].Sub = "下一条：" + r.Date[:5] + " " + label
			}
		}
	}
	out.Schedule = out.Schedule[:min(30, len(out.Schedule))]
	return out, nil
}
func channelNames(channels string) string {
	names := []string{}
	for _, c := range strings.Split(channels, ",") {
		if c == "telegram" {
			names = append(names, "Telegram")
		}
		if c == "webhook" {
			names = append(names, "Webhook")
		}
	}
	return strings.Join(names, "、")
}
func reminderText(key string) string {
	parts := strings.Split(key, ":")
	switch parts[0] {
	case "exp":
		if len(parts) > 2 {
			switch parts[2] {
			case "0":
				return "今天到期"
			case "-1":
				return "已过期 1 天，记得续费"
			default:
				return "还有 " + parts[2] + " 天到期，需要手动续费"
			}
		}
	case "auto":
		return "3 天后自动扣费，确认余额"
	case "pct":
		return "本周期流量用到 " + parts[len(parts)-1] + "%"
	case "pred":
		return "按最近 3 天速度预测，重置前会用完流量"
	case "advance":
		return "已按自动续费顺延"
	}
	return key
}
func billingForm(b store.Billing) url.Values {
	return url.Values{"provider": {b.Provider}, "expiry": {b.Expiry}, "cycle": {b.Cycle}, "currency": {b.Currency}, "price": {b.Price}, "auto_renew": {strconv.FormatBool(b.AutoRenew)}, "quota_gb": {strconv.Itoa(b.QuotaGB)}, "reset_day": {strconv.Itoa(b.ResetDay)}, "direction": {b.Direction}, "remind_days": strings.FieldsFunc(b.RemindDays, func(r rune) bool { return r == ',' }), "remind_pct": strings.FieldsFunc(b.RemindPct, func(r rune) bool { return r == ',' }), "predict": {strconv.FormatBool(b.Predict)}, "notify": strings.FieldsFunc(b.Notify, func(r rune) bool { return r == ',' })}
}
func (h *Handler) billing(w http.ResponseWriter, r *http.Request, sess session) {
	data := h.base(sess)
	view, err := h.billingData()
	if err != nil {
		h.serverError(w, err)
		return
	}
	data.Billing = view
	name := r.URL.Query().Get("edit")
	status := 200
	if r.Method == "POST" {
		name = r.PathValue("name")
		idx := slices.IndexFunc(view.Rows, func(v billingRow) bool { return v.Name == name })
		if idx < 0 {
			http.NotFound(w, r)
			return
		}
		ip := requestip.ClientIP(r, h.Config.TrustedProxies)
		if strings.HasSuffix(r.URL.Path, "/renewed") {
			err = h.Store.Renew(name, h.Now(), sess.User, ip)
		} else {
			f := r.PostForm
			b := store.Billing{Node: name, Provider: f.Get("provider"), Expiry: f.Get("expiry"), Cycle: f.Get("cycle"), Currency: f.Get("currency"), Price: f.Get("price"), AutoRenew: f.Get("auto_renew") == "true", Direction: f.Get("direction"), RemindDays: strings.Join(f["remind_days"], ","), RemindPct: strings.Join(f["remind_pct"], ","), Predict: f.Get("predict") == "true", Notify: strings.Join(f["notify"], ",")}
			b.QuotaGB, err = strconv.Atoi(f.Get("quota_gb"))
			if err == nil {
				b.ResetDay, err = strconv.Atoi(f.Get("reset_day"))
			}
			if err != nil {
				err = fmt.Errorf("额度和重置日须为整数")
			}
			if err == nil {
				for _, key := range []string{"auto_renew", "predict"} {
					if value := f.Get(key); value != "" && value != "true" && value != "false" {
						err = fmt.Errorf("复选框值无效")
					}
				}
			}
			if err == nil {
				channels := []string{}
				for _, c := range data.Channels {
					channels = append(channels, strings.ToLower(c))
				}
				err = b.Validate(channels)
			}
			var calibration *uint64
			if err == nil && f.Get("calibrate") != "" {
				var n uint64
				n, err = store.ParseGB(f.Get("calibrate"))
				calibration = &n
			}
			if err == nil {
				err = h.Store.SaveBilling(b, calibration, h.Now(), sess.User, ip)
			}
		}
		if err == nil {
			http.Redirect(w, r, "/billing?edit="+url.QueryEscape(name)+"&saved=1", 303)
			return
		}
		data.Error = err.Error()
		status = 400
	}
	if name != "" {
		idx := slices.IndexFunc(view.Rows, func(v billingRow) bool { return v.Name == name })
		if idx < 0 {
			http.NotFound(w, r)
			return
		}
		row := view.Rows[idx]
		form := billingForm(row.Bill)
		if status == 400 {
			form = r.PostForm
		}
		data.Billing.Editor = &billingEditor{Name: name, DisplayName: row.DisplayName, Current: strconv.FormatFloat(float64(store.Counted(row.Traffic, row.Bill.Direction))/1e9, 'f', 3, 64), Form: form}
		if status == 400 {
			data.Billing.Editor.Calibrate = r.PostForm.Get("calibrate")
		}
	}
	if r.URL.Query().Get("saved") == "1" {
		data.Success = "已保存，提醒已按新规则重新排期"
	}
	h.render(w, r, "billing", data, status)
}

// budgetReason describes why a node cannot contribute to a particular estimate.
func budgetReason(reason, cycle string) string {
	if reason == "missing_price" && cycle == "once" {
		return "账单信息待补，请补充价格并确认续费周期"
	}
	switch reason {
	case "missing_billing", "missing_price":
		return "账单信息待补"
	case "invalid_price":
		return "价格无效，账单信息待补"
	case "unsupported_currency":
		return "币种待确认"
	case "unsupported_cycle":
		return "续费周期待确认"
	case "once":
		return "一次性费用，不计入持续成本"
	case "missing_expiry":
		return "到期日待补"
	case "invalid_expiry":
		return "到期日无效"
	case "overdue_expiry":
		return "到期日已过，待确认"
	default:
		return ""
	}
}
