package store

import (
	"strings"
	"testing"
	"time"
)

func TestReminderDatesAndDedup(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	expiry := time.Date(2026, 10, 31, 0, 0, 0, 0, loc)
	b := DefaultBilling("node")
	b.Expiry = expiry.Format("2006-01-02")
	b.RemindDays = "30,14,7,3,1"
	b.RemindPct = ""
	b.Predict = false
	for _, n := range []int{30, 14, 7, 3, 1, 0, -1} {
		now := expiry.AddDate(0, 0, -n).Add(9 * time.Hour)
		r := DecideReminders(b, Traffic{}, nil, nil, now)
		if len(r) != 1 || !strings.HasPrefix(r[0].Key, "exp:"+b.Expiry+":") {
			t.Fatal(n, r)
		}
		if len(DecideReminders(b, Traffic{}, nil, map[string]bool{r[0].Key: true}, now)) != 0 {
			t.Fatal("duplicate")
		}
		if len(DecideReminders(b, Traffic{}, nil, nil, now.Add(-time.Second))) != 0 {
			t.Fatal("before 09:00")
		}
	}
	for _, n := range []int{29, 8, 2, -2, -3} {
		if r := DecideReminders(b, Traffic{}, nil, nil, expiry.AddDate(0, 0, -n).Add(10*time.Hour)); len(r) != 0 {
			t.Fatal("backfilled", n, r)
		}
	}
	now := expiry.AddDate(0, 0, -3).Add(9 * time.Hour)
	old := DecideReminders(b, Traffic{}, nil, nil, now)[0].Key
	b.Expiry = "2026-11-04"
	r := DecideReminders(b, Traffic{}, nil, map[string]bool{old: true}, now)
	if len(r) != 1 || r[0].Key == old {
		t.Fatal("expiry change", r)
	}
	b.AutoRenew = true
	b.Expiry = "2026-10-31"
	for _, n := range []int{7, 3, 1, 0, -1} {
		r := DecideReminders(b, Traffic{}, nil, nil, expiry.AddDate(0, 0, -n).Add(9*time.Hour))
		if n == 3 {
			if len(r) != 1 || r[0].Key != "auto:2026-10-31" {
				t.Fatal(r)
			}
		} else if len(r) != 0 {
			t.Fatal(n, r)
		}
	}
	b.Expiry = "2026-01-31"
	at := time.Date(2026, 2, 2, 0, 0, 0, 0, loc)
	r = DecideReminders(b, Traffic{}, nil, nil, at)
	if len(r) != 1 || r[0].Advance != "2026-02-28" {
		t.Fatal(r)
	}
	if r = DecideReminders(b, Traffic{}, nil, nil, at.Add(-time.Second)); len(r) != 0 {
		t.Fatal(r)
	}
	b.Cycle = "once"
	if r = DecideReminders(b, Traffic{}, nil, nil, at); len(r) != 0 {
		t.Fatal(r)
	}
}
func TestTrafficReminderDecisions(t *testing.T) {
	b := DefaultBilling("node")
	b.QuotaGB = 1000
	b.RemindPct = "50,80,90,95,100"
	b.Predict = false
	tr := Traffic{CycleStart: "2026-10-01", UsedTX: 960000000000, Adjust: "0"}
	now := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	r := DecideReminders(b, tr, nil, nil, now)
	if len(r) != 1 || r[0].Key != "pct:2026-10-01:95" || len(r[0].Keys) != 4 {
		t.Fatal(r)
	}
	seen := map[string]bool{}
	for _, key := range r[0].Keys {
		seen[key] = true
	}
	if r = DecideReminders(b, tr, nil, seen, now); len(r) != 0 {
		t.Fatal(r)
	}
	tr.UsedTX = 1000000000000
	if r = DecideReminders(b, tr, nil, seen, now); len(r) != 1 || r[0].Key != "pct:2026-10-01:100" {
		t.Fatal(r)
	}
	b.Predict = true
	b.RemindPct = ""
	tr.UsedTX = 800000000000
	days := []Daily{{Day: "2026-10-24", TX: 60000000000}, {Day: "2026-10-26", TX: 100000000000}, {Day: "2026-10-27", TX: ^uint64(0)}}
	r = DecideReminders(b, tr, days, nil, now)
	if len(r) != 1 || r[0].Key != "pred:2026-10-01" || !strings.Contains(r[0].Detail, "才重置") {
		t.Fatal(r)
	}
	if len(DecideReminders(b, tr, days, map[string]bool{r[0].Key: true}, now)) != 0 {
		t.Fatal("prediction duplicate")
	}
	if len(DecideReminders(b, tr, nil, nil, now)) != 0 {
		t.Fatal("no complete days")
	}
	if len(DecideReminders(b, tr, days[2:], nil, now)) != 0 {
		t.Fatal("today counted")
	}
	if got := PredictionText(b, tr, days, now, true); got != "节点失联，统计暂停" {
		t.Fatal(got)
	}
	if got := PredictionText(b, tr, days, now, false); !strings.Contains(got, "用完") {
		t.Fatal(got)
	}
	tr.UsedTX = 0
	if got := PredictionText(b, tr, days, now, false); !strings.Contains(got, "预计重置前用到") {
		t.Fatal(got)
	}
}

func TestReminderTransactionAutoAdvanceAndTargets(t *testing.T) {
	s := billingStore(t)
	now := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC)
	b := DefaultBilling("node")
	b.Expiry = "2026-01-31"
	b.AutoRenew = true
	b.RemindPct = ""
	b.Predict = false
	if err := s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReminders(now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Billing("node")
	if got.Expiry != "2026-02-28" {
		t.Fatal(got)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='billing_auto_advance'`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	b.AutoRenew = false
	b.Expiry = "2026-02-05"
	b.Notify = "telegram"
	if err := s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.CheckReminders(now); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.Pending(20)
	if err != nil || len(pending) != 1 || pending[0].Targets != "telegram" || pending[0].Kind != "billing" {
		t.Fatal(pending, err)
	}
	b.Expiry = "2026-02-03"
	b.Notify = ""
	if err = s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckReminders(now); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='billing' AND notified=1`).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}

func TestAutoRenewReminderCost(t *testing.T) {
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ currency, price, want string }{{"CNY", "58", "3 天后自动扣费（¥58），确认余额"}, {"USD", "15.50", "3 天后自动扣费（$15.50），确认余额"}, {"EUR", "12", "3 天后自动扣费（€12），确认余额"}, {"CNY", "", "3 天后自动扣费，确认余额"}} {
		b := DefaultBilling("node")
		b.Expiry = "2026-10-30"
		b.AutoRenew = true
		b.Currency = tc.currency
		b.Price = tc.price
		reminders := DecideReminders(b, Traffic{}, nil, nil, now)
		if len(reminders) != 1 || reminders[0].Detail != tc.want {
			t.Fatal(tc, reminders)
		}
	}
}
