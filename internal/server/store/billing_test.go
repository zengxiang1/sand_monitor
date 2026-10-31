package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func billingStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.Location = time.UTC
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = s.AddNode("node", pub, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestThreeYearRenewalAndMonthlyTraffic(t *testing.T) {
	s := billingStore(t)
	b := DefaultBilling("node")
	b.Expiry, b.Cycle, b.Price = "2024-02-29", "three_year", "88"
	if err := b.Validate(nil); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2024, 3, 28, 12, 0, 0, 0, time.UTC)
	if err := s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE traffic SET used_tx='99',used_rx='88',adjust='10'`); err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []string{"2027-02-28", "2030-02-28", "2033-02-28", "2036-02-29"} {
		if err := s.Renew("node", now, "admin", ""); err != nil {
			t.Fatal(err)
		}
		got, err := s.Billing("node")
		if err != nil || got.Expiry != expiry || got.AnchorDay != 29 {
			t.Fatal(got, err)
		}
	}
	tr, err := s.Traffic("node")
	if err != nil || tr.CycleStart != "2024-02-29" || tr.UsedTX != 99 || tr.UsedRX != 88 {
		t.Fatal("manual renewal changed traffic", tr, err)
	}
	reset := time.Date(2024, 3, 29, 0, 0, 0, 0, time.UTC)
	if err := s.CheckReminders(reset); err != nil {
		t.Fatal(err)
	}
	tr, err = s.Traffic("node")
	if err != nil || tr.CycleStart != "2024-03-29" || tr.UsedTX != 0 || tr.UsedRX != 0 || tr.Adjust != "0" {
		t.Fatal("three-year billing must still reset traffic monthly", tr, err)
	}
	saved, err := s.Billing("node")
	if err != nil {
		t.Fatal(err)
	}
	if got := NextReset(reset, &saved).Format("2006-01-02"); got != "2024-04-29" {
		t.Fatal(got)
	}
	for _, cycle := range []string{"once", "unknown"} {
		if got := CycleMonths(cycle); got != 0 {
			t.Fatal(cycle, got)
		}
		if got := Advance("2024-02-29", cycle, 29, time.UTC); got != "2024-02-29" {
			t.Fatal(cycle, got)
		}
	}
}
func TestTrafficAccounting(t *testing.T) {
	s := billingStore(t)
	loc, _ := time.LoadLocation("Asia/Shanghai")
	s.Location = loc
	at := time.Date(2026, 10, 27, 23, 59, 55, 0, loc)
	cases := []struct {
		totals [2]uint64
		up     float64
		want   [2]uint64
	}{{[2]uint64{100, 200}, 100, [2]uint64{0, 0}}, {[2]uint64{150, 280}, 105, [2]uint64{50, 80}}, {[2]uint64{20, 30}, 2, [2]uint64{70, 110}}, {[2]uint64{10, 40}, 7, [2]uint64{80, 120}}, {[2]uint64{1000000000011, 45}, 12, [2]uint64{80, 125}}, {[2]uint64{1000000000012, 50}, 17, [2]uint64{81, 130}}}
	for i, tc := range cases {
		r := proto.Report{NetTotal: tc.totals, Up: tc.up}
		if err := s.Accept("node", uint64(i+1), at.Add(time.Duration(i)*5*time.Second), "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
			t.Fatal(err)
		}
		got, err := s.Traffic("node")
		if err != nil || got.UsedTX != tc.want[0] || got.UsedRX != tc.want[1] || got.FirstSeen != at.Unix() {
			t.Fatal(i, got, err)
		}
	}
	days, err := s.Days("node", "2026-10-27")
	if err != nil || len(days) != 2 || days[0].Online != 5 || days[1].Online != 20 || days[1].TX != 81 || days[1].RX != 130 {
		t.Fatal(days, err)
	}
	r := proto.Report{NetTotal: [2]uint64{1000000000013, 51}, Up: 100}
	if err = s.Accept("node", 7, at.Add(time.Hour), "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	days, _ = s.Days("node", "2026-10-27")
	if days[1].Online != 20 {
		t.Fatal("offline gap counted", days)
	}
	if err = s.Accept("node", 8, at.Add(time.Hour+5*time.Second), "192.0.2.1", &r, func() error { return nil }, func(*sql.Tx, Node) error { return errors.New("rollback") }); err == nil {
		t.Fatal("expected rollback")
	}
	days, _ = s.Days("node", "2026-10-27")
	if days[1].Online != 20 {
		t.Fatal("accounting survived rollback")
	}
}
func TestOnlineAccountingGaps(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		gap     time.Duration
		started time.Time
		outage  string
		ended   bool
		want    int64
	}{
		{name: "short", gap: 5 * time.Second, want: 5},
		{name: "short boundary", gap: 15 * time.Second, want: 15},
		{name: "long", gap: 16 * time.Second},
		{name: "member", gap: 40 * time.Second, outage: `{"since":1,"detected":2,"members":{"node":{"last_seen":1,"recovered":0,"outage":false}},"notified":false}`, want: 40},
		{name: "nonmember", gap: 40 * time.Second, outage: `{"members":{"other":{"last_seen":1}}}`},
		{name: "outage ended", gap: 40 * time.Second, outage: `{"members":{"node":{"last_seen":1}}}`, ended: true},
		{name: "no startup time", gap: 30 * time.Second},
		{name: "restart", gap: 30 * time.Second, started: at.Add(15 * time.Second), want: 30},
		{name: "stale before startup", gap: 10*time.Minute + 15*time.Second, started: at.Add(10 * time.Minute)},
		{name: "late after startup", gap: 10*time.Minute + 15*time.Second, started: at.Add(15 * time.Second)},
		{name: "restart boundaries", gap: 150 * time.Second, started: at.Add(75 * time.Second), want: 150},
		{name: "before startup limit exceeded", gap: 91 * time.Second, started: at.Add(76 * time.Second)},
		{name: "after startup limit exceeded", gap: 91 * time.Second, started: at.Add(15 * time.Second)},
		{name: "gap after startup", gap: 30 * time.Second, started: at.Add(-time.Second)},
		{name: "gap before startup", gap: 30 * time.Second, started: at.Add(31 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := billingStore(t)
			s.StartedAt = tc.started
			r := proto.Report{Up: 100}
			if err := s.Accept("node", 1, at, "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
				t.Fatal(err)
			}
			if tc.outage != "" {
				if err := s.SetKV("receiver.outage", tc.outage); err != nil {
					t.Fatal(err)
				}
			}
			if tc.ended {
				if _, err := s.DB.Exec(`DELETE FROM kv WHERE key='receiver.outage'`); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Accept("node", 2, at.Add(tc.gap), "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
				t.Fatal(err)
			}
			days, err := s.Days("node", "2026-10-27")
			if err != nil || len(days) != 1 || days[0].Online != tc.want {
				t.Fatalf("daily = %+v, err = %v; want online %d", days, err, tc.want)
			}
		})
	}
}
func TestOnlineAccountingGapsAcrossMidnight(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 27, 23, 59, 45, 0, loc)
	for _, tc := range []struct {
		name   string
		member bool
	}{{"outage", true}, {"restart", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := billingStore(t)
			s.Location = loc
			if tc.member {
				if err := s.SetKV("receiver.outage", `{"members":{"node":{"last_seen":1}}}`); err != nil {
					t.Fatal(err)
				}
			} else {
				s.StartedAt = at.Add(20 * time.Second)
			}
			r := proto.Report{Up: 100}
			for i, now := range []time.Time{at, at.Add(40 * time.Second)} {
				if err := s.Accept("node", uint64(i+1), now, "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
					t.Fatal(err)
				}
			}
			days, err := s.Days("node", "2026-10-27")
			if err != nil || len(days) != 2 || days[0].Day != "2026-10-27" || days[0].Online != 15 || days[1].Day != "2026-10-28" || days[1].Online != 25 {
				t.Fatal(days, err)
			}
		})
	}
}
func TestSaturationDirectionsAndCalibration(t *testing.T) {
	if SatAdd(math.MaxUint64-1, 10) != math.MaxUint64 {
		t.Fatal("overflow")
	}
	for mode, want := range map[string]uint64{"both": 30, "out": 10, "in": 20, "max": 20} {
		if got := Counted(Traffic{UsedTX: 10, UsedRX: 20, Adjust: "-5"}, mode); got != want-5 {
			t.Fatal(mode, got)
		}
		if got := Counted(Traffic{UsedTX: 10, UsedRX: 20, Adjust: "-100"}, mode); got != 0 {
			t.Fatal(got)
		}
	}
	if Counted(Traffic{UsedTX: math.MaxUint64, UsedRX: 10, Adjust: "1"}, "both") != math.MaxUint64 {
		t.Fatal("count overflow")
	}
	s := billingStore(t)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r := proto.Report{Up: 10}
	if err := s.Accept("node", 1, now, "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE traffic SET used_tx='18446744073709551614',used_rx='100'`); err != nil {
		t.Fatal(err)
	}
	b := DefaultBilling("node")
	n := uint64(2000000000)
	if err := s.SaveBilling(b, &n, now, "admin", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	tr, err := s.Traffic("node")
	if err != nil || Counted(tr, "both") != n {
		t.Fatal(tr, err)
	}
	r.NetTotal = [2]uint64{20, 30}
	r.Up = 15
	if err = s.Accept("node", 2, now.Add(5*time.Second), "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	tr, _ = s.Traffic("node")
	if tr.UsedTX != math.MaxUint64 {
		t.Fatal("persistence overflow", tr)
	}
	for v, want := range map[string]uint64{"0": 0, "1.5": 1500000000, "0.000000001": 1, "18446744073.709551615": math.MaxUint64} {
		n, err := ParseGB(v)
		if err != nil || n != want {
			t.Fatal(v, n, err)
		}
	}
	for _, v := range []string{"-1", "NaN", "1e9", "1.0000000001", "18446744074"} {
		if _, err := ParseGB(v); err == nil {
			t.Fatal(v)
		}
	}
}
func TestCycleBoundariesAndRenewal(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	for _, tc := range []struct {
		today, expiry string
		reset         int
		want, next    string
	}{{"2026-02-28", "2026-01-31", 0, "2026-02-28", "2026-03-31"}, {"2024-02-29", "2024-01-31", 0, "2024-02-29", "2024-03-31"}, {"2026-02-27", "2026-01-31", 0, "2026-01-31", "2026-02-28"}, {"2026-10-15", "2026-10-22", 5, "2026-10-05", "2026-11-05"}, {"2026-10-15", "", 0, "2026-10-01", "2026-11-01"}} {
		now, _ := time.ParseInLocation("2006-01-02", tc.today, loc)
		b := DefaultBilling("node")
		b.Expiry = tc.expiry
		if expiry, err := time.Parse("2006-01-02", b.Expiry); err == nil {
			b.AnchorDay = expiry.Day()
		}
		b.ResetDay = tc.reset
		if got := CycleStart(now, &b).Format("2006-01-02"); got != tc.want {
			t.Fatal(tc, got)
		}
		if got := NextReset(now, &b).Format("2006-01-02"); got != tc.next {
			t.Fatal(tc, got)
		}
	}
	now := time.Date(2026, 2, 28, 0, 0, 0, 0, loc)
	if CycleStart(now, nil).Format("2006-01-02") != "2026-02-01" {
		t.Fatal("natural month")
	}
	for _, tc := range []struct{ date, cycle, want string }{{"2026-01-31", "month", "2026-02-28"}, {"2024-01-31", "month", "2024-02-29"}, {"2026-11-30", "quarter", "2027-02-28"}, {"2024-02-29", "year", "2025-02-28"}, {"2026-08-31", "half", "2027-02-28"}, {"2026-01-31", "once", "2026-01-31"}} {
		date, _ := time.Parse("2006-01-02", tc.date)
		if got := Advance(tc.date, tc.cycle, date.Day(), loc); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	if got := Advance("2026-01-31", "month", 0, loc); got != "2026-02-28" {
		t.Fatal("zero anchor", got)
	}
	zero := DefaultBilling("node")
	zero.Expiry, zero.AutoRenew, zero.AnchorDay = "2026-01-31", true, 0
	if r := DecideReminders(zero, Traffic{}, nil, map[string]bool{}, time.Date(2026, 3, 5, 10, 0, 0, 0, loc)); len(r) != 1 || r[0].Advance != "2026-03-31" {
		t.Fatal("zero anchor catch-up", r)
	}
	s := billingStore(t)
	s.Location = loc
	b := DefaultBilling("node")
	b.Expiry = "2026-01-31"
	b.RemindDays = ""
	b.RemindPct = ""
	b.Predict = false
	previous := now.AddDate(0, 0, -1)
	if err := s.SaveBilling(b, nil, previous, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE traffic SET used_tx='99',used_rx='88',adjust='10'`); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReminders(now); err != nil {
		t.Fatal(err)
	}
	tr, _ := s.Traffic("node")
	if tr.CycleStart != "2026-02-28" || tr.UsedTX != 0 || tr.UsedRX != 0 || tr.Adjust != "0" {
		t.Fatal(tr)
	}
	var n int
	if err := s.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='traffic_reset' AND notified=1`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	r := proto.Report{NetTotal: [2]uint64{12, 34}, Up: 100}
	if err := s.Accept("node", 1, now, "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReminders(now); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='traffic_reset'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("double roll", n, err)
	}
}
func TestAvailabilityStatesAndSummary(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	today := now.Format("2006-01-02")
	for _, tc := range []struct {
		first, online int64
		state, pct    string
	}{{0, 0, "none", "—"}, {now.Unix() + 1, 0, "none", "—"}, {now.Add(-time.Hour).Unix(), 3600, "ok", "100"}, {now.Add(-time.Hour).Unix(), 3540, "ok", "98.33"}, {now.Add(-time.Hour).Unix(), 3539, "partial", "98.30"}, {now.Add(-2 * time.Hour).Unix(), 3600, "down", "50.00"}} {
		a := Availability45(tc.first, []Daily{{Day: today, Online: tc.online}}, now)
		if len(a.Days) != 45 || a.Days[44].State != tc.state || a.Pct != tc.pct {
			t.Fatal(tc, a)
		}
		if a.Days[43].State != "none" {
			t.Fatal("before first_seen")
		}
	}
	start := now.AddDate(0, 0, -44)
	start = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
	days := []Daily{}
	for i := 0; i < 45; i++ {
		online := int64(86400)
		if i == 44 {
			online = 43200
		}
		days = append(days, Daily{Day: start.AddDate(0, 0, i).Format("2006-01-02"), Online: online})
	}
	a := Availability45(start.Unix(), days, now)
	if a.Pct != "100" {
		t.Fatal(a)
	}
}
func TestPhaseThreeMigrationAndRetention(t *testing.T) {
	s := billingStore(t)
	path := filepath.Join(t.TempDir(), "v3.db")
	if _, err := s.DB.Exec(`VACUUM INTO ?`, path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(downgradeV7 + `DROP TABLE metrics_1m;DROP TABLE metrics_1h;DROP TABLE billing;DROP TABLE traffic;DROP TABLE daily;DROP TABLE reminders;DROP TABLE kv;ALTER TABLE events DROP COLUMN targets;PRAGMA user_version=3;INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(1,'admin','','retained','v3');`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	up, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	var version int
	if err = up.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 9 {
		t.Fatal(version, err)
	}
	var detail string
	if err = up.DB.QueryRow(`SELECT detail FROM audit_log`).Scan(&detail); err != nil || detail != "v3" {
		t.Fatal(detail, err)
	}
	if _, err = up.Node("node"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, days := range []int{59, 61} {
		if _, err = s.DB.Exec(`INSERT INTO daily VALUES('node',?,'0','0',0)`, now.AddDate(0, 0, -days).Format("2006-01-02")); err != nil {
			t.Fatal(err)
		}
	}
	for _, days := range []int{399, 401} {
		if _, err = s.DB.Exec(`INSERT INTO reminders VALUES('node',?,?, '')`, days, now.AddDate(0, 0, -days).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"daily", "reminders"} {
		var n int
		if err = s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 1 {
			t.Fatal(table, n, err)
		}
	}
}

func TestCalibrationContinuesAndUnbilledRolls(t *testing.T) {
	s := billingStore(t)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := proto.Report{NetTotal: [2]uint64{100, 200}, Up: 100}
	if err := s.Accept("node", 1, now, "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	b := DefaultBilling("node")
	calibration := uint64(2000000000)
	if err := s.SaveBilling(b, &calibration, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	r.NetTotal = [2]uint64{130, 240}
	r.Up = 105
	if err := s.Accept("node", 2, now.Add(5*time.Second), "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	tr, err := s.Traffic("node")
	if err != nil || Counted(tr, "both") != calibration+70 {
		t.Fatal(tr, err)
	}
	if _, err = s.DB.Exec(`DELETE FROM billing`); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckReminders(now.AddDate(0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	tr, _ = s.Traffic("node")
	if tr.CycleStart != "2026-11-01" || tr.UsedTX != 0 || tr.Adjust != "0" {
		t.Fatal(tr)
	}
	b.ResetDay = 2
	if err = s.SaveBilling(b, nil, now.AddDate(0, 0, 1), "admin", ""); err != nil {
		t.Fatal(err)
	}
	r.NetTotal = [2]uint64{200, 300}
	r.Up = 200
	if err = s.Accept("node", 3, now.AddDate(0, 0, 2), "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	tr, _ = s.Traffic("node")
	if tr.CycleStart != "2026-11-02" || tr.UsedTX != 70 || tr.UsedRX != 60 {
		t.Fatal(tr)
	}
	var n int
	if err = s.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='traffic_reset' AND notified=1`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

func TestSaveBillingRecountsChangedCycle(t *testing.T) {
	s := billingStore(t)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for i, report := range []struct {
		at     time.Time
		tx, rx uint64
	}{{time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC), 100, 200}, {time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), 200, 400}, {time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), 400, 700}, {now, 700, 1100}} {
		r := proto.Report{NetTotal: [2]uint64{report.tx, report.rx}, Up: float64(i+1) * 86400}
		if err := s.Accept("node", uint64(i+1), report.at, "192.0.2.1", &r, func() error { return nil }, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`INSERT INTO daily VALUES('node','2026-09-28','9000','9000',0),('node','2026-10-28','9000','9000',0);UPDATE traffic SET adjust='123'`); err != nil {
		t.Fatal(err)
	}
	before, err := s.Traffic("node")
	if err != nil {
		t.Fatal(err)
	}
	b := DefaultBilling("node")
	b.Expiry = "2026-10-31"
	if err = s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.Traffic("node")
	if err != nil || got.CycleStart != "2026-09-30" || got.UsedTX != 600 || got.UsedRX != 900 || got.Adjust != "0" || got.LastTX != before.LastTX || got.LastRX != before.LastRX || got.LastUp != before.LastUp || got.FirstSeen != before.FirstSeen {
		t.Fatal(got, err)
	}
	b.ResetDay = 15
	calibration := uint64(2000)
	if err = s.SaveBilling(b, &calibration, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err = s.Traffic("node")
	if err != nil || got.CycleStart != "2026-10-15" || got.UsedTX != 300 || got.UsedRX != 400 || got.Adjust != "1300" || Counted(got, b.Direction) != calibration {
		t.Fatal(got, err)
	}
	if err = s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err = s.Traffic("node")
	if err != nil || Counted(got, b.Direction) != calibration {
		t.Fatal("unchanged cycle lost adjustment", got, err)
	}
	b.ResetDay = 2
	if err = s.SaveBilling(b, nil, now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err = s.Traffic("node")
	if err != nil || got.CycleStart != "2026-10-02" || got.UsedTX != 300 || got.UsedRX != 400 || got.Adjust != "0" {
		t.Fatal(got, err)
	}
	var resets int
	if err = s.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='traffic_reset'`).Scan(&resets); err != nil || resets != 0 {
		t.Fatal("settings changes generated reset events", resets, err)
	}
}
