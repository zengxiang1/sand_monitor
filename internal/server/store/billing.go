package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"wanglou/internal/proto"
)

func migrateBilling(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE billing(node TEXT PRIMARY KEY REFERENCES nodes(name),provider TEXT NOT NULL,expiry TEXT NOT NULL,cycle TEXT NOT NULL,currency TEXT NOT NULL,price TEXT NOT NULL,auto_renew INTEGER NOT NULL,quota_gb INTEGER NOT NULL,reset_day INTEGER NOT NULL,direction TEXT NOT NULL,remind_days TEXT NOT NULL,remind_pct TEXT NOT NULL,predict INTEGER NOT NULL,notify TEXT NOT NULL,updated_at INTEGER NOT NULL);
 CREATE TABLE traffic(node TEXT PRIMARY KEY REFERENCES nodes(name),cycle_start TEXT NOT NULL,used_tx TEXT NOT NULL,used_rx TEXT NOT NULL,adjust TEXT NOT NULL,last_tx TEXT NOT NULL,last_rx TEXT NOT NULL,last_up REAL NOT NULL,first_seen INTEGER NOT NULL);
 CREATE TABLE daily(node TEXT NOT NULL REFERENCES nodes(name),day TEXT NOT NULL,tx TEXT NOT NULL,rx TEXT NOT NULL,online INTEGER NOT NULL,PRIMARY KEY(node,day));
 CREATE TABLE reminders(node TEXT NOT NULL,key TEXT NOT NULL,ts INTEGER NOT NULL,channels TEXT NOT NULL,PRIMARY KEY(node,key));
 CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 ALTER TABLE events ADD COLUMN targets TEXT NOT NULL DEFAULT '';
 PRAGMA user_version=4;`)
	return err
}

type Billing struct {
	Node, Provider, Expiry, Cycle, Currency, Price string
	AutoRenew                                      bool
	QuotaGB, ResetDay, AnchorDay                   int
	Direction, RemindDays, RemindPct               string
	Predict                                        bool
	Notify                                         string
	UpdatedAt                                      int64
}
type Traffic struct {
	Node, CycleStart string
	UsedTX, UsedRX   uint64
	Adjust           string
	LastTX, LastRX   uint64
	LastUp           float64
	FirstSeen        int64
}
type Daily struct {
	Day    string
	TX, RX uint64
	Online int64
}
type Day struct {
	Date, State            string
	Down, Online, Observed int64
}
type Availability struct {
	Pct  string
	Days []Day
}

const billColumns = `node,provider,expiry,cycle,currency,price,auto_renew,quota_gb,reset_day,direction,remind_days,remind_pct,predict,notify,updated_at,anchor_day`
const trafficColumns = `node,cycle_start,used_tx,used_rx,adjust,last_tx,last_rx,last_up,first_seen`

var pricePattern = regexp.MustCompile(`^\d{1,7}(\.\d{1,2})?$`)

func DefaultBilling(node string) Billing {
	return Billing{Node: node, AnchorDay: 1, Cycle: "month", Currency: "CNY", Direction: "both", RemindDays: "7,3,1", RemindPct: "80,95,100", Predict: true}
}
func CurrencySymbol(currency string) string {
	return map[string]string{"CNY": "¥", "USD": "$", "EUR": "€"}[currency]
}
func (b Billing) Cost() string {
	if b.Price == "" {
		return ""
	}
	return CurrencySymbol(b.Currency) + b.Price
}
func (b Billing) Validate(channels []string) error {
	if !proto.ValidNode(b.Node) || !utf8.ValidString(b.Provider) || utf8.RuneCountInString(b.Provider) > 64 {
		return fmt.Errorf("服务商最多 64 个字符")
	}
	if b.Expiry != "" {
		if _, err := time.Parse("2006-01-02", b.Expiry); err != nil {
			return fmt.Errorf("到期日格式无效")
		}
	}
	if !slices.Contains([]string{"month", "quarter", "half", "year", "three_year", "once"}, b.Cycle) || !slices.Contains([]string{"CNY", "USD", "EUR"}, b.Currency) || b.Price != "" && !pricePattern.MatchString(b.Price) {
		return fmt.Errorf("续费周期、币种或价格无效")
	}
	if b.QuotaGB < 0 || b.QuotaGB > 10000000 || b.ResetDay < 0 || b.ResetDay > 28 || !slices.Contains([]string{"both", "out", "in", "max"}, b.Direction) {
		return fmt.Errorf("流量额度、重置日或计费方式无效")
	}
	for _, v := range []struct {
		value   string
		allowed []string
	}{{b.RemindDays, []string{"30", "14", "7", "3", "1"}}, {b.RemindPct, []string{"50", "80", "90", "95", "100"}}, {b.Notify, channels}} {
		seen := map[string]bool{}
		if v.value == "" {
			continue
		}
		for _, item := range strings.Split(v.value, ",") {
			if !slices.Contains(v.allowed, item) || seen[item] {
				return fmt.Errorf("提醒阈值或通知渠道无效")
			}
			seen[item] = true
		}
	}
	return nil
}
func scanBilling(row scanner) (b Billing, err error) {
	err = row.Scan(&b.Node, &b.Provider, &b.Expiry, &b.Cycle, &b.Currency, &b.Price, &b.AutoRenew, &b.QuotaGB, &b.ResetDay, &b.Direction, &b.RemindDays, &b.RemindPct, &b.Predict, &b.Notify, &b.UpdatedAt, &b.AnchorDay)
	return
}
func scanTraffic(row scanner) (t Traffic, err error) {
	err = row.Scan(&t.Node, &t.CycleStart, &t.UsedTX, &t.UsedRX, &t.Adjust, &t.LastTX, &t.LastRX, &t.LastUp, &t.FirstSeen)
	return
}
func (s *Store) Billing(node string) (Billing, error) {
	return scanBilling(s.DB.QueryRow(`SELECT `+billColumns+` FROM billing WHERE node=?`, node))
}
func (s *Store) Traffic(node string) (Traffic, error) {
	t, err := scanTraffic(s.DB.QueryRow(`SELECT `+trafficColumns+` FROM traffic WHERE node=?`, node))
	if err == sql.ErrNoRows {
		return Traffic{Node: node, Adjust: "0"}, nil
	}
	return t, err
}
func (s *Store) Days(node, since string) ([]Daily, error) {
	rows, err := s.DB.Query(`SELECT day,tx,rx,online FROM daily WHERE node=? AND day>=? ORDER BY day`, node, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Daily{}
	for rows.Next() {
		var d Daily
		if err = rows.Scan(&d.Day, &d.TX, &d.RX, &d.Online); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func SatAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}
func RawCount(tx, rx uint64, direction string) uint64 {
	switch direction {
	case "out":
		return tx
	case "in":
		return rx
	case "max":
		return max(tx, rx)
	}
	return SatAdd(tx, rx)
}
func Counted(t Traffic, direction string) uint64 {
	n := new(big.Int).SetUint64(RawCount(t.UsedTX, t.UsedRX, direction))
	adjust, _ := new(big.Int).SetString(t.Adjust, 10)
	if adjust != nil {
		n.Add(n, adjust)
	}
	if n.Sign() < 0 {
		return 0
	}
	if !n.IsUint64() {
		return math.MaxUint64
	}
	return n.Uint64()
}
func ParseGB(value string) (uint64, error) {
	if !regexp.MustCompile(`^\d+(\.\d{1,9})?$`).MatchString(value) {
		return 0, fmt.Errorf("校准用量无效")
	}
	n, ok := new(big.Rat).SetString(value)
	if !ok {
		return 0, fmt.Errorf("校准用量无效")
	}
	n.Mul(n, new(big.Rat).SetInt64(1000000000))
	if !n.IsInt() || !n.Num().IsUint64() {
		return 0, fmt.Errorf("校准用量超出范围")
	}
	return n.Num().Uint64(), nil
}
func AddMonths(t time.Time, months, anchorDay int) time.Time {
	if anchorDay < 1 || anchorDay > 31 {
		anchorDay = t.Day()
	}
	first := time.Date(t.Year(), t.Month()+time.Month(months), 1, 0, 0, 0, 0, t.Location())
	last := first.AddDate(0, 1, -1).Day()
	return time.Date(first.Year(), first.Month(), min(anchorDay, last), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
}

// CycleMonths returns the number of calendar months in a recurring billing cycle.
// One-time and unknown cycles return zero.
func CycleMonths(cycle string) int {
	return map[string]int{"month": 1, "quarter": 3, "half": 6, "year": 12, "three_year": 36}[cycle]
}
func Advance(expiry, cycle string, anchorDay int, loc *time.Location) string {
	t, err := time.ParseInLocation("2006-01-02", expiry, loc)
	months := CycleMonths(cycle)
	if err != nil || months == 0 {
		return expiry
	}
	return AddMonths(t, months, anchorDay).Format("2006-01-02")
}
func (b Billing) Anchor() int {
	if b.AnchorDay >= 1 && b.AnchorDay <= 31 {
		return b.AnchorDay
	}
	if t, e := time.Parse("2006-01-02", b.Expiry); e == nil {
		return t.Day()
	}
	return 1
}
func ResetDay(b *Billing) int {
	if b == nil {
		return 1
	}
	if b.ResetDay != 0 {
		return b.ResetDay
	}
	return b.Anchor()
}
func CycleStart(now time.Time, b *Billing) time.Time {
	day := ResetDay(b)
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	candidate := start.AddDate(0, 0, min(day, start.AddDate(0, 1, -1).Day())-1)
	if candidate.After(now) {
		start = start.AddDate(0, -1, 0)
		candidate = start.AddDate(0, 0, min(day, start.AddDate(0, 1, -1).Day())-1)
	}
	return candidate
}
func NextReset(now time.Time, b *Billing) time.Time {
	start := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
	candidate := time.Date(now.Year(), now.Month(), min(ResetDay(b), start.AddDate(0, 0, -1).Day()), 0, 0, 0, 0, now.Location())
	if candidate.After(now) {
		return candidate
	}
	return start.AddDate(0, 0, min(ResetDay(b), start.AddDate(0, 1, -1).Day())-1)
}
func RollCycle(tx *sql.Tx, t *Traffic, b *Billing, now time.Time) error {
	start := CycleStart(now, b).Format("2006-01-02")
	if t.CycleStart == start {
		return nil
	}
	old := t.CycleStart
	t.CycleStart = start
	t.UsedTX = 0
	t.UsedRX = 0
	t.Adjust = "0"
	if b != nil && old != "" {
		_, err := tx.Exec(`INSERT INTO events(ts,node,kind,detail,notified) VALUES(?,?,'traffic_reset','流量周期重置，用量清零',1)`, now.Unix(), t.Node)
		return err
	}
	return nil
}
func saveTraffic(tx *sql.Tx, t Traffic) error {
	_, err := tx.Exec(`INSERT INTO traffic VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(node) DO UPDATE SET cycle_start=excluded.cycle_start,used_tx=excluded.used_tx,used_rx=excluded.used_rx,adjust=excluded.adjust,last_tx=excluded.last_tx,last_rx=excluded.last_rx,last_up=excluded.last_up,first_seen=excluded.first_seen`, t.Node, t.CycleStart, strconv.FormatUint(t.UsedTX, 10), strconv.FormatUint(t.UsedRX, 10), t.Adjust, strconv.FormatUint(t.LastTX, 10), strconv.FormatUint(t.LastRX, 10), t.LastUp, t.FirstSeen)
	return err
}
func (s *Store) account(tx *sql.Tx, n Node, r *proto.Report, now time.Time) error {
	now = now.In(s.Location)
	b, err := scanBilling(tx.QueryRow(`SELECT `+billColumns+` FROM billing WHERE node=?`, n.Name))
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	var bill *Billing
	if err == nil {
		bill = &b
	}
	t, err := scanTraffic(tx.QueryRow(`SELECT `+trafficColumns+` FROM traffic WHERE node=?`, n.Name))
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		t = Traffic{Node: n.Name, Adjust: "0"}
	}
	if err = RollCycle(tx, &t, bill, now); err != nil {
		return err
	}
	delta := func(current, last uint64) uint64 {
		if t.FirstSeen == 0 {
			return 0
		}
		d := current
		if r.Up >= t.LastUp && current >= last {
			d = current - last
		}
		if d > 1000000000000 {
			return 0
		}
		return d
	}
	txBytes, rxBytes := delta(r.NetTotal[0], t.LastTX), delta(r.NetTotal[1], t.LastRX)
	t.UsedTX = SatAdd(t.UsedTX, txBytes)
	t.UsedRX = SatAdd(t.UsedRX, rxBytes)
	t.LastTX = r.NetTotal[0]
	t.LastRX = r.NetTotal[1]
	t.LastUp = r.Up
	if t.FirstSeen == 0 {
		t.FirstSeen = now.Unix()
	}
	if err = saveTraffic(tx, t); err != nil {
		return err
	}
	day := now.Format("2006-01-02")
	var d Daily
	err = tx.QueryRow(`SELECT tx,rx,online FROM daily WHERE node=? AND day=?`, n.Name, day).Scan(&d.TX, &d.RX, &d.Online)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO daily VALUES(?,?,?,?,?) ON CONFLICT(node,day) DO UPDATE SET tx=excluded.tx,rx=excluded.rx`, n.Name, day, strconv.FormatUint(SatAdd(d.TX, txBytes), 10), strconv.FormatUint(SatAdd(d.RX, rxBytes), 10), d.Online); err != nil {
		return err
	}
	online := false
	if n.LastSeen > 0 && now.Unix() >= n.LastSeen {
		last := time.Unix(n.LastSeen, 0)
		grace := 3*s.Interval + time.Minute
		online = now.Sub(last) <= 3*s.Interval
		if !s.StartedAt.IsZero() && !last.After(s.StartedAt) && !now.Before(s.StartedAt) {
			online = online || s.StartedAt.Sub(last) <= grace && now.Sub(s.StartedAt) <= grace
		}
		if !online {
			var raw string
			err = tx.QueryRow(`SELECT value FROM kv WHERE key='receiver.outage'`).Scan(&raw)
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if err == nil {
				var outage struct {
					Members map[string]json.RawMessage `json:"members"`
				}
				if err = json.Unmarshal([]byte(raw), &outage); err != nil {
					return err
				}
				_, online = outage.Members[n.Name]
			}
		}
	}
	if online {
		for start := time.Unix(n.LastSeen, 0).In(s.Location); start.Before(now); {
			midnight := time.Date(start.Year(), start.Month(), start.Day()+1, 0, 0, 0, 0, s.Location)
			end := now
			if midnight.Before(end) {
				end = midnight
			}
			if _, err = tx.Exec(`INSERT INTO daily VALUES(?,?,'0','0',?) ON CONFLICT(node,day) DO UPDATE SET online=online+excluded.online`, n.Name, start.Format("2006-01-02"), end.Unix()-start.Unix()); err != nil {
				return err
			}
			start = end
		}
	}
	return nil
}
func (s *Store) SaveBilling(b Billing, calibrate *uint64, now time.Time, user, ip string) error {
	b.AnchorDay = 1
	if b.Expiry != "" {
		expiry, err := time.Parse("2006-01-02", b.Expiry)
		if err != nil {
			return err
		}
		b.AnchorDay = expiry.Day()
	}
	return s.Transaction(func(tx *sql.Tx) error {
		var active bool
		if err := tx.QueryRow(`SELECT revoked_at=0 FROM nodes WHERE name=?`, b.Node).Scan(&active); err != nil {
			return err
		}
		if !active {
			return ErrNode
		}
		_, err := tx.Exec(`INSERT INTO billing(`+billColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node) DO UPDATE SET provider=excluded.provider,expiry=excluded.expiry,cycle=excluded.cycle,currency=excluded.currency,price=excluded.price,auto_renew=excluded.auto_renew,quota_gb=excluded.quota_gb,reset_day=excluded.reset_day,direction=excluded.direction,remind_days=excluded.remind_days,remind_pct=excluded.remind_pct,predict=excluded.predict,notify=excluded.notify,updated_at=excluded.updated_at,anchor_day=excluded.anchor_day`, b.Node, b.Provider, b.Expiry, b.Cycle, b.Currency, b.Price, b.AutoRenew, b.QuotaGB, b.ResetDay, b.Direction, b.RemindDays, b.RemindPct, b.Predict, b.Notify, now.Unix(), b.AnchorDay)
		if err != nil {
			return err
		}
		t, err := scanTraffic(tx.QueryRow(`SELECT `+trafficColumns+` FROM traffic WHERE node=?`, b.Node))
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == sql.ErrNoRows {
			t = Traffic{Node: b.Node, Adjust: "0"}
		}
		local := now.In(s.Location)
		start := CycleStart(local, &b).Format("2006-01-02")
		if start != t.CycleStart {
			t.CycleStart, t.Adjust = start, "0"
			t.UsedTX, t.UsedRX = 0, 0
			rows, err := tx.Query(`SELECT tx,rx FROM daily WHERE node=? AND day>=? AND day<=?`, b.Node, start, local.Format("2006-01-02"))
			if err != nil {
				return err
			}
			for rows.Next() {
				var txBytes, rxBytes uint64
				if err = rows.Scan(&txBytes, &rxBytes); err != nil {
					rows.Close()
					return err
				}
				t.UsedTX, t.UsedRX = SatAdd(t.UsedTX, txBytes), SatAdd(t.UsedRX, rxBytes)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		if calibrate != nil {
			t.Adjust = new(big.Int).Sub(new(big.Int).SetUint64(*calibrate), new(big.Int).SetUint64(RawCount(t.UsedTX, t.UsedRX, b.Direction))).String()
			if _, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,'traffic_calibrate',?)`, now.Unix(), user, ip, b.Node); err != nil {
				return err
			}
		}
		if err = saveTraffic(tx, t); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,'billing_save',?)`, now.Unix(), user, ip, b.Node)
		return err
	})
}
func (s *Store) Renew(node string, now time.Time, user, ip string) error {
	return s.Transaction(func(tx *sql.Tx) error {
		b, err := scanBilling(tx.QueryRow(`SELECT `+billColumns+` FROM billing WHERE node=? AND EXISTS(SELECT 1 FROM nodes WHERE name=? AND revoked_at=0)`, node, node))
		if err != nil {
			return err
		}
		if b.Expiry == "" || CycleMonths(b.Cycle) == 0 {
			return fmt.Errorf("没有可续费的周期")
		}
		expiry := Advance(b.Expiry, b.Cycle, b.Anchor(), s.Location)
		if _, err = tx.Exec(`UPDATE billing SET expiry=?,updated_at=? WHERE node=?`, expiry, now.Unix(), node); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,'billing_renewed',?)`, now.Unix(), user, ip, node+" "+expiry)
		return err
	})
}
func Availability45(first int64, days []Daily, now time.Time) Availability {
	out := Availability{Pct: "—", Days: []Day{}}
	var total, online int64
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for i := -44; i <= 0; i++ {
		start := today.AddDate(0, 0, i)
		end := start.AddDate(0, 0, 1)
		if end.After(now) {
			end = now
		}
		observed := int64(0)
		if first > 0 {
			observed = max(int64(0), end.Unix()-max(start.Unix(), first))
		}
		d := Day{Date: start.Format("2006-01-02"), State: "none", Observed: observed}
		for _, r := range days {
			if r.Day == d.Date {
				d.Online = min(observed, max(int64(0), r.Online))
				break
			}
		}
		d.Down = observed - d.Online
		if observed > 0 {
			switch {
			case d.Down <= 60:
				d.State = "ok"
			case d.Down < 3600:
				d.State = "partial"
			default:
				d.State = "down"
			}
		}
		total += observed
		online += d.Online
		out.Days = append(out.Days, d)
	}
	if total > 0 {
		if online == total {
			out.Pct = "100"
		} else {
			out.Pct = fmt.Sprintf("%.2f", math.Floor(float64(online)/float64(total)*10000)/100)
		}
	}
	return out
}
func (s *Store) KV(key string) (string, error) {
	var value string
	err := s.DB.QueryRow(`SELECT value FROM kv WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}
func (s *Store) SetKV(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO kv VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
