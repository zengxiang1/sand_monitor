package store

import (
	"crypto/ed25519"
	"math/big"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func newBudgetStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.Location = time.UTC
	return s
}

func addBudgetNode(t *testing.T, s *Store, name, cycle, price, currency, expiry string) {
	t.Helper()
	if err := s.AddNode(name, make(ed25519.PublicKey, ed25519.PublicKeySize), time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if cycle != "" {
		b := DefaultBilling(name)
		b.Cycle, b.Price, b.Currency, b.Expiry = cycle, price, currency, expiry
		if err := s.SaveBilling(b, nil, time.Unix(100, 0), "admin", ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBudgetFixtureAndReadOnly(t *testing.T) {
	s := newBudgetStore(t)
	for _, row := range []struct{ name, cycle, price, expiry string }{
		{"prepaid-a", "three_year", "88", "2028-11-28"},
		{"prepaid-b", "three_year", "88", "2028-11-28"},
		{"annual-a", "year", "39.9", "2027-11-05"},
		{"annual-b", "year", "49", "2028-04-03"},
		{"pending-a", "once", "", "2027-01-27"},
		{"pending-b", "once", "", "2027-01-14"},
	} {
		addBudgetNode(t, s, row.name, row.cycle, row.price, "USD", row.expiry)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET display_name='示例节点' WHERE name='prepaid-a'`); err != nil {
		t.Fatal(err)
	}
	var before, after int
	if err := s.DB.QueryRow(`SELECT total_changes()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// Enforce read-only operation, including no implicit expiry/traffic mutation.
	if _, err := s.DB.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 31, 23, 30, 0, 0, time.UTC)
	b, err := s.Budget(now)
	if err != nil {
		t.Fatal(err)
	}
	if b.Start != "2026-10-31" || b.End != "2027-10-31" || b.TotalNodes != 6 || b.PendingNodes != 2 || b.ExcludedNodes != 0 || b.CashIncluded != 4 || b.AnnualIncluded != 4 {
		t.Fatalf("coverage: %+v", b)
	}
	usd := b.Currencies[1]
	if usd.Cash != "0.00" || usd.Annual != "147.57" || usd.Monthly != "12.30" || usd.CashIncluded != 4 || len(b.Months) != 0 {
		t.Fatalf("totals: %+v months %+v", usd, b.Months)
	}
	if b.Currencies[0].Cash != "" || b.Currencies[0].Annual != "" || b.Currencies[2].Monthly != "" {
		t.Fatal("unknown totals must be empty", b.Currencies)
	}
	for _, n := range b.Nodes {
		if n.Name == "prepaid-a" && n.DisplayName != "示例节点" {
			t.Fatal(n)
		}
	}
	if err := s.DB.QueryRow(`SELECT total_changes()`).Scan(&after); err != nil || before != after {
		t.Fatal("budget mutated database", before, after, err)
	}
	if again, err := s.Budget(now); err != nil || !reflect.DeepEqual(b, again) {
		t.Fatal("budget is not repeatable", err)
	}
}

func TestBudgetCyclesAndWindow(t *testing.T) {
	for _, tc := range []struct {
		cycle          string
		months, events int
		annual         string
	}{
		{"month", 1, 12, "144.00"},
		{"quarter", 3, 4, "48.00"},
		{"half", 6, 2, "24.00"},
		{"year", 12, 1, "12.00"},
		{"three_year", 36, 1, "4.00"},
	} {
		t.Run(tc.cycle, func(t *testing.T) {
			s := newBudgetStore(t)
			addBudgetNode(t, s, "today", tc.cycle, "12", "USD", "2026-10-31")
			addBudgetNode(t, s, "end", tc.cycle, "12", "USD", "2027-10-31")
			b, err := s.Budget(time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			if CycleMonths(tc.cycle) != tc.months || b.CashIncluded != 2 || len(b.Nodes[1].Renewals) != tc.events || b.Nodes[1].Annual != tc.annual || b.Nodes[0].Cash != "0.00" {
				t.Fatalf("%+v", b)
			}
			if b.Nodes[1].Renewals[0].Date != "2026-10-31" || b.Nodes[1].Cash != newMoney(tc.events*12) {
				t.Fatalf("today not included or charge divided by cycle: %+v", b.Nodes[1])
			}
			if tc.cycle == "month" && (b.Nodes[1].Renewals[1].Date != "2026-11-30" || b.Nodes[1].Renewals[2].Date != "2026-12-31") {
				t.Fatal("anchor drift", b.Nodes[1].Renewals)
			}
		})
	}
}

func newMoney(n int) string {
	return new(big.Rat).SetInt64(int64(n)).FloatString(2)
}

func TestBudgetExactAggregationAndCurrency(t *testing.T) {
	s := newBudgetStore(t)
	addBudgetNode(t, s, "one", "three_year", "0.01", "USD", "2027-01-01")
	addBudgetNode(t, s, "two", "three_year", "0.01", "USD", "2027-01-02")
	addBudgetNode(t, s, "three", "three_year", "0.01", "USD", "2027-01-03")
	addBudgetNode(t, s, "cny", "month", "0.01", "CNY", "2027-01-01")
	addBudgetNode(t, s, "zero", "year", "0", "EUR", "2027-01-01")
	b, err := s.Budget(time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if b.Currencies[1].Annual != "0.01" || b.Currencies[1].Cash != "0.03" || b.Currencies[0].Annual != "0.12" || b.Currencies[2].Cash != "0.00" || b.Currencies[2].Annual != "0.00" || b.PendingNodes != 0 {
		t.Fatal(b.Currencies, b.PendingNodes)
	}
	if len(b.Months) != 14 || b.Months[1].Currency != "EUR" || b.Months[2].Currency != "USD" || b.Months[2].Amount != "0.03" || b.Months[2].Renewals != 3 {
		t.Fatal(b.Months)
	}
	// Monthly 0.005 rounds upward; annual fractions were aggregated above.
	addBudgetNode(t, s, "half", "three_year", "0.03", "USD", "2027-01-04")
	addBudgetNode(t, s, "round", "half", "0.01", "USD", "2027-01-05")
	addBudgetNode(t, s, "monthly-round", "year", "0.06", "EUR", "2027-01-05")
	b, err = s.Budget(time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC))
	if err != nil || b.Currencies[1].Annual != "0.04" || b.Currencies[2].Monthly != "0.01" {
		t.Fatal(b.Currencies, err)
	}
}

func TestBudgetExclusionAndPartialCoverage(t *testing.T) {
	s := newBudgetStore(t)
	for _, row := range []struct{ name, cycle, price, currency, expiry string }{
		{"missing", "", "", "", ""},
		{"price", "year", "", "USD", "2027-01-01"},
		{"no-expiry", "month", "1", "USD", ""},
		{"overdue", "year", "12", "USD", "2026-12-31"},
		{"once", "once", "100", "USD", "2027-01-01"},
		{"once-price", "once", "", "USD", "2027-01-01"},
		{"cycle", "bogus", "12", "USD", "2027-01-01"},
		{"currency", "year", "12", "GBP", "2027-01-01"},
		{"invalid-price", "year", "wrong", "USD", "2027-01-01"},
		{"invalid-expiry", "year", "12", "USD", "2027-01-01"},
		{"offline", "year", "12", "USD", "2027-01-01"},
		{"revoked", "year", "1200", "USD", "2027-01-01"},
	} {
		addBudgetNode(t, s, row.name, row.cycle, row.price, row.currency, row.expiry)
	}
	if _, err := s.DB.Exec(`UPDATE billing SET expiry='bad' WHERE node='invalid-expiry'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke("revoked", time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	b, err := s.Budget(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if b.TotalNodes != 11 || b.ExcludedNodes != 1 || b.PendingNodes != 9 || b.CashIncluded != 1 || b.AnnualIncluded != 4 || b.Currencies[1].Cash != "12.00" || b.Currencies[1].Annual != "48.00" {
		t.Fatalf("%+v", b)
	}
	want := map[string]string{"missing": "missing_billing", "price": "missing_price", "no-expiry": "missing_expiry", "overdue": "overdue_expiry", "once": "once", "once-price": "missing_price", "cycle": "unsupported_cycle", "currency": "unsupported_currency", "invalid-price": "invalid_price", "invalid-expiry": "invalid_expiry", "offline": ""}
	for _, n := range b.Nodes {
		if n.CashReason != want[n.Name] {
			t.Fatal(n)
		}
		if (n.Name == "no-expiry" || n.Name == "overdue" || n.Name == "invalid-expiry") && (!n.AnnualIncluded || n.AnnualReason != "") {
			t.Fatal("expiry must not prevent annualization", n)
		}
	}
}

func TestBudgetLocalLeapWindow(t *testing.T) {
	s := newBudgetStore(t)
	s.Location = time.FixedZone("local", 8*60*60)
	addBudgetNode(t, s, "leap", "month", "1", "USD", "2024-02-29")
	// It is already February 29 in the store's local timezone.
	b, err := s.Budget(time.Date(2024, 2, 28, 17, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if b.Start != "2024-02-29" || b.End != "2025-02-28" || b.Nodes[0].Cash != "12.00" || b.Nodes[0].Renewals[1].Date != "2024-03-29" || b.Nodes[0].Renewals[11].Date != "2025-01-29" {
		t.Fatalf("%+v", b)
	}
}
