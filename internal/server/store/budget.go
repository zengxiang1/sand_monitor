package store

import (
	"math/big"
	"sort"
	"time"
)

// Budget projects retained nodes at their current billing price. Start is
// inclusive and End exclusive, both in the store's local calendar. Amounts are
// decimal strings rounded only after aggregation; an empty amount is unknown.
type Budget struct {
	Start, End                              string
	TotalNodes, PendingNodes, ExcludedNodes int
	CashIncluded, AnnualIncluded            int
	Currencies                              []BudgetCurrency
	Months                                  []BudgetMonth
	Nodes                                   []BudgetNode
}

type BudgetCurrency struct {
	Currency, Cash, Annual, Monthly string
	CashIncluded, AnnualIncluded    int
}

type BudgetMonth struct {
	Month, Currency, Amount string
	Renewals                int
}

// CashIncluded counts nodes whose scheduled cash cost can be determined, even
// when no renewal falls in the window. AnnualIncluded also governs Monthly.
// Reasons are empty when included, otherwise one of missing_billing,
// missing_price, invalid_price, unsupported_currency, unsupported_cycle, once,
// missing_expiry, invalid_expiry, overdue_expiry.
type BudgetNode struct {
	Name, DisplayName, Provider, Price, Currency, Cycle, Expiry string
	Cash, Annual, Monthly                                       string
	CashIncluded, AnnualIncluded                                bool
	CashReason, AnnualReason                                    string
	Renewals                                                    []BudgetRenewal
}

type BudgetRenewal struct {
	Date, Amount string
}

type budgetSum struct {
	cash, annual           *big.Rat
	cashCount, annualCount int
}

// Budget reads a single snapshot and never advances expiry dates, resets
// traffic, or emits reminders. Offline and manually renewed nodes are retained.
func (s *Store) Budget(now time.Time) (Budget, error) {
	loc := s.Location
	if loc == nil {
		loc = now.Location()
	}
	now = now.In(loc)
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	end := AddMonths(start, 12, start.Day())
	out := Budget{Start: start.Format("2006-01-02"), End: end.Format("2006-01-02"), Nodes: []BudgetNode{}, Months: []BudgetMonth{}}
	rows, err := s.DB.Query(`SELECT n.name,n.display_name,b.node IS NOT NULL,
 COALESCE(b.provider,''),COALESCE(b.price,''),COALESCE(b.currency,''),COALESCE(b.cycle,''),COALESCE(b.expiry,''),COALESCE(b.anchor_day,0)
 FROM nodes n LEFT JOIN billing b ON b.node=n.name WHERE n.revoked_at=0 ORDER BY n.name`)
	if err != nil {
		return Budget{}, err
	}
	defer rows.Close()
	sums := map[string]*budgetSum{}
	for _, currency := range []string{"CNY", "USD", "EUR"} {
		sums[currency] = &budgetSum{cash: new(big.Rat), annual: new(big.Rat)}
	}
	months := map[string]*big.Rat{}
	counts := map[string]int{}
	for rows.Next() {
		n := BudgetNode{Renewals: []BudgetRenewal{}}
		var hasBilling bool
		var anchor int
		if err = rows.Scan(&n.Name, &n.DisplayName, &hasBilling, &n.Provider, &n.Price, &n.Currency, &n.Cycle, &n.Expiry, &anchor); err != nil {
			return Budget{}, err
		}
		out.TotalNodes++
		reason := ""
		switch {
		case !hasBilling:
			reason = "missing_billing"
		case n.Price == "":
			reason = "missing_price"
		case !pricePattern.MatchString(n.Price):
			reason = "invalid_price"
		case sums[n.Currency] == nil:
			reason = "unsupported_currency"
		case n.Cycle == "once":
			reason = "once"
		case CycleMonths(n.Cycle) == 0:
			reason = "unsupported_cycle"
		}
		n.CashReason, n.AnnualReason = reason, reason
		if reason != "" {
			if reason == "once" {
				out.ExcludedNodes++
			} else {
				out.PendingNodes++
			}
			out.Nodes = append(out.Nodes, n)
			continue
		}
		price, _ := new(big.Rat).SetString(n.Price)
		sum := sums[n.Currency]
		annual := new(big.Rat).Mul(price, big.NewRat(12, int64(CycleMonths(n.Cycle))))
		n.Annual, n.Monthly = annual.FloatString(2), new(big.Rat).Quo(annual, big.NewRat(12, 1)).FloatString(2)
		n.AnnualIncluded = true
		out.AnnualIncluded++
		sum.annualCount++
		sum.annual.Add(sum.annual, annual)
		expiry, parseErr := time.ParseInLocation("2006-01-02", n.Expiry, loc)
		switch {
		case n.Expiry == "":
			n.CashReason = "missing_expiry"
		case parseErr != nil:
			n.CashReason = "invalid_expiry"
		case expiry.Before(start):
			n.CashReason = "overdue_expiry"
		}
		if n.CashReason != "" {
			out.PendingNodes++
			out.Nodes = append(out.Nodes, n)
			continue
		}
		n.CashIncluded = true
		out.CashIncluded++
		sum.cashCount++
		cash := new(big.Rat)
		if anchor < 1 || anchor > 31 {
			anchor = expiry.Day()
		}
		for due := expiry; due.Before(end); due = AddMonths(due, CycleMonths(n.Cycle), anchor) {
			cash.Add(cash, price)
			n.Renewals = append(n.Renewals, BudgetRenewal{Date: due.Format("2006-01-02"), Amount: price.FloatString(2)})
			key := due.Format("2006-01") + " " + n.Currency
			if months[key] == nil {
				months[key] = new(big.Rat)
			}
			months[key].Add(months[key], price)
			counts[key]++
		}
		n.Cash = cash.FloatString(2)
		sum.cash.Add(sum.cash, cash)
		out.Nodes = append(out.Nodes, n)
	}
	if err = rows.Err(); err != nil {
		return Budget{}, err
	}
	for _, currency := range []string{"CNY", "USD", "EUR"} {
		sum := sums[currency]
		c := BudgetCurrency{Currency: currency, CashIncluded: sum.cashCount, AnnualIncluded: sum.annualCount}
		if sum.cashCount > 0 {
			c.Cash = sum.cash.FloatString(2)
		}
		if sum.annualCount > 0 {
			c.Annual = sum.annual.FloatString(2)
			c.Monthly = new(big.Rat).Quo(sum.annual, big.NewRat(12, 1)).FloatString(2)
		}
		out.Currencies = append(out.Currencies, c)
	}
	keys := make([]string, 0, len(months))
	for key := range months {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out.Months = append(out.Months, BudgetMonth{Month: key[:7], Currency: key[8:], Amount: months[key].FloatString(2), Renewals: counts[key]})
	}
	return out, nil
}
