package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func budgetFixture(t *testing.T) *fixture {
	t.Helper()
	f := setup(t)
	f.s.Location = time.FixedZone("CST", 8*60*60)
	f.now = time.Date(2026, 10, 31, 12, 0, 0, 0, f.s.Location)
	if _, err := f.s.DB.Exec(`UPDATE sessions SET created_at=?,last_seen=?`, f.now.Unix(), f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	return f
}
func saveBudgetNode(t *testing.T, f *fixture, name, cycle, currency, price, expiry string) {
	t.Helper()
	if name != "node" {
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.s.AddNode(name, key, f.now); err != nil {
			t.Fatal(err)
		}
	}
	b := store.DefaultBilling(name)
	b.Cycle, b.Currency, b.Price, b.Expiry = cycle, currency, price, expiry
	if err := f.s.SaveBilling(b, nil, f.now, "admin", ""); err != nil {
		t.Fatal(err)
	}
}
func budgetSection(t *testing.T, body, id string) string {
	t.Helper()
	s := regexp.MustCompile(`(?s)<section[^>]*aria-labelledby="` + id + `".*?</section>`).FindString(body)
	if s == "" {
		t.Fatal("budget section missing", id)
	}
	return s
}
func TestBudgetThreeYearEditorSaveAndRenew(t *testing.T) {
	f := budgetFixture(t)
	form := billingForm(store.DefaultBilling("node"))
	for key, value := range map[string]string{"csrf": f.csrf, "cycle": "three_year", "currency": "USD", "price": "88", "expiry": "2028-11-28"} {
		form.Set(key, value)
	}
	if w := f.request("POST", "/billing/node", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	w := f.request("GET", "/billing?edit=node", nil, true)
	for _, text := range []string{`value="three_year" selected>三年付`, "三年付填写三年总价", `aria-describedby="billing-price-help"`, "三年付 $88", "已续费一期"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Error("missing", text)
		}
	}
	if w := f.request("POST", "/billing/node/renewed", url.Values{"csrf": {f.csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	b, err := f.s.Billing("node")
	if err != nil || b.Expiry != "2031-11-28" || b.Cycle != "three_year" || b.Price != "88" {
		t.Fatal(b, err)
	}
}
func TestBudgetKnownFixtureAndCollapsedDetails(t *testing.T) {
	f := budgetFixture(t)
	if err := f.s.Revoke("node", f.now); err != nil {
		t.Fatal(err)
	}
	for _, n := range []struct{ name, cycle, price, expiry string }{
		{"prepaid-a", "three_year", "88", "2028-11-28"}, {"prepaid-b", "three_year", "88", "2028-11-28"},
		{"annual-a", "year", "39.9", "2027-11-05"}, {"annual-b", "year", "49", "2028-04-03"},
		{"pending-a", "once", "", "2027-01-27"}, {"pending-b", "once", "", "2027-01-14"},
	} {
		saveBudgetNode(t, f, n.name, n.cycle, "USD", n.price, n.expiry)
	}
	w := f.request("GET", "/billing", nil, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	body := w.Body.String()
	cash := budgetSection(t, body, "budget-cash-title")
	annual := budgetSection(t, body, "budget-average-title")
	for _, text := range []string{"USD 0.00", "已覆盖 4 / 6 台", "2026-10-31", "2027-10-31", "2 台账单信息待补", "请补充价格并确认续费周期", `href="/billing?edit=pending-a#editor"`, `href="/billing?edit=pending-b#editor"`} {
		if !strings.Contains(cash, text) {
			t.Error("cash missing", text)
		}
	}
	for _, text := range []string{"USD 147.57", "USD 12.30", "已覆盖 4 / 6 台", "2 台账单信息待补"} {
		if !strings.Contains(annual, text) {
			t.Error("annual missing", text)
		}
	}
	for _, id := range []string{"budget-months", "budget-nodes"} {
		tag := regexp.MustCompile(`<details\b[^>]*id="` + id + `"[^>]*>`).FindString(body)
		if tag == "" || strings.Contains(tag, "open") {
			t.Error("details must start collapsed", tag)
		}
	}
	if !strings.Contains(body, "已覆盖节点在此期间无需续费") || !strings.Contains(body, "各币种分别统计，不做汇率换算") {
		t.Fatal("missing forecast explanation")
	}
}
func TestBudgetIncompleteSeparateCoverageAndMultipleCurrencies(t *testing.T) {
	f := budgetFixture(t)
	saveBudgetNode(t, f, "node", "month", "CNY", "12", "")
	saveBudgetNode(t, f, "usd", "year", "USD", "24", "2026-11-01")
	saveBudgetNode(t, f, "euro", "quarter", "EUR", "9", "2026-11-02")
	saveBudgetNode(t, f, "once", "once", "USD", "100", "2026-12-01")
	w := f.request("GET", "/billing", nil, true)
	body := w.Body.String()
	cash := budgetSection(t, body, "budget-cash-title")
	annual := budgetSection(t, body, "budget-average-title")
	for _, text := range []string{"已覆盖 2 / 4 台", "USD 24.00", "EUR 36.00", "到期日待补", `href="/billing?edit=node#editor"`, "另有 1 台一次性费用"} {
		if !strings.Contains(cash, text) {
			t.Error("cash missing", text)
		}
	}
	if strings.Contains(cash, "CNY 0.00") {
		t.Error("missing expiry shown as zero cash")
	}
	for _, text := range []string{"已覆盖 3 / 4 台", "CNY 144.00", "CNY 12.00", "USD 24.00", "EUR 36.00", "已计入年均", `href="/billing?edit=node#editor"`} {
		if !strings.Contains(annual, text) {
			t.Error("annual missing", text)
		}
	}
	if strings.Contains(body, "总计") {
		t.Error("must not sum currencies")
	}
}
func TestBudgetUnknownEmptyAndPrivacy(t *testing.T) {
	f := budgetFixture(t)
	w := f.request("GET", "/billing", nil, true)
	for _, id := range []string{"budget-cash-title", "budget-average-title"} {
		section := budgetSection(t, w.Body.String(), id)
		if !strings.Contains(section, "暂无可估算金额") || !strings.Contains(section, "已覆盖 0 / 1 台") || strings.Contains(section, "0.00") {
			t.Fatal("unknown rendered as free", section)
		}
	}
	if err := f.s.Revoke("node", f.now); err != nil {
		t.Fatal(err)
	}
	w = f.request("GET", "/billing", nil, true)
	if !strings.Contains(w.Body.String(), "暂无服务器") || strings.Contains(w.Body.String(), "账单信息待补") {
		t.Fatal("empty state", w.Body)
	}
	saveBudgetNode(t, f, "private-cost", "year", "USD", "867.53", "2026-11-05")
	if w := f.request("GET", "/billing", nil, false); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatal("billing auth", w.Code)
	}
	if w := f.request("GET", "/billing?fragment=1", nil, false); w.Code != 401 {
		t.Fatal("fragment auth", w.Code)
	}
	c := status.DefaultConfig()
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/s/", "/login"} {
		w := f.request("GET", path, nil, false)
		for _, secret := range []string{"867.53", "budget-cash-title", "budget-average-title", "未来 12 个月预计续费"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("public cost leak", path, secret)
			}
		}
	}
}
