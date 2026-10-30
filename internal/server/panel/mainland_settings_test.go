package panel

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"wanglou/internal/server/mainland"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func TestMainlandSettingsDirectoryNavigationAndAuthorization(t *testing.T) {
	f := setup(t)
	calls := 0
	f.h.Config.MainlandLocations = func(ctx context.Context) ([]mainland.LocationOption, error) {
		calls++
		if _, bounded := ctx.Deadline(); !bounded {
			t.Error("directory request has no deadline")
		}
		return []mainland.LocationOption{{ASN: 4837, City: "Shanghai", Count: 2}, {ASN: 4837, City: "Wuhan", Count: 3}, {ASN: 4134, City: "Beijing", Count: 4}, {ASN: 9808, City: "Guangzhou", Count: 1}}, nil
	}
	for _, tc := range []struct{ path, carrier, city string }{{"/mainland", "中国联通", "Shanghai · 2 个在线探针"}, {"/mainland?asn=4134", "中国电信", "Beijing · 4 个在线探针"}} {
		w := f.request("GET", tc.path, nil, true)
		body := w.Body.String()
		for _, marker := range []string{`href="/mainland" aria-current="page"`, "国内探测", tc.carrier, tc.city, "每小时一次", "单个探针访问本轮各节点", "仅当前主控", "不绑定固定机器", `method="get" action="/mainland"`, `method="post" action="/mainland"`} {
			if w.Code != 200 || !strings.Contains(body, marker) {
				t.Error("settings page missing content", tc.path, marker, w.Code)
			}
		}
		if strings.Contains(body, `data-refresh="true"`) || input(t, body, "csrf") != f.csrf {
			t.Fatal("settings form refresh or CSRF contract changed", body)
		}
		checkHeaders(t, w)
	}
	saved, err := f.s.MainlandSource()
	if err != nil || saved != (store.MainlandSource{ASN: 4837}) {
		t.Fatal("GET carrier selection persisted configuration", saved, err)
	}
	if w := f.request("GET", "/mainland?asn=9999", nil, true); w.Code != 400 || !strings.Contains(w.Body.String(), "请选择联通、电信或移动") {
		t.Fatal(w.Code, w.Body)
	}
	before := calls
	if w := f.request("GET", "/mainland", nil, false); w.Code != 303 {
		t.Fatal("settings GET exposed", w.Code)
	}
	if w := f.request("POST", "/mainland", url.Values{"asn": {"4837"}}, false); w.Code != 401 {
		t.Fatal("settings POST exposed", w.Code)
	}
	if w := f.request("POST", "/mainland", url.Values{"asn": {"4837"}, "csrf": {"wrong"}}, true); w.Code != 403 {
		t.Fatal("settings POST ignored CSRF", w.Code)
	}
	if calls != before {
		t.Fatal("unauthorized request reached provider")
	}
}

func TestMainlandSettingsSaveValidationAuditAndHourGate(t *testing.T) {
	f := setup(t)
	f.h.Config.MainlandLocations = func(context.Context) ([]mainland.LocationOption, error) {
		return []mainland.LocationOption{{ASN: 4837, City: "Wuhan", Count: 3}, {ASN: 4134, City: "Beijing", Count: 2}}, nil
	}
	if err := f.s.SetKV("mainland.last_attempt", "123456789"); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {f.csrf}, "asn": {"4134"}, "city": {"Beijing"}}
	w := f.request("POST", "/mainland", form, true)
	if w.Code != 303 || w.Header().Get("Location") != "/mainland?saved=1" {
		t.Fatal(w.Code, w.Body)
	}
	saved, err := f.s.MainlandSource()
	if err != nil || saved != (store.MainlandSource{ASN: 4134, City: "Beijing"}) {
		t.Fatal(saved, err)
	}
	gate, err := f.s.KV("mainland.last_attempt")
	if err != nil || gate != "123456789" {
		t.Fatal("saving source reset the hourly schedule", gate, err)
	}
	var user, detail string
	if err := f.s.DB.QueryRow(`SELECT user,detail FROM audit_log WHERE action='mainland_source_set' ORDER BY rowid DESC LIMIT 1`).Scan(&user, &detail); err != nil || user != "admin" || detail != `asn=4134 city="Beijing"` {
		t.Fatal("source change missing audit entry", user, detail, err)
	}
	for _, tc := range []struct{ asn, city string }{{"4837", "Beijing"}, {"4134", "invented-city"}, {"9999", ""}, {"", ""}, {"4134", "bad\ncity"}} {
		form.Set("asn", tc.asn)
		form.Set("city", tc.city)
		if w := f.request("POST", "/mainland", form, true); w.Code != 400 {
			t.Fatal("unsupported selection accepted", tc, w.Code, w.Body)
		}
		got, err := f.s.MainlandSource()
		if err != nil || got != saved {
			t.Fatal("rejected selection changed configuration", tc, got, err)
		}
	}
	var count int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='mainland_source_set'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected selections wrote successful-change audit", count, err)
	}
	w = f.request("GET", "/mainland?saved=1", nil, true)
	if !strings.Contains(w.Body.String(), "下一个到期的每小时轮次生效") {
		t.Fatal(w.Body)
	}
}

func TestMainlandSettingsUnavailableDirectoryKeepsSavedOrAuto(t *testing.T) {
	f := setup(t)
	if err := f.s.SetMainlandSource(store.MainlandSource{ASN: 4837, City: "Wuhan"}); err != nil {
		t.Fatal(err)
	}
	f.h.Config.MainlandLocations = func(context.Context) ([]mainland.LocationOption, error) {
		return []mainland.LocationOption{{ASN: 4837, City: "not-authoritative", Count: 9}}, errors.New("private-provider-url")
	}
	w := f.request("GET", "/mainland", nil, true)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "在线目录暂时不可用") || !strings.Contains(body, "Wuhan · 已保存，在线状态未知") || strings.Contains(body, "not-authoritative") || strings.Contains(body, "private-provider-url") || strings.Contains(body, "0 个在线探针") {
		t.Fatal("directory failure produced misleading online choices", w.Code, body)
	}
	form := url.Values{"csrf": {f.csrf}, "asn": {"4837"}, "city": {"Wuhan"}}
	if w := f.request("POST", "/mainland", form, true); w.Code != 303 {
		t.Fatal("saved source cannot be retained during outage", w.Code, w.Body)
	}
	form.Set("city", "not-authoritative")
	if w := f.request("POST", "/mainland", form, true); w.Code != 400 {
		t.Fatal("failed directory authorized a new city", w.Code)
	}
	form.Set("asn", "9808")
	form.Set("city", "Wuhan")
	if w := f.request("POST", "/mainland", form, true); w.Code != 400 {
		t.Fatal("saved city reused across carriers during outage", w.Code)
	}
	form.Set("city", "")
	if w := f.request("POST", "/mainland", form, true); w.Code != 303 {
		t.Fatal("automatic selection unavailable during directory outage", w.Code, w.Body)
	}
	got, err := f.s.MainlandSource()
	if err != nil || got != (store.MainlandSource{ASN: 9808}) {
		t.Fatal(got, err)
	}
}

func TestMainlandSettingsOfflineSavedCityAndEscaping(t *testing.T) {
	f := setup(t)
	city := `<script>alert("source")</script>`
	if err := f.s.SetMainlandSource(store.MainlandSource{ASN: 4837, City: city}); err != nil {
		t.Fatal(err)
	}
	f.h.Config.MainlandLocations = func(context.Context) ([]mainland.LocationOption, error) {
		return []mainland.LocationOption{{ASN: 4837, City: "Shanghai", Count: 2}}, nil
	}
	w := f.request("GET", "/mainland", nil, true)
	body := w.Body.String()
	if w.Code != 200 || strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "已保存，当前未在线") {
		t.Fatal("saved offline city was lost or unescaped", body)
	}
	if w := f.request("POST", "/mainland", url.Values{"csrf": {f.csrf}, "asn": {"4837"}, "city": {city}}, true); w.Code != 303 {
		t.Fatal("offline saved city cannot be retained", w.Code, w.Body)
	}
}

func TestMainlandPrivateViewsFollowConfiguredSource(t *testing.T) {
	f := setup(t)
	if err := f.s.SetMainlandProbes("node", []store.MainlandProbe{{Carrier: "中国联通", ASN: 4837, City: "Wuhan", Country: "CN", Time: f.now.Unix(), TCPMS: 51.2, Sent: 3, Received: 3, Status: "ok"}, {Carrier: "中国电信", ASN: 4134, City: "Beijing", Country: "CN", Time: f.now.Unix(), TCPMS: 71.4, Sent: 3, Received: 3, Status: "ok"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source     store.MainlandSource
		show, hide string
	}{{store.MainlandSource{ASN: 4837, City: "Wuhan"}, "51.2 ms", "71.4 ms"}, {store.MainlandSource{ASN: 4134, City: "Beijing"}, "71.4 ms", "51.2 ms"}, {store.MainlandSource{ASN: 4837, City: "Changsha"}, "暂无数据", "51.2 ms"}, {store.MainlandSource{ASN: 9808}, "暂无数据", "71.4 ms"}} {
		if err := f.s.SetMainlandSource(tc.source); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/", "/nodes/node"} {
			w := f.request("GET", path, nil, true)
			block := regexp.MustCompile(`(?s)<section class="card (?:flush|stack)" id="mainland-(?:overview|access)">.*?</section>`).FindString(w.Body.String())
			if w.Code != 200 || !strings.Contains(block, tc.show) || strings.Contains(block, tc.hide) || !strings.Contains(block, tc.source.Carrier()) {
				t.Fatal("source change reused or mislabeled previous result", tc.source, path, block)
			}
		}
	}
}

func TestMainlandSettingsSaveInvalidatesPublicHome(t *testing.T) {
	f := setup(t)
	f.h.Config.MainlandLocations = func(context.Context) ([]mainland.LocationOption, error) {
		return []mainland.LocationOption{{ASN: 4134, City: "Beijing", Count: 2}}, nil
	}
	if err := f.s.SetMainlandProbes("node", []store.MainlandProbe{{Carrier: "中国联通", ASN: 4837, City: "Wuhan", Time: f.now.Unix(), TCPMS: 51.2, Sent: 3, Received: 3, Status: "ok"}}); err != nil {
		t.Fatal(err)
	}
	c := status.DefaultConfig()
	c.Nodes = []status.Selection{{Node: "node", Public: true, Name: "公开节点"}}
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if body := f.request("GET", "/", nil, false).Body.String(); !strings.Contains(body, "51.2 ms") || f.h.publicHTML == nil {
		t.Fatal("initial public source not cached", body)
	}
	if w := f.request("POST", "/mainland", url.Values{"csrf": {f.csrf}, "asn": {"4134"}, "city": {"Beijing"}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	body := f.request("GET", "/", nil, false).Body.String()
	if strings.Contains(body, "51.2 ms") || !strings.Contains(body, "中国电信") || !strings.Contains(body, "暂无数据") {
		t.Fatal("source change retained previous public cache", body)
	}
}
