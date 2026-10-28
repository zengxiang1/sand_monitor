package panel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/ingest"
	"wanglou/internal/server/store"
)

type fixture struct {
	h      *Handler
	s      *store.Store
	now    time.Time
	secret string
	cookie *http.Cookie
	csrf   string
	key    ed25519.PrivateKey
	seq    uint64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f := &fixture{s: s, now: time.Unix(2000000000, 0), secret: NewTOTPSecret(), csrf: randomToken(32)}
	hash, err := HashPassword("example-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO admins(user,pw_hash,totp_secret,created_at) VALUES(?,?,?,?)`, "admin", hash, f.secret, f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	if err = s.AddNode("node", pub, f.now); err != nil {
		t.Fatal(err)
	}
	ing := ingest.New(s, alert.New(s, alert.DefaultConfig()))
	ing.Now = func() time.Time { return f.now }
	ing.Logf = func(string, ...any) {}
	channels, err := alert.NewChannels(s, alert.Telegram{Token: "token", ChatID: "123"}, alert.Webhook{URL: "https://hook.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	f.h = New(s, ing, Config{CookieSecure: true, PublicIngestURL: "https://monitor.example.com", Channels: channels})
	f.h.Now = func() time.Time { return f.now }
	f.h.Logf = func(string, ...any) {}
	f.cookie = &http.Cookie{Name: f.h.cookieName(), Value: randomToken(32)}
	if _, err = s.DB.Exec(`INSERT INTO sessions VALUES(?,?,?,?,?,?)`, store.TokenHash(f.cookie.Value), "admin", f.csrf, f.now.Unix(), f.now.Unix(), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) request(method, path string, form url.Values, auth bool) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "https://panel.example.com"+path, body)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://panel.example.com")
	}
	if auth {
		req.AddCookie(f.cookie)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}
func input(t *testing.T, body, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("input %s missing: %.300s", name, body)
	}
	return html.UnescapeString(match[1])
}
func (f *fixture) loginForm(t *testing.T) (url.Values, *http.Cookie) {
	t.Helper()
	w := f.request("GET", "/login", nil, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	return url.Values{"csrf": {input(t, w.Body.String(), "csrf")}, "user": {"admin"}, "password": {"example-password"}, "totp": {totp(f.secret, f.now.Unix()/30, 6)}}, w.Result().Cookies()[0]
}
func (f *fixture) submitLogin(form url.Values, csrfCookie *http.Cookie, ip string, old *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://panel.example.com/login", strings.NewReader(form.Encode()))
	r.RemoteAddr = ip + ":1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://panel.example.com")
	r.AddCookie(csrfCookie)
	if old != nil {
		r.AddCookie(old)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}
func checkHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for key, value := range map[string]string{"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"} {
		if w.Header().Get(key) != value {
			t.Fatalf("%s=%q", key, w.Header().Get(key))
		}
	}
}
func TestRouteTableAuthAndHeaders(t *testing.T) {
	f := setup(t)
	for _, route := range routes {
		if route.public {
			continue
		}
		t.Run(route.pattern, func(t *testing.T) {
			method, path, _ := strings.Cut(route.pattern, " ")
			path = strings.NewReplacer("{$}", "", "{name}", "node", "{id}", "1").Replace(path)
			for _, fragment := range []bool{false, true} {
				endpoint := path
				if fragment {
					endpoint += "?fragment=1"
				}
				w := f.request(method, endpoint, url.Values{}, false)
				want := 401
				if route.page && !fragment {
					want = 303
				}
				if w.Code != want {
					t.Fatal(endpoint, w.Code, w.Body)
				}
				checkHeaders(t, w)
				if want == 303 && w.Header().Get("Location") != "/login" {
					t.Fatal("redirect")
				}
			}
		})
	}
	for _, path := range []string{"/login", "/static/panel.css", "/static/panel.js", "/missing", "/v1/report", "/healthz"} {
		w := f.request("GET", path, nil, false)
		checkHeaders(t, w)
	}
	for _, path := range []string{"/", "/nodes/node", "/enroll", "/?fragment=1", "/nodes/node?fragment=1", "/enroll?fragment=1"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body)
		}
		checkHeaders(t, w)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
	}
}
func TestLoginFailuresLimitsRotationAndReplay(t *testing.T) {
	f := setup(t)
	form, cookie := f.loginForm(t)
	goodCode := form.Get("totp")
	var body string
	for _, tc := range []struct{ user, password, code string }{{"admin", "wrong", goodCode}, {"admin", "example-password", "000000"}, {"absent", "example-password", goodCode}} {
		form.Set("user", tc.user)
		form.Set("password", tc.password)
		form.Set("totp", tc.code)
		w := f.submitLogin(form, cookie, "192.0.2.10", nil)
		if w.Code != 401 {
			t.Fatal(w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), loginError) {
			t.Fatal("generic error missing")
		}
		if body != "" && body != w.Body.String() {
			t.Fatal("failure responses differ")
		}
		body = w.Body.String()
		checkHeaders(t, w)
	}
	form.Set("user", "admin")
	form.Set("password", "example-password")
	form.Set("totp", goodCode)
	w := f.submitLogin(form, cookie, "192.0.2.11", f.cookie)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-wanglou_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Path != "/" || sessionCookie.Domain != "" || sessionCookie.Value == f.cookie.Value {
		t.Fatal("cookie attributes")
	}
	var rawCount, oldCount int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM sessions WHERE token_hash=?`, sessionCookie.Value).Scan(&rawCount); err != nil || rawCount != 0 {
		t.Fatal("raw token stored", err)
	}
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM sessions WHERE token_hash=?`, store.TokenHash(f.cookie.Value)).Scan(&oldCount); err != nil || oldCount != 0 {
		t.Fatal("old session survived", err)
	}
	w = f.submitLogin(form, cookie, "192.0.2.12", nil)
	if w.Code != 401 {
		t.Fatal("replayed TOTP accepted", w.Code)
	}
	f.cookie = sessionCookie
	if w = f.request("GET", "/", nil, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var last int64
	if err := f.s.DB.QueryRow(`SELECT totp_last_step FROM admins WHERE user='admin'`).Scan(&last); err != nil || last != f.now.Unix()/30 {
		t.Fatal(last, err)
	}
	form.Set("password", "wrong")
	for i := 0; i < 6; i++ {
		w = f.submitLogin(form, cookie, "192.0.2.20", nil)
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatal(i, w.Code)
		}
		if !strings.Contains(w.Body.String(), loginError) {
			t.Fatal("rate error differs")
		}
	}
}
func TestUserLock(t *testing.T) {
	f := setup(t)
	form, cookie := f.loginForm(t)
	form.Set("password", "wrong")
	for i := 0; i < 10; i++ {
		if w := f.submitLogin(form, cookie, fmt.Sprintf("192.0.2.%d", i+1), nil); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	form.Set("password", "example-password")
	if w := f.submitLogin(form, cookie, "192.0.2.100", nil); w.Code != 401 {
		t.Fatal("locked user logged in", w.Code)
	}
	f.now = f.now.Add(901 * time.Second)
	form.Set("totp", totp(f.secret, f.now.Unix()/30, 6))
	if w := f.submitLogin(form, cookie, "192.0.2.100", nil); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestCSRFAndOrigin(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct{ token, origin string }{{"", "https://panel.example.com"}, {"wrong", "https://panel.example.com"}, {f.csrf, ""}, {f.csrf, "https://other.example.com"}, {f.csrf, "null"}, {f.csrf, "https://panel.example.com.evil.invalid"}} {
		r := httptest.NewRequest("POST", "https://panel.example.com/logout", strings.NewReader(url.Values{"csrf": {tc.token}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", tc.origin)
		r.AddCookie(f.cookie)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(tc, w.Code)
		}
		checkHeaders(t, w)
	}
	for _, origin := range []string{"", "https://other.example.com"} {
		r := httptest.NewRequest("POST", "https://panel.example.com/login", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	form, cookie := f.loginForm(t)
	form.Set("csrf", "wrong")
	if w := f.submitLogin(form, cookie, "192.0.2.1", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestSessionExpiryAndAdminInvalidation(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct {
		name          string
		created, last int64
	}{{"idle", f.now.Unix(), f.now.Add(-12 * time.Hour).Unix()}, {"absolute", f.now.Add(-7 * 24 * time.Hour).Unix(), f.now.Unix()}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.s.DB.Exec(`UPDATE sessions SET created_at=?,last_seen=?`, tc.created, tc.last); err != nil {
				t.Fatal(err)
			}
			if w := f.request("GET", "/?fragment=1", nil, true); w.Code != 401 {
				t.Fatal(w.Code)
			}
		})
	}
	if _, err := f.s.DB.Exec(`UPDATE sessions SET created_at=?,last_seen=?`, f.now.Unix(), f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	if w := f.request("POST", "/logout", url.Values{"csrf": {f.csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := f.request("GET", "/?fragment=1", nil, true); w.Code != 401 {
		t.Fatal("logout session survived")
	}
	for _, action := range []string{"passwd", "reset-totp", "remove"} {
		if _, err := f.s.DB.Exec(`INSERT INTO sessions VALUES(?,?,?,?,?,?)`, store.TokenHash(f.cookie.Value), "admin", f.csrf, f.now.Unix(), f.now.Unix(), "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Admin(f.s, action, "admin", true, strings.NewReader("another-example-password\n"), &out); err != nil {
			t.Fatal(err)
		}
		if w := f.request("GET", "/?fragment=1", nil, true); w.Code != 401 {
			t.Fatal(action, "session survived")
		}
	}
	if err := Admin(f.s, "add", "other-admin", false, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Admin(f.s, "list", "", false, nil, &output); err != nil || !strings.Contains(output.String(), "other-admin") || strings.Contains(output.String(), "pbkdf2") || strings.Contains(output.String(), "otpauth") {
		t.Fatal(output.String(), err)
	}
}
func (f *fixture) report(t *testing.T, name string, report proto.Report, want int) {
	t.Helper()
	f.seq++
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://monitor.example.com/v1/report", bytes.NewReader(body))
	req.Header.Set(proto.NodeHeader, name)
	req.Header.Set(proto.SeqHeader, fmt.Sprint(f.seq))
	req.Header.Set(proto.TsHeader, fmt.Sprint(f.now.Unix()))
	req.Header.Set(proto.SigHeader, proto.Sign(f.key, name, f.seq, f.now.Unix(), body))
	w := httptest.NewRecorder()
	f.h.Ingest.ServeHTTP(w, req)
	if w.Code != want || w.Body.Len() != 0 {
		t.Fatal("report", w.Code, w.Body)
	}
}
func TestXSSActionsAndRevocation(t *testing.T) {
	f := setup(t)
	r := sampleReport()
	f.report(t, "node", r, 204)
	f.now = f.now.Add(5 * time.Second)
	names := []string{`<script>alert(1)</script>`, `"><img src=x onerror=1>`}
	r.Login = []proto.Login{{User: names[0], From: "203.0.113.7", Time: f.now.Unix()}, {User: names[1], From: "203.0.113.8", Time: f.now.Unix()}}
	f.report(t, "node", r, 204)
	for _, path := range []string{"/", "/nodes/node"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		for _, name := range names {
			if strings.Contains(w.Body.String(), name) || !strings.Contains(w.Body.String(), html.EscapeString(name)) {
				t.Fatal("unsafe or missing output", path, name, w.Body)
			}
		}
	}
	if w := f.request("POST", "/nodes/node/known-ip", url.Values{"csrf": {f.csrf}, "ip": {"203.0.113.7"}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	f.now = f.now.Add(5 * time.Second)
	r.Login = []proto.Login{{User: "root", From: "203.0.113.7", Time: f.now.Unix()}}
	f.report(t, "node", r, 204)
	var count int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='login_new_ip'`).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	for _, hours := range []string{"1", "8", "24", "0"} {
		if w := f.request("POST", "/nodes/node/mute", url.Values{"csrf": {f.csrf}, "hours": {hours}}, true); w.Code != 303 {
			t.Fatal(w.Code)
		}
		n, _ := f.s.Node("node")
		if hours == "0" && n.MutedUntil != 0 || hours != "0" && n.MutedUntil <= f.now.Unix() {
			t.Fatal("mute")
		}
	}
	if w := f.request("POST", "/nodes/node/note", url.Values{"csrf": {f.csrf}, "note": {strings.Repeat("字", 64)}}, true); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := f.request("POST", "/nodes/node/note", url.Values{"csrf": {f.csrf}, "note": {strings.Repeat("字", 65)}}, true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	var id int64
	if err := f.s.DB.QueryRow(`SELECT id FROM events WHERE kind='login_new_ip' LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if w := f.request("POST", fmt.Sprintf("/events/%d/ack", id), url.Values{"csrf": {f.csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM events WHERE acked_at>0`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if w := f.request("POST", "/nodes/node/revoke", url.Values{"csrf": {f.csrf}}, true); w.Code != 400 {
		t.Fatal("no confirmation", w.Code)
	}
	if w := f.request("POST", "/nodes/node/revoke", url.Values{"csrf": {f.csrf}, "confirm": {"yes"}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	f.report(t, "node", r, 401)
	if f.h.Ingest.Stats().Accepted != 3 {
		t.Fatal(f.h.Ingest.Stats())
	}
}
func TestPortIsolation(t *testing.T) {
	f := setup(t)
	for _, entry := range routes {
		if strings.Contains(entry.pattern, "/enroll") && entry.pattern == "GET /enroll" {
			continue
		}
		method, path, _ := strings.Cut(entry.pattern, " ")
		path = strings.NewReplacer("{$}", "", "{name}", "node", "{id}", "1").Replace(path)
		r := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		f.h.Ingest.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal(entry.pattern, w.Code)
		}
	}
	for _, tc := range []struct{ method, path string }{{"GET", "/healthz"}, {"POST", "/v1/report"}, {"POST", "/enroll"}} {
		w := f.request(tc.method, tc.path, nil, false)
		if w.Code != 404 {
			t.Fatal(tc, w.Code)
		}
	}
}

func sampleReport() proto.Report {
	return proto.Report{Version: 1, CPU: 12, Load: [3]float64{.3, .2, .1}, Mem: [2]float64{512, 1024}, Swap: [2]float64{0, 512}, Disk: [2]float64{20, 40}, Net: [2]float64{1024, 2048}, Conn: [2]uint64{4, 2}, Up: 86400, Bin: "sha256:" + strings.Repeat("a", 64), OS: "linux", Arch: "amd64"}
}

func TestDevelopmentCookieAndLoginAudit(t *testing.T) {
	f := setup(t)
	f.h.Config.CookieSecure = false
	form, cookie := f.loginForm(t)
	w := f.submitLogin(form, cookie, "192.0.2.10", nil)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	var issued *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "wanglou_session" {
			issued = c
		}
	}
	if issued == nil || issued.Secure || !issued.HttpOnly || issued.Path != "/" || issued.Domain != "" || issued.SameSite != http.SameSiteStrictMode {
		t.Fatal("development cookie")
	}
	f.cookie = issued
	var csrf string
	if err := f.s.DB.QueryRow(`SELECT csrf FROM sessions WHERE token_hash=?`, store.TokenHash(f.cookie.Value)).Scan(&csrf); err != nil {
		t.Fatal(err)
	}
	if w = f.request("POST", "/logout", url.Values{"csrf": {csrf}}, true); w.Code != 303 {
		t.Fatal(w.Code)
	}
	form.Set("password", "wrong")
	if w = f.submitLogin(form, cookie, "192.0.2.10", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, action := range []string{"login_success", "login_failure", "logout"} {
		var count int
		if err := f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action=? AND user='admin'`, action).Scan(&count); err != nil || count != 1 {
			t.Fatal(action, count, err)
		}
	}
}

func TestStaticFilesOnly(t *testing.T) {
	f := setup(t)
	for _, path := range []string{"/static", "/static/", "/static/panel.css/", "/static/missing"} {
		w := f.request("GET", path, nil, false)
		if w.Code != 404 {
			t.Fatal(path, w.Code, w.Body)
		}
		checkHeaders(t, w)
	}
	for _, name := range []string{"panel.css", "panel.js"} {
		w := f.request("GET", "/static/"+name, nil, false)
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatal(name, w.Code)
		}
		checkHeaders(t, w)
	}
}
