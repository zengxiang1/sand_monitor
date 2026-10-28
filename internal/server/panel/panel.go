package panel

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/eventtext"
	"wanglou/internal/server/ingest"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/requestip"
	"wanglou/internal/server/store"
)

//go:embed web/*.html web/static/*
var assets embed.FS

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
const loginError = "用户名、口令或验证码错误"
const loginLimitEntries = 4096

var passwordHashes = make(chan struct{}, 2)

type option struct{ Value, Label string }

type Config struct {
	BackupIngestURL                    string
	PeerStatus                         func(time.Time) string
	MemoryThreshold, DiskThreshold     float64
	Sustain                            time.Duration
	CookieSecure                       bool
	PublicIngestURL                    string
	TrustedProxies                     []netip.Prefix
	Interval                           time.Duration
	NotifyCooldown                     time.Duration
	Channels                           *alert.Channels
	PublicDir, PublicURL, HeartbeatURL string
	HeartbeatStatus                    func(time.Time) string
	Exporter                           *status.Exporter
}
type route struct {
	pattern      string
	page, public bool
	action       string
}

var routes = []route{
	{"GET /notify", true, false, "notify"}, {"POST /notify/telegram", false, false, "notify-set"}, {"POST /notify/telegram/disable", false, false, "notify-disable"}, {"POST /notify/telegram/test", false, false, "notify-test"},
	{"GET /billing", true, false, "billing"}, {"POST /billing/{name}", false, false, "billing"}, {"POST /billing/{name}/renewed", false, false, "billing"},
	{"GET /public", true, false, "public"}, {"POST /public", false, false, "public"}, {"POST /public/token", false, false, "public-token"}, {"POST /public/announcements", false, false, "announcement"}, {"POST /public/announcements/{id}/delete", false, false, "announcement-delete"}, {"GET /public/preview", true, false, "public-preview"},
	{"GET /login", true, true, "login"}, {"POST /login", false, true, "login"}, {"GET /static/", false, true, "static"},
	{"GET /{$}", true, false, "overview"}, {"GET /nodes/{name}", true, false, "node"}, {"GET /enroll", true, false, "enroll"},
	{"POST /logout", false, false, "logout"}, {"POST /events/{id}/ack", false, false, "ack"},
	{"POST /nodes/{name}/mute", false, false, "mute"}, {"POST /nodes/{name}/revoke", false, false, "revoke"},
	{"POST /nodes/{name}/display-name", false, false, "node_display_name"},
	{"POST /nodes/{name}/note", false, false, "note"}, {"POST /nodes/{name}/known-ip", false, false, "known-ip"},
	{"POST /enroll/preview", false, false, "preview"}, {"POST /enroll/codes", false, false, "codes"}, {"POST /enroll/confirm", false, false, "confirm"},
}

type failures struct {
	count         int
	since, locked int64
}
type session struct{ User, CSRF, Hash string }
type Handler struct {
	Store          *store.Store
	Ingest         *ingest.Handler
	Config         Config
	Now            func() time.Time
	Logf           func(string, ...any)
	mux            *http.ServeMux
	templates      *template.Template
	signingKey     string
	dummy          string
	mu             sync.Mutex
	ips, users     map[string]failures
	notifyMu       sync.Mutex
	notifyFailures map[string]failures
	notifyTestAt   time.Time
	publicMu       sync.Mutex
	publicRaw      string
	publicHTML     []byte
	publicExpires  time.Time
}

func New(s *store.Store, ing *ingest.Handler, c Config) *Handler {
	if c.MemoryThreshold == 0 {
		c.MemoryThreshold = 90
	}
	if c.DiskThreshold == 0 {
		c.DiskThreshold = 90
	}
	if c.Sustain == 0 {
		c.Sustain = 5 * time.Minute
	}
	if c.Interval == 0 {
		c.Interval = 5 * time.Second
	}
	dummy, err := HashPassword(randomToken(24))
	if err != nil {
		panic(err)
	}
	h := &Handler{Store: s, Ingest: ing, Config: c, Now: time.Now, Logf: log.Printf, dummy: dummy, signingKey: randomToken(32), notifyFailures: map[string]failures{}, ips: map[string]failures{}, users: map[string]failures{}, mux: http.NewServeMux()}
	h.templates = template.Must(template.New("panel").Funcs(template.FuncMap{"time": formatTime, "has": func(f url.Values, k, v string) bool { return slices.Contains(f[k], v) }, "seq": func(n int) []int {
		a := make([]int, n)
		for i := range a {
			a[i] = i + 1
		}
		return a
	}, "str": strconv.Itoa, "cycle": func(s string) string { return cycleLabels[s] }, "annStatus": status.AnnouncementStatus, "lower": strings.ToLower, "listCycles": func() []string { return []string{"month", "quarter", "half", "year", "once"} }, "listCurrencies": func() []string { return []string{"CNY", "USD", "EUR"} }, "listDays": func() []string { return []string{"30", "14", "7", "3", "1"} }, "listPct": func() []string { return []string{"50", "80", "90", "95", "100"} }, "currency": store.CurrencySymbol, "directions": func() []option {
		return []option{{"both", "上行 + 下行合计"}, {"out", "只算上行（出站）"}, {"in", "只算下行（入站）"}, {"max", "取两者中较大的"}}
	}, "publicIntervals": func() []option {
		return []option{{"30", "每 30 秒"}, {"60", "每 1 分钟"}, {"300", "每 5 分钟"}}
	}, "annStatuses": func() []option {
		return []option{{"investigating", "排查中"}, {"monitoring", "已修复，观察中"}, {"resolved", "已恢复"}, {"scheduled", "计划维护"}, {"done", "维护完成"}}
	}, "relative": func(ts int64) string { return relative(ts, h.Now()) }, "percent": percent, "number": formatNumber, "rate": formatRate, "memory": formatMemory, "uptime": formatUptime, "kind": eventtext.Kind, "describeEvent": h.describeEvent, "clock": func(ts int64) string { return time.Unix(ts, 0).Format("15:04") }}).ParseFS(assets, "web/*.html"))
	static, _ := fs.Sub(assets, "web/static")
	for _, entry := range routes {
		h.mux.HandleFunc(entry.pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				origin, err := url.Parse(r.Header.Get("Origin"))
				if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.Host != r.Host || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
					http.Error(w, "Forbidden", 403)
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 16384)
				if r.ParseForm() != nil {
					http.Error(w, "Bad request", 400)
					return
				}
			}
			var sess session
			if !entry.public {
				var err error
				sess, err = h.authenticate(r)
				publicHome := entry.action == "overview" && (r.Method == "GET" || r.Method == "HEAD") && r.URL.Query().Get("fragment") != "1"
				if publicHome {
					w.Header().Set("Cache-Control", "no-store")
				}
				if errors.Is(err, sql.ErrNoRows) && publicHome {
					var html []byte
					html, err = h.publicHome()
					if err == nil {
						if html != nil {
							w.Header().Set("Content-Type", "text/html; charset=utf-8")
							_, _ = w.Write(html)
							return
						}
						err = sql.ErrNoRows
					}
				}
				if errors.Is(err, sql.ErrNoRows) {
					if entry.page && r.URL.Query().Get("fragment") != "1" {
						http.Redirect(w, r, "/login", http.StatusSeeOther)
					} else {
						http.Error(w, "Unauthorized", 401)
					}
					return
				}
				if err != nil {
					if publicHome {
						h.Logf("panel: %v", err)
						http.Error(w, "服务暂时不可用", 500)
					} else {
						h.serverError(w, err)
					}
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				if r.Method == "POST" && subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(sess.CSRF)) != 1 {
					http.Error(w, "Forbidden", 403)
					return
				}
			}
			switch entry.action {
			case "static":
				name := strings.TrimPrefix(r.URL.Path, "/static/")
				if name == "status.css" {
					w.Header().Set("Content-Type", "text/css; charset=utf-8")
					_, _ = w.Write(status.CSS())
					return
				}
				info, err := fs.Stat(static, name)
				if err != nil || info.IsDir() {
					http.NotFound(w, r)
					return
				}
				http.StripPrefix("/static/", http.FileServer(http.FS(static))).ServeHTTP(w, r)
			case "login":
				h.login(w, r)
			case "logout":
				h.logout(w, r, sess)
			case "notify", "notify-set", "notify-disable", "notify-test":
				h.notify(w, r, sess, entry.action)
			case "billing":
				h.billing(w, r, sess)
			case "public", "public-token", "announcement", "announcement-delete", "public-preview":
				h.public(w, r, sess, entry.action)
			case "overview":
				h.overview(w, r, sess)
			case "node":
				h.node(w, r, sess)
			case "enroll", "preview", "codes", "confirm":
				h.enroll(w, r, sess, entry.action)
			default:
				h.mutate(w, r, sess, entry.action)
			}
		})
	}
	return h
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", CSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	if _, pattern := h.mux.Handler(r); pattern == "" || r.URL.Path == "/static" {
		http.NotFound(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}
func (h *Handler) cookieName() string {
	if h.Config.CookieSecure {
		return "__Host-wanglou_session"
	}
	return "wanglou_session"
}
func (h *Handler) cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: h.Config.CookieSecure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (h *Handler) authenticate(r *http.Request) (session, error) {
	cookie, err := r.Cookie(h.cookieName())
	if err != nil {
		return session{}, sql.ErrNoRows
	}
	sess := session{Hash: store.TokenHash(cookie.Value)}
	now := h.Now().Unix()
	err = h.Store.DB.QueryRow(`SELECT user,csrf FROM sessions WHERE token_hash=? AND last_seen>? AND created_at>?`, sess.Hash, now-43200, now-604800).Scan(&sess.User, &sess.CSRF)
	if err == nil {
		_, err = h.Store.DB.Exec(`UPDATE sessions SET last_seen=? WHERE token_hash=?`, now, sess.Hash)
	}
	return sess, err
}
func (h *Handler) serverError(w http.ResponseWriter, err error) {
	h.Logf("panel: %v", err)
	http.Error(w, "服务暂时不可用", 503)
}
func (h *Handler) audit(user, ip, action, detail string) error {
	_, err := h.Store.DB.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, h.Now().Unix(), user, ip, action, detail)
	return err
}
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data page, status int) {
	if name == "login" && status != http.StatusTooManyRequests {
		_, c, err := h.publishedPublic()
		if err != nil {
			h.Logf("panel: %v", err)
			http.Error(w, "服务暂时不可用", 500)
			return
		}
		data.PublicHome = c.Access == "public"
	}
	if data.User != "" {
		nodes, err := h.Store.Nodes()
		if err != nil {
			h.serverError(w, err)
			return
		}
		last := ""
		if cookie, err := r.Cookie("wanglou_last_node"); err == nil {
			last = cookie.Value
		}
		if name == "node" && data.Node.RevokedAt == 0 {
			last = data.Node.Name
		}
		data.NodeLink = ""
		for _, node := range nodes {
			if node.RevokedAt != 0 {
				continue
			}
			if data.NodeLink == "" || node.Name == last {
				data.NodeLink = "/nodes/" + node.Name
			}
			if node.Name == last {
				break
			}
		}
	}
	userRunes := []rune(data.User)
	data.UserInitials = string(userRunes[:min(2, len(userRunes))])
	data.Page = name
	data.Refresh = data.User != "" && (name == "overview" || name == "node" || name == "enroll" && data.Code != "" && data.Pubkey == "")
	var output bytes.Buffer
	target := "layout"
	if r.URL.Query().Get("fragment") == "1" {
		target = "content"
	}
	if err := h.templates.ExecuteTemplate(&output, target, data); err != nil {
		h.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := ""
	if c, err := r.Cookie("wanglou_login_csrf"); err == nil {
		token = c.Value
	}
	if r.Method == "GET" {
		token = randomToken(32)
		h.cookie(w, "wanglou_login_csrf", token, 900)
		h.render(w, r, "login", page{CSRF: token}, 200)
		return
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(r.PostForm.Get("csrf"))) != 1 {
		http.Error(w, "Forbidden", 403)
		return
	}
	user := r.PostForm.Get("user")
	validUser := proto.ValidNode(user)
	if !validUser {
		user = ""
	}
	ip := requestip.ClientIP(r, h.Config.TrustedProxies)
	now := h.Now().Unix()
	h.mu.Lock()
	for _, entries := range []map[string]failures{h.ips, h.users} {
		for key, value := range entries {
			if value.since+900 <= now && value.locked <= now {
				delete(entries, key)
			}
		}
	}

	ipLimit, ipExists := h.ips[ip]
	userLimit, userExists := h.users[user]
	limited := ipLimit.count >= 5 || !ipExists && len(h.ips) >= loginLimitEntries || validUser && !userExists && len(h.users) >= loginLimitEntries
	locked := userLimit.locked > now
	if !limited {
		if !ipExists {
			h.ips[ip] = failures{since: now}
		}
		if validUser && !userExists {
			h.users[user] = failures{since: now}
		}
	}
	h.mu.Unlock()
	if limited {
		h.Logf("panel login limited user=%q ip=%q", user, ip)
		h.render(w, r, "login", page{CSRF: token, Error: loginError}, 429)
		return
	}
	hash := h.dummy
	var secret string
	var last int64
	exists := false
	if validUser {
		err := h.Store.DB.QueryRow(`SELECT pw_hash,totp_secret,totp_last_step FROM admins WHERE user=?`, user).Scan(&hash, &secret, &last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			h.serverError(w, err)
			return
		}
		exists = err == nil
	}
	select {
	case passwordHashes <- struct{}{}:
	case <-r.Context().Done():
		http.Error(w, "Request timeout", 408)
		return
	}
	if r.Context().Err() != nil {
		<-passwordHashes
		http.Error(w, "Request timeout", 408)
		return
	}
	passwordOK := CheckPassword(hash, r.PostForm.Get("password"))
	<-passwordHashes
	step, codeOK := totpStep(secret, r.PostForm.Get("totp"), now, last)
	if exists && passwordOK && codeOK && !locked {
		value := randomToken(32)
		csrf := randomToken(32)
		err := h.Store.Transaction(func(tx *sql.Tx) error {
			result, err := tx.Exec(`UPDATE admins SET totp_last_step=?,last_login=? WHERE user=? AND totp_last_step<? AND pw_hash=? AND totp_secret=?`, step, now, user, step, hash, secret)
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if count != 1 {
				return sql.ErrNoRows
			}
			if old, e := r.Cookie(h.cookieName()); e == nil {
				if _, err = tx.Exec(`DELETE FROM sessions WHERE token_hash=?`, store.TokenHash(old.Value)); err != nil {
					return err
				}
			}
			if _, err = tx.Exec(`INSERT INTO sessions VALUES(?,?,?,?,?,?)`, store.TokenHash(value), user, csrf, now, now, ip); err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now, user, ip, "login_success", "")
			return err
		})
		if err == nil {
			h.cookie(w, h.cookieName(), value, 604800)
			h.cookie(w, "wanglou_login_csrf", "", -1)
			http.Redirect(w, r, "/", 303)
			return
		}
		if !errors.Is(err, sql.ErrNoRows) {
			h.serverError(w, err)
			return
		}
	}
	h.mu.Lock()
	for _, item := range []struct {
		entries map[string]failures
		key     string
		limit   int
	}{{h.ips, ip, 5}, {h.users, user, 10}} {
		if item.limit == 10 && !validUser {
			continue
		}
		value, ok := item.entries[item.key]
		if !ok {
			continue
		}
		if value.since+900 <= now && value.locked <= now {
			value = failures{since: now}
		}
		value.count++
		if item.limit == 10 && value.count >= 10 && value.locked <= now {
			value.locked = now + 900
		}
		item.entries[item.key] = value
	}
	h.mu.Unlock()
	h.Logf("panel login failed user=%q ip=%q", user, ip)
	if err := h.audit(user, ip, "login_failure", ""); err != nil {
		h.serverError(w, err)
		return
	}
	h.render(w, r, "login", page{CSRF: token, Error: loginError}, 401)
}
func (h *Handler) logout(w http.ResponseWriter, r *http.Request, sess session) {
	if _, err := h.Store.DB.Exec(`DELETE FROM sessions WHERE token_hash=?`, sess.Hash); err != nil {
		h.serverError(w, err)
		return
	}
	if err := h.audit(sess.User, requestip.ClientIP(r, h.Config.TrustedProxies), "logout", ""); err != nil {
		h.serverError(w, err)
		return
	}
	h.cookie(w, h.cookieName(), "", -1)
	http.Redirect(w, r, "/login", 303)
}

func safeNote(value string) bool {
	return len([]rune(value)) <= 64 && !strings.ContainsAny(value, "\x00\r\n")
}
