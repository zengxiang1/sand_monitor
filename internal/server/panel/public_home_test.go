package panel

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func TestPublicHomeConditionsAndLoginLink(t *testing.T) {
	f := setup(t)
	c := status.DefaultConfig()
	c.Title, c.Interval = "已发布的状态", 60
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = status.Save(f.s, c, false, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, raw string
		public    bool
	}{
		{"unpublished", "", false},
		{"malformed", "{", false},
		{"null", "null", false},
		{"empty", "{}", false},
		{"public", string(raw), true},
		{"token", strings.Replace(string(raw), `"Access":"public"`, `"Access":"token"`, 1), false},
		{"invalid title", strings.Replace(string(raw), c.Title, "", 1), false},
		{"invalid interval", strings.Replace(string(raw), `"Interval":60`, `"Interval":1`, 1), false},
		{"invalid access", strings.Replace(string(raw), `"Access":"public"`, `"Access":"other"`, 1), false},
		{"invalid token", strings.Replace(string(raw), c.Token, "bad", 1), false},
		{"public again", string(raw), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.s.SetKV("public.published", tc.raw); err != nil {
				t.Fatal(err)
			}
			w := f.request("GET", "/", nil, false)
			checkHeaders(t, w)
			if tc.public {
				if w.Code != 200 || !strings.Contains(w.Body.String(), c.Title) || !strings.Contains(w.Body.String(), `href="/login">登录</a>`) || !strings.Contains(w.Body.String(), `http-equiv="refresh" content="60"`) {
					t.Fatal(w.Code, w.Body)
				}
				if w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Header())
				}
			} else if w.Code != 303 || w.Header().Get("Location") != "/login" {
				t.Fatal(w.Code, w.Header(), w.Body)
			}
			if head := f.request("HEAD", "/", nil, false); (head.Code == 200) != tc.public {
				t.Fatal("HEAD", head.Code)
			}
			w = f.request("GET", "/login", nil, false)
			if w.Code != 200 || strings.Contains(w.Body.String(), `href="/">查看状态页</a>`) != tc.public {
				t.Fatal(w.Code, w.Body)
			}
			checkHeaders(t, w)
		})
	}
	form, cookie := f.loginForm(t)
	form.Set("password", "wrong")
	w := f.submitLogin(form, cookie, "192.0.2.10", nil)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `href="/">查看状态页</a>`) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestPublicHomeKeepsRouteAuthentication(t *testing.T) {
	f := setup(t)
	if err := status.Save(f.s, status.DefaultConfig(), true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	for _, entry := range routes {
		if entry.public {
			continue
		}
		method, path, _ := strings.Cut(entry.pattern, " ")
		path = strings.NewReplacer("{$}", "", "{name}", "node", "{id}", "1").Replace(path)
		for _, fragment := range []bool{false, true} {
			endpoint := path
			if fragment {
				endpoint += "?fragment=1"
			}
			want := 401
			if entry.page && !fragment {
				want = 303
				if path == "/" {
					want = 200
				}
			}
			w := f.request(method, endpoint, url.Values{}, false)
			if w.Code != want || want == 303 && w.Header().Get("Location") != "/login" {
				t.Fatal(method, endpoint, w.Code, w.Body)
			}
			checkHeaders(t, w)
		}
	}
	w := f.request("GET", "/", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "总览") || !strings.Contains(w.Body.String(), `action="/logout"`) || strings.Contains(w.Body.String(), `href="/login"`) {
		t.Fatal(w.Code, w.Body)
	}
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"HEAD", "/", 200}, {"POST", "/", 404}, {"GET", "/index.html", 404}, {"GET", "/status.json", 404}} {
		w = f.request(tc.method, tc.path, nil, false)
		if w.Code != tc.want {
			t.Fatal(tc, w.Code)
		}
	}
}

func TestPublicHomeWhitelistExportAndPreview(t *testing.T) {
	f := setup(t)
	f.report(t, "node", sampleReport(), 204)
	if _, err := f.s.DB.Exec(`UPDATE nodes SET display_name='private_display_name_75',last_ip='192.0.2.78',note='private_note_71',fingerprint='private_fingerprint_72';INSERT INTO logins VALUES('node',?,'private_user_73','192.0.2.77',1)`, f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	b := store.DefaultBilling("node")
	b.Provider, b.Price, b.Expiry = "private_provider_74", "65432.10", "2037-12-23"
	if err := f.s.SaveBilling(b, nil, f.now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	c := status.DefaultConfig()
	c.Title = "已发布标题"
	c.Nodes = []status.Selection{{Node: "node", Public: true, Name: "公开显示名"}}
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	d, err := status.Build(f.s, c, f.now)
	if err != nil {
		t.Fatal(err)
	}
	want, err := status.Render(d, status.RenderOptions{Login: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Title, c.Nodes[0].Name = "未发布草稿标题", "未发布草稿名称"
	if err = status.Save(f.s, c, false, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	w := f.request("GET", "/", nil, false)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatal(w.Code, w.Body)
	}
	for _, marker := range []string{"private_display_name_75", "192.0.2.78", "192.0.2.77", "private_note_71", "private_fingerprint_72", "private_user_73", "private_provider_74", "65432.10", "2037-12-23", "未发布草稿标题", "未发布草稿名称", `<script`, `<style`, `style=`, `href="/nodes/`, `src=`} {
		if strings.Contains(w.Body.String(), marker) {
			t.Error("leaked or unsafe HTML", marker)
		}
	}
	if !strings.Contains(w.Body.String(), `href="/static/status.css"`) {
		t.Fatal(w.Body)
	}
	css := f.request("GET", "/static/status.css", nil, false)
	if css.Code != 200 || !bytes.Equal(css.Body.Bytes(), status.CSS()) || !strings.Contains(css.Body.String(), ".login-link{") {
		t.Fatal(css.Code, css.Body)
	}
	dir := t.TempDir()
	e := status.Exporter{Store: f.s, Dir: dir}
	if err = e.Export(f.now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{`href="/login"`, `href="/static/`, "panel.example.com", "未发布草稿标题"} {
		if strings.Contains(string(raw), marker) {
			t.Error("panel or draft data in export", marker)
		}
	}
	w = f.request("GET", "/public/preview", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "预览 · 未发布") || !strings.Contains(w.Body.String(), "未发布草稿标题") || strings.Contains(w.Body.String(), `href="/login"`) || strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestPublicHomeCache(t *testing.T) {
	f := setup(t)
	c := status.DefaultConfig()
	c.Nodes = []status.Selection{{Node: "node", Public: true, Name: "公开节点"}}
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for _, advance := range []time.Duration{0, time.Second} {
		f.now = f.now.Add(advance)
		var wg sync.WaitGroup
		start := make(chan struct{})
		html := make([][]byte, 20)
		for i := range html {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				var err error
				html[i], err = f.h.publicHome()
				if err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
		for _, data := range html {
			if len(data) == 0 || &data[0] != &html[0][0] {
				t.Fatal("concurrent requests rendered more than once")
			}
		}
		if previous != nil && &previous[0] == &html[0][0] {
			t.Fatal("expired cache reused")
		}
		want := "正常 0　离线 1"
		if advance != 0 {
			want = "正常 1　离线 0"
		}
		if !strings.Contains(string(html[0]), want) {
			t.Fatal("expired cache did not rebuild node status", string(html[0]))
		}
		previous = html[0]
		if _, err := f.s.DB.Exec(`ALTER TABLE metrics RENAME TO hidden_metrics`); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(29 * time.Second)
		if _, err := f.s.DB.Exec(`UPDATE nodes SET last_seen=?`, f.now.Unix()); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			w := f.request("GET", "/", nil, false)
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), previous) {
				t.Fatal("cache hit queried metrics or rebuilt", w.Code, w.Body)
			}
		}
		if _, err := f.s.DB.Exec(`ALTER TABLE hidden_metrics RENAME TO metrics`); err != nil {
			t.Fatal(err)
		}
	}
	c.Title, c.Interval = "重新发布的标题", 60
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	w := f.request("GET", "/", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), c.Title) || !strings.Contains(w.Body.String(), `http-equiv="refresh" content="60"`) || &previous[0] == &f.h.publicHTML[0] {
		t.Fatal("republish did not invalidate cache", w.Code, w.Body)
	}
	previous = f.h.publicHTML
	raw, err := f.s.KV("public.published")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.SetKV("public.published", raw+" "); err != nil {
		t.Fatal(err)
	}
	if w = f.request("GET", "/", nil, false); w.Code != 200 || &previous[0] == &f.h.publicHTML[0] {
		t.Fatal("cache key is not the raw config", w.Code)
	}
	previous = f.h.publicHTML
	f.now = f.now.Add(59 * time.Second)
	if w = f.request("GET", "/", nil, false); w.Code != 200 || &previous[0] != &f.h.publicHTML[0] {
		t.Fatal("updated interval was not used", w.Code)
	}
	f.now = f.now.Add(time.Second)
	if w = f.request("GET", "/", nil, false); w.Code != 200 || &previous[0] == &f.h.publicHTML[0] {
		t.Fatal("updated interval did not expire", w.Code)
	}
	form := publicForm(f)
	form.Set("publish", "1")
	form.Set("title", "通过面板重新发布")
	if w = f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	if w = f.request("GET", "/", nil, false); w.Code != 200 || !strings.Contains(w.Body.String(), "通过面板重新发布") {
		t.Fatal("panel publish did not invalidate cache", w.Code, w.Body)
	}
}

func TestPublicHomeSessionsAndDatabaseErrors(t *testing.T) {
	f := setup(t)
	if err := status.Save(f.s, status.DefaultConfig(), true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		age, idle time.Duration
	}{
		{"idle expired", 0, 12 * time.Hour},
		{"age expired", 7 * 24 * time.Hour, 0},
	} {
		if _, err := f.s.DB.Exec(`UPDATE sessions SET created_at=?,last_seen=?`, f.now.Add(-tc.age).Unix(), f.now.Add(-tc.idle).Unix()); err != nil {
			t.Fatal(err)
		}
		w := f.request("GET", "/", nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `href="/login">登录</a>`) {
			t.Fatal(tc.name, w.Code, w.Body)
		}
	}
	f.cookie.Value = "invalid-session"
	if w := f.request("GET", "/", nil, true); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/login">登录</a>`) {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := f.s.DB.Exec(`ALTER TABLE nodes RENAME TO hidden_nodes`); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(30 * time.Second)
	if w := f.request("GET", "/", nil, false); w.Code != 500 {
		t.Fatal("build error", w.Code, w.Body)
	}
	if _, err := f.s.DB.Exec(`ALTER TABLE hidden_nodes RENAME TO nodes`); err != nil {
		t.Fatal(err)
	}
	if w := f.request("GET", "/", nil, false); w.Code != 200 {
		t.Fatal("build error was cached", w.Code, w.Body)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/login"} {
		for _, auth := range []bool{false, true} {
			w := f.request("GET", path, nil, auth)
			if w.Code != 500 {
				t.Fatal(path, auth, w.Code, w.Body)
			}
			checkHeaders(t, w)
		}
	}
}
