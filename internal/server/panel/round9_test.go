package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"wanglou/internal/server/store"
)

func TestDisplayNameValidationAndPages(t *testing.T) {
	f := setup(t)
	for _, value := range []string{strings.Repeat("中", 33), "bad\x00", "bad\n", "bad\t", "bad\u007f", string([]byte{255})} {
		w := f.request("POST", "/nodes/node/display-name", url.Values{"csrf": {f.csrf}, "display_name": {value}}, true)
		if w.Code != 400 {
			t.Fatalf("%q: %d", value, w.Code)
		}
	}
	for _, value := range []string{strings.Repeat("中", 32), "", "  东京 <一号>  "} {
		w := f.request("POST", "/nodes/node/display-name", url.Values{"csrf": {f.csrf}, "display_name": {value}}, true)
		if w.Code != 303 {
			t.Fatal(w.Code, w.Body)
		}
		n, err := f.s.Node("node")
		if err != nil || n.DisplayName != strings.TrimSpace(value) || n.Name != "node" {
			t.Fatal(n, err)
		}
	}
	b := store.DefaultBilling("node")
	b.Expiry = f.now.AddDate(0, 0, 1).Format("2006-01-02")
	b.QuotaGB = 1
	used := uint64(900000000)
	if err := f.s.SaveBilling(b, &used, f.now, "admin", ""); err != nil {
		t.Fatal(err)
	}
	var audits int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='node_display_name' AND detail LIKE 'node%'`).Scan(&audits); err != nil || audits != 3 {
		t.Fatal(audits, err)
	}
	if _, err := f.s.DB.Exec(`INSERT INTO events(ts,node,kind,detail,suppressed,notified) VALUES(?,'node','offline','recorded',1,1)`, f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/nodes/node", "/billing", "/billing?edit=node"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "东京 &lt;一号&gt;") || !strings.Contains(w.Body.String(), `class="node-identity">· node`) {
			t.Fatal(path, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "<一号>") || strings.Contains(w.Body.String(), `style=`) || strings.Contains(w.Body.String(), `<script>`) {
			t.Fatal("unsafe output", path)
		}
	}
	if w := f.request("GET", "/", nil, true); !strings.Contains(w.Body.String(), "已合并，未推送") || !strings.Contains(w.Body.String(), `class="node-name row-link"`) {
		t.Fatal(w.Body)
	}
	css, err := assets.ReadFile("web/static/panel.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{".node-row{position:relative}", ".row-link::after", "position:absolute;inset:0", ".node-row:hover", "max-height:360px;overflow-y:auto"} {
		if !strings.Contains(string(css), rule) {
			t.Fatal("missing CSS", rule)
		}
	}
}

func TestNodeSwitcherAndLastNode(t *testing.T) {
	f := setup(t)
	n, err := f.s.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		if err := f.s.AddNode(fmt.Sprintf("server-%02d", i), n.Pubkey, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.Revoke("server-24", f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DB.Exec(`UPDATE nodes SET display_name='最后一台',last_seen=? WHERE name='server-23'`, f.now.Unix()); err != nil {
		t.Fatal(err)
	}
	w := f.request("GET", "/nodes/server-23", nil, true)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `href="/nodes/server-23" aria-current="page"`) || !strings.Contains(body, "最后一台") || !strings.Contains(body, "正常") {
		t.Fatal(w.Code, body)
	}
	start := strings.Index(body, `aria-label="节点切换"`)
	end := strings.Index(body[start:], "</nav>") + start
	menu := body[start:end]
	if strings.Contains(menu, "server-24") || strings.Count(menu, "<a ") != 25 || strings.Index(menu, "server-01") > strings.Index(menu, "server-23") {
		t.Fatal(menu)
	}
	var last *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "wanglou_last_node" {
			last = cookie
		}
	}
	if last == nil || last.Value != "server-23" || !last.Secure || !last.HttpOnly || last.SameSite != http.SameSiteStrictMode || last.Path != "/" || last.Domain != "" {
		t.Fatal(last)
	}
	for _, value := range []string{"server-23", "server-24", "missing", "../../etc"} {
		for _, path := range []string{"/", "/billing", "/notify", "/enroll", "/public"} {
			req := httptest.NewRequest("GET", "https://panel.example.com"+path, nil)
			req.AddCookie(f.cookie)
			req.AddCookie(&http.Cookie{Name: "wanglou_last_node", Value: value})
			out := httptest.NewRecorder()
			f.h.ServeHTTP(out, req)
			want := "node"
			if value == "server-23" {
				want = value
			}
			if out.Code != 200 || !strings.Contains(out.Body.String(), `href="/nodes/`+want+`" >节点详情</a>`) {
				t.Fatal(value, path, out.Code, out.Body)
			}
		}
	}
	if err := f.s.Revoke("node", f.now); err != nil {
		t.Fatal(err)
	}
	if w := f.request("GET", "/", nil, true); !strings.Contains(w.Body.String(), `href="/nodes/server-00" >节点详情</a>`) {
		t.Fatal(w.Body)
	}
	f.h.Config.CookieSecure = false
	if w := f.request("GET", "/nodes/server-00", nil, true); w.Code != 303 {
		t.Fatal("old auth cookie should fail", w.Code)
	}
	f.cookie.Name = f.h.cookieName()
	w = f.request("GET", "/nodes/server-00", nil, true)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "wanglou_last_node" && cookie.Secure {
			t.Fatal(cookie)
		}
	}
}
