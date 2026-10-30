package panel

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestPanelShellAndRefreshFragments(t *testing.T) {
	f := setup(t)
	_, enroll := f.pendingCode(t, "new-node")
	for _, path := range []string{"/", "/nodes/node", "/billing", "/notify", "/public", enroll} {
		w := f.request("GET", path, nil, true)
		body := w.Body.String()
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") != CSP {
			t.Fatal(path, w.Code, w.Header())
		}
		main := regexp.MustCompile(`(?s)<main id="panel-content"[^>]*>(.*?)</main>`).FindStringSubmatch(body)
		if len(main) != 2 {
			t.Fatal(path, "missing refresh container")
		}
		for _, marker := range []string{`class="sidebar"`, `class="topbar"`, `aria-label="面包屑"`, `action="/logout"`, `class="avatar" aria-hidden="true">ad`, "已通过 TOTP"} {
			if !strings.Contains(body, marker) || strings.Contains(main[1], marker) {
				t.Error(path, "shell must stay outside refreshed content", marker)
			}
		}
		navigation := regexp.MustCompile(`(?s)<nav class="sidebar-nav".*?</nav>`).FindString(body)
		if strings.Count(navigation, `aria-current="page"`) != 1 || strings.Count(navigation, `<a `) != 7 || !strings.Contains(navigation, ">监控</p>") || !strings.Contains(navigation, ">设置</p>") {
			t.Error(path, "incorrect active or grouped navigation", navigation)
		}
		for _, tag := range regexp.MustCompile(`<svg\b[^>]*>`).FindAllString(navigation, -1) {
			if !strings.Contains(tag, `aria-hidden="true"`) {
				t.Error(path, "navigation icon lacks aria-hidden", tag)
			}
		}
		fragmentPath := path + "?fragment=1"
		if strings.Contains(path, "?") {
			fragmentPath = path + "&fragment=1"
		}
		fragment := f.request("GET", fragmentPath, nil, true)
		fragmentHTML := fragment.Body.String()
		if path == enroll {
			fullToken, fragmentToken := input(t, main[1], "state"), input(t, fragmentHTML, "state")
			fullState, err := readEnrollment(fullToken, f.csrf, f.h.signingKey, f.now)
			if err != nil {
				t.Fatal(err)
			}
			fragmentState, err := readEnrollment(fragmentToken, f.csrf, f.h.signingKey, f.now)
			if err != nil || fullState != fragmentState {
				t.Fatal("enrollment state changed", err)
			}
			fragmentHTML = strings.ReplaceAll(fragmentHTML, fragmentToken, fullToken)
		}
		if fragment.Code != 200 || fragmentHTML != main[1] {
			t.Fatal(path, "fragment differs from the refresh container", fragment.Code)
		}
		refreshing := path == "/" || path == "/nodes/node" || path == enroll
		if strings.Contains(main[0], `data-refresh="true"`) != refreshing || strings.Contains(fragment.Body.String(), `data-panel-refresh="true"`) != refreshing {
			t.Error(path, "refresh contract changed")
		}
	}
}

func TestPanelNotificationFormsAndCooldown(t *testing.T) {
	f := setupNotify(t, nil)
	for _, duration := range []time.Duration{0, 30 * time.Minute, 30 * time.Second} {
		f.h.Config.NotifyCooldown = duration
		want := "已关闭"
		if duration == 30*time.Minute {
			want = "30 分钟"
		}
		if duration == 30*time.Second {
			want = "0.5 分钟"
		}
		for _, path := range []string{"/", "/notify"} {
			w := f.request("GET", path, nil, true)
			if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
				t.Fatal(path, duration, w.Code, w.Body)
			}
		}
	}
	body := f.request("GET", "/notify", nil, true).Body.String()
	form := regexp.MustCompile(`(?s)<form id="telegram-config".*?</form>`).FindString(body)
	if !strings.Contains(form, `action="/notify/telegram"`) || input(t, form, "csrf") != f.csrf || input(t, form, "token") != "" || !strings.Contains(body, `<button class="primary" form="telegram-config">保存</button>`) {
		t.Fatal("save button lost its independent CSRF-protected form", body)
	}
	for _, name := range []string{"token", "chat_id", "totp"} {
		if !strings.Contains(form, `name="`+name+`"`) {
			t.Error("missing field", name)
		}
	}
	if strings.Contains(body, `action="/notify/telegram/disable"`) || strings.Contains(body, `action="/notify/telegram/test"`) {
		t.Fatal("unconfigured channel exposes enabled-only actions")
	}
}

func TestOverviewKnownIPActionAndNodeSections(t *testing.T) {
	f := setup(t)
	report := sampleReport()
	f.report(t, "node", report, 204)
	f.now = f.now.Add(5 * time.Second)
	report.Login = []proto.Login{{User: "root", From: "203.0.113.7", Time: f.now.Unix()}}
	f.report(t, "node", report, 204)
	body := f.request("GET", "/", nil, true).Body.String()
	form := regexp.MustCompile(`(?s)<form method="post" action="/nodes/node/known-ip">.*?</form>`).FindString(body)
	if form == "" || !strings.Contains(form, "是我本人，标为常用") || input(t, form, "csrf") != f.csrf {
		t.Fatal("new login action must use the existing known-IP endpoint", body)
	}
	ip := input(t, form, "ip")
	if w := f.request("POST", "/nodes/node/known-ip", url.Values{"csrf": {f.csrf}, "ip": {ip}}, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	body = f.request("GET", "/nodes/node?range=24h", nil, true).Body.String()
	for _, marker := range []string{`class="name-forms"`, `action="/nodes/node/display-name"`, `action="/nodes/node/note"`, `action="/nodes/node/revoke"`, `name="confirm" value="yes"`, `href="?range=24h" aria-current="page" aria-pressed="true"`, `href="?range=1h" aria-pressed="false"`} {
		if !strings.Contains(body, marker) {
			t.Error("node page lost independent controls", marker)
		}
	}
	if strings.Count(body, `class="card metric"`) != 4 || strings.Count(body, `class="history"`) != 4 || strings.Index(body, ">登录记录</h2>") > strings.Index(body, ">身份与完整性</h2>") {
		t.Error("node metrics, history or column order changed")
	}
}
