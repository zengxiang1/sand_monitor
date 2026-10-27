package panel

import (
	"crypto/ed25519"
	"html"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/peer"
)

func TestDualReceiverPanel(t *testing.T) {
	f := setup(t)
	for _, path := range []string{"/enroll", "/nodes/node"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 || strings.Contains(w.Body.String(), "--backup-server") || strings.Contains(w.Body.String(), "备用接收端上也要吊销") {
			t.Fatal(path, w.Code, w.Body)
		}
	}
	w := f.request("GET", "/", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<dt>对端接收端</dt><dd>未配置</dd>") {
		t.Fatal(w.Code, w.Body)
	}
	f.h.Config.BackupIngestURL = "https://backup.example.com/base"
	loop := &peer.Loop{URL: "https://peer.example.com/private-path"}
	f.h.Config.PeerStatus = loop.Status
	w = f.request("GET", "/", nil, true)
	body := w.Body.String()
	if !strings.Contains(body, "对端接收端") || !strings.Contains(body, "peer.example.com") || strings.Contains(body, "/private-path") {
		t.Fatal(body)
	}
	f.h.Config.PeerStatus = func(time.Time) string { return "peer.example.com · 正常 · 3 秒前" }
	w = f.request("GET", "/", nil, true)
	if !strings.Contains(w.Body.String(), "正常 · 3 秒前") {
		t.Fatal(w.Body)
	}
	f.h.Config.PeerStatus = func(time.Time) string { return "peer.example.com · 不可达 · 2 分钟" }
	w = f.request("GET", "/", nil, true)
	if !strings.Contains(w.Body.String(), "不可达 · 2 分钟") {
		t.Fatal(w.Body)
	}
	w = f.request("GET", "/enroll?name=node", nil, true)
	if w.Code != 200 || !strings.Contains(html.UnescapeString(w.Body.String()), "--backup-server 'https://backup.example.com/base'") {
		t.Fatal(w.Code, w.Body)
	}
	w = f.request("GET", "/enroll?enabled=node", nil, true)
	body = html.UnescapeString(w.Body.String())
	line := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "node")
	for _, want := range []string{"还需在备用接收端登记同一公钥", "wanglou-server node add --name node --pubkey '" + line + "'", "wanglou-agent enroll <备用端注册码> --backup", `data-copy="backup-command"`} {
		if !strings.Contains(body, want) {
			t.Fatal("missing", want, body)
		}
	}
	w = f.request("GET", "/nodes/node", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "备用接收端上也要吊销") || !strings.Contains(w.Body.String(), "wanglou-server node revoke --name node") {
		t.Fatal(w.Code, w.Body)
	}
}
