package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wanglou/internal/proto"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func TestPublicProbeToggleHomePreviewAndExport(t *testing.T) {
	f := setup(t)
	r := sampleReport()
	r.Probes = []proto.Probe{{Target: "https://public.example/private-path?token=private-secret", Time: f.now.Unix(), IP: "192.0.2.233", TCPMS: 24.5, TTFBMS: 61.2, Status: 200}, {Target: "https://[2001:db8::88]/private-ip-path", Time: f.now.Unix(), IP: "2001:db8::88", Error: "tls"}}
	f.report(t, "node", r, 204)
	if err := f.s.SetMainlandProbes("node", []store.MainlandProbe{{Carrier: "中国联通", City: "Shanghai", ASN: 4837, Time: f.now.Unix(), TCPMS: 68.7, Sent: 3, Received: 3, Status: "ok"}}); err != nil {
		t.Fatal(err)
	}
	w := f.request("GET", "/public", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="probes" value="true" checked`) || !strings.Contains(w.Body.String(), "单个中国大陆探针到节点的 TCP 往返建连延迟与成功率") {
		t.Fatal("new public settings missing connectivity control", w.Code, w.Body)
	}
	form := publicForm(f)
	form.Set("probes", "invalid")
	if w := f.request("POST", "/public", form, true); w.Code != 400 {
		t.Fatal("invalid public field switch accepted", w.Code)
	}
	form.Set("probes", "true")
	form.Set("publish", "1")
	if w := f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c, err := status.Load(f.s, "public.published")
	if err != nil || !c.Fields.Probes {
		t.Fatal("connectivity switch not published", c, err)
	}
	for _, tc := range []struct {
		path string
		auth bool
	}{{"/", false}, {"/public/preview", true}} {
		w := f.request("GET", tc.path, nil, tc.auth)
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "国内访问") || !strings.Contains(body, "68.7 ms") || strings.Contains(body, "国内连接") || strings.Contains(body, "24.5 ms") {
			t.Fatal("missing public latest connection results", tc.path, w.Code, body)
		}
		for _, private := range []string{"private-path", "private-secret", "private-ip-path", "192.0.2.233", "2001:db8::88", `href="/nodes/`} {
			if strings.Contains(body, private) {
				t.Error("public page leaked probe diagnostic", tc.path, private)
			}
		}
	}
	dir := t.TempDir()
	if err := (&status.Exporter{Store: f.s, Dir: dir}).Export(f.now); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"index.html", "status.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || !strings.Contains(string(raw), "Shanghai") || strings.Contains(string(raw), "public.example") || strings.Contains(string(raw), "private-secret") || strings.Contains(string(raw), "2001:db8::88") {
			t.Fatal("unsafe or incomplete static public projection", file, string(raw), err)
		}
	}
	for _, path := range []string{"/public", "/public/preview", "/nodes/node", "/?fragment=1"} {
		w := f.request("GET", path, nil, false)
		if w.Code != 303 && !(path == "/?fragment=1" && w.Code == 401) {
			t.Fatal("private route exposed by public connectivity", path, w.Code)
		}
	}
	form.Del("probes")
	if w := f.request("POST", "/public", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	for _, tc := range []struct {
		path string
		auth bool
	}{{"/", false}, {"/public/preview", true}} {
		body := f.request("GET", tc.path, nil, tc.auth).Body.String()
		if strings.Contains(body, "国内访问") || strings.Contains(body, "68.7 ms") || strings.Contains(body, "public.example") {
			t.Fatal("disabled public connectivity remains visible", tc.path)
		}
	}
	c, err = status.Load(f.s, "public.published")
	if err != nil || c.Fields.Probes {
		t.Fatal("disabled connectivity remains published", c, err)
	}
}
