package panel

import (
	"strings"
	"testing"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func TestPublicMainlandHomePreviewAndPrivateRoutes(t *testing.T) {
	f := setup(t)
	if err := f.s.SetMainlandProbes("node", []store.MainlandProbe{{Carrier: "中国联通", City: "Shanghai", Network: "private-source-network", Country: "CN", ASN: 4837, MeasurementID: "private-measurement-id", Time: f.now.Unix(), TCPMS: 64.2, Sent: 3, Received: 2, Status: "ok"}}); err != nil {
		t.Fatal(err)
	}
	c := status.DefaultConfig()
	c.Nodes = []status.Selection{{Node: "node", Public: true, Name: "公开节点"}}
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		auth bool
	}{{"/", false}, {"/public/preview", true}} {
		w := f.request("GET", tc.path, nil, tc.auth)
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "国内访问") || !strings.Contains(body, "64.2 ms") || !strings.Contains(body, "成功 2/3") || !strings.Contains(body, "66.7%") {
			t.Fatal("independent external result missing from public page", tc.path, w.Code, body)
		}
		for _, secret := range []string{"private-source-network", "private-measurement-id", "AS4837", `href="/nodes/`} {
			if strings.Contains(body, secret) {
				t.Error("private diagnostic in public mainland page", tc.path, secret)
			}
		}
	}
	for _, path := range []string{"/public/preview", "/nodes/node", "/public"} {
		if w := f.request("GET", path, nil, false); w.Code != 303 || w.Header().Get("Location") != "/login" {
			t.Fatal("public mainland section exposed private route", path, w.Code, w.Header())
		}
	}
	c.Fields.Probes = false
	if err := status.Save(f.s, c, true, f.now, "admin", "", "public_draft"); err != nil {
		t.Fatal(err)
	}
	if body := f.request("GET", "/", nil, false).Body.String(); strings.Contains(body, "国内访问") || strings.Contains(body, "64.2 ms") {
		t.Fatal("disabled public mainland section remains visible", body)
	}
}
