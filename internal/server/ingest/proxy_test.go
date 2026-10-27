package ingest_test

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestForwardedClientIP(t *testing.T) {
	for _, tc := range []struct{ name, peer, forwarded, want string }{
		{"untrusted spoof ignored", "192.0.2.1:4321", "203.0.113.7", "192.0.2.1"},
		{"trusted peer", "172.30.0.2:4321", "203.0.113.7", "203.0.113.7"},
		{"rightmost untrusted", "172.30.0.2:4321", "198.51.100.9, 203.0.113.7, 172.30.0.3", "203.0.113.7"},
		{"missing header", "172.30.0.2:4321", "", "172.30.0.2"},
		{"invalid hop", "172.30.0.2:4321", "198.51.100.9, invalid", "172.30.0.2"},
		{"all trusted", "172.30.0.2:4321", "172.30.0.3", "172.30.0.2"},
		{"IPv6", "[2001:db8:1::2]:4321", "2001:db8:2::7, 2001:db8:1::3", "2001:db8:2::7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newSetup(t)
			x.h.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}
			body, _ := json.Marshal(sample())
			r := signed(x.key, "node", 1, x.now.Unix(), body)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			check(t, x.h, r, 204)
			n, err := x.s.Node("node")
			if err != nil || n.LastIP != tc.want {
				t.Fatal(n.LastIP, err)
			}
		})
	}
}

func TestProxyIPLimiter(t *testing.T) {
	x := newSetup(t)
	x.h.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}
	x.h.IPBurst = 1
	body, _ := json.Marshal(sample())
	for i, tc := range []struct {
		peer, forwarded string
		want            int
	}{
		{"172.30.0.2:4321", "203.0.113.7", 204},
		{"172.30.0.2:4321", "203.0.113.7", 429},
		{"172.30.0.2:4321", "203.0.113.8", 204},
		{"192.0.2.1:4321", "203.0.113.9", 204},
		{"192.0.2.1:4321", "203.0.113.10", 429},
	} {
		r := signed(x.key, "node", uint64(i+1), x.now.Unix(), body)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.forwarded)
		check(t, x.h, r, tc.want)
	}
}

func TestHealthEndpoint(t *testing.T) {
	x := newSetup(t)
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	x.h.ServeHTTP(w, r)
	if w.Code != 204 || w.Body.Len() != 0 || w.Header().Get("Content-Type") != "" || w.Header().Get("Server") != "" {
		t.Fatal(w)
	}
	var count int
	if err := x.s.DB.QueryRow(`SELECT count(*) FROM metrics`).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	check(t, x.h, httptest.NewRequest("POST", "/healthz", nil), 400)
	if err := x.s.Close(); err != nil {
		t.Fatal(err)
	}
	check(t, x.h, httptest.NewRequest("GET", "/healthz", nil), 503)
}
