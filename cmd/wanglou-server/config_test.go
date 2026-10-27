package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestEnvironmentConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	if err := os.WriteFile(path, []byte(`database = "file.db"
listen = ":8443"
webhook_url = "https://hooks.example.invalid/old"
listen_plain = false
trusted_proxies = ["192.0.2.0/24"]
`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfigEnv(path, []string{
		"UNRELATED=value", "WANGLOU_DATABASE=env.db", "WANGLOU_LISTEN=:8080",
		"WANGLOU_LISTEN_PLAIN=true", "WANGLOU_TRUSTED_PROXIES=172.30.0.0/24, 2001:db8::/32",
		"WANGLOU_TLS_CERT=cert", "WANGLOU_TLS_KEY=key", "WANGLOU_WEBHOOK_URL=",
		"WANGLOU_TELEGRAM_TOKEN=token", "WANGLOU_TELEGRAM_CHAT_ID=chat",
		"WANGLOU_INTERVAL=10s", "WANGLOU_RESOURCE_DURATION=2m",
		"WANGLOU_MEMORY_THRESHOLD=85", "WANGLOU_DISK_THRESHOLD=95",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Database != "env.db" || c.Listen != ":8080" || !c.ListenPlain || c.WebhookURL != "" || c.TLSCert != "cert" || c.TLSKey != "key" || c.TelegramToken != "token" || c.TelegramChatID != "chat" || c.Alerts.Interval != 10*time.Second || c.Alerts.Sustain != 2*time.Minute || c.Alerts.MemoryThreshold != 85 || c.Alerts.DiskThreshold != 95 {
		t.Fatalf("environment overrides not applied")
	}
	want := []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if !reflect.DeepEqual(c.TrustedProxies, want) {
		t.Fatal(c.TrustedProxies)
	}
	c, err = loadConfigEnv(path, nil)
	if err != nil || c.Database != "file.db" || len(c.TrustedProxies) != 1 || c.TrustedProxies[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatal(c, err)
	}
	// Both the default config file and an explicitly empty path are optional.
	for _, p := range []string{"", filepath.Join(t.TempDir(), "absent.toml")} {
		if _, err := loadConfigEnv(p, []string{"WANGLOU_DATABASE=env.db"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidEnvironmentAndPlainConfiguration(t *testing.T) {
	for _, environment := range [][]string{
		{"WANGLOU_UNKNOWN=value"}, {"WANGLOU_listen=:8080"}, {"WANGLOU_=value"},
		{"WANGLOU_LISTEN_PLAIN=true"},
		{"WANGLOU_LISTEN_PLAIN=true", "WANGLOU_TRUSTED_PROXIES="},
		{"WANGLOU_TRUSTED_PROXIES=172.30.0.1"}, {"WANGLOU_TRUSTED_PROXIES=invalid/24"},
		{"WANGLOU_LISTEN_PLAIN=invalid"}, {"WANGLOU_INTERVAL=invalid"},
		{"WANGLOU_MEMORY_THRESHOLD=NaN"}, {"WANGLOU_TELEGRAM_TOKEN=token"},
		{"WANGLOU_TLS_CERT=cert"}, {"WANGLOU_DATABASE="},
	} {
		if _, err := loadConfigEnv("", environment); err == nil {
			t.Fatal("accepted invalid environment", environment)
		}
	}
	path := filepath.Join(t.TempDir(), "server.toml")
	for _, text := range []string{`listen_plain = true`, "listen_plain = true\ntrusted_proxies = []", `trusted_proxies = ["invalid"]`, "unknown = true"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfigEnv(path, nil); err == nil {
			t.Fatal("accepted", text)
		}
	}
	// A supplied but malformed file is not silently discarded in env-only mode.
	if _, err := loadConfigEnv(path, []string{"WANGLOU_DATABASE=env.db"}); err == nil {
		t.Fatal("ignored malformed file")
	}
}

func TestTransportValidation(t *testing.T) {
	for _, tc := range []struct {
		listen                   string
		plain, insecure, tls, ok bool
	}{
		{":8080", true, false, false, true}, {":8080", true, true, false, false},
		{":8080", false, true, false, false}, {"0.0.0.0:8080", false, true, false, false},
		{"localhost:8080", false, true, false, false}, {"127.0.0.1:8080", false, true, false, true},
		{"[::1]:8080", false, true, false, true}, {":8443", false, false, false, false},
		{":8443", false, false, true, true},
	} {
		c := config{Listen: tc.listen, ListenPlain: tc.plain, PanelCookieSecure: true}
		if tc.tls {
			c.TLSCert = "cert"
			c.TLSKey = "key"
		}
		if err := c.validateTransport(tc.insecure); (err == nil) != tc.ok {
			t.Fatal(tc, err)
		}
	}
}

func TestPanelConfiguration(t *testing.T) {
	c, err := loadConfigEnv("", []string{"WANGLOU_PANEL_LISTEN=127.0.0.1:8081", "WANGLOU_LISTEN=127.0.0.1:8080", "WANGLOU_PUBLIC_INGEST_URL=http://127.0.0.1:8080", "WANGLOU_PANEL_COOKIE_SECURE=false"})
	if err != nil || c.PanelListen != "127.0.0.1:8081" || c.PanelCookieSecure || c.PublicIngestURL != "http://127.0.0.1:8080" {
		t.Fatal(c, err)
	}
	if err = c.validateTransport(true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		panel, url           string
		secure, insecure, ok bool
	}{
		{"127.0.0.1:8081", "https://monitor.example.com", true, true, true},
		{"127.0.0.1:8081", "https://monitor.example.com", false, false, false},
		{"127.0.0.1:8081", "http://monitor.example.com", true, false, false},
		{"127.0.0.1:8080", "", true, true, false},
		{":8081", "", true, true, false},
		{"127.0.0.1:8081", "https://user@monitor.example.com", true, true, false},
		{"127.0.0.1:8081", "https://monitor.example.com?query=1", true, true, false},
		{"127.0.0.1:8081", "https://monitor.example.com#fragment", true, true, false},
		{"127.0.0.1:8081", "javascript:alert(1)", true, true, false},
		{"127.0.0.1:8081", "https://monitor.example.com", true, false, true},
	} {
		c := config{Listen: "127.0.0.1:8080", PanelListen: tc.panel, PanelCookieSecure: tc.secure, PublicIngestURL: tc.url, TLSCert: "cert", TLSKey: "key"}
		if err := c.validateTransport(tc.insecure); (err == nil) != tc.ok {
			t.Fatal(tc, err)
		}
	}
	path := filepath.Join(t.TempDir(), "panel.toml")
	if err = os.WriteFile(path, []byte("panel_listen = \"127.0.0.1:8081\"\npublic_ingest_url = \"https://monitor.example.com\"\npanel_cookie_secure = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = loadConfigEnv(path, nil)
	if err != nil || !c.PanelCookieSecure || c.PanelListen != "127.0.0.1:8081" {
		t.Fatal(c, err)
	}
}
