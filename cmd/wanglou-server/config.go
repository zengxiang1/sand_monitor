package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"wanglou/internal/localconfig"
	"wanglou/internal/server/alert"
)

const defaultConfig = "/etc/wanglou/server.toml"

type config struct {
	Database, Listen, TLSCert, TLSKey, WebhookURL, TelegramToken, TelegramChatID string
	ListenPlain                                                                  bool
	TrustedProxies                                                               []netip.Prefix
	Alerts                                                                       alert.Config
}

// Missing configuration files are optional; malformed or unreadable files are
// errors. Environment variables override the file, including empty strings.
func loadConfig(path string) (config, error) { return loadConfigEnv(path, os.Environ()) }
func loadConfigEnv(path string, environment []string) (config, error) {
	c := config{Database: "/var/lib/wanglou/wanglou.db", Listen: ":8443", Alerts: alert.DefaultConfig()}
	apply := func(key, value string, env bool) (err error) {
		stringValue := func() (string, error) {
			if env {
				return value, nil
			}
			return localconfig.String(value)
		}
		switch key {
		case "database":
			c.Database, err = stringValue()
		case "listen":
			c.Listen, err = stringValue()
		case "tls_cert":
			c.TLSCert, err = stringValue()
		case "tls_key":
			c.TLSKey, err = stringValue()
		case "webhook_url":
			c.WebhookURL, err = stringValue()
		case "telegram_token":
			c.TelegramToken, err = stringValue()
		case "telegram_chat_id":
			c.TelegramChatID, err = stringValue()
		case "listen_plain":
			c.ListenPlain, err = strconv.ParseBool(value)
		case "trusted_proxies":
			var values []string
			if env {
				if strings.TrimSpace(value) != "" {
					values = strings.Split(value, ",")
				}
			} else {
				values, err = localconfig.Strings(value)
			}
			if err != nil {
				return err
			}
			c.TrustedProxies = nil
			for _, s := range values {
				prefix, e := netip.ParsePrefix(strings.TrimSpace(s))
				if e != nil {
					return fmt.Errorf("invalid trusted_proxies CIDR")
				}
				c.TrustedProxies = append(c.TrustedProxies, prefix.Masked())
			}
		case "interval", "resource_duration":
			var s string
			s, err = stringValue()
			if err == nil {
				var d time.Duration
				d, err = time.ParseDuration(s)
				if key == "interval" {
					c.Alerts.Interval = d
				} else {
					c.Alerts.Sustain = d
				}
			}
		case "memory_threshold":
			c.Alerts.MemoryThreshold, err = strconv.ParseFloat(value, 64)
		case "disk_threshold":
			c.Alerts.DiskThreshold, err = strconv.ParseFloat(value, 64)
		default:
			return fmt.Errorf("unknown key %q", key)
		}
		return err
	}
	if path != "" {
		err := localconfig.Read(path, func(k, v string) error { return apply(k, v, false) })
		if err != nil && !os.IsNotExist(err) {
			return c, err
		}
	}
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "WANGLOU_") {
			continue
		}
		key := strings.ToLower(strings.TrimPrefix(name, "WANGLOU_"))
		if name != "WANGLOU_"+strings.ToUpper(key) {
			return c, fmt.Errorf("unknown environment variable %q", name)
		}
		if err := apply(key, value, true); err != nil {
			return c, fmt.Errorf("invalid environment variable %q: %w", name, err)
		}
	}
	if c.Database == "" || c.Listen == "" || c.Alerts.Interval < time.Second || c.Alerts.Sustain < time.Second || !(c.Alerts.MemoryThreshold > 0 && c.Alerts.MemoryThreshold <= 100) || !(c.Alerts.DiskThreshold > 0 && c.Alerts.DiskThreshold <= 100) {
		return c, fmt.Errorf("invalid configuration")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") || (c.TelegramToken == "") != (c.TelegramChatID == "") {
		return c, fmt.Errorf("TLS and Telegram settings require both fields")
	}
	if c.ListenPlain && len(c.TrustedProxies) == 0 {
		return c, fmt.Errorf("listen_plain requires trusted_proxies CIDRs")
	}
	return c, nil
}
func (c config) validateTransport(insecure bool) error {
	if insecure {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("--insecure-http must bind a loopback IP")
		}
	}
	if !insecure && !c.ListenPlain && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("TLS certificate and key required; use listen_plain behind trusted proxies or --insecure-http for local development")
	}
	return nil
}
