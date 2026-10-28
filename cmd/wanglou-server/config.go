package main

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"
	"wanglou/internal/localconfig"
	"wanglou/internal/server/alert"
)

const defaultConfig = "/etc/wanglou/server.toml"

type config struct {
	InstanceName, AlertScope, PeerURL, BackupIngestURL                           string
	Database, Listen, TLSCert, TLSKey, WebhookURL, TelegramToken, TelegramChatID string
	TelegramAPIBase, Timezone, PublicDir, PublicURL, HeartbeatURL                string
	RetentionDays                                                                int
	Location                                                                     *time.Location
	ListenPlain                                                                  bool
	PanelListen, PublicIngestURL                                                 string
	PanelCookieSecure                                                            bool
	TrustedProxies                                                               []netip.Prefix
	Alerts                                                                       alert.Config
}

// Missing configuration files are optional; malformed or unreadable files are
// errors. Environment variables override the file, including empty strings.
func loadConfig(path string) (config, error) { return loadConfigEnv(path, os.Environ()) }
func loadConfigEnv(path string, environment []string) (config, error) {
	c := config{TelegramAPIBase: "https://api.telegram.org", InstanceName: "望楼", AlertScope: "all", RetentionDays: 90, Timezone: "Local", Database: "/var/lib/wanglou/wanglou.db", Listen: ":8443", PanelCookieSecure: true, Alerts: alert.DefaultConfig()}
	apply := func(key, value string, env bool) (err error) {
		stringValue := func() (string, error) {
			if env {
				return value, nil
			}
			return localconfig.String(value)
		}
		switch key {
		case "instance_name":
			c.InstanceName, err = stringValue()
		case "alert_scope":
			c.AlertScope, err = stringValue()
		case "peer_url":
			c.PeerURL, err = stringValue()
		case "backup_ingest_url":
			c.BackupIngestURL, err = stringValue()
		case "retention_days":
			c.RetentionDays, err = strconv.Atoi(value)
		case "timezone":
			c.Timezone, err = stringValue()
		case "public_dir":
			c.PublicDir, err = stringValue()
		case "public_url":
			c.PublicURL, err = stringValue()
		case "heartbeat_url":
			c.HeartbeatURL, err = stringValue()
		case "database":
			c.Database, err = stringValue()
		case "panel_listen":
			c.PanelListen, err = stringValue()
		case "public_ingest_url":
			c.PublicIngestURL, err = stringValue()
		case "panel_cookie_secure":
			c.PanelCookieSecure, err = strconv.ParseBool(value)
		case "listen":
			c.Listen, err = stringValue()
		case "tls_cert":
			c.TLSCert, err = stringValue()
		case "tls_key":
			c.TLSKey, err = stringValue()
		case "webhook_url":
			c.WebhookURL, err = stringValue()
		case "telegram_api_base":
			c.TelegramAPIBase, err = stringValue()
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
	if utf8.RuneCountInString(c.InstanceName) > 16 || (c.AlertScope != "all" && c.AlertScope != "security") {
		return c, fmt.Errorf("invalid instance_name or alert_scope")
	}
	if c.RetentionDays < 7 || c.RetentionDays > 3650 || c.Database == "" || c.Listen == "" || c.Alerts.Interval < time.Second || c.Alerts.Sustain < time.Second || !(c.Alerts.MemoryThreshold > 0 && c.Alerts.MemoryThreshold <= 100) || !(c.Alerts.DiskThreshold > 0 && c.Alerts.DiskThreshold <= 100) {
		return c, fmt.Errorf("invalid configuration")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") || (c.TelegramToken == "") != (c.TelegramChatID == "") {
		return c, fmt.Errorf("TLS and Telegram settings require both fields")
	}
	if c.ListenPlain && len(c.TrustedProxies) == 0 {
		return c, fmt.Errorf("listen_plain requires trusted_proxies CIDRs")
	}
	c.TelegramAPIBase = strings.TrimRight(c.TelegramAPIBase, "/")
	if c.TelegramAPIBase == "" {
		return c, fmt.Errorf("telegram_api_base requires HTTPS")
	}
	var err error
	c.Location, err = time.LoadLocation(c.Timezone)
	if err != nil {
		return c, fmt.Errorf("invalid timezone")
	}
	return c, nil
}
func (c config) validateTransport(insecure bool) error {
	if c.PanelListen != "" && c.PanelListen == c.Listen {
		return fmt.Errorf("panel_listen must differ from listen")
	}
	if !insecure && !c.PanelCookieSecure {
		return fmt.Errorf("panel_cookie_secure=false requires --insecure-http")
	}
	for key, value := range map[string]string{"public_url": c.PublicURL, "heartbeat_url": c.HeartbeatURL} {
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(insecure && u.Scheme == "http")) {
			return fmt.Errorf("%s requires HTTPS", key)
		}
	}
	for key, value := range map[string]string{"telegram_api_base": c.TelegramAPIBase, "public_ingest_url": c.PublicIngestURL, "peer_url": c.PeerURL, "backup_ingest_url": c.BackupIngestURL} {
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") || (u.Scheme != "https" && !(insecure && u.Scheme == "http")) {
			return fmt.Errorf("%s requires HTTPS", key)
		}
	}
	if insecure {
		for _, listen := range []string{c.Listen, c.PanelListen} {
			if listen == "" {
				continue
			}
			host, _, err := net.SplitHostPort(listen)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("--insecure-http must bind a loopback IP")
			}
		}
	}
	if !insecure && !c.ListenPlain && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("TLS certificate and key required; use listen_plain behind trusted proxies or --insecure-http for local development")
	}
	return nil
}
