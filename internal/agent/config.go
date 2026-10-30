package agent

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"wanglou/internal/agent/collect"
	"wanglou/internal/localconfig"
	"wanglou/internal/proto"
)

const DefaultConfig = "/etc/wanglou/agent.toml"
const DefaultKey = "/etc/wanglou/node.key"

type Config struct {
	Name, Server, BackupServer, Key, StateFile string
	ProcRoot, RootFS, WtmpPath                 string
	Interval                                   time.Duration
	InsecureHTTP                               bool
	ProbeTargets                               []string
}

func LoadConfig(path string) (Config, error) {
	c := Config{Key: DefaultKey, StateFile: "/var/lib/wanglou/agent.seq", Interval: 5 * time.Second, ProcRoot: collect.DefaultProcRoot, RootFS: collect.DefaultRootFS, WtmpPath: collect.DefaultWtmpPath}
	e := localconfig.Read(path, func(k, v string) (e error) {
		switch k {
		case "name":
			c.Name, e = localconfig.String(v)
		case "server":
			c.Server, e = localconfig.String(v)
		case "backup_server":
			c.BackupServer, e = localconfig.String(v)
		case "key":
			c.Key, e = localconfig.String(v)
		case "state_file":
			c.StateFile, e = localconfig.String(v)
		case "proc_root":
			c.ProcRoot, e = localconfig.String(v)
		case "root_fs":
			c.RootFS, e = localconfig.String(v)
		case "wtmp_path":
			c.WtmpPath, e = localconfig.String(v)
		case "probe_targets":
			c.ProbeTargets, e = localconfig.Strings(v)
		case "interval":
			var s string
			s, e = localconfig.String(v)
			if e == nil {
				c.Interval, e = time.ParseDuration(s)
			}
		case "insecure_http":
			c.InsecureHTTP, e = strconv.ParseBool(v)
		default:
			e = fmt.Errorf("unknown key %q", k)
		}
		return
	})
	if e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if err := proto.ValidateProbeTargets(c.ProbeTargets); err != nil {
		return err
	}
	if !proto.ValidNode(c.Name) || c.Key == "" || c.StateFile == "" || c.Interval <= 0 {
		return fmt.Errorf("invalid name, key, state_file or interval")
	}
	for _, path := range []string{c.ProcRoot, c.RootFS, c.WtmpPath} {
		if path != "" && !filepath.IsAbs(path) {
			return fmt.Errorf("collector paths must be absolute")
		}
	}
	normalized := []string{}
	for _, target := range []string{c.Server, c.BackupServer} {
		if target == "" && len(normalized) > 0 {
			continue
		}
		u, e := url.Parse(target)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(target, "#") || (u.Scheme != "https" && !(c.InsecureHTTP && u.Scheme == "http")) {
			return fmt.Errorf("server requires HTTPS (or explicit insecure_http for local development)")
		}
		u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
		normalized = append(normalized, strings.TrimRight(u.String(), "/"))
	}
	if len(normalized) == 2 && normalized[0] == normalized[1] {
		return fmt.Errorf("backup_server must differ from server")
	}

	return nil
}
func WriteConfig(path string, c Config, force bool) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if force {
		if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(f, "name = %q\nserver = %q\nbackup_server = %q\nkey = %q\nstate_file = %q\ninterval = %q\ninsecure_http = %t\nproc_root = %q\nroot_fs = %q\nwtmp_path = %q\n", c.Name, c.Server, c.BackupServer, c.Key, c.StateFile, c.Interval.String(), c.InsecureHTTP, c.ProcRoot, c.RootFS, c.WtmpPath)
	if e == nil && c.ProbeTargets != nil {
		values := make([]string, len(c.ProbeTargets))
		for i, target := range c.ProbeTargets {
			values[i] = strconv.Quote(target)
		}
		_, e = fmt.Fprintf(f, "probe_targets = [%s]\n", strings.Join(values, ", "))
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
