package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"wanglou/internal/agent"
	"wanglou/internal/testutil"
)

func TestCommands(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "key")
	config := filepath.Join(d, "agent.toml")
	args := []string{"init", "--name", "node", "--server", "https://example.com", "--key", key, "--config", config, "--state", filepath.Join(d, "seq")}
	if e := run(args); e != nil {
		t.Fatal(e)
	}
	if e := run(args); e == nil {
		t.Fatal("overwrote init")
	}
	if e := run([]string{"fingerprint", "--key", key}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"version"}); e != nil {
		t.Fatal(e)
	}
	if _, e := agent.LoadConfig(config); e != nil {
		t.Fatal(e)
	}
	if e := run(append(args, "--force")); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(key); e != nil {
		t.Fatal(e)
	}
	for _, a := range [][]string{nil, {"unknown"}, {"init", "--name", "bad/name"}, {"fingerprint", "--key", filepath.Join(d, "missing")}} {
		if run(a) == nil {
			t.Fatal(a)
		}
	}
}

func TestContainerInitPaths(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "agent.toml")
	key := filepath.Join(d, "node.key")
	if err := run([]string{"init", "--name", "container-node", "--server", "https://monitor.example.invalid", "--key", key, "--config", path, "--state", filepath.Join(d, "agent.seq"), "--proc-root", "/host/proc", "--root-fs", "/host/root", "--wtmp-path", "/host/wtmp"}); err != nil {
		t.Fatal(err)
	}
	c, err := agent.LoadConfig(path)
	if err != nil || c.ProcRoot != "/host/proc" || c.RootFS != "/host/root" || c.WtmpPath != "/host/wtmp" {
		t.Fatal(c, err)
	}
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal(info, err)
	}
}

func TestBackupInitAndEnroll(t *testing.T) {
	d := t.TempDir()
	path, key := filepath.Join(d, "agent.toml"), filepath.Join(d, "key")
	if err := run([]string{"init", "--name", "node", "--server", "https://primary.example.com", "--backup-server", "https://backup.example.com", "--key", key, "--config", path, "--state", filepath.Join(d, "seq")}); err != nil {
		t.Fatal(err)
	}
	c, err := agent.LoadConfig(path)
	if err != nil || c.BackupServer != "https://backup.example.com" {
		t.Fatal(c, err)
	}
	c.Server, c.BackupServer, c.InsecureHTTP = "http://primary.localhost", "http://backup.localhost", true
	if err := agent.WriteConfig(path, c, true); err != nil {
		t.Fatal(err)
	}
	var primaryCalls, backupCalls atomic.Int32
	_, primary := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { primaryCalls.Add(1); w.WriteHeader(204) }))
	_, backup := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll" {
			t.Error(r.URL)
		}
		backupCalls.Add(1)
		w.WriteHeader(204)
	}))
	previous := http.DefaultTransport
	http.DefaultTransport = enrollTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "backup.localhost" {
			return backup.Transport.RoundTrip(r)
		}
		return primary.Transport.RoundTrip(r)
	})
	defer func() { http.DefaultTransport = previous }()
	if err := run([]string{"enroll", "ABCD-EFGH", "--backup", "--config", path}); err != nil {
		t.Fatal(err)
	}
	if backupCalls.Load() != 1 || primaryCalls.Load() != 0 {
		t.Fatal(primaryCalls.Load(), backupCalls.Load())
	}
	if err := run([]string{"enroll", "ABCD-EFGH", "--config", path}); err != nil {
		t.Fatal(err)
	}
	if backupCalls.Load() != 1 || primaryCalls.Load() != 1 {
		t.Fatal(primaryCalls.Load(), backupCalls.Load())
	}
}

type enrollTransport func(*http.Request) (*http.Response, error)

func (f enrollTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
