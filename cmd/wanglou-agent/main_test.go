package main

import (
	"os"
	"path/filepath"
	"testing"
	"wanglou/internal/agent"
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
