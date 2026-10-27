package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func TestCommands(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "server.toml")
	db := filepath.Join(d, "db")
	if e := os.WriteFile(path, []byte(fmt.Sprintf("database = %q\nlisten = \"127.0.0.1:8443\"\n", db)), 0600); e != nil {
		t.Fatal(e)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, a := range [][]string{{"migrate", "--config", path}, {"node", "add", "--config", path, "--name", "node", "--pubkey", proto.PublicKeyLine(pub, "node")}, {"node", "list", "--config", path}, {"node", "revoke", "--config", path, "--name", "node"}, {"node", "list", "--config", path}} {
		if e := run(a); e != nil {
			t.Fatal(a, e)
		}
	}
	s, e := store.Open(db)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n, e := s.Node("node")
	if e != nil || n.RevokedAt == 0 {
		t.Fatal(n, e)
	}
	if run([]string{"serve", "--config", path}) == nil {
		t.Fatal("allowed implicit HTTP")
	}
	if run([]string{"unknown", "--config", path}) == nil {
		t.Fatal("unknown command")
	}
}
func TestConfigValidation(t *testing.T) {
	for _, text := range []string{"memory_threshold = 0", "memory_threshold = NaN", "disk_threshold = 101", "interval = \"0s\"", "resource_duration = \"-1s\"", "tls_cert = \"cert\"", "telegram_token = \"token\"", "unknown = true"} {
		p := filepath.Join(t.TempDir(), "server.toml")
		if e := os.WriteFile(p, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := loadConfig(p); e == nil {
			t.Fatal(text)
		}
	}
}
