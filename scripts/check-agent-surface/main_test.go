package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectSurface(t *testing.T) {
	for _, s := range []string{`package bad;import "os/exec";var _=exec.Command`, `package bad;import n "net";var _=n.ListenTCP`, `package bad;import h "net/http";var _=&h.Server{}`, `package bad;import "syscall";var _=syscall.ForkExec`, `package bad;import . "net/http";var _=Serve`, `package bad;import "os";var _=os.StartProcess`, `package bad;import h "net/http";var _=h.ServeFile`} {
		p := filepath.Join(t.TempDir(), "bad.go")
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		if inspect(p) == nil {
			t.Fatal("missed", s)
		}
	}
	if check(strings.NewReader(`{"ImportPath":"os/exec","Standard":true}`)) == nil {
		t.Fatal("closure")
	}
	if check(strings.NewReader("")) == nil {
		t.Fatal("empty closure")
	}
}

func TestAllowHTTP2ClientConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.go")
	if err := os.WriteFile(p, []byte(`package client; import "net/http"; var _ = &http.HTTP2Config{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspect(p); err != nil {
		t.Fatal(err)
	}
	if !forbidden("net/http", "Server") {
		t.Fatal("http.Server must remain forbidden")
	}
}
