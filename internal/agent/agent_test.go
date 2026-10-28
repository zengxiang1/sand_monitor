package agent

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func report() proto.Report {
	return proto.Report{Version: 1, Bin: "sha256:" + strings.Repeat("a", 64), OS: "test", Arch: "test", Login: []proto.Login{}}
}
func config(t *testing.T) Config {
	t.Helper()
	d := t.TempDir()
	return Config{Name: "node", Server: "https://localhost", Key: filepath.Join(d, "key"), StateFile: filepath.Join(d, "state"), Interval: 5 * time.Second}
}
func TestKeyAndConfig(t *testing.T) {
	c := config(t)
	key, e := GenerateKey(c.Key, false)
	if e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(c.Key)
	if info.Mode().Perm() != 0400 {
		t.Fatal(info.Mode())
	}
	loaded, e := LoadKey(c.Key)
	if e != nil || !key.Equal(loaded) {
		t.Fatal(e)
	}
	if _, e = GenerateKey(c.Key, false); e == nil {
		t.Fatal("overwritten")
	}
	replacement, e := GenerateKey(c.Key, true)
	if e != nil || replacement.Equal(key) {
		t.Fatal("force", e)
	}
	path := filepath.Join(t.TempDir(), "agent.toml")
	if e = WriteConfig(path, c, false); e != nil {
		t.Fatal(e)
	}
	read, e := LoadConfig(path)
	if e != nil || read != c {
		t.Fatal(read, e)
	}
	if e = WriteConfig(path, c, false); e == nil {
		t.Fatal("overwrote config")
	}
	if e = os.Chmod(c.Key, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadKey(c.Key); e == nil {
		t.Fatal("accepted loose key permissions")
	}
	for _, server := range []string{"http://localhost", "https://", "https://user@host", "https://host?foo=bar"} {
		bad := c
		bad.Server = server
		if bad.Validate() == nil {
			t.Fatal(server)
		}
	}
	if err := os.WriteFile(path, []byte("unknown = 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, e = LoadConfig(path); e == nil {
		t.Fatal("unknown config")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type endless struct {
	read   int
	closed bool
}

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '!'
	}
	e.read += len(p)
	return len(p), nil
}
func (e *endless) Close() error { e.closed = true; return nil }
func TestClientPersistenceAndBoundedDiscard(t *testing.T) {
	c := config(t)
	key, e := GenerateKey(c.Key, false)
	if e != nil {
		t.Fatal(e)
	}
	var prev uint64
	now := time.Unix(1700000000, 0)
	for i := 0; i < 3; i++ {
		client, e := NewClient(c, key)
		if e != nil {
			t.Fatal(e)
		}
		client.Now = func() time.Time { return now.Add(-time.Duration(i) * time.Hour) }
		response := &endless{}
		client.http["primary"].Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			seq, _ := strconv.ParseUint(req.Header.Get(proto.SeqHeader), 10, 64)
			ts, _ := strconv.ParseInt(req.Header.Get(proto.TsHeader), 10, 64)
			if seq <= prev || !proto.Verify(key.Public().(ed25519.PublicKey), c.Name, seq, ts, body, req.Header.Get(proto.SigHeader)) {
				t.Fatal("sequence or signature")
			}
			prev = seq
			return &http.Response{StatusCode: 204, Body: response, Header: make(http.Header)}, nil
		})
		if e = client.Send(context.Background(), report()); e != nil {
			t.Fatal(e)
		}
		if response.read != 4096 || !response.closed {
			t.Fatal("unbounded or unclosed response", response)
		}
	}
}
func TestClientRedirectAndFailure(t *testing.T) {
	c := config(t)
	key, _ := GenerateKey(c.Key, false)
	client, _ := NewClient(c, key)
	var calls atomic.Int32
	client.http["primary"].Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://elsewhere"}}, Body: io.NopCloser(strings.NewReader("remote instructions are ignored"))}, nil
	})
	if e := client.Send(context.Background(), report()); e == nil {
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("followed redirect")
	}
	if Backoff(1) != time.Second || Backoff(7) != 60*time.Second || Backoff(100) != 60*time.Second {
		t.Fatal("backoff")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := Run(ctx, c); e != nil {
		t.Fatal(e)
	}
}

func TestCollectorPathConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.toml")
	base := "name = \"node\"\nserver = \"https://monitor.example.invalid\"\n"
	if err := os.WriteFile(p, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil || c.ProcRoot != "/proc" || c.RootFS != "/" || c.WtmpPath != "/var/log/wtmp" {
		t.Fatal(c, err)
	}
	for _, key := range []string{"proc_root", "root_fs", "wtmp_path"} {
		if err := os.WriteFile(p, []byte(base+key+" = \"relative/path\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(p); err == nil {
			t.Fatal("accepted relative", key)
		}
	}
}
