package ingest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"wanglou/internal/agent"
	"wanglou/internal/proto"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/ingest"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func sample() proto.Report {
	return proto.Report{Version: 1, CPU: 12.4, Load: [3]float64{.21, .18, .12}, Mem: [2]float64{812, 2048}, Swap: [2]float64{0, 512}, Disk: [2]float64{18.2, 40}, Net: [2]float64{1532, 8841}, NetTotal: [2]uint64{123456, 7890}, Conn: [2]uint64{41, 6}, Up: 864000, Login: []proto.Login{}, Bin: "sha256:" + strings.Repeat("a", 64), OS: "linux", Arch: "amd64"}
}

type setup struct {
	s    *store.Store
	h    *ingest.Handler
	key  ed25519.PrivateKey
	now  time.Time
	path string
}

func newSetup(t *testing.T) setup {
	t.Helper()
	path := filepath.Join(t.TempDir(), "monitor.db")
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1700000000, 0)
	if e = s.AddNode("node", pub, now); e != nil {
		t.Fatal(e)
	}
	engine := alert.New(s, alert.DefaultConfig())
	h := ingest.New(s, engine)
	h.Now = func() time.Time { return now }
	return setup{s, h, key, now, path}
}
func signed(key ed25519.PrivateKey, node string, seq uint64, ts int64, body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/v1/report", bytes.NewReader(body))
	r.Header.Set(proto.NodeHeader, node)
	r.Header.Set(proto.SeqHeader, strconv.FormatUint(seq, 10))
	r.Header.Set(proto.TsHeader, strconv.FormatInt(ts, 10))
	r.Header.Set(proto.SigHeader, proto.Sign(key, node, seq, ts, body))
	return r
}
func check(t *testing.T, h http.Handler, r *http.Request, want int) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want || w.Body.Len() != 0 {
		t.Fatalf("status=%d want=%d body=%q", w.Code, want, w.Body.String())
	}
}
func TestAuthenticationFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   int
		modify func(*testing.T, setup, []byte) *http.Request
	}{
		{"valid", 204, func(t *testing.T, x setup, b []byte) *http.Request { return signed(x.key, "node", 1, x.now.Unix(), b) }},
		{"wrong signature", 401, func(t *testing.T, x setup, b []byte) *http.Request {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			return signed(key, "node", 1, x.now.Unix(), b)
		}},
		{"tampered body", 401, func(t *testing.T, x setup, b []byte) *http.Request {
			r := signed(x.key, "node", 1, x.now.Unix(), b)
			r.Body = io.NopCloser(strings.NewReader(string(b) + " "))
			return r
		}},
		{"expired", 401, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix()-61, b)
		}},
		{"future", 401, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix()+61, b)
		}},
		{"past boundary", 204, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix()-60, b)
		}},
		{"future boundary", 204, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix()+60, b)
		}},
		{"unknown", 401, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "unknown", 1, x.now.Unix(), b)
		}},
		{"revoked", 401, func(t *testing.T, x setup, b []byte) *http.Request {
			if e := x.s.Revoke("node", x.now); e != nil {
				t.Fatal(e)
			}
			return signed(x.key, "node", 1, x.now.Unix(), b)
		}},
		{"body too large before headers", 413, func(t *testing.T, x setup, b []byte) *http.Request {
			return httptest.NewRequest("POST", "/v1/report", strings.NewReader(strings.Repeat("x", proto.MaxBody+1)))
		}},
		{"exact body limit", 204, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix(), append(b, bytes.Repeat([]byte(" "), proto.MaxBody-len(b))...))
		}},
		{"missing headers", 400, func(t *testing.T, x setup, b []byte) *http.Request {
			return httptest.NewRequest("POST", "/v1/report", bytes.NewReader(b))
		}},
		{"bad json", 400, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix(), []byte("{"))
		}},
		{"unknown fields", 400, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix(), append([]byte(`{"extra":1,`), b[1:]...))
		}},
		{"trailing json", 400, func(t *testing.T, x setup, b []byte) *http.Request {
			return signed(x.key, "node", 1, x.now.Unix(), append(b, []byte(` {}`)...))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newSetup(t)
			body, _ := json.Marshal(sample())
			check(t, x.h, tc.modify(t, x, body), tc.want)
			var count int
			if e := x.s.DB.QueryRow(`SELECT count(*) FROM metrics`).Scan(&count); e != nil {
				t.Fatal(e)
			}
			if (tc.want == 204) != (count == 1) {
				t.Fatal("unexpected persistence", count)
			}
		})
	}
}
func TestHeaderFormats(t *testing.T) {
	for _, tc := range []struct{ header, value string }{{proto.NodeHeader, "bad/node"}, {proto.SeqHeader, "-1"}, {proto.SeqHeader, "01"}, {proto.SeqHeader, "18446744073709551616"}, {proto.SeqHeader, "+1"}, {proto.TsHeader, "1.1"}, {proto.TsHeader, "+1700000000"}, {proto.SigHeader, "!"}, {proto.SigHeader, base64.StdEncoding.EncodeToString([]byte("short"))}} {
		t.Run(tc.header+"="+tc.value, func(t *testing.T) {
			x := newSetup(t)
			b, _ := json.Marshal(sample())
			r := signed(x.key, "node", 1, x.now.Unix(), b)
			r.Header.Set(tc.header, tc.value)
			check(t, x.h, r, 400)
		})
	}
	for _, header := range []string{proto.NodeHeader, proto.SeqHeader, proto.TsHeader, proto.SigHeader} {
		t.Run("duplicate "+header, func(t *testing.T) {
			x := newSetup(t)
			b, _ := json.Marshal(sample())
			r := signed(x.key, "node", 1, x.now.Unix(), b)
			r.Header.Add(header, r.Header.Get(header))
			check(t, x.h, r, 400)
		})
	}
}
func TestReplayRollbackPersistenceAndUInt64(t *testing.T) {
	x := newSetup(t)
	b, _ := json.Marshal(sample())
	check(t, x.h, signed(x.key, "node", 10, x.now.Unix(), b), 204)
	check(t, x.h, signed(x.key, "node", 10, x.now.Unix(), b), 401)
	check(t, x.h, signed(x.key, "node", 9, x.now.Unix(), b), 401)
	if e := x.s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := store.Open(x.path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h := ingest.New(s, nil)
	h.Now = func() time.Time { return x.now }
	check(t, h, signed(x.key, "node", 10, x.now.Unix(), b), 401)
	check(t, h, signed(x.key, "node", ^uint64(0), x.now.Unix(), b), 204)
	n, e := s.Node("node")
	if e != nil || n.LastSeq != ^uint64(0) {
		t.Fatal(n, e)
	}
	check(t, h, signed(x.key, "node", ^uint64(0)-1, x.now.Unix(), b), 401)
}
func TestPerNodeRateLimitAndValidationOrder(t *testing.T) {
	x := newSetup(t)
	b, _ := json.Marshal(sample())
	for seq := uint64(1); seq <= 5; seq++ {
		check(t, x.h, signed(x.key, "node", seq, x.now.Unix(), b), 204)
	}
	check(t, x.h, signed(x.key, "node", 5, x.now.Unix(), b), 401) // replay precedes rate limit
	check(t, x.h, signed(x.key, "node", 6, x.now.Unix()-61, b), 401)
	check(t, x.h, signed(x.key, "node", 6, x.now.Unix(), b), 429)
	n, _ := x.s.Node("node")
	if n.LastSeq != 5 {
		t.Fatal("rate rejection consumed sequence")
	}
	pub, other, _ := ed25519.GenerateKey(rand.Reader)
	if e := x.s.AddNode("other", pub, x.now); e != nil {
		t.Fatal(e)
	}
	check(t, x.h, signed(other, "other", 1, x.now.Unix(), b), 204)
	x.h.Now = func() time.Time { return x.now.Add(500 * time.Millisecond) }
	check(t, x.h, signed(x.key, "node", 6, x.now.Unix(), b), 204)
	counts := x.h.FailureCounts()
	if counts["rate"] != 1 || counts["sequence"] != 1 || counts["timestamp"] != 1 {
		t.Fatal(counts)
	}
}
func TestConcurrentReplay(t *testing.T) {
	x := newSetup(t)
	b, _ := json.Marshal(sample())
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			x.h.ServeHTTP(w, signed(x.key, "node", 1, x.now.Unix(), b))
			mu.Lock()
			statuses[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if statuses[204] != 1 || statuses[401] != 19 {
		t.Fatal(statuses)
	}
}
func TestEndToEndRealAgent(t *testing.T) {
	x := newSetup(t)
	x.h.Now = time.Now
	server, httpClient := testutil.NewServer(t, x.h)
	client, e := agent.NewClient(agent.Config{Name: "node", Server: server.URL, Key: "unused", StateFile: filepath.Join(t.TempDir(), "seq"), Interval: 5 * time.Second, InsecureHTTP: true}, x.key, httpClient.Transport)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Send(context.Background(), sample()); e != nil {
		t.Fatal(e)
	}
	var cpu, mem, disk float64
	var total string
	var tcp int
	if e = x.s.DB.QueryRow(`SELECT cpu,mem_used,disk_used,net_total_tx,tcp FROM metrics WHERE node='node'`).Scan(&cpu, &mem, &disk, &total, &tcp); e != nil {
		t.Fatal(e)
	}
	if cpu != 12.4 || mem != 812 || disk != 18.2 || total != "123456" || tcp != 41 {
		t.Fatal(cpu, mem, disk, total, tcp)
	}
	n, e := x.s.Node("node")
	if e != nil || n.LastSeen == 0 || n.LastSeq == 0 || n.LastIP != "127.0.0.1" {
		t.Fatal(n, e)
	}
}
func TestSignatureBeforeTimestamp(t *testing.T) {
	x := newSetup(t)
	b, _ := json.Marshal(sample())
	r := signed(x.key, "node", 1, x.now.Unix()-100, b)
	r.Header.Set(proto.SigHeader, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	check(t, x.h, r, 401)
	if fmt.Sprint(x.h.FailureCounts()) != "map[signature:1]" {
		t.Fatal(x.h.FailureCounts())
	}
}

func TestSequenceAndRateBeforeJSON(t *testing.T) {
	x := newSetup(t)
	body, _ := json.Marshal(sample())
	for seq := uint64(1); seq <= 5; seq++ {
		check(t, x.h, signed(x.key, "node", seq, x.now.Unix(), body), 204)
	}
	check(t, x.h, signed(x.key, "node", 5, x.now.Unix(), []byte("{")), 401)
	check(t, x.h, signed(x.key, "node", 6, x.now.Unix(), []byte("{")), 429)
}

func TestOutageReport(t *testing.T) {
	for _, tc := range []struct {
		outage *proto.Outage
		status int
	}{{nil, 204}, {&proto.Outage{Since: 1, Failures: 2}, 204}, {&proto.Outage{Since: 0, Failures: 2}, 400}, {&proto.Outage{Since: 1, Failures: 0}, 400}} {
		x := newSetup(t)
		r := sample()
		r.Outage = tc.outage
		body, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		check(t, x.h, signed(x.key, "node", 1, x.now.Unix(), body), tc.status)
	}
}
