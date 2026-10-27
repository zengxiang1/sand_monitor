package ingest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func TestIPLimitBeforeDatabaseAndForwarding(t *testing.T) {
	h := New(nil, nil)
	now := time.Unix(1700000000, 0)
	h.Now = func() time.Time { return now }
	// Malformed requests consume the unauthenticated allowance without any DB.
	for i := 0; i < 41; i++ {
		r := httptest.NewRequest("POST", "/v1/report", nil)
		r.RemoteAddr = "192.0.2.1:" + strconv.Itoa(1000+i)
		r.Header.Set("X-Forwarded-For", "192.0.2."+strconv.Itoa(i+2))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 400
		if i == 40 {
			want = 429
		}
		if w.Code != want || w.Body.Len() != 0 {
			t.Fatal(i, w.Code, w.Body.String())
		}
	}
	// A well-formed header set is throttled before the nil database is touched.
	r := httptest.NewRequest("POST", "/v1/report", nil)
	r.RemoteAddr = "192.0.2.1:9999"
	r.Header.Set(proto.NodeHeader, "node")
	r.Header.Set(proto.SeqHeader, "1")
	r.Header.Set(proto.TsHeader, strconv.FormatInt(now.Unix(), 10))
	r.Header.Set(proto.SigHeader, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	now = now.Add(50 * time.Millisecond)
	if !h.allowIP("192.0.2.1", now) || h.allowIP("192.0.2.1", now) {
		t.Fatal("20/s refill")
	}
	if !h.allowIP("192.0.2.2", now) {
		t.Fatal("independent IP")
	}
}
func TestIPBoundAndIdleEviction(t *testing.T) {
	h := New(nil, nil)
	h.MaxIPs = 3
	now := time.Unix(1700000000, 0)
	for _, ip := range []string{"a", "b", "c", "a", "d"} {
		h.allowIP(ip, now)
	}
	if len(h.ips) != 3 || h.ips["b"] != nil || h.ips["a"] == nil {
		t.Fatal("LRU bound", h.ips)
	}
	h.allowIP("new", now.Add(h.IPIdle))
	if len(h.ips) != 1 {
		t.Fatal("idle entries retained", len(h.ips))
	}
}
func TestAggregatedRejectionLogging(t *testing.T) {
	h := New(nil, nil)
	now := time.Unix(1700000000, 0)
	h.Now = func() time.Time { return now }
	calls := 0
	h.Logf = func(format string, args ...any) { calls++ }
	for range 1000 {
		h.fail(httptest.NewRecorder(), 401, "signature")
	}
	if calls != 0 {
		t.Fatal("per-request logging")
	}
	now = now.Add(time.Minute)
	h.LogFailures()
	for range 1000 {
		h.fail(httptest.NewRecorder(), 401, "signature")
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	now = now.Add(time.Minute)
	h.LogFailures()
	if calls != 2 || h.FailureCounts()["signature"] != 2000 {
		t.Fatal(calls, h.FailureCounts())
	}
	now = now.Add(time.Minute)
	h.LogFailures()
	if calls != 2 {
		t.Fatal("empty log")
	}
}
func TestInternalFailures503(t *testing.T) {
	for _, failure := range []string{"lookup", "write", "corrupt-seq"} {
		t.Run(failure, func(t *testing.T) {
			s, err := store.Open(filepath.Join(t.TempDir(), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			now := time.Unix(1700000000, 0)
			if err = s.AddNode("node", pub, now); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "lookup":
				s.Close()
			case "write":
				_, err = s.DB.Exec(`DROP TABLE metrics`)
			case "corrupt-seq":
				_, err = s.DB.Exec(`UPDATE nodes SET last_seq='invalid'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			h := New(s, nil)
			h.Now = func() time.Time { return now }
			body, _ := json.Marshal(proto.Report{Version: 1, Bin: "sha256:" + strings.Repeat("a", 64), OS: "linux", Arch: "amd64"})
			r := httptest.NewRequest(http.MethodPost, "/v1/report", bytes.NewReader(body))
			r.Header.Set(proto.NodeHeader, "node")
			r.Header.Set(proto.SeqHeader, "1")
			r.Header.Set(proto.TsHeader, strconv.FormatInt(now.Unix(), 10))
			r.Header.Set(proto.SigHeader, proto.Sign(key, "node", 1, now.Unix(), body))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 503 || w.Body.Len() != 0 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
