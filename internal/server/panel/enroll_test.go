package panel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"wanglou/internal/agent"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func (f *fixture) pendingCode(t *testing.T, name string) (enrollment, string) {
	t.Helper()
	w := f.request("POST", "/enroll/codes", url.Values{"csrf": {f.csrf}, "name": {name}, "note": {"新加坡 · 2C4G"}}, true)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	state, err := readEnrollment(u.Query().Get("state"), f.csrf, f.h.signingKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`).MatchString(state.Code) || state.Hash != store.TokenHash(state.Code) || state.Expires != f.now.Add(10*time.Minute).Unix() {
		t.Fatal("code format")
	}
	var hash string
	if err = f.s.DB.QueryRow(`SELECT code_hash FROM enroll_codes WHERE name=?`, name).Scan(&hash); err != nil || hash != state.Hash {
		t.Fatal(hash, err)
	}
	return state, location
}
func (f *fixture) submitCode(t *testing.T, code, line string, want int) {
	t.Helper()
	body, err := json.Marshal(struct {
		Code   string `json:"code"`
		Pubkey string `json:"pubkey"`
	}{code, line})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	f.h.Ingest.ServeHTTP(w, r)
	if w.Code != want || w.Body.Len() != 0 {
		t.Fatal("enroll", w.Code, w.Body)
	}
}
func TestEnrollmentLifecycleWithRealAgent(t *testing.T) {
	f := setup(t)
	state, location := f.pendingCode(t, "new-node")
	f.report(t, "new-node", sampleReport(), 401)
	wrongLine := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "other-node")
	f.submitCode(t, state.Code, wrongLine, 400)
	server, httpClient := testutil.NewServer(t, f.h.Ingest)
	c, err := agent.NewClient(agent.Config{Name: "new-node", Server: server.URL, Key: "unused", StateFile: filepath.Join(t.TempDir(), "seq"), Interval: 5 * time.Second, InsecureHTTP: true}, f.key, httpClient.Transport)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Enroll(context.Background(), state.Code); err != nil {
		t.Fatal(err)
	}
	if err = c.Enroll(context.Background(), state.Code); err == nil {
		t.Fatal("code reused")
	}
	if _, err = f.s.Node("new-node"); err != sql.ErrNoRows {
		t.Fatal("node exists before confirmation", err)
	}
	f.report(t, "new-node", sampleReport(), 401)
	w := f.request("GET", location+"&fragment=1", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已收到公钥") || strings.Contains(w.Body.String(), "<!doctype") {
		t.Fatal(w.Code, w.Body)
	}
	form := url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {input(t, w.Body.String(), "pubkey")}, "matched": {"yes"}}
	original := form.Get("pubkey")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	form.Set("pubkey", proto.PublicKeyLine(pub, "new-node"))
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 400 {
		t.Fatal("tampered key", w.Code)
	}
	form.Set("pubkey", original)
	form.Del("matched")
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 400 {
		t.Fatal("unchecked fingerprint", w.Code)
	}
	form.Set("matched", "yes")
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	if w = f.request("GET", w.Header().Get("Location"), nil, true); w.Code != 200 || !strings.Contains(w.Body.String(), "已启用，正在等待第一次上报") {
		t.Fatal(w.Code, w.Body)
	}
	n, err := f.s.Node("new-node")
	if err != nil || n.Note != state.Note {
		t.Fatal(n, err)
	}
	f.report(t, "new-node", sampleReport(), 204)
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 400 {
		t.Fatal("confirmation replay")
	}
	f.submitCode(t, state.Code, original, 404)
	var count int
	if err = f.s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action IN ('node_enable','enroll_code')`).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}
func TestEnrollmentExpiryReplacementAndPaste(t *testing.T) {
	f := setup(t)
	f.submitCode(t, "XXXX-XXXX", proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "fresh"), 404)
	state, location := f.pendingCode(t, "fresh")
	line := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "fresh")
	f.submitCode(t, "XXXX-XXXX", line, 400)
	f.submitCode(t, state.Code, line, 204)
	w := f.request("GET", location, nil, true)
	form := url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {line}, "matched": {"yes"}}
	replacement, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := f.s.DB.Exec(`UPDATE enroll_codes SET pubkey=? WHERE code_hash=?`, proto.PublicKeyLine(replacement, "fresh"), state.Hash); err != nil {
		t.Fatal(err)
	}
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 400 {
		t.Fatal("replaced DB key", w.Code)
	}
	f.now = f.now.Add(601 * time.Second)
	f.submitCode(t, state.Code, line, 404)
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 400 {
		t.Fatal("expired confirmation", w.Code)
	}
	if w = f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {"pasted"}, "pubkey": {line}}, true); w.Code != 400 {
		t.Fatal("name mismatch", w.Code)
	}
	pasted := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "pasted")
	var before, after int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM enroll_codes`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	w = f.request("POST", "/enroll/preview", url.Values{"csrf": {f.csrf}, "name": {"pasted"}, "note": {"test"}, "pubkey": {pasted}}, true)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM enroll_codes`).Scan(&after); err != nil || before != after {
		t.Fatal("paste preview wrote DB", err)
	}
	if _, err := f.s.Node("pasted"); err != sql.ErrNoRows {
		t.Fatal("paste created node early", err)
	}
	w = f.request("GET", w.Header().Get("Location"), nil, true)
	form = url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {pasted}, "matched": {"yes"}}
	token := form.Get("state")
	form.Set("state", token+"x")
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 400 {
		t.Fatal("tampered preview", w.Code)
	}
	form.Set("state", token)
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := f.s.Node("pasted"); err != nil {
		t.Fatal(err)
	}
}
func TestEnrollLimits(t *testing.T) {
	f := setup(t)
	state, _ := f.pendingCode(t, "limited")
	line := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), "limited")
	for i := 0; i < 10; i++ {
		f.submitCode(t, "XXXX-XXXX", line, 400)
	}
	f.submitCode(t, state.Code, line, 429)
	f.now = f.now.Add(time.Minute)
	r := httptest.NewRequest("POST", "/enroll", io.NopCloser(strings.NewReader(strings.Repeat("x", 4097))))
	w := httptest.NewRecorder()
	f.h.Ingest.ServeHTTP(w, r)
	if w.Code != 413 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body)
	}
	f.submitCode(t, state.Code, line, 204)
}
func TestHistoryBuckets120000Rows(t *testing.T) {
	f := setup(t)
	_, err := f.s.DB.Exec(`WITH RECURSIVE samples(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM samples WHERE i<119999) INSERT INTO metrics(node,ts,cpu,mem_used,mem_total,disk_used,disk_total,net_tx,net_rx) SELECT 'node',?+i*5,i%100,512,1024,20,40,1024,2048 FROM samples`, f.now.Add(-7*24*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Rollup(context.Background(), f.now); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	points, err := f.h.history("node", 7*24*time.Hour)
	elapsed := time.Since(start)
	if err != nil || len(points) > 360 || len(points) < 350 || elapsed >= 200*time.Millisecond {
		t.Fatalf("points=%d duration=%s err=%v", len(points), elapsed, err)
	}
	if points[0].Mem != 50 || points[0].Disk != 50 {
		t.Fatal("bucket averages")
	}
	for _, duration := range []time.Duration{time.Hour, 24 * time.Hour} {
		points, err = f.h.history("node", duration)
		if err != nil || len(points) > 360 {
			t.Fatal(len(points), err)
		}
	}
	start = time.Now()
	w := f.request("GET", "/nodes/node?range=7d", nil, true)
	elapsed = time.Since(start)
	if w.Code != 200 || elapsed >= 200*time.Millisecond {
		t.Fatal("chart render", w.Code, elapsed)
	}
	t.Logf("120000 rows: 7d chart render %s, <=360 points", elapsed)
}

func TestEnrollmentStateEncryption(t *testing.T) {
	now := time.Unix(2000000000, 0)
	csrf := randomToken(32)
	key := randomToken(32)
	state := enrollment{Name: "test-node", Note: "test note", Code: "K7QF-29XM", Hash: store.TokenHash("K7QF-29XM"), Expires: now.Add(10 * time.Minute).Unix()}
	token := sealEnrollment(state, csrf, key)
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, state.Code) || bytes.Contains(decoded, []byte(state.Code)) || json.Valid(decoded) {
		t.Fatal("enrollment code visible in token")
	}
	got, err := readEnrollment(token, csrf, key, now)
	if err != nil || got != state {
		t.Fatal("encrypted state did not round trip", err)
	}
	if token == sealEnrollment(state, csrf, key) {
		t.Fatal("nonce reused")
	}
	for _, tc := range []struct{ csrf, key string }{{randomToken(32), key}, {csrf, randomToken(32)}} {
		if _, err = readEnrollment(token, tc.csrf, tc.key, now); err == nil {
			t.Fatal("wrong session or key accepted")
		}
	}
	decoded[len(decoded)-1] ^= 1
	if _, err = readEnrollment(base64.RawURLEncoding.EncodeToString(decoded), csrf, key, now); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	for _, invalid := range []string{"", "not-a-token", base64.RawURLEncoding.EncodeToString([]byte("short"))} {
		if _, err = readEnrollment(invalid, csrf, key, now); err == nil {
			t.Fatal("invalid ciphertext accepted")
		}
	}
	got, err = readEnrollment(token, csrf, key, now.Add(10*time.Minute))
	if err == nil || got.Name != state.Name {
		t.Fatal("expiry not checked")
	}
}
func TestEnrollRefreshAndStaleState(t *testing.T) {
	f := setup(t)
	w := f.request("GET", "/enroll", nil, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), `data-refresh="true"`) {
		t.Fatal("step 1 should not refresh", w.Code)
	}
	state, location := f.pendingCode(t, "pending-node")
	for _, suffix := range []string{"", "&fragment=1"} {
		w = f.request("GET", location+suffix, nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `data-panel-refresh="true"`) {
			t.Fatal("waiting code should refresh", w.Code, w.Body)
		}
		if suffix == "" && !strings.Contains(w.Body.String(), `data-refresh="true"`) {
			t.Fatal("waiting page did not enable polling")
		}
	}
	line := proto.PublicKeyLine(f.key.Public().(ed25519.PublicKey), state.Name)
	f.submitCode(t, state.Code, line, 204)
	for _, suffix := range []string{"", "&fragment=1"} {
		w = f.request("GET", location+suffix, nil, true)
		if w.Code != 200 || strings.Contains(w.Body.String(), `data-refresh="true"`) || !strings.Contains(w.Body.String(), `data-panel-refresh="false"`) {
			t.Fatal("received key should stop polling", w.Code, w.Body)
		}
	}
	form := url.Values{"csrf": {f.csrf}, "state": {input(t, w.Body.String(), "state")}, "pubkey": {line}, "matched": {"yes"}}
	if w = f.request("POST", "/enroll/confirm", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	w = f.request("GET", location, nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<!doctype html>") || !strings.Contains(w.Body.String(), "已确认") || strings.Contains(w.Body.String(), `data-refresh="true"`) {
		t.Fatal("confirmed URL did not render friendly page", w.Code, w.Body)
	}
	if input(t, w.Body.String(), "pubkey") != "" {
		t.Fatal("confirmed state still offers a key")
	}
	_, location = f.pendingCode(t, "expired-node")
	f.now = f.now.Add(601 * time.Second)
	for _, suffix := range []string{"", "&fragment=1"} {
		w = f.request("GET", location+suffix, nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "已失效") || !strings.Contains(w.Body.String(), "接入一台新服务器") || strings.Contains(w.Body.String(), `data-refresh="true"`) || !strings.Contains(w.Body.String(), `data-panel-refresh="false"`) {
			t.Fatal("expired URL did not render friendly page", w.Code, w.Body)
		}
	}
	w = f.request("GET", "/enroll?state=invalid", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已失效") {
		t.Fatal("invalid state page", w.Code, w.Body)
	}
}
