// Package ingest is the single, signed, uplink-only report endpoint.
package ingest

import (
	"bytes"
	"container/list"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/requestip"
	"wanglou/internal/server/store"
)

var errRate = errors.New("rate limited")
var errReport = errors.New("invalid report")

type bucket struct {
	tokens float64
	at     time.Time
}
type ipBucket struct {
	name   string
	bucket bucket
	seen   time.Time
}
type Handler struct {
	TrustedProxies  []netip.Prefix
	IPRate, IPBurst float64
	MaxIPs          int
	IPIdle          time.Duration
	Logf            func(string, ...any)
	ips             map[string]*list.Element
	lru             list.List
	pendingFailures map[string]uint64
	lastLog         time.Time
	Store           *store.Store
	Alerts          *alert.Engine
	Now             func() time.Time
	Rate            float64
	Burst           float64
	mu              sync.Mutex
	buckets         map[string]bucket
	failures        map[string]uint64
	accepted        uint64
	enrollIPs       map[string]bucket
}

func New(s *store.Store, a *alert.Engine) *Handler {
	return &Handler{Store: s, Alerts: a, Now: time.Now, Rate: 2, Burst: 5, IPRate: 20, IPBurst: 40, MaxIPs: 4096, IPIdle: 5 * time.Minute, Logf: log.Printf, ips: map[string]*list.Element{}, pendingFailures: map[string]uint64{}, buckets: map[string]bucket{}, failures: map[string]uint64{}, enrollIPs: map[string]bucket{}}
}

type Statistics struct {
	Accepted uint64
	Rejected map[string]uint64
}

func (h *Handler) Stats() Statistics {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := Statistics{Accepted: h.accepted, Rejected: map[string]uint64{}}
	for k, v := range h.failures {
		out.Rejected[k] = v
	}
	return out
}
func (h *Handler) enrollment(w http.ResponseWriter, r *http.Request, ip string, now time.Time) {
	var active int
	if err := h.Store.DB.QueryRow(`SELECT count(*) FROM enroll_codes WHERE expires_at>? AND used_at=0`, now.Unix()).Scan(&active); err != nil {
		h.fail(w, 503, "storage")
		return
	}
	if active == 0 {
		w.WriteHeader(404)
		return
	}
	h.mu.Lock()
	b := h.enrollIPs[ip]
	if now.Sub(b.at) >= time.Minute {
		b = bucket{at: now}
	}
	allowed := b.tokens < 10
	b.tokens++
	h.enrollIPs[ip] = b
	for address, entry := range h.enrollIPs {
		if now.Sub(entry.at) >= time.Minute {
			delete(h.enrollIPs, address)
		}
	}
	h.mu.Unlock()
	if !allowed {
		h.fail(w, 429, "enroll_rate")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		h.fail(w, 413, "enroll_body")
		return
	}
	var input struct {
		Code   string `json:"code"`
		Pubkey string `json:"pubkey"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		h.fail(w, 400, "enroll")
		return
	}
	var extra json.RawMessage
	if decoder.Decode(&extra) != io.EOF || h.Store.SubmitEnrollment(input.Code, input.Pubkey, now) != nil {
		h.fail(w, 400, "enroll")
		return
	}
	w.WriteHeader(204)
}
func (h *Handler) FailureCounts() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range h.failures {
		out[k] = v
	}
	return out
}
func (h *Handler) fail(w http.ResponseWriter, status int, reason string) {
	h.mu.Lock()
	h.failures[reason]++
	h.pendingFailures[reason]++
	h.mu.Unlock()
	h.LogFailures()
	w.WriteHeader(status)
}

// LogFailures emits aggregated deltas at most once per minute. It is also
// called by a background ticker so quiet periods do not leave counts unlogged.
func (h *Handler) LogFailures() {
	now := h.Now()
	h.mu.Lock()
	if h.lastLog.IsZero() || now.Before(h.lastLog) {
		h.lastLog = now
		h.mu.Unlock()
		return
	}
	if now.Sub(h.lastLog) < time.Minute {
		h.mu.Unlock()
		return
	}
	h.lastLog = now
	counts := h.pendingFailures
	h.pendingFailures = map[string]uint64{}
	h.mu.Unlock()
	if len(counts) > 0 {
		h.Logf("ingest rejection counts: %v", counts)
	}
}
func (h *Handler) RunLogging(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.LogFailures()
		}
	}
}
func (h *Handler) allowIP(ip string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for tail := h.lru.Back(); tail != nil; tail = h.lru.Back() {
		b := tail.Value.(*ipBucket)
		if now.Sub(b.seen) < h.IPIdle {
			break
		}
		delete(h.ips, b.name)
		h.lru.Remove(tail)
	}
	element, ok := h.ips[ip]
	if !ok {
		if len(h.ips) >= h.MaxIPs {
			tail := h.lru.Back()
			delete(h.ips, tail.Value.(*ipBucket).name)
			h.lru.Remove(tail)
		}
		element = h.lru.PushFront(&ipBucket{name: ip, bucket: bucket{tokens: h.IPBurst, at: now}, seen: now})
		h.ips[ip] = element
	}
	entry := element.Value.(*ipBucket)
	entry.seen = now
	h.lru.MoveToFront(element)
	elapsed := now.Sub(entry.bucket.at).Seconds()
	if elapsed > 0 {
		entry.bucket.tokens = min(h.IPBurst, entry.bucket.tokens+elapsed*h.IPRate)
		entry.bucket.at = now
	}
	if entry.bucket.tokens < 1 {
		return false
	}
	entry.bucket.tokens--
	return true
}
func (h *Handler) clientIP(r *http.Request) string { return requestip.ClientIP(r, h.TrustedProxies) }
func (h *Handler) allow(node string, now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buckets[node]
	if !ok {
		b = bucket{tokens: h.Burst, at: now}
	}
	elapsed := now.Sub(b.at).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * h.Rate
		if b.tokens > h.Burst {
			b.tokens = h.Burst
		}
		b.at = now
	}
	if b.tokens < 1 {
		h.buckets[node] = b
		return errRate
	}
	b.tokens--
	h.buckets[node] = b
	return nil
}
func single(r *http.Request, key string) (string, bool) {
	v := r.Header.Values(key)
	returnValue := ""
	if len(v) == 1 {
		returnValue = v[0]
	}
	return returnValue, len(v) == 1 && returnValue != ""
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := h.Now()
	ip := h.clientIP(r)
	if !h.allowIP(ip, now) {
		h.fail(w, 429, "ip_rate")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		if err := h.Store.DB.PingContext(r.Context()); err != nil {
			h.fail(w, 503, "storage")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/enroll" {
		h.enrollment(w, r, ip, now)
		return
	}
	if r.URL.Path == "/healthz" {
		h.fail(w, 400, "endpoint")
		return
	}
	if r.URL.Path != "/v1/report" {
		w.WriteHeader(404)
		return
	}
	// Read through a strict bound before inspecting any authentication headers.
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, proto.MaxBody))
	if e != nil {
		var limit *http.MaxBytesError
		if errors.As(e, &limit) {
			h.fail(w, 413, "body_limit")
		} else {
			h.fail(w, 400, "body_read")
		}
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/report" {
		h.fail(w, 400, "endpoint")
		return
	}
	node, nok := single(r, proto.NodeHeader)
	seqText, sok := single(r, proto.SeqHeader)
	tsText, tok := single(r, proto.TsHeader)
	sig, gok := single(r, proto.SigHeader)
	seq, se := strconv.ParseUint(seqText, 10, 64)
	ts, te := strconv.ParseInt(tsText, 10, 64)
	sigBytes, ge := base64.StdEncoding.Strict().DecodeString(sig)
	if !nok || !sok || !tok || !gok || !proto.ValidNode(node) || se != nil || te != nil || seqText != strconv.FormatUint(seq, 10) || tsText != strconv.FormatInt(ts, 10) || ge != nil || len(sigBytes) != 64 || base64.StdEncoding.EncodeToString(sigBytes) != sig {
		h.fail(w, 400, "headers")
		return
	}
	n, e := h.Store.Node(node)
	if errors.Is(e, sql.ErrNoRows) || (e == nil && n.RevokedAt != 0) {
		h.fail(w, 401, "node")
		return
	}
	if e != nil {
		h.fail(w, 503, "storage")
		return
	}
	if !proto.Verify(n.Pubkey, node, seq, ts, body, sig) {
		h.fail(w, 401, "signature")
		return
	}
	now = h.Now()
	if ts < now.Unix()-60 || ts > now.Unix()+60 {
		h.fail(w, 401, "timestamp")
		return
	}
	var report proto.Report
	var evaluate func(*sql.Tx, store.Node) error
	if h.Alerts != nil {
		evaluate = func(tx *sql.Tx, n store.Node) error { return h.Alerts.Report(tx, n, report, now) }
	}
	e = h.Store.Accept(node, seq, now, ip, &report, func() error {
		if err := h.allow(node, now); err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&report) != nil {
			return errReport
		}
		var extra json.RawMessage
		if decoder.Decode(&extra) != io.EOF || report.Validate() != nil {
			return errReport
		}
		return nil
	}, evaluate)
	switch {
	case e == nil:
		h.mu.Lock()
		h.accepted++
		h.mu.Unlock()
		w.WriteHeader(204)
	case errors.Is(e, errReport):
		h.fail(w, 400, "report")
	case errors.Is(e, errRate):
		h.fail(w, 429, "rate")
	case errors.Is(e, store.ErrReplay):
		h.fail(w, 401, "sequence")
	case errors.Is(e, store.ErrNode):
		h.fail(w, 401, "node")
	default:
		h.fail(w, 503, "storage")
	}
}
