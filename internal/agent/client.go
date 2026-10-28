package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"wanglou/internal/proto"
)

type Client struct {
	config        Config
	key           ed25519.PrivateKey
	http          map[string]*http.Client
	ownTransports bool
	mu            sync.Mutex
	seq           uint64
	Now           func() time.Time
}

// An optional transport supports embedding and socket-free integration tests.
// Redirect policy, response handling and timeout remain fixed by this client.
func NewClient(c Config, key ed25519.PrivateKey, transport ...http.RoundTripper) (*Client, error) {
	return newClient(c, key, nil, transport...)
}

// configure is a per-client test hook for TLS trust and shorter network timers.
func newClient(c Config, key ed25519.PrivateKey, configure func(*http.Transport), transport ...http.RoundTripper) (*Client, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key")
	}
	if len(transport) > 1 {
		return nil, fmt.Errorf("at most one transport is allowed")
	}
	base, standardTransport := http.DefaultTransport.(*http.Transport)
	client := &Client{config: c, key: key, Now: time.Now, http: make(map[string]*http.Client), ownTransports: len(transport) == 0 && standardTransport}
	for _, target := range []string{"primary", "backup"} {
		if target == "backup" && c.BackupServer == "" {
			continue
		}
		h := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if len(transport) == 1 {
			h.Transport = transport[0]
		} else if standardTransport {
			t := base.Clone()
			t.HTTP2 = &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 5 * time.Second, WriteByteTimeout: 10 * time.Second}
			if configure != nil {
				configure(t)
			}
			h.Transport = t
		} else {
			// Preserve embedding/tests that replace the global RoundTripper.
			h.Transport = http.DefaultTransport
		}
		client.http[target] = h
	}
	b, e := os.ReadFile(c.StateFile)
	if e == nil {
		client.seq, e = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	} else if os.IsNotExist(e) {
		e = nil
	}
	if e != nil {
		return nil, e
	}
	return client, nil
}

// do shares connection recovery between reports and enrollment.
func (c *Client) do(target string, req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	h := c.http[target]
	c.mu.Unlock()
	resp, err := h.Do(req)
	if err != nil {
		h.CloseIdleConnections()
		if c.ownTransports {
			c.mu.Lock()
			if c.http[target] == h {
				// HTTP/2 cancellation can return before the stream finishes
				// cleanup, so CloseIdleConnections may still see it as busy.
				// A fresh pool guarantees the next request cannot reuse it.
				next := *h
				next.Transport = h.Transport.(*http.Transport).Clone()
				c.http[target] = &next
			}
			c.mu.Unlock()
		}
	}
	return resp, err
}

func (c *Client) nextSeq() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := uint64(c.Now().UnixNano())
	if n <= c.seq {
		if c.seq == math.MaxUint64 {
			return 0, fmt.Errorf("sequence exhausted")
		}
		n = c.seq + 1
	}
	if e := os.MkdirAll(filepath.Dir(c.config.StateFile), 0700); e != nil {
		return 0, e
	}
	f, e := os.CreateTemp(filepath.Dir(c.config.StateFile), ".seq-*")
	if e != nil {
		return 0, e
	}
	defer os.Remove(f.Name())
	if _, e = fmt.Fprintf(f, "%d\n", n); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return 0, e
	}
	if e = os.Rename(f.Name(), c.config.StateFile); e != nil {
		return 0, e
	}
	d, e := os.Open(filepath.Dir(c.config.StateFile))
	if e != nil {
		return 0, e
	}
	e = d.Sync()
	_ = d.Close()
	if e != nil {
		return 0, e
	}
	c.seq = n
	return n, nil
}
func (c *Client) Send(ctx context.Context, r proto.Report) error {
	return c.SendTo(ctx, "primary", r)
}
func (c *Client) target(target string) (string, error) {
	switch target {
	case "primary":
		return c.config.Server, nil
	case "backup":
		if c.config.BackupServer != "" {
			return c.config.BackupServer, nil
		}
	}
	return "", fmt.Errorf("target %q is not configured", target)
}
func (c *Client) SendTo(ctx context.Context, target string, r proto.Report) error {
	server, e := c.target(target)
	if e != nil {
		return e
	}
	if e := r.Validate(); e != nil {
		return e
	}
	body, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(body) > proto.MaxBody {
		return fmt.Errorf("report exceeds 64 KiB")
	}
	seq, e := c.nextSeq()
	if e != nil {
		return e
	}
	ts := c.Now().Unix()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/v1/report", bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proto.NodeHeader, c.config.Name)
	req.Header.Set(proto.SeqHeader, strconv.FormatUint(seq, 10))
	req.Header.Set(proto.TsHeader, strconv.FormatInt(ts, 10))
	req.Header.Set(proto.SigHeader, proto.Sign(c.key, c.config.Name, seq, ts, body))
	resp, e := c.do(target, req)
	if e != nil {
		return e
	}
	// No response content is interpreted. Bound the drain, even on errors.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("report status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Enroll(ctx context.Context, code string) error {
	return c.EnrollTo(ctx, "primary", code)
}
func (c *Client) EnrollTo(ctx context.Context, target, code string) error {
	server, err := c.target(target)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Code   string `json:"code"`
		Pubkey string `json:"pubkey"`
	}{code, proto.PublicKeyLine(c.key.Public().(ed25519.PublicKey), c.config.Name)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(target, req)
	if err != nil {
		return fmt.Errorf("注册失败")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("注册失败")
	}
	return nil
}
