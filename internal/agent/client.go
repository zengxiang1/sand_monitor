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
	config Config
	key    ed25519.PrivateKey
	http   *http.Client
	mu     sync.Mutex
	seq    uint64
	Now    func() time.Time
}

// An optional transport supports embedding and socket-free integration tests.
// Redirect policy, response handling and timeout remain fixed by this client.
func NewClient(c Config, key ed25519.PrivateKey, transport ...http.RoundTripper) (*Client, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key")
	}
	client := &Client{config: c, key: key, Now: time.Now, http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if len(transport) > 1 {
		return nil, fmt.Errorf("at most one transport is allowed")
	}
	if len(transport) == 1 {
		client.http.Transport = transport[0]
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
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.Server, "/")+"/v1/report", bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proto.NodeHeader, c.config.Name)
	req.Header.Set(proto.SeqHeader, strconv.FormatUint(seq, 10))
	req.Header.Set(proto.TsHeader, strconv.FormatInt(ts, 10))
	req.Header.Set(proto.SigHeader, proto.Sign(c.key, c.config.Name, seq, ts, body))
	resp, e := c.http.Do(req)
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
