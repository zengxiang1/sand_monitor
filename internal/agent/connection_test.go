package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type closingTransport struct {
	roundTripFunc
	closed int
}

func (t *closingTransport) CloseIdleConnections() { t.closed++ }

func TestConnectionDiscard(t *testing.T) {
	for _, enroll := range []bool{false, true} {
		for _, status := range []int{0, 204, 401, 503, 302} {
			t.Run(fmt.Sprintf("enroll=%v/status=%d", enroll, status), func(t *testing.T) {
				c := config(t)
				c.BackupServer = "https://backup.localhost"
				key, err := GenerateKey(c.Key, false)
				if err != nil {
					t.Fatal(err)
				}
				networkError := errors.New("connection reset")
				transport := &closingTransport{roundTripFunc: func(*http.Request) (*http.Response, error) {
					if status == 0 {
						return nil, networkError
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://elsewhere"}}, Body: http.NoBody}, nil
				}}
				client, err := NewClient(c, key, transport)
				if err != nil {
					t.Fatal(err)
				}
				for i, target := range []string{"primary", "backup"} {
					if client.http[target].Transport != transport || client.http[target].Timeout != 5*time.Second {
						t.Fatal("injection or timeout changed")
					}
					if enroll {
						err = client.EnrollTo(context.Background(), target, "ABCD-EFGH")
					} else {
						err = client.SendTo(context.Background(), target, report())
					}
					if (err == nil) != (status == 204) {
						t.Fatal("unexpected result", err)
					}
					if !enroll && status == 0 && !errors.Is(err, networkError) {
						t.Fatal("network error lost", err)
					}
					want := 0
					if status == 0 {
						want = i + 1
					}
					if transport.closed != want {
						t.Fatalf("close calls = %d, want %d", transport.closed, want)
					}
				}
			})
		}
	}
}

func TestTargetTransports(t *testing.T) {
	c := config(t)
	c.BackupServer = "https://backup.localhost"
	key, err := GenerateKey(c.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(c, key)
	if err != nil {
		t.Fatal(err)
	}
	primary := client.http["primary"].Transport.(*http.Transport)
	backup := client.http["backup"].Transport.(*http.Transport)
	defaults := http.DefaultTransport.(*http.Transport)
	if primary == backup || primary == defaults || backup == defaults || primary.HTTP2 == backup.HTTP2 {
		t.Fatal("shared default pools or HTTP2 configuration")
	}
	for _, transport := range []*http.Transport{primary, backup} {
		if transport.HTTP2.SendPingTimeout != 15*time.Second || transport.HTTP2.PingTimeout != 5*time.Second || transport.HTTP2.WriteByteTimeout != 10*time.Second {
			t.Fatal("HTTP2 timers", transport.HTTP2)
		}
		if transport.Proxy == nil || transport.DialContext == nil || transport.ForceAttemptHTTP2 != defaults.ForceAttemptHTTP2 || transport.IdleConnTimeout != defaults.IdleConnTimeout || transport.TLSHandshakeTimeout != defaults.TLSHandshakeTimeout || transport.MaxIdleConns != defaults.MaxIdleConns {
			t.Fatal("default transport settings lost")
		}
	}
	// The recovery call belongs to the selected target, even when the two
	// injected stand-ins have independent CloseIdleConnections methods.
	failed := &closingTransport{roundTripFunc: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	}}
	healthy := &closingTransport{roundTripFunc: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
	}}
	client, err = NewClient(c, key, failed)
	if err != nil {
		t.Fatal(err)
	}
	client.http["backup"].Transport = healthy
	if err := client.Send(context.Background(), report()); err == nil {
		t.Fatal("expected primary failure")
	}
	if err := client.SendTo(context.Background(), "backup", report()); err != nil {
		t.Fatal(err)
	}
	if failed.closed != 1 || healthy.closed != 0 {
		t.Fatal("discard affected the wrong target", failed.closed, healthy.closed)
	}
}

func TestOwnedTransportReplacement(t *testing.T) {
	c := config(t)
	c.BackupServer = "https://backup.localhost"
	key, err := GenerateKey(c.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClient(c, key, func(transport *http.Transport) {
		transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("network unavailable")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"primary", "backup"} {
		beforePrimary, beforeBackup := client.http["primary"], client.http["backup"]
		before := client.http[target]
		if err := client.SendTo(context.Background(), target, report()); err == nil {
			t.Fatal("expected network failure")
		}
		after := client.http[target]
		if after == before || after.Transport == before.Transport {
			t.Fatal("failed target retained its connection pool")
		}
		if (target == "primary" && client.http["backup"] != beforeBackup) || (target == "backup" && client.http["primary"] != beforePrimary) {
			t.Fatal("replacement affected the other target")
		}
		transport := after.Transport.(*http.Transport)
		if after.Timeout != before.Timeout || transport.HTTP2.SendPingTimeout != 15*time.Second || transport.HTTP2.PingTimeout != 5*time.Second || transport.HTTP2.WriteByteTimeout != 10*time.Second || transport.DialContext == nil {
			t.Fatal("replacement lost client or transport settings")
		}
	}
}

// Each accepted connection can be frozen permanently. Frozen traffic is read
// and discarded in both directions, without forwarding bytes or closing sockets.
// Keeping the readers alive lets the test observe the client's eventual FIN.
// Only existing connections are frozen; the listener keeps accepting new ones.
type frozenConn struct {
	mu           sync.Mutex
	frozen       bool
	client       net.Conn
	upstream     net.Conn
	clientClosed chan struct{}
}

func (c *frozenConn) freeze() {
	c.mu.Lock()
	c.frozen = true
	c.mu.Unlock()
}

type freezingProxy struct {
	listener net.Listener
	mu       sync.Mutex
	conns    []*frozenConn
	wg       sync.WaitGroup
}

func newFreezingProxy(t *testing.T, upstream string) *freezingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezingProxy{listener: listener}
	acceptedDone := make(chan struct{})
	p.wg.Go(func() {
		defer close(acceptedDone)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := net.DialTimeout("tcp", upstream, time.Second)
			if err != nil {
				client.Close()
				t.Error(err)
				return
			}
			conn := &frozenConn{client: client, upstream: server, clientClosed: make(chan struct{})}
			p.mu.Lock()
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			for _, fromClient := range []bool{true, false} {
				p.wg.Go(func() {
					src, dst := conn.client, conn.upstream
					if !fromClient {
						src, dst = dst, src
					}
					defer src.Close()
					defer dst.Close()
					if fromClient {
						defer close(conn.clientClosed)
					}
					buf := make([]byte, 32*1024)
					for {
						n, err := src.Read(buf)
						if n > 0 {
							conn.mu.Lock()
							if !conn.frozen {
								_, err = dst.Write(buf[:n])
							}
							conn.mu.Unlock()
						}
						if err != nil {
							return
						}
					}
				})
			}
		}
	})
	t.Cleanup(func() {
		listener.Close()
		<-acceptedDone
		// No more connections can be appended after the accept loop exits.
		p.mu.Lock()
		for _, c := range p.conns {
			c.client.Close()
			c.upstream.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *freezingProxy) connections() []*frozenConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*frozenConn(nil), p.conns...)
}

func newHTTP2RecoveryClient(t *testing.T, configure func(*http.Transport)) (*Client, *freezingProxy, <-chan time.Time) {
	t.Helper()
	received := make(chan time.Time, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS.NegotiatedProtocol != "h2" {
			t.Error("request did not use TLS + HTTP/2", r.Proto)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
		received <- time.Now()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	proxy := newFreezingProxy(t, server.Listener.Addr().String())
	c := config(t)
	c.Server = "https://" + proxy.listener.Addr().String()
	key, err := GenerateKey(c.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := newClient(c, key, func(transport *http.Transport) {
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
		if configure != nil {
			configure(transport)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	client.http["primary"].Timeout = 500 * time.Millisecond
	t.Cleanup(func() { client.http["primary"].CloseIdleConnections() })
	return client, proxy, received
}

func TestHTTP2FrozenConnectionRecovery(t *testing.T) {
	for _, enroll := range []bool{false, true} {
		t.Run(fmt.Sprintf("enroll=%v", enroll), func(t *testing.T) {
			client, proxy, received := newHTTP2RecoveryClient(t, nil)
			send := func() error {
				if enroll {
					return client.Enroll(context.Background(), "ABCD-EFGH")
				}
				return client.Send(context.Background(), report())
			}
			for range 2 {
				if err := send(); err != nil {
					t.Fatal("initial request", err)
				}
				<-received
			}
			conns := proxy.connections()
			if len(conns) != 1 {
				t.Fatal("healthy HTTP2 connection not reused", len(conns))
			}
			conns[0].freeze()
			start := time.Now()
			if !enroll {
				timeout := client.http["primary"].Timeout
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				sampler := newLoopSampler(t, client.config)
				go func() {
					defer close(done)
					_ = runLoop(ctx, client.config, client, sampler, make(chan time.Time), Backoff)
				}()
				defer func() { cancel(); <-done }()
				limit := timeout + Backoff(1) + 2*time.Second
				select {
				case recovered := <-received:
					elapsed := recovered.Sub(start)
					if elapsed < timeout+Backoff(1)-100*time.Millisecond || elapsed > limit {
						t.Fatal("automatic recovery outside one timeout + one backoff + 2s", elapsed)
					}
				case <-time.After(limit):
					t.Fatal("no automatic recovery without a periodic tick")
				}
				if got := len(proxy.connections()); got != len(conns)+1 {
					t.Fatal("retry must establish one new TCP/TLS connection", got)
				}
				return
			}
			err := send()
			elapsed := time.Since(start)
			if err == nil || (!enroll && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("frozen request must time out", err)
			}
			if elapsed < 400*time.Millisecond || elapsed > 2500*time.Millisecond {
				t.Fatal("request timeout outside generous bounds", elapsed)
			}
			// Use the unchanged production backoff, then retry exactly once.
			time.Sleep(Backoff(1))
			if err := send(); err != nil {
				t.Fatal("first retry did not recover", err, "connections", len(proxy.connections()))
			}
			if got := len(proxy.connections()); got != len(conns)+1 {
				t.Fatal("retry must establish one new TCP/TLS connection", got)
			}
			if elapsed := time.Since(start); elapsed > client.http["primary"].Timeout+Backoff(1)+2*time.Second {
				t.Fatal("recovery exceeded one timeout + one backoff + 2s", elapsed)
			}
			t.Logf("timed out in %v; recovered in %v using connection #2", elapsed, time.Since(start))
		})
	}
}

func TestHTTP2IdleHeartbeat(t *testing.T) {
	const sendPing, ping = 300 * time.Millisecond, 200 * time.Millisecond
	client, proxy, _ := newHTTP2RecoveryClient(t, func(transport *http.Transport) {
		transport.HTTP2.SendPingTimeout = sendPing
		transport.HTTP2.PingTimeout = ping
	})
	if err := client.Send(context.Background(), report()); err != nil {
		t.Fatal(err)
	}
	conns := proxy.connections()
	if len(conns) != 1 {
		t.Fatal("expected one connection", len(conns))
	}
	conns[0].freeze()
	start := time.Now()
	// No requests, cancellation or CloseIdleConnections until the observation.
	select {
	case <-conns[0].clientClosed:
		t.Logf("idle heartbeat closed client socket in %v", time.Since(start))
	case <-time.After(sendPing + ping + 2*time.Second):
		t.Fatal("heartbeat did not close frozen idle HTTP2 socket")
	}
	if got := len(proxy.connections()); got != 1 {
		t.Fatal("heartbeat unexpectedly dialed a new connection", got)
	}
	if err := client.Send(context.Background(), report()); err != nil {
		t.Fatal("request after heartbeat", err)
	}
	if got := len(proxy.connections()); got != 2 {
		t.Fatal("heartbeat did not remove dead connection", got)
	}
}
