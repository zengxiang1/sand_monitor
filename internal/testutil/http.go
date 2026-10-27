// Package testutil supplies an httptest server over real HTTP transports backed
// by net.Pipe. This runs full HTTP request/response handling even in sandboxes
// that prohibit binding loopback sockets. No test is skipped in those sandboxes.
package testutil

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type listener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *listener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *listener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }

type conn struct{ net.Conn }

func (c conn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321} }
func NewServer(t *testing.T, h http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	l := &listener{connections: make(chan net.Conn), done: make(chan struct{})}
	server := &httptest.Server{Listener: l, Config: &http.Server{Handler: h}}
	server.Start()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, peer := net.Pipe()
		select {
		case l.connections <- conn{peer}:
			return client, nil
		case <-ctx.Done():
			client.Close()
			peer.Close()
			return nil, ctx.Err()
		case <-l.done:
			client.Close()
			peer.Close()
			return nil, net.ErrClosed
		}
	}}
	client := &http.Client{Transport: transport}
	t.Cleanup(func() { transport.CloseIdleConnections(); server.Close() })
	return server, client
}
