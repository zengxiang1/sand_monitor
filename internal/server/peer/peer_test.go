package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

type notifier struct {
	calls  int
	events []store.Event
	fail   bool
}

func (n *notifier) ID() string   { return "test" }
func (n *notifier) Kind() string { return "webhook" }
func (n *notifier) Notify(_ context.Context, e store.Event) error {
	n.calls++
	if n.fail {
		return errors.New("failed")
	}
	n.events = append(n.events, e)
	return nil
}
func TestPeerTransitionsAndRedirects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		status, redirects := 204, 0
		server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/base/healthz" || r.Method != "GET" {
				t.Error(r.URL, r.Method)
			}
			if r.URL.Path == "/redirect" {
				redirects++
			}
			w.Header().Set("Location", "/redirect")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "ignored")
		}))
		good, bad := &notifier{}, &notifier{fail: true}
		l := &Loop{URL: server.URL + "/base/", Transport: client.Transport, Notifiers: staticNotifiers(bad, good)}
		now := time.Unix(1700000000, 0)
		if got := (&Loop{}).Status(now); got != "未配置" {
			t.Fatal(got)
		}
		l.Check(context.Background(), now)
		if !strings.Contains(l.Status(now.Add(9*time.Second)), "正常 · 9 秒前") || strings.Contains(l.Status(now), "/base") {
			t.Fatal(l.Status(now))
		}
		for i, code := range []int{500, 302, 400} {
			status = code
			l.Check(context.Background(), now.Add(time.Duration(i+1)*30*time.Second))
			if good.calls != 0 || bad.calls != 0 {
				t.Fatal("early alarm")
			}
			if got := l.Status(now); !strings.Contains(got, fmt.Sprintf("连续 %d 次检查失败", i+1)) {
				t.Fatal(got)
			}
		}
		status = 503
		l.Check(context.Background(), now.Add(120*time.Second))
		if good.calls != 1 || bad.calls != 4 || !strings.Contains(good.events[0].Detail, "不可达") {
			t.Fatal(good, bad)
		}
		if !strings.Contains(l.Status(now.Add(180*time.Second)), "不可达 · 1 分钟") {
			t.Fatal(l.Status(now))
		}
		for range 3 {
			l.Check(context.Background(), now.Add(180*time.Second))
		}
		if good.calls != 1 || redirects != 0 {
			t.Fatal("repeat or redirect", good.calls, redirects)
		}
		status = 299
		l.Check(context.Background(), now.Add(240*time.Second))
		l.Check(context.Background(), now.Add(270*time.Second))
		if good.calls != 2 || bad.calls != 8 || !strings.Contains(good.events[1].Detail, "已恢复") {
			t.Fatal(good, bad)
		}
		if good.events[0].Node != "" || good.events[0].Kind != "peer" {
			t.Fatal(good.events)
		}
		status = 500
		for range 4 {
			l.Check(context.Background(), now.Add(300*time.Second))
		}
		if good.calls != 3 {
			t.Fatal("second outage missed")
		}
	})
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPeerTimeoutAndBoundedDiscard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		n := &notifier{}
		l := &Loop{URL: "https://peer.example.invalid", Notifiers: staticNotifiers(n), Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		for range 4 {
			l.Check(context.Background(), time.Now())
		}
		if time.Since(now) != 40*time.Second || n.calls != 1 {
			t.Fatal(time.Since(now), n.calls)
		}
	})
	body := &countingBody{}
	l := &Loop{URL: "https://peer.example.invalid", Transport: transportFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 204, Body: body}, nil })}
	l.Check(context.Background(), time.Now())
	if body.read != 4096 || !body.closed {
		t.Fatal(body)
	}
}

type countingBody struct {
	read   int
	closed bool
}

func (b *countingBody) Read(p []byte) (int, error) { b.read += len(p); return len(p), nil }
func (b *countingBody) Close() error               { b.closed = true; return nil }

type notifyFunc func(context.Context, store.Event) error

func (f notifyFunc) ID() string                                          { return "test" }
func (f notifyFunc) Kind() string                                        { return "webhook" }
func (f notifyFunc) Notify(ctx context.Context, event store.Event) error { return f(ctx, event) }

func TestPeerNotificationRetryDelays(t *testing.T) {
	for _, failures := range []int{0, 1, 2, 3, 4} {
		t.Run(strconv.Itoa(failures), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var attempts []time.Time
				n := notifyFunc(func(context.Context, store.Event) error {
					attempts = append(attempts, time.Now())
					if len(attempts) <= failures {
						return errors.New("failed")
					}
					return nil
				})
				l := &Loop{URL: "https://peer.example.invalid", failures: 3, Notifiers: staticNotifiers(n), Transport: transportFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 500, Body: http.NoBody}, nil
				})}
				started := time.Now()
				l.Check(context.Background(), started)
				want := min(failures+1, 4)
				if len(attempts) != want {
					t.Fatal("retry count", len(attempts), want)
				}
				for i := 1; i < len(attempts); i++ {
					if got, want := attempts[i].Sub(attempts[i-1]), time.Second*time.Duration(1<<(i-1)); got != want {
						t.Fatal("retry delay", got, want)
					}
				}
				if time.Now() != attempts[len(attempts)-1] {
					t.Fatal("waited after final attempt")
				}
			})
		})
	}
}

func TestPeerNotificationRetryCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		n := notifyFunc(func(context.Context, store.Event) error { calls++; return errors.New("failed") })
		l := &Loop{URL: "https://peer.example.invalid", failures: 3, Notifiers: staticNotifiers(n, n), Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: http.NoBody}, nil
		})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); l.Check(ctx, time.Now()) }()
		synctest.Wait()
		if calls != 1 {
			t.Fatal("did not wait before retry", calls)
		}
		started := time.Now()
		time.Sleep(500 * time.Millisecond)
		cancel()
		<-done
		if calls != 1 || time.Since(started) != 500*time.Millisecond {
			t.Fatal("cancellation did not interrupt retry wait", calls, time.Since(started))
		}
	})
}

func staticNotifiers(notifiers ...alert.Notifier) func() []alert.Notifier {
	return func() []alert.Notifier { return notifiers }
}

func TestPeerReadsRuntimeChannels(t *testing.T) {
	current := []alert.Notifier{}
	n := &notifier{}
	status := 503
	l := &Loop{URL: "https://peer.example.invalid", Notifiers: func() []alert.Notifier { return current }, Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	for range 4 {
		l.Check(context.Background(), time.Now())
	}
	current = []alert.Notifier{n}
	status = 204
	l.Check(context.Background(), time.Now())
	if n.calls != 1 || !strings.Contains(n.events[0].Detail, "已恢复") {
		t.Fatal("peer did not read new channels")
	}
	current = nil
	status = 503
	for range 4 {
		l.Check(context.Background(), time.Now())
	}
	if n.calls != 1 {
		t.Fatal("peer used disabled channels")
	}
}
