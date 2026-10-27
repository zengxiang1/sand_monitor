package heartbeat

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
	"wanglou/internal/testutil"
)

func TestHeartbeatGatedByAllLoops(t *testing.T) {
	calls := 0
	redirect := false
	s, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.ContentLength > 0 || r.URL.RawQuery != "" {
			t.Error("heartbeat sent data")
		}
		if redirect {
			w.Header().Set("Location", "/other")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(204)
	}))
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	l := Loop{URL: s.URL, Client: client}
	now := time.Unix(2000000000, 0)
	if got := l.Status(now); got != "等待首次发送" {
		t.Fatal(got)
	}
	if err := l.Check(context.Background(), now); err != nil || calls != 0 {
		t.Fatal(err, calls)
	}
	if got := l.Status(now); got != "失败（尚未成功）" {
		t.Fatal(got)
	}
	l.Offline.Store(now.Unix())
	if err := l.Check(context.Background(), now); err != nil || calls != 0 {
		t.Fatal(err, calls)
	}
	l.Reminders.Store(now.Unix())
	l.Rollup.Store(now.Unix())
	if err := l.Check(context.Background(), now); err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	if l.Status(now) != "0 分钟前" {
		t.Fatal(l.Status(now))
	}
	for _, stuck := range []string{"offline", "reminders", "rollup"} {
		l.Offline.Store(now.Unix())
		l.Reminders.Store(now.Unix())
		l.Rollup.Store(now.Unix())
		if stuck == "offline" {
			l.Offline.Store(now.Add(-121 * time.Second).Unix())
		} else if stuck == "reminders" {
			l.Reminders.Store(now.Add(-121 * time.Second).Unix())
		} else {
			l.Rollup.Store(now.Add(-301 * time.Second).Unix())
		}
		if err := l.Check(context.Background(), now); err != nil || calls != 1 {
			t.Fatal(stuck, err, calls)
		}
		if !strings.Contains(l.Status(now), "失败") {
			t.Fatal(l.Status(now))
		}
	}
	l.Offline.Store(now.Unix())
	l.Reminders.Store(now.Unix())
	l.Rollup.Store(now.Unix())
	redirect = true
	if err := l.Check(context.Background(), now); err == nil || calls != 2 {
		t.Fatal("redirect followed", err, calls)
	}
	if (&Loop{}).Status(now) != "未配置" {
		t.Fatal("unconfigured")
	}
}
