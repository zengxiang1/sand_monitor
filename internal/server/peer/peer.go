package peer

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/store"
)

type Loop struct {
	URL           string
	Transport     http.RoundTripper
	Notifiers     func() []alert.Notifier
	mu            sync.Mutex
	failures      int
	down, success time.Time
}

func (l *Loop) Check(ctx context.Context, now time.Time) {
	if l.URL == "" {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: l.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(l.URL, "/")+"/healthz", nil)
	healthy := false
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			healthy = resp.StatusCode >= 200 && resp.StatusCode < 300
		}
	}
	l.mu.Lock()
	message := ""
	u, _ := url.Parse(l.URL)
	if healthy {
		l.success = now
		l.failures = 0
		if !l.down.IsZero() {
			message = "对端接收端 " + u.Host + " 已恢复"
			l.down = time.Time{}
		}
	} else {
		l.failures++
		if l.failures == 4 {
			l.down = now
			message = "对端接收端 " + u.Host + " 不可达"
		}
	}
	l.mu.Unlock()
	if message == "" {
		return
	}
	notifiers := []alert.Notifier{}
	if l.Notifiers != nil {
		notifiers = l.Notifiers()
	}
	for _, notifier := range notifiers {
		var err error
		for attempt := 0; attempt < 4; attempt++ {
			if ctx.Err() != nil {
				return
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = notifier.Notify(attemptCtx, store.Event{Time: now.Unix(), Kind: "peer", Detail: message})
			cancel()
			if err == nil {
				break
			}
			if attempt < 3 {
				timer := time.NewTimer(time.Second * time.Duration(1<<attempt))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
		if err != nil {
			log.Printf("peer notification failed: %s", notifier.Kind())
		}
	}
}
func (l *Loop) Status(now time.Time) string {
	if l.URL == "" {
		return "未配置"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	u, _ := url.Parse(l.URL)
	if !l.down.IsZero() {
		return fmt.Sprintf("%s · 不可达 · %d 分钟", u.Host, max(0, int(now.Sub(l.down).Minutes())))
	}
	if l.failures > 0 {
		return fmt.Sprintf("%s · 连续 %d 次检查失败", u.Host, l.failures)
	}
	if l.success.IsZero() {
		return u.Host + " · 等待首次检查"
	}
	return fmt.Sprintf("%s · 正常 · %d 秒前", u.Host, max(0, int(now.Sub(l.success).Seconds())))
}
func (l *Loop) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.Check(ctx, now)
		}
	}
}
