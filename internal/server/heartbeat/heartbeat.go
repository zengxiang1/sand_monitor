package heartbeat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type Loop struct {
	URL                        string
	Client                     *http.Client
	Offline, Reminders, Rollup atomic.Int64
	success                    atomic.Int64
	failed                     atomic.Bool
}

func (l *Loop) Check(ctx context.Context, now time.Time) error {
	if l.URL == "" {
		return nil
	}
	healthy := func(ts int64) bool { return ts > 0 && now.Unix()-ts <= 120 }
	if !healthy(l.Offline.Load()) || !healthy(l.Reminders.Load()) || l.Rollup.Load() == 0 || now.Unix()-l.Rollup.Load() > 300 {
		l.failed.Store(true)
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, "GET", l.URL, nil)
	if err != nil {
		l.failed.Store(true)
		return err
	}
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, err := client.Do(request)
	if err != nil {
		l.failed.Store(true)
		return fmt.Errorf("heartbeat transport failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		l.failed.Store(true)
		return fmt.Errorf("heartbeat status %d", response.StatusCode)
	}
	l.success.Store(now.Unix())
	l.failed.Store(false)
	return nil
}
func (l *Loop) Status(now time.Time) string {
	if l.URL == "" {
		return "未配置"
	}
	ts := l.success.Load()
	minutes := max(int64(0), (now.Unix()-ts)/60)
	if ts == 0 {
		if l.failed.Load() {
			return "失败（尚未成功）"
		}
		return "等待首次发送"
	}
	if l.failed.Load() || now.Unix()-l.Offline.Load() > 120 || now.Unix()-l.Reminders.Load() > 120 || l.Rollup.Load() == 0 || now.Unix()-l.Rollup.Load() > 300 {
		return fmt.Sprintf("失败（%d 分钟前成功过）", minutes)
	}
	return fmt.Sprintf("%d 分钟前", minutes)
}
