package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/agent/collect"
	"wanglou/internal/proto"
)

func newLoopSampler(t *testing.T, c Config) *sampleCounter {
	t.Helper()
	collector, err := collect.NewWithState(report().Bin, c.StateFile+".logins.json", collect.Options{WtmpPath: filepath.Join(t.TempDir(), "absent")}, c.StateFile+".backup.logins.json")
	if err != nil {
		t.Fatal(err)
	}
	return &sampleCounter{Collector: collector}
}

func TestLoopRetryRefreshAndIsolation(t *testing.T) {
	for _, backup := range []bool{false, true} {
		t.Run(fmt.Sprintf("backup=%v", backup), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := config(t)
				if backup {
					c.BackupServer = "https://backup.localhost"
				}
				key, err := GenerateKey(c.Key, false)
				if err != nil {
					t.Fatal(err)
				}
				type sent struct {
					report proto.Report
					ts     int64
				}
				reports := make(chan sent, 4)
				var backupCalls atomic.Int32
				primaryCalls := 0
				client, err := NewClient(c, key, roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Host == "backup.localhost" {
						backupCalls.Add(1)
						return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
					}
					var r proto.Report
					if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
						t.Error(err)
					}
					ts, err := strconv.ParseInt(req.Header.Get(proto.TsHeader), 10, 64)
					if err != nil {
						t.Error(err)
					}
					reports <- sent{r, ts}
					primaryCalls++
					status := 204
					if primaryCalls == 1 {
						status = 503
					}
					return &http.Response{StatusCode: status, Body: http.NoBody}, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				sampler := newLoopSampler(t, c)
				ticks := make(chan time.Time)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); _ = runLoop(ctx, c, client, sampler, ticks, Backoff) }()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				time.Sleep(Backoff(1) - time.Nanosecond)
				synctest.Wait()
				if len(reports) != 1 {
					t.Fatal("retry before ready", len(reports))
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if len(reports) != 2 || sampler.count.Load() != 2 {
					t.Fatal("retry did not resample automatically", len(reports), sampler.count.Load())
				}
				first, second := <-reports, <-reports
				if first.report.Up == second.report.Up || first.ts == second.ts {
					t.Fatal("retry reused sample or timestamp", first, second)
				}
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				if len(reports) != 0 || (backup && backupCalls.Load() != 1) || (!backup && backupCalls.Load() != 0) {
					t.Fatal("unexpected extra send after recovery", len(reports), backupCalls.Load())
				}
				ticks <- time.Now()
				synctest.Wait()
				if len(reports) != 1 || (backup && backupCalls.Load() != 2) {
					t.Fatal("periodic sends did not resume", len(reports), backupCalls.Load())
				}
				cancel()
				<-done
			})
		})
	}
}

func TestLoopRetryBackoffAndBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := config(t)
		key, err := GenerateKey(c.Key, false)
		if err != nil {
			t.Fatal(err)
		}
		starts := make(chan time.Time, 10)
		var active atomic.Int32
		release := make(chan struct{})
		client, err := NewClient(c, key, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if active.Add(1) != 1 {
				t.Error("overlapping requests", active.Load())
			}
			defer active.Add(-1)
			starts <- time.Now()
			select {
			case <-release:
				return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}))
		if err != nil {
			t.Fatal(err)
		}
		sampler := newLoopSampler(t, c)
		ticks := make(chan time.Time)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = runLoop(ctx, c, client, sampler, ticks, Backoff) }()
		defer func() { cancel(); <-done }()
		synctest.Wait()
		if len(starts) != 1 {
			t.Fatal("missing initial request", len(starts))
		}
		<-starts
		for i, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second} {
			time.Sleep(2 * time.Second)
			ticks <- time.Now()
			synctest.Wait()
			if active.Load() != 1 || len(starts) != 0 || int(sampler.count.Load()) != i+1 {
				t.Fatal("sent or sampled while busy", active.Load(), len(starts), sampler.count.Load())
			}
			failedAt := time.Now()
			release <- struct{}{}
			synctest.Wait()
			time.Sleep(delay - time.Nanosecond)
			ticks <- time.Now()
			synctest.Wait()
			if active.Load() != 0 || len(starts) != 0 {
				t.Fatal("sent before backoff ended", i, active.Load(), len(starts))
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if active.Load() != 1 || len(starts) != 1 {
				t.Fatal("missing automatic retry", i, active.Load(), len(starts))
			}
			started := <-starts
			if started.Sub(failedAt) != delay {
				t.Fatal("incorrect retry backoff", i, started, failedAt)
			}
		}
		cancel()
		<-done
		if active.Load() != 0 {
			t.Fatal("request still running after exit", active.Load())
		}
	})
}

func TestLoopCancelRetry(t *testing.T) {
	for _, beforeStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("before-start=%v", beforeStart), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := config(t)
				key, err := GenerateKey(c.Key, false)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				client, err := NewClient(c, key, roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				sampler := newLoopSampler(t, c)
				ticks := make(chan time.Time, 1)
				ctx, cancel := context.WithCancel(context.Background())
				if beforeStart {
					cancel()
				}
				done := make(chan struct{})
				go func() { defer close(done); _ = runLoop(ctx, c, client, sampler, ticks, Backoff) }()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				cancel()
				<-done
				ticks <- time.Now()
				time.Sleep(time.Minute)
				synctest.Wait()
				want := 1
				if beforeStart {
					want = 0
				}
				if calls != want || int(sampler.count.Load()) != want {
					t.Fatal("sent after cancellation", calls, sampler.count.Load())
				}
			})
		})
	}
}

func TestLoopOutagePerTargetAndCompatibility(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := config(t)
				c.BackupServer = "https://backup.localhost"
				key, err := GenerateKey(c.Key, false)
				if err != nil {
					t.Fatal(err)
				}
				type sent struct {
					target string
					at     int64
					outage *proto.Outage
				}
				reports := make(chan sent, 20)
				calls := map[string]int{}
				var mu sync.Mutex
				client, err := NewClient(c, key, roundTripFunc(func(req *http.Request) (*http.Response, error) {
					var r proto.Report
					if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
						t.Error(err)
					}
					target := req.URL.Host
					reports <- sent{target, time.Now().Unix(), r.Outage}
					mu.Lock()
					calls[target]++
					n := calls[target]
					mu.Unlock()
					status := 204
					if target == "backup.localhost" && n <= 1 || target != "backup.localhost" && (n <= 2 || n == 5) {
						status = 503
					}
					if legacy && target != "backup.localhost" && r.Outage != nil {
						status = 400
					}
					// Timeouts must count from the start, rather than the failed response.
					time.Sleep(time.Second)
					return &http.Response{StatusCode: status, Body: http.NoBody}, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				ticks := make(chan time.Time)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				sampler := newLoopSampler(t, c)
				go func() { defer close(done); _ = runLoop(ctx, c, client, sampler, ticks, Backoff) }()
				defer func() { cancel(); <-done }()
				time.Sleep(10 * time.Second)
				synctest.Wait()
				for range 3 {
					ticks <- time.Now()
					time.Sleep(10 * time.Second)
					synctest.Wait()
				}
				cancel()
				<-done
				close(reports)
				byTarget := map[string][]sent{}
				for r := range reports {
					byTarget[r.target] = append(byTarget[r.target], r)
				}
				for target, sent := range byTarget {
					isBackup := target == "backup.localhost"
					wantCalls := 7
					if isBackup {
						wantCalls = 5
					}
					if len(sent) != wantCalls {
						t.Fatal(target, len(sent), wantCalls)
					}
					for i, r := range sent {
						failures := 0
						since := sent[0].at
						if i == 1 {
							failures = 1
						}
						if !isBackup && i == 2 && !legacy {
							failures = 2
						}
						if !isBackup && i == 5 && !legacy {
							failures, since = 1, sent[4].at
						}
						if failures == 0 && r.outage != nil || failures > 0 && (r.outage == nil || r.outage.Failures != failures || r.outage.Since != since) {
							t.Fatalf("%s send %d: outage=%+v, want since=%d failures=%d", target, i, r.outage, since, failures)
						}
					}
				}
			})
		})
	}
}
