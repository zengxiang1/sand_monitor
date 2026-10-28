package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/agent/collect"
	"wanglou/internal/proto"
	"wanglou/internal/testutil"
)

func TestBackupConfiguration(t *testing.T) {
	c := config(t)
	c.Server = "https://monitor.example.com/base/"
	for _, backup := range []string{"https://MONITOR.EXAMPLE.COM/base", "HTTPS://monitor.example.com/base/", "https://monitor.example.com/base///", "http://backup.example.com", "https://user@backup.example.com", "https://backup.example.com?q=1", "https://backup.example.com#fragment", "https://backup.example.com?", "https://backup.example.com#", "relative"} {
		c.BackupServer = backup
		if c.Validate() == nil {
			t.Fatal("accepted backup", backup)
		}
	}
	c.BackupServer = "https://backup.example.com"
	path := filepath.Join(t.TempDir(), "config")
	if err := WriteConfig(path, c, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || loaded.BackupServer != c.BackupServer {
		t.Fatal(loaded, err)
	}
	c.InsecureHTTP, c.BackupServer = true, "http://backup.localhost"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("name='node'\nserver='https://monitor.example.com'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadConfig(path)
	if err != nil || loaded.BackupServer != "" {
		t.Fatal(loaded, err)
	}
}

type sampleCounter struct {
	*collect.Collector
	count atomic.Int32
}

func (s *sampleCounter) Sample() (proto.Report, error) {
	n := s.count.Add(1)
	r := report()
	r.Up, r.CPU = float64(n), float64(n)
	return r, nil
}

func TestDualLoopIsolation(t *testing.T) {
	for _, mode := range []string{"single", "both", "backup-stalls", "primary-stalls", "backup-500", "primary-500"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := config(t)
				c.Server, c.BackupServer, c.InsecureHTTP = "http://primary.localhost", "http://backup.localhost", true
				if mode == "single" {
					c.BackupServer = ""
				}
				key, err := GenerateKey(c.Key, false)
				if err != nil {
					t.Fatal(err)
				}
				received := map[string][]proto.Report{}
				sequences := map[string][]uint64{}
				seen := map[uint64]bool{}
				active := map[string]int{}
				var mu sync.Mutex
				recovering := false
				handler := func(target string) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						body, _ := io.ReadAll(req.Body)
						seq, _ := strconv.ParseUint(req.Header.Get(proto.SeqHeader), 10, 64)
						ts, _ := strconv.ParseInt(req.Header.Get(proto.TsHeader), 10, 64)
						if req.URL.Path != "/v1/report" || !proto.Verify(key.Public().(ed25519.PublicKey), c.Name, seq, ts, body, req.Header.Get(proto.SigHeader)) {
							t.Error("bad signature or path")
						}
						var r proto.Report
						if err := json.Unmarshal(body, &r); err != nil {
							t.Error(err)
						}
						mu.Lock()
						active[target]++
						if active[target] > 1 || seen[seq] {
							t.Error("overlapping request or duplicate seq")
						}
						seen[seq] = true
						prev := sequences[target]
						if len(prev) > 0 && seq <= prev[len(prev)-1] {
							t.Error("sequence rollback")
						}
						sequences[target] = append(prev, seq)
						received[target] = append(received[target], r)
						fail := !recovering && strings.HasPrefix(mode, target+"-")
						mu.Unlock()
						defer func() { mu.Lock(); active[target]--; mu.Unlock() }()
						if fail && strings.HasSuffix(mode, "stalls") {
							<-req.Context().Done()
							return
						}
						if fail {
							w.WriteHeader(500)
							return
						}
						w.WriteHeader(204)
					})
				}
				_, primary := testutil.NewServer(t, handler("primary"))
				_, backup := testutil.NewServer(t, handler("backup"))
				transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host == "backup.localhost" {
						return backup.Transport.RoundTrip(r)
					}
					return primary.Transport.RoundTrip(r)
				})
				client, err := NewClient(c, key, transport)
				if err != nil {
					t.Fatal(err)
				}
				collector, err := collect.NewWithState(report().Bin, c.StateFile+".logins.json", collect.Options{WtmpPath: filepath.Join(t.TempDir(), "absent")}, c.StateFile+".backup.logins.json")
				if err != nil {
					t.Fatal(err)
				}
				sampler := &sampleCounter{Collector: collector}
				ticks := make(chan time.Time)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); _ = runLoop(ctx, c, client, sampler, ticks, Backoff) }()
				synctest.Wait()
				healthy := "primary"
				if strings.HasPrefix(mode, "primary-") {
					healthy = "backup"
				}
				for cycle := 0; cycle < 15; cycle++ {
					time.Sleep(time.Second)
					ticks <- time.Now()
					synctest.Wait()
				}
				mu.Lock()
				wantSamples := 16
				if strings.Contains(mode, "-") {
					failed := "backup"
					if healthy == "backup" {
						failed = "primary"
					}
					wantSamples += len(received[failed]) - 1
				}
				if len(received[healthy]) != 16 || int(sampler.count.Load()) != wantSamples {
					t.Errorf("cadence changed: healthy=%d samples=%d", len(received[healthy]), sampler.count.Load())
				}
				if mode == "both" {
					for i, r := range received["primary"] {
						if r.Up != received["backup"][i].Up || r.CPU != received["backup"][i].CPU {
							t.Error("different samples")
						}
					}
				}
				if mode == "single" && len(received["backup"]) != 0 {
					t.Error("unexpected backup send")
				}
				failed := "backup"
				if healthy == "backup" {
					failed = "primary"
				}
				before := len(received[failed])
				recovering = true
				mu.Unlock()
				for range 20 {
					time.Sleep(time.Second)
					ticks <- time.Now()
					synctest.Wait()
				}
				mu.Lock()
				if mode != "single" && len(received[failed]) <= before {
					t.Error("did not resume after backoff")
				}
				mu.Unlock()
				cancel()
				<-done
			})
		})
	}
}

func TestConcurrentSequencesAcrossRestart(t *testing.T) {
	c := config(t)
	c.BackupServer = "https://backup.localhost"
	key, err := GenerateKey(c.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[uint64]bool{}
	var maximum uint64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seq, _ := strconv.ParseUint(req.Header.Get(proto.SeqHeader), 10, 64)
		mu.Lock()
		defer mu.Unlock()
		if seen[seq] {
			t.Error("duplicate seq", seq)
		}
		seen[seq] = true
		maximum = max(maximum, seq)
		return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
	})
	for restart := range 2 {
		client, err := NewClient(c, key, transport)
		if err != nil {
			t.Fatal(err)
		}
		client.Now = func() time.Time { return time.Unix(1700000000-int64(restart)*3600, 0) }
		previous := maximum
		var wg sync.WaitGroup
		for i := range 24 {
			wg.Go(func() {
				target := "primary"
				if i%2 == 1 {
					target = "backup"
				}
				if err := client.SendTo(context.Background(), target, report()); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if maximum <= previous || len(seen) != (restart+1)*24 {
			t.Fatal("restart sequence", maximum, previous, len(seen))
		}
	}
}

func TestDualLoginCatchup(t *testing.T) {
	c := config(t)
	wtmp := filepath.Join(t.TempDir(), "wtmp")
	appendLogin := func(user string, ts uint32) {
		size := 384
		if runtime.GOARCH == "arm64" {
			size = 400
		}
		raw := make([]byte, size)
		binary.LittleEndian.PutUint16(raw, 7)
		copy(raw[44:76], user)
		copy(raw[76:332], "203.0.113.7")
		if size == 400 {
			binary.LittleEndian.PutUint64(raw[344:352], uint64(ts))
		} else {
			binary.LittleEndian.PutUint32(raw[340:344], ts)
		}
		f, err := os.OpenFile(wtmp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	options := collect.Options{WtmpPath: wtmp}
	primaryState, backupState := c.StateFile+".logins.json", c.StateFile+".backup.logins.json"
	appendLogin("baseline", 100)
	_, err := collect.NewWithState(report().Bin, primaryState, options)
	if err != nil {
		t.Fatal(err)
	}
	appendLogin("before-upgrade", 101)
	upgraded, err := collect.NewWithState(report().Bin, primaryState, options, backupState)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]int{"primary": 1, "backup": 0} {
		got, err := upgraded.Logins(target)
		if err != nil || len(got) != want {
			t.Fatal(target, got, err)
		}
		if err = upgraded.Acknowledge(target); err != nil {
			t.Fatal(err)
		}
	}
	appendLogin("during-outage", 102)
	synctest.Test(t, func(t *testing.T) {
		key, err := GenerateKey(c.Key, false)
		if err != nil {
			t.Fatal(err)
		}
		c.Server, c.BackupServer, c.InsecureHTTP = "http://primary.localhost", "http://backup.localhost", true
		var mu sync.Mutex
		received := map[string][]proto.Login{}
		backupDown := true
		_, primary := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var report proto.Report
			_ = json.NewDecoder(r.Body).Decode(&report)
			mu.Lock()
			received["primary"] = append(received["primary"], report.Login...)
			mu.Unlock()
			w.WriteHeader(204)
		}))
		_, backup := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			if backupDown {
				w.WriteHeader(500)
				return
			}
			var report proto.Report
			_ = json.NewDecoder(r.Body).Decode(&report)
			received["backup"] = append(received["backup"], report.Login...)
			w.WriteHeader(204)
		}))
		client, err := NewClient(c, key, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "backup.localhost" {
				return backup.Transport.RoundTrip(r)
			}
			return primary.Transport.RoundTrip(r)
		}))
		if err != nil {
			t.Fatal(err)
		}
		ticks := make(chan time.Time)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = runLoop(ctx, c, client, &sampleCounter{Collector: upgraded}, ticks, Backoff)
		}()
		synctest.Wait()
		appendLogin("later-in-outage", 103)
		for range 4 {
			time.Sleep(time.Second)
			ticks <- time.Now()
			synctest.Wait()
		}
		mu.Lock()
		backupDown = false
		mu.Unlock()
		for range 12 {
			time.Sleep(time.Second)
			ticks <- time.Now()
			synctest.Wait()
		}
		cancel()
		<-done
		for _, target := range []string{"primary", "backup"} {
			got := received[target]
			if len(got) != 2 || got[0].User != "during-outage" || got[1].User != "later-in-outage" {
				t.Fatal(target, got)
			}
		}
	})
	restarted, err := collect.NewWithState(report().Bin, primaryState, options, backupState)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"primary", "backup"} {
		got, err := restarted.Logins(target)
		if err != nil || len(got) != 0 {
			t.Fatal("duplicate after restart", target, got, err)
		}
	}
}

func TestEnrollBackupTarget(t *testing.T) {
	c := config(t)
	c.Server, c.BackupServer = "https://primary.localhost", "https://backup.localhost"
	key, _ := GenerateKey(c.Key, false)
	client, err := NewClient(c, key, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "backup.localhost" || r.URL.Path != "/enroll" {
			return nil, fmt.Errorf("wrong target %s", r.URL)
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.EnrollTo(context.Background(), "backup", "ABCD-EFGH"); err != nil {
		t.Fatal(err)
	}
	c.BackupServer = ""
	client, _ = NewClient(c, key)
	if err = client.EnrollTo(context.Background(), "backup", "ABCD-EFGH"); err == nil {
		t.Fatal("missing backup accepted")
	}
}

func TestTargetFailureLogLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := config(t)
		c.BackupServer = "https://backup.localhost"
		key, err := GenerateKey(c.Key, false)
		if err != nil {
			t.Fatal(err)
		}
		var status atomic.Int32
		status.Store(401)
		client, err := NewClient(c, key, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: int(status.Load()), Body: http.NoBody}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		collector, err := collect.NewWithState(report().Bin, c.StateFile+".logins.json", collect.Options{WtmpPath: filepath.Join(t.TempDir(), "absent")}, c.StateFile+".backup.logins.json")
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&output)
		defer log.SetOutput(previous)
		ticks := make(chan time.Time)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = runLoop(ctx, c, client, &sampleCounter{Collector: collector}, ticks, func(failures int) time.Duration {
				if failures == 5 {
					return 10 * time.Minute
				}
				return time.Second
			})
		}()
		defer func() { cancel(); <-done }()
		synctest.Wait()
		advance := func(delay time.Duration) { time.Sleep(delay); ticks <- time.Now(); synctest.Wait() }
		for range 3 {
			advance(time.Second)
		}
		if strings.Count(output.String(), "failed:") != 2 || !strings.Contains(output.String(), "report to primary failed:") || !strings.Contains(output.String(), "report to backup failed:") {
			t.Fatal(output.String())
		}
		status.Store(500)
		advance(time.Second)
		if strings.Count(output.String(), "failed:") != 4 {
			t.Fatal(output.String())
		}
		advance(10 * time.Minute)
		if strings.Count(output.String(), "failed:") != 6 {
			t.Fatal(output.String())
		}
		status.Store(204)
		advance(time.Second)
		for _, target := range []string{"primary", "backup"} {
			if strings.Count(output.String(), "report to "+target+" recovered after 6 failures") != 1 {
				t.Fatal(output.String())
			}
		}
		advance(time.Second)
		if strings.Count(output.String(), "recovered after") != 2 {
			t.Fatal(output.String())
		}
		status.Store(500)
		advance(time.Second)
		if strings.Count(output.String(), "failed:") != 8 {
			t.Fatal(output.String())
		}
		cancel()
		<-done
	})
}
