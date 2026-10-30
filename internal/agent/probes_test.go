package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/proto"
)

func TestHTTPSProbe(t *testing.T) {
	var requests, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/delay":
			time.Sleep(20 * time.Millisecond)
			_, _ = io.WriteString(w, "ok")
		case "/redirect":
			w.Header().Set("Location", "/delay")
			w.WriteHeader(302)
		case "/http":
			w.WriteHeader(503)
		case "/read":
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "short")
		case "/bounded":
			_, _ = io.WriteString(w, strings.Repeat("x", 8192))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/timeout":
			<-r.Context().Done()
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	trust := func(transport *http.Transport) {
		transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, tc := range []struct {
		path, code string
		status     int
	}{
		{"/delay", "", 200}, {"/redirect", "", 302}, {"/http", "http", 503}, {"/read", "read", 200}, {"/bounded", "", 200}, {"/timeout", "timeout", 0},
	} {
		t.Run(tc.path, func(t *testing.T) {
			before := requests.Load()
			result := probeHTTPS(context.Background(), server.URL+tc.path, 200*time.Millisecond, trust)
			if result.Error != tc.code || result.Status != tc.status || result.IP != "127.0.0.1" && tc.path != "/timeout" {
				t.Fatal(result)
			}
			if err := result.Validate(); err != nil {
				t.Fatal(result, err)
			}
			if result.TLSMS <= 0 || result.TCPMS <= 0 || result.TotalMS <= 0 {
				t.Fatal("missing timings", result)
			}
			if tc.path == "/delay" && (result.TTFBMS < 20 || result.TotalMS < result.TTFBMS) {
				t.Fatal("latency", result)
			}
			if requests.Load() != before+1 {
				t.Fatal("redirect followed or missing request")
			}
		})
	}
	if connections.Load() != 6 {
		t.Fatal("connection reused", connections.Load())
	}
	if result := probeHTTPS(context.Background(), server.URL, time.Second, nil); result.Error != "tls" {
		t.Fatal("accepted untrusted certificate", result)
	}
	for _, tc := range []struct {
		err  error
		code string
	}{
		{&net.DNSError{Err: "no such host", Name: "example.invalid"}, "dns"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}, "connect"},
	} {
		result := probeHTTPS(context.Background(), "https://example.invalid/", time.Second, func(transport *http.Transport) {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				trace := httptrace.ContextClientTrace(ctx)
				trace.ConnectStart(network, addr)
				trace.ConnectDone(network, addr, tc.err)
				return nil, tc.err
			}
		})
		if result.Error != tc.code {
			t.Fatal(result)
		}
	}
}

func TestProbeWinningConnectionTrace(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"failure", fmt.Errorf("losing attempt")}, {"success", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			loser := make(chan struct{})
			callbackDone := make(chan struct{})
			probeDone := make(chan struct{})
			lateDone := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(loser)
				<-callbackDone
				time.Sleep(10 * time.Millisecond)
				_, _ = io.WriteString(w, "ok")
			}))
			defer server.Close()
			result := probeHTTPS(context.Background(), server.URL, time.Second, func(transport *http.Transport) {
				transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					trace := httptrace.ContextClientTrace(ctx)
					trace.ConnectStart("tcp", "[::1]:1")
					go func() {
						defer close(lateDone)
						<-loser
						time.Sleep(30 * time.Millisecond)
						trace.ConnectDone("tcp", "[::1]:1", tc.err)
						close(callbackDone)
						<-probeDone
						trace.ConnectDone("tcp", "[::1]:1", tc.err)
					}()
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
			})
			close(probeDone)
			<-lateDone
			if result.Error != "" || result.IP != "127.0.0.1" || result.TotalMS-result.TCPMS < 20 {
				t.Fatal("losing dial overwrote winner", result)
			}
		})
	}
}

func TestProbeRunnerCadenceAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls, active, maximum atomic.Int32
		runner := newProbeRunner(ctx, []string{"a", "b", "c"}, 10*time.Second, func(ctx context.Context, target string) proto.Probe {
			calls.Add(1)
			current := active.Add(1)
			maximum.Store(max(maximum.Load(), current))
			defer active.Add(-1)
			select {
			case <-ctx.Done():
				return proto.Probe{Error: "timeout"}
			case <-time.After(5 * time.Second):
			}
			return proto.Probe{Target: target, Time: time.Now().Unix(), Status: 200}
		})
		time.Sleep(9 * time.Second)
		synctest.Wait()
		if calls.Load() != 0 || len(runner.snapshot()) != 0 {
			t.Fatal("ignored initial jitter")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 2 || maximum.Load() != 2 {
			t.Fatal("worker bound", calls.Load(), maximum.Load())
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		first := runner.snapshot()
		if len(first) != 3 || first[0].Target != "a" || first[2].Target != "c" {
			t.Fatal(first)
		}
		time.Sleep(time.Hour - 11*time.Second)
		synctest.Wait()
		if calls.Load() != 3 || !reflect.DeepEqual(first, runner.snapshot()) {
			t.Fatal("sample timestamp changed without probe")
		}
		copy := runner.snapshot()
		copy[0].Time = 0
		if runner.snapshot()[0].Time == 0 {
			t.Fatal("snapshot aliases stored state")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 5 {
			t.Fatal("hourly cadence", calls.Load())
		}
		cancel()
		<-runner.done
		if !reflect.DeepEqual(first, runner.snapshot()) {
			t.Fatal("shutdown cancellation replaced completed samples")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	runner := startProbes(ctx, []string{})
	<-runner.done
	cancel()
	if len(runner.snapshot()) != 0 {
		t.Fatal("disabled probes")
	}
}

func TestProbeConfig(t *testing.T) {
	for _, targets := range [][]string{nil, {}, {"https://example.com/a,b", "https://example.net/path?q=1"}} {
		c := config(t)
		c.ProbeTargets = targets
		path := filepath.Join(t.TempDir(), "agent.toml")
		if err := WriteConfig(path, c, false); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadConfig(path)
		if err != nil || !reflect.DeepEqual(loaded.ProbeTargets, targets) {
			t.Fatal(loaded.ProbeTargets, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runner := startProbes(ctx, loaded.ProbeTargets)
		<-runner.done
		if !reflect.DeepEqual(runner.targets, targets) {
			t.Fatal("configured probe targets changed", runner.targets)
		}
	}
	path := filepath.Join(t.TempDir(), "old.toml")
	if err := os.WriteFile(path, []byte("name='node'\nserver='https://monitor.example.com'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || loaded.ProbeTargets != nil {
		t.Fatal(loaded, err)
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		runner := startProbes(ctx, loaded.ProbeTargets)
		defer func() { cancel(); <-runner.done }()
		synctest.Wait()
		select {
		case <-runner.done:
		default:
			t.Fatal("legacy config started an outbound probe scheduler")
		}
		if len(runner.targets) != 0 || len(runner.snapshot()) != 0 {
			t.Fatal("legacy config enabled implicit outbound targets", runner.targets)
		}
	})
}

func TestProbeCompatibilityPerDestination(t *testing.T) {
	c := config(t)
	c.BackupServer = "https://backup.localhost"
	key, err := GenerateKey(c.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	received := map[string][]proto.Report{}
	client, err := NewClient(c, key, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var r proto.Report
		if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		received[req.URL.Host] = append(received[req.URL.Host], r)
		status := 204
		if req.URL.Host == "localhost" && len(r.Probes) > 0 {
			status = 400
		}
		return &http.Response{StatusCode: status, Body: http.NoBody}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := report()
	r.Probes = []proto.Probe{{Target: "https://example.com/", Time: 1, Status: 200}}
	r.Outage = &proto.Outage{Since: 1, Failures: 1}
	for _, target := range []string{"primary", "primary", "backup"} {
		if err := client.SendTo(context.Background(), target, r); err != nil {
			t.Fatal(err)
		}
	}
	primary := received["localhost"]
	if len(primary) != 3 || len(primary[0].Probes) != 1 || len(primary[1].Probes) != 0 || len(primary[2].Probes) != 0 {
		t.Fatal(primary)
	}
	for _, report := range primary {
		if report.Outage == nil {
			t.Fatal("probe rejection disabled outage")
		}
	}
	if len(received["backup.localhost"][0].Probes) != 1 {
		t.Fatal("primary rejection disabled backup probes")
	}
}

func TestProbeCompatibilityWithOlderOutageReceiver(t *testing.T) {
	c := config(t)
	key, err := GenerateKey(c.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	var sent []proto.Report
	client, err := NewClient(c, key, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var r proto.Report
		if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		sent = append(sent, r)
		status := 204
		if len(r.Probes) > 0 || r.Outage != nil {
			status = 400
		}
		return &http.Response{StatusCode: status, Body: http.NoBody}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := report()
	r.Probes = []proto.Probe{{Target: "https://example.com/", Time: 1, Status: 200}}
	r.Outage = &proto.Outage{Since: 1, Failures: 1}
	if err := client.Send(context.Background(), r); err == nil {
		t.Fatal("expected legacy outage failure after probe retry")
	}
	if err := client.Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || sent[0].Outage == nil || len(sent[0].Probes) != 1 || sent[1].Outage == nil || len(sent[1].Probes) != 0 || sent[2].Outage != nil || len(sent[2].Probes) != 0 {
		t.Fatal(sent)
	}
}

func TestProbeSamplerDoesNotWaitForProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	runner := newProbeRunner(ctx, []string{"https://example.com/"}, 0, func(ctx context.Context, target string) proto.Probe {
		close(started)
		<-ctx.Done()
		return proto.Probe{Target: target, Error: "timeout"}
	})
	defer func() { cancel(); <-runner.done }()
	<-started
	collector := &sampleCounter{}
	sampler := probeSampler{sampler: collector, probes: runner}
	r, err := sampler.Sample()
	if err != nil || r.Up != 1 || len(r.Probes) != 0 {
		t.Fatal(r, err)
	}
	runner.mu.Lock()
	runner.latest["https://example.com/"] = proto.Probe{Target: "https://example.com/", Time: 7, Status: 200}
	runner.mu.Unlock()
	first, err := sampler.Sample()
	if err != nil {
		t.Fatal(err)
	}
	second, err := sampler.Sample()
	if err != nil || !reflect.DeepEqual(first.Probes, second.Probes) || second.Probes[0].Time != 7 {
		t.Fatal(first, second, err)
	}
}
