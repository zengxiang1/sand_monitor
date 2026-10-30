package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
	"wanglou/internal/proto"
)

// probeHTTPS receives a target already validated at the configuration boundary.
// configure is only used by tests to trust their local TLS server.
func probeHTTPS(ctx context.Context, target string, timeout time.Duration, configure func(*http.Transport)) proto.Probe {
	start := time.Now()
	result := proto.Probe{Target: target, Time: start.Unix()}
	transport := &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: timeout}
	if configure != nil {
		configure(transport)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var mu sync.Mutex
	var dnsStart, tlsStart time.Time
	connectStarts := map[string]time.Time{}
	connectTimes := map[string]float64{}
	phaseError := ""
	connected := false
	selected := false
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { mu.Lock(); dnsStart = time.Now(); mu.Unlock() },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			mu.Lock()
			defer mu.Unlock()
			result.DNSMS = float64(time.Since(dnsStart)) / float64(time.Millisecond)
			if info.Err != nil {
				phaseError = "dns"
			}
		},
		ConnectStart: func(network, addr string) { mu.Lock(); connectStarts[network+addr] = time.Now(); mu.Unlock() },
		ConnectDone: func(network, addr string, err error) {
			mu.Lock()
			defer mu.Unlock()
			if !selected && (err == nil || !connected) {
				result.TCPMS = float64(time.Since(connectStarts[network+addr])) / float64(time.Millisecond)
			}
			if err == nil {
				connectTimes[addr] = float64(time.Since(connectStarts[network+addr])) / float64(time.Millisecond)
			}
			if err != nil && !connected {
				phaseError = "connect"
			} else if err == nil {
				connected = true
				if phaseError == "connect" {
					phaseError = ""
				}
			}
		},
		TLSHandshakeStart: func() { mu.Lock(); tlsStart = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			result.TLSMS = float64(time.Since(tlsStart)) / float64(time.Millisecond)
			if err != nil {
				phaseError = "tls"
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			selected = true
			host, _, _ := net.SplitHostPort(info.Conn.RemoteAddr().String())
			result.IP = host
			result.TCPMS = connectTimes[info.Conn.RemoteAddr().String()]
		},
		GotFirstResponseByte: func() { mu.Lock(); result.TTFBMS = float64(time.Since(start)) / float64(time.Millisecond); mu.Unlock() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target, nil)
	if err != nil {
		result.Error = "request"
		result.TotalMS = float64(time.Since(start)) / float64(time.Millisecond)
		return result
	}
	resp, err := client.Do(req)
	if err == nil {
		mu.Lock()
		result.Status = resp.StatusCode
		phaseError = ""
		mu.Unlock()
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		mu.Lock()
		if err != nil {
			phaseError = "read"
		} else if resp.StatusCode < 200 || resp.StatusCode > 399 {
			phaseError = "http"
		}
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	result.TotalMS = float64(time.Since(start)) / float64(time.Millisecond)
	result.Error = phaseError
	if err != nil {
		var networkError net.Error
		var dnsError *net.DNSError
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
			result.Error = "timeout"
		case errors.As(err, &dnsError):
			result.Error = "dns"
		case result.Error == "":
			result.Error = "request"
		}
	}
	return result
}

type probeRunner struct {
	targets []string
	mu      sync.Mutex
	latest  map[string]proto.Probe
	done    chan struct{}
}

func newProbeRunner(ctx context.Context, targets []string, delay time.Duration, probe func(context.Context, string) proto.Probe) *probeRunner {
	runner := &probeRunner{targets: targets, latest: map[string]proto.Probe{}, done: make(chan struct{})}
	go func() {
		defer close(runner.done)
		if len(targets) == 0 {
			return
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		ticker := time.NewTicker(proto.ProbeInterval)
		defer ticker.Stop()
		for {
			jobs := make(chan string, len(targets))
			for _, target := range targets {
				jobs <- target
			}
			close(jobs)
			var workers sync.WaitGroup
			for range min(2, len(targets)) {
				workers.Go(func() {
					for target := range jobs {
						if ctx.Err() != nil {
							return
						}
						result := probe(ctx, target)
						if ctx.Err() != nil {
							return
						}
						runner.mu.Lock()
						runner.latest[target] = result
						runner.mu.Unlock()
					}
				})
			}
			workers.Wait()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return runner
}

func (r *probeRunner) snapshot() []proto.Probe {
	r.mu.Lock()
	defer r.mu.Unlock()
	results := make([]proto.Probe, 0, len(r.latest))
	for _, target := range r.targets {
		if result, ok := r.latest[target]; ok {
			results = append(results, result)
		}
	}
	return results
}

type probeSampler struct {
	sampler
	probes *probeRunner
}

func (s probeSampler) Sample() (proto.Report, error) {
	report, err := s.sampler.Sample()
	report.Probes = s.probes.snapshot()
	return report, err
}

func startProbes(ctx context.Context, targets []string) *probeRunner {
	return newProbeRunner(ctx, targets, time.Duration(rand.Int64N(int64(10*time.Second)+1)), func(ctx context.Context, target string) proto.Probe {
		return probeHTTPS(ctx, target, 5*time.Second, nil)
	})
}
