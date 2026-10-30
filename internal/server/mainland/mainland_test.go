package mainland

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
	"wanglou/internal/testutil"
)

func TestFixtureRequestPollingAndPersistentHourlySkip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture, err := os.ReadFile("testdata/tcp.json")
		if err != nil {
			t.Fatal(err)
		}
		var result measurement
		if err = json.Unmarshal(fixture, &result); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "db")
		s, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { s.Close() }()
		now := time.Now()
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		if err = s.AddNode("node", pub, now); err != nil {
			t.Fatal(err)
		}
		posts, polls := 0, 0
		server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.UserAgent(), "Wanglou/") || r.Header.Get("Accept-Encoding") != "gzip" {
				t.Error("missing client identification or compression", r.Header)
			}
			if r.Method == http.MethodPost {
				posts++
				if r.URL.Path != "/v1/measurements" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("create route", r.URL, r.Header)
				}
				var request measurementRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if request.Type != "ping" || request.Target != "203.0.113.7" || request.MeasurementOptions != (measurementOptions{Protocol: "TCP", Port: 22, Packets: 3}) || !reflect.DeepEqual(request.Locations, json.RawMessage(`[{"country":"CN","asn":4837,"limit":1}]`)) {
					t.Errorf("wrong TCP request: %+v", request)
				}
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"id":"fixture-measurement","probesCount":1}`))
				return
			}
			polls++
			if r.Method != http.MethodGet || r.URL.Path != "/v1/measurements/fixture-measurement" {
				t.Error("poll route", r.Method, r.URL)
			}
			if polls == 1 {
				w.Header().Set("ETag", `"progress"`)
				inProgress := result
				inProgress.Status, inProgress.Results = "in-progress", nil
				_ = json.NewEncoder(w).Encode(inProgress)
				return
			}
			if polls <= 3 && r.Header.Get("If-None-Match") != `"progress"` {
				t.Error("ETag not preserved", r.Header)
			}
			if polls == 2 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"finished"`)
			_, _ = w.Write(fixture)
		}))
		loop := &Loop{Store: s, BaseURL: server.URL, Transport: client.Transport, Targets: []Target{{Node: "node", Address: netip.MustParseAddrPort("203.0.113.7:22")}}}
		if err = loop.Check(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		got, err := s.MainlandProbes("node")
		if err != nil || len(got) != 1 {
			t.Fatal(got, err)
		}
		for i, want := range []float64{111.1} {
			if got[i].Status != "ok" || got[i].TCPMS != want || got[i].Sent != 3 || got[i].Received != 3 || got[i].Country != "CN" || got[i].ASN != 4837 || got[i].MeasurementID != "fixture-measurement" || got[i].Time != now.Unix() {
				t.Fatalf("actual source and average: %+v", got[i])
			}
		}
		if got[0].City != "Wuhan" {
			t.Fatal(got)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err = store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		loop = &Loop{Store: s, BaseURL: server.URL, Transport: client.Transport, Targets: loop.Targets}
		if err = loop.Check(context.Background(), now.Add(proto.ProbeInterval-time.Second)); err != nil || posts != 1 {
			t.Fatal("restart repeated hourly batch", posts, err)
		}
		if err = loop.Check(context.Background(), now.Add(proto.ProbeInterval)); err != nil || posts != 2 {
			t.Fatal("next hourly batch missing", posts, err)
		}
	})
}

func TestProviderBoundaryCountsAndMissingCarriers(t *testing.T) {
	for _, tc := range []string{"partial", "no-connections", "internal-error", "missing-carrier", "foreign-country", "wrong-asn", "wrong-target", "wrong-protocol", "wrong-port", "wrong-resolved-address", "invalid-counts", "missing-average", "missing-received"} {
		t.Run(tc, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				body, err := os.ReadFile("testdata/tcp.json")
				if err != nil {
					t.Fatal(err)
				}
				var result measurement
				if err = json.Unmarshal(body, &result); err != nil {
					t.Fatal(err)
				}
				want, wantErr := "unavailable", false
				switch tc {
				case "partial":
					received := 1
					result.Results[0].Result.Stats.RCV = &received
					want = "ok"
				case "no-connections":
					received := 0
					result.Results[0].Result.Stats.RCV, result.Results[0].Result.Stats.Avg = &received, nil
					want = "failed"
				case "internal-error":
					result.Results[0].Result.Status = "failed"
				case "missing-carrier":
					result.Results = result.Results[1:]
				case "foreign-country":
					result.Results[0].Probe.Country = "HK"
				case "wrong-asn":
					result.Results[0].Probe.ASN = 4134
				case "wrong-target":
					result.Target, wantErr = "203.0.113.8", true
				case "wrong-protocol":
					result.MeasurementOptions.Protocol, wantErr = "ICMP", true
				case "wrong-port":
					result.MeasurementOptions.Port, wantErr = 80, true
				case "wrong-resolved-address":
					result.Results[0].Result.ResolvedAddress = "203.0.113.8"
				case "invalid-counts":
					received := 4
					result.Results[0].Result.Stats.RCV = &received
				case "missing-received":
					result.Results[0].Result.Stats.RCV = nil
				case "missing-average":
					result.Results[0].Result.Stats.Avg = nil
				}
				server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						_, _ = w.Write([]byte(`{"id":"fixture-measurement"}`))
						return
					}
					_ = json.NewEncoder(w).Encode(result)
				}))
				loop := &Loop{BaseURL: server.URL, Transport: client.Transport}
				got, err := loop.measure(context.Background(), Target{Node: "node", Address: netip.MustParseAddrPort("203.0.113.7:22")}, time.Now(), store.MainlandSource{ASN: 4837}, json.RawMessage(`[{"country":"CN","asn":4837,"limit":1}]`))
				if (err != nil) != wantErr || len(got) != 1 || got[0].Status != want {
					t.Fatal(got, err)
				}
				if tc == "partial" && (got[0].Sent != 3 || got[0].Received != 1 || got[0].TCPMS != 111.1) {
					t.Fatal("lost partial-success counts or actual average", got)
				}
				if tc == "foreign-country" || tc == "wrong-asn" || tc == "missing-carrier" {
					if got[0].Country != "" || got[0].City != "" || got[0].Network != "" {
						t.Fatal("non-mainland fallback accepted", got)
					}
				}
			})
		})
	}
}

func TestProviderFailureTimeoutCancellationAndResponseBound(t *testing.T) {
	for _, tc := range []string{"http-error", "oversized", "timeout", "cancel"} {
		t.Run(tc, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				fixture, err := os.ReadFile("testdata/tcp.json")
				if err != nil {
					t.Fatal(err)
				}
				var progress measurement
				if err = json.Unmarshal(fixture, &progress); err != nil {
					t.Fatal(err)
				}
				progress.Status, progress.Results = "in-progress", nil
				server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					switch tc {
					case "http-error":
						w.WriteHeader(http.StatusTooManyRequests)
					case "oversized":
						_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					default:
						if r.Method == http.MethodPost {
							_, _ = w.Write([]byte(`{"id":"fixture-measurement"}`))
						} else {
							_ = json.NewEncoder(w).Encode(progress)
						}
					}
				}))
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if tc == "cancel" {
					go func() { time.Sleep(time.Second); cancel() }()
				}
				loop := &Loop{BaseURL: server.URL, Transport: client.Transport}
				started := time.Now()
				got, err := loop.measure(ctx, Target{Node: "node", Address: netip.MustParseAddrPort("203.0.113.7:22")}, started, store.MainlandSource{ASN: 4837}, json.RawMessage(`[{"country":"CN","asn":4837,"limit":1}]`))
				if err == nil || len(got) != 1 || got[0].Status != "unavailable" || got[0].Sent != 0 {
					t.Fatal("provider failure became target failure", got, err)
				}
				if (tc == "http-error" || tc == "oversized") && calls != 1 {
					t.Fatal("retried failed create", calls)
				}
				if tc == "timeout" && (time.Since(started) != time.Minute || calls > 31) {
					t.Fatal("unbounded polling", time.Since(started), calls)
				}
				if tc == "cancel" && (!errors.Is(err, context.Canceled) || calls != 1) {
					t.Fatal("cancellation ignored", calls, err)
				}
			})
		})
	}
}

func TestBatchProviderFailureReplacesOldDataAndSkipsRevokedNodes(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, name := range []string{"node", "revoked"} {
		if err = s.AddNode(name, pub, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Revoke("revoked", now); err != nil {
		t.Fatal(err)
	}
	if err = s.SetMainlandProbes("node", []store.MainlandProbe{{Carrier: "中国联通", Status: "ok", TCPMS: 123}}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	loop := &Loop{Store: s, BaseURL: server.URL, Transport: client.Transport}
	for _, name := range []string{"node", "revoked", "unknown"} {
		loop.Targets = append(loop.Targets, Target{Node: name, Address: netip.MustParseAddrPort("203.0.113.7:22")})
	}
	if err = loop.Check(context.Background(), now); err == nil || calls.Load() != 1 {
		t.Fatal("revoked/unknown target called or provider error hidden", calls.Load(), err)
	}
	got, err := s.MainlandProbes("node")
	if err != nil || len(got) != 1 || got[0].Status != "unavailable" || got[0].TCPMS != 0 || got[0].Time != now.Unix() {
		t.Fatal("old success not replaced", got, err)
	}
	if err = loop.Check(context.Background(), now.Add(time.Minute)); err != nil || calls.Load() != 1 {
		t.Fatal("provider failure retried inside hour", calls.Load(), err)
	}
}

func TestOneProbeReusedAcrossSixServersWithoutResampling(t *testing.T) {
	for _, scenario := range []string{"success", "first-zero-success", "first-create-error", "first-missing-id", "first-poll-error", "later-create-error", "later-missing-probe"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fixture, err := os.ReadFile("testdata/tcp.json")
				if err != nil {
					t.Fatal(err)
				}
				s, err := store.Open(filepath.Join(t.TempDir(), "db"))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				now := time.Now()
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				targets := []Target{}
				for i := range 6 {
					name := fmt.Sprintf("node-%d", i)
					if err = s.AddNode(name, pub, now); err != nil {
						t.Fatal(err)
					}
					port := 22
					if i == 5 {
						port = 331
					}
					targets = append(targets, Target{Node: name, Address: netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:%d", i+7, port))})
				}
				requests := []measurementRequest{}
				server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						var request measurementRequest
						if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
							t.Error(err)
						}
						i := len(requests)
						requests = append(requests, request)
						if request.Type != "ping" || request.Target != targets[i].Address.Addr().String() || request.MeasurementOptions != (measurementOptions{Protocol: "TCP", Port: targets[i].Address.Port(), Packets: 3}) {
							t.Errorf("wrong target/options: %+v", request)
						}
						if i == 0 {
							var selected []location
							if err := json.Unmarshal(request.Locations, &selected); err != nil || !reflect.DeepEqual(selected, []location{{Country: "CN", ASN: 4837, Limit: 1}}) {
								t.Error("first selection must be exactly one mainland point", string(request.Locations), err)
							}
						} else {
							var seed string
							if err := json.Unmarshal(request.Locations, &seed); err != nil || seed != "measurement-0" {
								t.Error("resampled instead of reusing first point", string(request.Locations), err)
							}
						}
						if i == 0 && scenario == "first-create-error" || i == 1 && scenario == "later-create-error" {
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						if i == 0 && scenario == "first-missing-id" {
							_, _ = w.Write([]byte(`{}`))
							return
						}
						_, _ = fmt.Fprintf(w, `{"id":"measurement-%d","probesCount":1}`, i)
						return
					}
					i, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/v1/measurements/measurement-"))
					if err != nil || i < 0 || i >= len(requests) {
						t.Error("invalid poll", r.URL, err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if i == 0 && scenario == "first-poll-error" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					var result measurement
					if err := json.Unmarshal(fixture, &result); err != nil {
						t.Error(err)
					}
					result.ID, result.Target, result.MeasurementOptions.Port = fmt.Sprintf("measurement-%d", i), requests[i].Target, requests[i].MeasurementOptions.Port
					result.Results[0].Result.ResolvedAddress = result.Target
					if i == 0 && scenario == "first-zero-success" {
						received := 0
						result.Results[0].Result.Stats.RCV, result.Results[0].Result.Stats.Avg = &received, nil
					}
					if i == 2 && scenario == "later-missing-probe" {
						result.Results = nil
					}
					_ = json.NewEncoder(w).Encode(result)
				}))
				loop := &Loop{Store: s, BaseURL: server.URL, Transport: client.Transport, Targets: targets}
				err = loop.Check(context.Background(), now)
				wantErr := scenario == "first-create-error" || scenario == "first-missing-id" || scenario == "first-poll-error" || scenario == "later-create-error"
				if (err != nil) != wantErr {
					t.Fatal("batch error", err)
				}
				wantRequests := 6
				if scenario == "first-create-error" || scenario == "first-missing-id" {
					wantRequests = 1
				}
				if len(requests) != wantRequests {
					t.Fatal("selected extra points after seed failure", len(requests), wantRequests)
				}
				for i, target := range targets {
					got, err := s.MainlandProbes(target.Node)
					if err != nil || len(got) != 1 {
						t.Fatal("expected one point per destination", target.Node, got, err)
					}
					want := "ok"
					if scenario == "first-create-error" || scenario == "first-missing-id" || scenario == "first-poll-error" && i == 0 || scenario == "later-create-error" && i == 1 || scenario == "later-missing-probe" && i == 2 {
						want = "unavailable"
					} else if scenario == "first-zero-success" && i == 0 {
						want = "failed"
					}
					if got[0].Status != want {
						t.Fatal("wrong per-node classification", target.Node, got, want)
					}
					if want == "ok" || want == "failed" {
						if got[0].City != "Wuhan" || got[0].Country != "CN" || got[0].ASN != 4837 || got[0].Network != "CHINA UNICOM China169 Backbone" {
							t.Fatal("did not retain true single-point source", got)
						}
					}
				}
				if err = loop.Check(context.Background(), now.Add(proto.ProbeInterval-time.Second)); err != nil || len(requests) != wantRequests {
					t.Fatal("repeated batch within the hour", len(requests), err)
				}
			})
		})
	}
}

func TestConfiguredSourcesBatchSnapshotAndHourlySchedule(t *testing.T) {
	for _, source := range []store.MainlandSource{{ASN: 4134, City: "Shanghai"}, {ASN: 4837, City: "Wuhan"}, {ASN: 9808}} {
		t.Run(strconv.Itoa(source.ASN), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fixture, err := os.ReadFile("testdata/tcp.json")
				if err != nil {
					t.Fatal(err)
				}
				s, err := store.Open(filepath.Join(t.TempDir(), "db"))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if err := s.SetMainlandSource(source); err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				targets := []Target{}
				for _, name := range []string{"one", "two"} {
					if err := s.AddNode(name, pub, now); err != nil {
						t.Fatal(err)
					}
					targets = append(targets, Target{Node: name, Address: netip.MustParseAddrPort("203.0.113.7:22")})
				}
				requests := 0
				next := store.MainlandSource{ASN: 4134, City: "Beijing"}
				server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						var request measurementRequest
						if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
							t.Error(err)
						}
						selected := source
						if requests >= 2 {
							selected = next
						}
						if requests%2 == 0 {
							var locations []location
							if err := json.Unmarshal(request.Locations, &locations); err != nil || !reflect.DeepEqual(locations, []location{{Country: "CN", ASN: selected.ASN, City: selected.City, Limit: 1}}) {
								t.Error("configured source not requested", string(request.Locations), err)
							}
						} else if string(request.Locations) != `"fixture-measurement"` {
							t.Error("later target did not reuse first source", string(request.Locations))
						}
						requests++
						if requests == 1 {
							if err := s.SetMainlandSource(next); err != nil {
								t.Error(err)
							}
						}
						_, _ = w.Write([]byte(`{"id":"fixture-measurement"}`))
						return
					}
					var result measurement
					if err := json.Unmarshal(fixture, &result); err != nil {
						t.Error(err)
					}
					selected := source
					if requests > 2 {
						selected = next
					}
					result.Results[0].Probe.ASN = selected.ASN
					if selected.City != "" {
						result.Results[0].Probe.City = selected.City
					}
					_ = json.NewEncoder(w).Encode(result)
				}))
				loop := &Loop{Store: s, Targets: targets, BaseURL: server.URL, Transport: client.Transport}
				if err := loop.Check(context.Background(), now); err != nil {
					t.Fatal(err)
				}
				for _, target := range targets {
					samples, err := s.MainlandProbes(target.Node)
					if err != nil || len(samples) != 1 || samples[0].Status != "ok" || samples[0].ASN != source.ASN || samples[0].Carrier != source.Carrier() || !source.Matches(samples[0]) {
						t.Fatal("source changed within batch", samples, err)
					}
				}
				if err := loop.Check(context.Background(), now.Add(time.Minute)); err != nil || requests != 2 {
					t.Fatal("saving source caused extra measurement", requests, err)
				}
				if err := loop.Check(context.Background(), now.Add(proto.ProbeInterval)); err != nil || requests != 4 {
					t.Fatal("next hourly batch missing", requests, err)
				}
				for _, target := range targets {
					samples, err := s.MainlandProbes(target.Node)
					if err != nil || len(samples) != 1 || samples[0].Status != "ok" || !next.Matches(samples[0]) {
						t.Fatal("next hour ignored saved source", samples, err)
					}
				}
			})
		})
	}
}

func TestCityMismatchStaysUnavailableWithoutFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture, err := os.ReadFile("testdata/tcp.json")
		if err != nil {
			t.Fatal(err)
		}
		posts := 0
		server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				posts++
				_, _ = w.Write([]byte(`{"id":"fixture-measurement"}`))
				return
			}
			_, _ = w.Write(fixture)
		}))
		source := store.MainlandSource{ASN: 4837, City: "Beijing"}
		loop := &Loop{BaseURL: server.URL, Transport: client.Transport}
		samples, err := loop.measure(context.Background(), Target{Node: "node", Address: netip.MustParseAddrPort("203.0.113.7:22")}, time.Now(), source, json.RawMessage(`[{"country":"CN","asn":4837,"city":"Beijing","limit":1}]`))
		if err != nil || posts != 1 || len(samples) != 1 || samples[0].Status != "unavailable" || samples[0].City != "Beijing" || samples[0].ASN != 4837 || samples[0].Carrier != source.Carrier() || samples[0].Country != "" || samples[0].Network != "" {
			t.Fatal("mismatched source accepted or retried", posts, samples, err)
		}
	})
}

func TestLocationsOnlineMainlandPoolsAndBoundaries(t *testing.T) {
	for _, scenario := range []string{"success", "http-error", "invalid-json", "null", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/v1/probes" {
					t.Error("directory issued measurement or wrong route", r.Method, r.URL)
				}
				switch scenario {
				case "http-error":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "invalid-json":
					_, _ = w.Write([]byte(`{"location":{}}`))
				case "null":
					_, _ = w.Write([]byte(`null`))
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat(" ", (16<<20)+1)))
				default:
					// Extra metadata also verifies the directory can exceed the
					// smaller measurement response limit.
					_, _ = fmt.Fprintf(w, `[
{"location":{"country":"CN","asn":4837,"city":"Wuhan"},"metadata":"%s"},
{"location":{"country":"CN","asn":4837,"city":"Wuhan"}},
{"location":{"country":"CN","asn":4134,"city":"Shanghai"}},
{"location":{"country":"CN","asn":9808,"city":"Beijing"}},
{"location":{"country":"HK","asn":4837,"city":"Hong Kong"}},
{"location":{"country":"CN","asn":1234,"city":"Wuhan"}},
{"location":{"country":"CN","asn":4837,"city":""}}
]`, strings.Repeat("x", 1<<20))
				}
			}))
			loop := &Loop{BaseURL: server.URL, Transport: client.Transport}
			got, err := loop.Locations(context.Background())
			if calls != 1 || (err != nil) != (scenario != "success") {
				t.Fatal(calls, got, err)
			}
			if scenario == "success" && !reflect.DeepEqual(got, []LocationOption{{ASN: 4134, City: "Shanghai", Count: 1}, {ASN: 4837, City: "Wuhan", Count: 2}, {ASN: 9808, City: "Beijing", Count: 1}}) {
				t.Fatal("wrong online source counts", got)
			}
		})
	}
}

func TestInvalidStoredSourceDoesNotClaimOrMeasure(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetKV("mainland.source", `{"asn":1234,"city":"Wuhan"}`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	loop := &Loop{Store: s, BaseURL: server.URL, Transport: client.Transport}
	if err := loop.Check(context.Background(), time.Now()); err == nil || calls != 0 {
		t.Fatal("invalid configuration measured", calls, err)
	}
	if last, err := s.KV("mainland.last_attempt"); err != nil || last != "" {
		t.Fatal("invalid configuration consumed hourly batch", last, err)
	}
}
