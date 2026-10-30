// Package mainland collects hourly third-party TCP measurements from China.
package mainland

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

type Target struct {
	Node    string
	Address netip.AddrPort
}

type Loop struct {
	Store     *store.Store
	Targets   []Target
	Transport http.RoundTripper
	BaseURL   string
}

type measurementOptions struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Packets  int    `json:"packets,omitempty"`
}

type location struct {
	Country string `json:"country"`
	ASN     int    `json:"asn"`
	City    string `json:"city,omitempty"`
	Limit   int    `json:"limit"`
}

type LocationOption struct {
	ASN   int    `json:"asn"`
	City  string `json:"city"`
	Count int    `json:"count"`
}

// Locations lists online city/network pools, never individual probe identities.
func (l *Loop) Locations(ctx context.Context) ([]LocationOption, error) {
	body, _, _, err := l.request(ctx, http.MethodGet, "/v1/probes", nil, "")
	if err != nil {
		return nil, err
	}
	var probes []struct {
		Location struct {
			Country string `json:"country"`
			ASN     int    `json:"asn"`
			City    string `json:"city"`
		} `json:"location"`
	}
	if err := json.Unmarshal(body, &probes); err != nil || probes == nil {
		return nil, fmt.Errorf("invalid provider probe list JSON")
	}
	counts := map[store.MainlandSource]int{}
	for _, probe := range probes {
		source := store.MainlandSource{ASN: probe.Location.ASN, City: probe.Location.City}
		if probe.Location.Country != "CN" || source.City == "" || source.Validate() != nil {
			continue
		}
		counts[source]++
	}
	options := make([]LocationOption, 0, len(counts))
	for source, count := range counts {
		options = append(options, LocationOption{ASN: source.ASN, City: source.City, Count: count})
	}
	sort.Slice(options, func(i, j int) bool {
		if options[i].ASN != options[j].ASN {
			return options[i].ASN < options[j].ASN
		}
		return options[i].City < options[j].City
	})
	return options, nil
}

type measurementRequest struct {
	Type               string             `json:"type"`
	Target             string             `json:"target"`
	MeasurementOptions measurementOptions `json:"measurementOptions"`
	Locations          json.RawMessage    `json:"locations"`
}

type measurement struct {
	ID                 string             `json:"id"`
	Type               string             `json:"type"`
	Status             string             `json:"status"`
	Target             string             `json:"target"`
	MeasurementOptions measurementOptions `json:"measurementOptions"`
	Results            []struct {
		Probe struct {
			Country string `json:"country"`
			City    string `json:"city"`
			ASN     int    `json:"asn"`
			Network string `json:"network"`
		} `json:"probe"`
		Result struct {
			Status          string `json:"status"`
			ResolvedAddress string `json:"resolvedAddress"`
			Stats           *struct {
				Avg   *float64 `json:"avg"`
				Total int      `json:"total"`
				RCV   *int     `json:"rcv"`
			} `json:"stats"`
		} `json:"result"`
	} `json:"results"`
}

// Check claims the hourly batch before contacting the provider, including when
// the previous process stopped during a measurement or the provider was down.
func (l *Loop) Check(ctx context.Context, now time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	source, err := l.Store.MainlandSource()
	if err != nil {
		return err
	}
	active := []Target{}
	for _, target := range l.Targets {
		node, err := l.Store.Node(target.Node)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if node.RevokedAt == 0 {
			active = append(active, target)
		}
	}
	if len(active) == 0 {
		return nil
	}
	claimed := false
	if err := l.Store.Transaction(func(tx *sql.Tx) error {
		var last int64
		if err := tx.QueryRow(`SELECT coalesce((SELECT CAST(value AS INTEGER) FROM kv WHERE key='mainland.last_attempt'),0)`).Scan(&last); err != nil {
			return err
		}
		if last != 0 && now.Sub(time.Unix(last, 0)) < proto.ProbeInterval {
			return nil
		}
		if _, err := tx.Exec(`INSERT INTO kv(key,value) VALUES('mainland.last_attempt',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, now.Unix()); err != nil {
			return err
		}
		claimed = true
		return nil
	}); err != nil || !claimed {
		return err
	}
	locations, err := json.Marshal([]location{{Country: "CN", ASN: source.ASN, City: source.City, Limit: 1}})
	if err != nil {
		return err
	}
	var failures []error
	for i, target := range active {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		samples, err := l.measure(ctx, target, now, source, locations)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", target.Node, err))
		}
		if err := l.Store.SetMainlandProbes(target.Node, samples); err != nil {
			return err
		}
		if i == 0 {
			// Every later server reuses the first measurement's probe. Without
			// its ID, leave the rest unavailable instead of selecting new points.
			locations = nil
			if samples[0].MeasurementID != "" {
				locations, err = json.Marshal(samples[0].MeasurementID)
				if err != nil {
					return err
				}
			}
		}
	}
	return errors.Join(failures...)
}

func (l *Loop) request(ctx context.Context, method, path string, payload []byte, etag string) ([]byte, string, int, error) {
	base := l.BaseURL
	if base == "" {
		base = "https://api.globalping.io"
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("User-Agent", "Wanglou/1.0")
	req.Header.Set("Accept", "application/json")
	if len(payload) != 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: l.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	maxBytes := 1 << 20
	if path == "/v1/probes" {
		maxBytes = 16 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, "", 0, err
	}
	if len(body) > maxBytes {
		return nil, "", resp.StatusCode, fmt.Errorf("provider response exceeds %d bytes", maxBytes)
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil, resp.Header.Get("ETag"), resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", resp.StatusCode, fmt.Errorf("provider HTTP %d", resp.StatusCode)
	}
	return body, resp.Header.Get("ETag"), resp.StatusCode, nil
}

func (l *Loop) measure(ctx context.Context, target Target, now time.Time, source store.MainlandSource, locations json.RawMessage) ([]store.MainlandProbe, error) {
	samples := []store.MainlandProbe{{Carrier: source.Carrier(), ASN: source.ASN, City: source.City, Time: now.Unix(), Status: "unavailable"}}
	if len(locations) == 0 {
		return samples, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	payload, err := json.Marshal(measurementRequest{Type: "ping", Target: target.Address.Addr().String(), MeasurementOptions: measurementOptions{Protocol: "TCP", Port: target.Address.Port(), Packets: 3}, Locations: locations})
	if err != nil {
		return samples, err
	}
	body, _, _, err := l.request(ctx, http.MethodPost, "/v1/measurements", payload, "")
	if err != nil {
		return samples, err
	}
	var created struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(body, &created); err != nil || created.ID == "" || len(created.ID) > 128 {
		return samples, fmt.Errorf("invalid provider measurement ID")
	}
	samples[0].MeasurementID = created.ID
	etag := ""
	for {
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return samples, ctx.Err()
		case <-timer.C:
		}
		var status int
		var nextETag string
		body, nextETag, status, err = l.request(ctx, http.MethodGet, "/v1/measurements/"+url.PathEscape(created.ID), nil, etag)
		if status != http.StatusNotModified || nextETag != "" {
			etag = nextETag
		}
		if err != nil {
			return samples, err
		}
		if status == http.StatusNotModified {
			continue
		}
		var data measurement
		if err = json.Unmarshal(body, &data); err != nil {
			return samples, fmt.Errorf("invalid provider measurement JSON")
		}
		if data.ID != created.ID || data.Type != "ping" || data.Target != target.Address.Addr().String() || data.MeasurementOptions.Protocol != "TCP" || data.MeasurementOptions.Port != target.Address.Port() {
			return samples, fmt.Errorf("provider measurement does not match requested TCP target")
		}
		if data.Status == "in-progress" {
			continue
		}
		if data.Status != "finished" {
			return samples, fmt.Errorf("provider measurement unavailable")
		}
		for _, result := range data.Results {
			if result.Probe.Country != "CN" || result.Probe.ASN != source.ASN || source.City != "" && result.Probe.City != source.City {
				continue
			}
			sample := &samples[0]
			sample.City, sample.Network, sample.Country = result.Probe.City, result.Probe.Network, result.Probe.Country
			stats := result.Result.Stats
			if result.Result.Status != "finished" || result.Result.ResolvedAddress != target.Address.Addr().String() || stats == nil || stats.Total < 1 || stats.Total > 3 || stats.RCV == nil || *stats.RCV < 0 || *stats.RCV > stats.Total {
				continue
			}
			if *stats.RCV > 0 && (stats.Avg == nil || math.IsNaN(*stats.Avg) || math.IsInf(*stats.Avg, 0) || *stats.Avg < 0 || *stats.Avg > 60000) {
				continue
			}
			sample.Sent, sample.Received, sample.Status = stats.Total, *stats.RCV, "failed"
			if *stats.RCV > 0 {
				sample.Status, sample.TCPMS = "ok", *stats.Avg
			}
		}

		return samples, nil
	}
}

func (l *Loop) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := l.Check(ctx, time.Now()); err != nil && ctx.Err() == nil {
			log.Printf("mainland TCP probes: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
