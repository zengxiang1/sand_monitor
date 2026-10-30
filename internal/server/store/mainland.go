package store

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

type MainlandSource struct {
	ASN  int    `json:"asn"`
	City string `json:"city"`
}

func (source MainlandSource) Carrier() string {
	switch source.ASN {
	case 4134:
		return "中国电信"
	case 4837:
		return "中国联通"
	case 9808:
		return "中国移动"
	default:
		return ""
	}
}

func (source MainlandSource) Validate() error {
	if source.Carrier() == "" {
		return errors.New("unsupported mainland ASN")
	}
	if !utf8.ValidString(source.City) || len(source.City) > 128 || source.City != strings.TrimSpace(source.City) || strings.ContainsFunc(source.City, unicode.IsControl) {
		return errors.New("invalid mainland city")
	}
	return nil
}

func (source MainlandSource) Matches(sample MainlandProbe) bool {
	return (sample.ASN == source.ASN || sample.ASN == 0 && sample.Status == "unavailable" && sample.Carrier == source.Carrier()) && (source.City == "" || sample.City == source.City)
}

func (s *Store) MainlandSource() (MainlandSource, error) {
	raw, err := s.KV("mainland.source")
	if err != nil {
		return MainlandSource{}, err
	}
	if raw == "" {
		return MainlandSource{ASN: 4837}, nil
	}
	var source MainlandSource
	if err = json.Unmarshal([]byte(raw), &source); err != nil {
		return MainlandSource{}, err
	}
	return source, source.Validate()
}

func (s *Store) SetMainlandSource(source MainlandSource) error {
	if err := source.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return err
	}
	return s.SetKV("mainland.source", string(raw))
}

// MainlandProbe is a provider-validated external TCP measurement, separate from
// the node's signed agent reports. Only the latest per-node batch is retained.
// Status is ok for any successful replies, failed for a completed test with no
// replies, or unavailable when the provider could not supply a completed test.
type MainlandProbe struct {
	Carrier       string  `json:"carrier"`
	City          string  `json:"city"`
	Network       string  `json:"network"`
	Country       string  `json:"country"`
	MeasurementID string  `json:"measurement_id"`
	Status        string  `json:"status"`
	ASN           int     `json:"asn"`
	Time          int64   `json:"time"`
	TCPMS         float64 `json:"tcp_ms"`
	Sent          int     `json:"sent"`
	Received      int     `json:"received"`
}

func (s *Store) MainlandProbes(node string) ([]MainlandProbe, error) {
	raw, err := s.KV("mainland.latest." + node)
	if err != nil {
		return nil, err
	}
	samples := []MainlandProbe{}
	if raw == "" {
		return samples, nil
	}
	err = json.Unmarshal([]byte(raw), &samples)
	return samples, err
}

func (s *Store) SetMainlandProbes(node string, samples []MainlandProbe) error {
	raw, err := json.Marshal(samples)
	if err != nil {
		return err
	}
	return s.SetKV("mainland.latest."+node, string(raw))
}
