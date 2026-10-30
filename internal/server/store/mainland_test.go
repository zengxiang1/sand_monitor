package store

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestMainlandLatestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	missing, err := s.MainlandProbes("node")
	if err != nil || len(missing) != 0 {
		t.Fatal(missing, err)
	}
	samples := []MainlandProbe{
		{Carrier: "中国电信", City: "Shanghai", Network: "CHINANET", Country: "CN", MeasurementID: "m1", Status: "ok", ASN: 4134, Time: 1700000000, TCPMS: 32.5, Sent: 3, Received: 2},
		{Carrier: "中国联通", City: "Beijing", Network: "CHINA UNICOM", Country: "CN", MeasurementID: "m1", Status: "failed", ASN: 4837, Time: 1700000000, Sent: 3},
		{Carrier: "中国移动", MeasurementID: "m1", Status: "unavailable", ASN: 9808, Time: 1700000000},
	}
	if err = s.SetMainlandProbes("node", samples); err != nil {
		t.Fatal(err)
	}
	got, err := s.MainlandProbes("node")
	if err != nil || !reflect.DeepEqual(got, samples) {
		t.Fatal(got, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.MainlandProbes("node")
	if err != nil || !reflect.DeepEqual(got, samples) {
		t.Fatal("latest batch did not survive reopen", got, err)
	}
	if err = s.SetMainlandProbes("other", samples); err != nil {
		t.Fatal(err)
	}
	replacement := []MainlandProbe{{Carrier: "中国电信", Country: "CN", MeasurementID: "m2", Status: "ok", ASN: 4134, Time: 1700003600, TCPMS: 21.25, Sent: 3, Received: 3}}
	if err = s.SetMainlandProbes("node", replacement); err != nil {
		t.Fatal(err)
	}
	got, err = s.MainlandProbes("node")
	if err != nil || !reflect.DeepEqual(got, replacement) {
		t.Fatal("latest batch was merged instead of replaced", got, err)
	}
	other, err := s.MainlandProbes("other")
	if err != nil || !reflect.DeepEqual(other, samples) {
		t.Fatal("overwrite changed another node", other, err)
	}
	var keys int
	if err = s.DB.QueryRow(`SELECT count(*) FROM kv WHERE key LIKE 'mainland.latest.%'`).Scan(&keys); err != nil || keys != 2 {
		t.Fatal("retained historical batches", keys, err)
	}
	if err = s.SetMainlandProbes("node", []MainlandProbe{}); err != nil {
		t.Fatal(err)
	}
	got, err = s.MainlandProbes("node")
	if err != nil || len(got) != 0 {
		t.Fatal("empty replacement kept old results", got, err)
	}
}

func TestMainlandSourcePersistenceValidationAndMatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if source, err := s.MainlandSource(); err != nil || source != (MainlandSource{ASN: 4837}) {
		t.Fatal("default source", source, err)
	}
	if err := s.SetKV("mainland.last_attempt", "1700000000"); err != nil {
		t.Fatal(err)
	}
	for _, source := range []MainlandSource{{ASN: 4134, City: "Shanghai"}, {ASN: 4837}, {ASN: 9808, City: "Xi'an"}} {
		if source.Carrier() == "" {
			t.Fatal("missing carrier", source)
		}
		if err := s.SetMainlandSource(source); err != nil {
			t.Fatal(err)
		}
		if got, err := s.MainlandSource(); err != nil || got != source {
			t.Fatal(got, err)
		}
	}
	if last, err := s.KV("mainland.last_attempt"); err != nil || last != "1700000000" {
		t.Fatal("source change reset hourly schedule", last, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := MainlandSource{ASN: 9808, City: "Xi'an"}
	if got, err := s.MainlandSource(); err != nil || got != want {
		t.Fatal("source not persisted", got, err)
	}
	for _, source := range []MainlandSource{{}, {ASN: 1234}, {ASN: 4837, City: " Wuhan"}, {ASN: 4837, City: "Wuhan\n"}, {ASN: 4837, City: string([]byte{0xff})}} {
		if source.Validate() == nil || s.SetMainlandSource(source) == nil {
			t.Fatal("invalid source accepted", source)
		}
	}
	if got, err := s.MainlandSource(); err != nil || got != want {
		t.Fatal("invalid write replaced source", got, err)
	}
	for _, raw := range []string{`{`, `{}`, `{"asn":1234,"city":""}`, `{"asn":4837,"city":"\n"}`} {
		if err := s.SetKV("mainland.source", raw); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MainlandSource(); err == nil {
			t.Fatal("invalid stored source accepted", raw)
		}
	}
	for _, tc := range []struct {
		source MainlandSource
		sample MainlandProbe
		want   bool
	}{
		{MainlandSource{ASN: 4837}, MainlandProbe{ASN: 4837, City: "Wuhan", Status: "ok"}, true},
		{MainlandSource{ASN: 4837, City: "Wuhan"}, MainlandProbe{ASN: 4837, City: "Wuhan", Status: "unavailable"}, true},
		{MainlandSource{ASN: 4837, City: "Wuhan"}, MainlandProbe{ASN: 4837, City: "Beijing", Status: "ok"}, false},
		{MainlandSource{ASN: 4837}, MainlandProbe{ASN: 4134, City: "Wuhan", Status: "ok"}, false},
		{MainlandSource{ASN: 4837}, MainlandProbe{Carrier: "中国联通", Status: "unavailable"}, true},
		{MainlandSource{ASN: 4837}, MainlandProbe{Carrier: "中国电信", Status: "unavailable"}, false},
		{MainlandSource{ASN: 4837, City: "Wuhan"}, MainlandProbe{Carrier: "中国联通", Status: "unavailable"}, false},
		{MainlandSource{ASN: 4837}, MainlandProbe{Carrier: "中国联通", Status: "ok"}, false},
	} {
		if got := tc.source.Matches(tc.sample); got != tc.want {
			t.Fatalf("source %+v sample %+v: got %v", tc.source, tc.sample, got)
		}
	}
}
