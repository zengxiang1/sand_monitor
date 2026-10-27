package main

import (
	"context"
	"net/http"
	"testing"
	"wanglou/internal/testutil"
)

func TestHealthcheckClient(t *testing.T) {
	for _, status := range []int{204, 200, 503, 302} {
		server, client := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/healthz" {
				t.Errorf("unexpected healthcheck request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(status)
		}))
		if err := checkHealth(context.Background(), server.URL+"/healthz", client); (err == nil) != (status == 204) {
			t.Fatal(status, err)
		}
	}
	for _, args := range [][]string{{"--url", "invalid"}, {"--url", "file:///healthz"}, {"extra"}, {"--unknown"}} {
		if err := run(append([]string{"healthcheck"}, args...)); err == nil {
			t.Fatal(args)
		}
	}
	if defaultHealthURL != "http://127.0.0.1:8080/healthz" {
		t.Fatal(defaultHealthURL)
	}
}
