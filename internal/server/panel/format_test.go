package panel

import (
	"strings"
	"testing"
)

func TestFormatRate(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  string
	}{
		{440, "440 B/s"}, {999, "999 B/s"}, {13 * 1024, "13 KB/s"}, {0, "0 B/s"}, {12.34, "12 B/s"}, {1023, "1023 B/s"}, {1024, "1 KB/s"}, {1536, "1.5 KB/s"},
		{1024 * 1024, "1 MB/s"}, {3.5 * 1024 * 1024, "3.5 MB/s"}, {1024 * 1024 * 1024, "1 GB/s"}, {2.5 * 1024 * 1024 * 1024, "2.5 GB/s"},
	} {
		if got := formatRate(tc.value); got != tc.want {
			t.Errorf("%g: got %q, want %q", tc.value, got, tc.want)
		}
	}
}
func TestFormatMemory(t *testing.T) {
	for _, tc := range []struct {
		used, total float64
		want        string
	}{
		{0, 0, "0.0 / 0.0 MiB"}, {0, 512, "0.0 / 512.0 MiB"}, {512, 1023, "512.0 / 1023.0 MiB"},
		{512, 1024, "0.5 / 1.0 GiB"}, {1433.6, 4096, "1.4 / 4.0 GiB"}, {512, 2048, "0.5 / 2.0 GiB"},
	} {
		if got := formatMemory(tc.used, tc.total); got != tc.want {
			t.Errorf("%g/%g: got %q, want %q", tc.used, tc.total, got, tc.want)
		}
	}
}
func TestFormatUptime(t *testing.T) {
	for _, tc := range []struct {
		seconds float64
		want    string
	}{
		{0, "0 分钟"}, {59.9, "0 分钟"}, {60, "1 分钟"}, {3599, "59 分钟"}, {3600, "1 小时 0 分钟"},
		{3660, "1 小时 1 分钟"}, {86399, "23 小时 59 分钟"}, {86400, "1 天 0 小时"}, {21*86400 + 3*3600 + 38*60, "21 天 3 小时"},
	} {
		if got := formatUptime(tc.seconds); got != tc.want {
			t.Errorf("%g: got %q, want %q", tc.seconds, got, tc.want)
		}
	}
}
func TestPageMetricFormatting(t *testing.T) {
	f := setup(t)
	report := sampleReport()
	report.Mem = [2]float64{1433.6, 4096}
	report.Swap = [2]float64{512, 2048}
	report.Net = [2]float64{3.5 * 1024 * 1024, 12.3 * 1024}
	report.Up = 21*86400 + 3*3600
	f.report(t, "node", report, 204)
	for _, path := range []string{"/", "/nodes/node"} {
		w := f.request("GET", path, nil, true)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), "1.4 / 4.0 GiB") {
			t.Fatal(path, "memory units missing")
		}
		if path == "/" {
			for _, want := range []string{"↑ 3.5 MB/s", "↓ 12.3 KB/s"} {
				if !strings.Contains(w.Body.String(), want) {
					t.Fatal("network rate missing", want)
				}
			}
		} else {
			for _, want := range []string{"0.5 / 2.0 GiB", "21 天 3 小时", "3.5 MB/s", "1.8 MB/s", "0 B/s"} {
				if !strings.Contains(w.Body.String(), want) {
					t.Fatal("node metric or chart label missing", want)
				}
			}
		}
	}
}

func TestNodeTitleSeparators(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct{ note, ip, want string }{
		{"", "", `class="muted mono">每 `},
		{"", "192.0.2.1", `class="muted mono">192.0.2.1 · 每 `},
		{"备注", "", `class="muted mono">备注 · 每 `},
		{"备注", "192.0.2.1", `class="muted mono">备注 · 192.0.2.1 · 每 `},
	} {
		if _, err := f.s.DB.Exec(`UPDATE nodes SET note=?,last_ip=? WHERE name='node'`, tc.note, tc.ip); err != nil {
			t.Fatal(err)
		}
		w := f.request("GET", "/nodes/node", nil, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
