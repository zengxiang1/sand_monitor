package eventtext

import "testing"

func TestDurationAndKinds(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    string
	}{{-1, "0 秒"}, {5, "5 秒"}, {60, "1 分 0 秒"}, {3599, "59 分 59 秒"}, {3600, "1 小时 0 分"}, {7325, "2 小时 2 分"}} {
		if got := Duration(tc.seconds); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	for kind, want := range map[string]string{"offline": "失联", "recovered": "恢复", "bin_changed": "二进制变化", "login_new_ip": "新登录", "resource": "资源告警", "billing": "续费", "traffic": "流量", "traffic_reset": "流量", "unknown": "unknown"} {
		if got := Kind(kind); got != want {
			t.Fatal(kind, got)
		}
	}
}
