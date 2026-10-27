package eventtext

import (
	"fmt"
	"time"
)

func Kind(kind string) string {
	names := map[string]string{"login_new_ip": "新登录", "offline": "失联", "recovered": "恢复", "bin_changed": "二进制变化", "resource": "资源告警", "billing": "续费", "traffic": "流量", "traffic_reset": "流量"}
	if label, ok := names[kind]; ok {
		return label
	}
	return kind
}

func Duration(seconds int64) string {
	seconds = max(0, seconds)
	if seconds < 60 {
		return fmt.Sprintf("%d 秒", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%d 分 %d 秒", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%d 小时 %d 分", seconds/3600, seconds/60%60)
}

func Offline(last int64, location *time.Location) string {
	if last == 0 {
		return "从未上报"
	}
	return "最近一次上报 " + time.Unix(last, 0).In(location).Format("2006-01-02 15:04:05")
}

func Resource(name string, threshold float64, sustain time.Duration) string {
	label := "内存"
	if name == "disk" {
		label = "磁盘"
	}
	duration := fmt.Sprintf("%g 秒", sustain.Seconds())
	if sustain%time.Minute == 0 {
		duration = fmt.Sprintf("%g 分钟", sustain.Minutes())
	}
	return fmt.Sprintf("%s超过 %g%%，已持续 %s", label, threshold, duration)
}
