package panel

import (
	"fmt"
	"slices"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

type mainlandProbeView struct {
	store.MainlandProbe
	State, Tone, TCP, Rate, CityText string
}

func mainlandViews(samples []store.MainlandProbe, source store.MainlandSource, now time.Time) []mainlandProbeView {
	v := mainlandProbeView{MainlandProbe: store.MainlandProbe{Carrier: source.Carrier(), City: source.City}, State: "暂无数据", Tone: "muted", TCP: "—", Rate: "—", CityText: "来源待定"}
	index := slices.IndexFunc(samples, source.Matches)
	if source.City != "" {
		v.CityText = source.City
	}
	if index >= 0 {
		v.MainlandProbe = samples[index]
		if v.City != "" {
			v.CityText = v.City
		}
		switch {
		case v.Time == 0:
		case now.Unix()-v.Time > int64(proto.ProbeMaxAge/time.Second):
			v.State = "暂无新数据"
		case v.Status == "unavailable":
			v.State = "探针不可用"
		case v.Status == "failed":
			v.State, v.Tone, v.Rate = "连接失败", "danger", "0%"
		case v.Status == "ok":
			v.State, v.Tone = "成功", "ok"
			v.TCP = fmt.Sprintf("%.1f ms", v.TCPMS)
			v.Rate = fmt.Sprintf("%.0f%%", float64(v.Received)*100/float64(v.Sent))
			if v.Received < v.Sent {
				v.State, v.Tone = "部分成功", "warn"
				v.Rate = fmt.Sprintf("%.1f%%", float64(v.Received)*100/float64(v.Sent))
			}
		}
	}
	return []mainlandProbeView{v}
}
