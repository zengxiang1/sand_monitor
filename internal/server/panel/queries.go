package panel

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"wanglou/internal/server/ingest"
	"wanglou/internal/server/store"
)

type metric struct {
	CPU, Load1, Load5, Load15, MemUsed, MemTotal, SwapUsed, SwapTotal, DiskUsed, DiskTotal, TX, RX, Up float64
	TCP, UDP                                                                                           int64
}
type nodeView struct {
	store.Node
	Metric                         metric
	Status, Tone, Spark, SparkArea string
	Active                         bool
	Tags                           []tag
}
type loginRecord struct {
	Time     int64
	User, IP string
	Known    bool
}
type chart struct{ Title, Line, Line2, Area, Top, Mid, Zero, Start, End, Summary string }
type tag struct{ Text, Tone string }
type page struct {
	Billing                                                                 billingPage
	Public                                                                  publicPage
	PublicDir, Heartbeat                                                    string
	HeartbeatConfigured                                                     bool
	Refresh                                                                 bool
	Page, User, CSRF, Error, NodeLink                                       string
	Nodes                                                                   []nodeView
	Node                                                                    nodeView
	Total, Online, Offline, Alerting, More                                  int
	Events, Banners                                                         []store.Event
	Logins                                                                  []loginRecord
	Charts                                                                  []chart
	Stats                                                                   ingest.Statistics
	Channels                                                                []string
	Interval, Range                                                         string
	Name, Note, PublicURL, Command, State, Code, Pubkey, Success, Remaining string
	Fingerprint                                                             []string
	Expires                                                                 int64
}

func formatTime(ts int64) string {
	if ts == 0 {
		return "—"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}
func relative(ts int64, now time.Time) string {
	if ts == 0 {
		return "从未上报"
	}
	seconds := max(int64(0), now.Unix()-ts)
	if seconds < 60 {
		return fmt.Sprintf("%d 秒前", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%d 分钟前", seconds/60)
	}
	if seconds < 86400 {
		return fmt.Sprintf("%d 小时前", seconds/3600)
	}
	return fmt.Sprintf("%d 天前", seconds/86400)
}
func percent(used, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return min(100, max(0, used/total*100))
}
func formatNumber(n float64) string { return fmt.Sprintf("%.1f", n) }
func formatRate(value float64) string {
	units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}
func formatMemory(used, total float64) string {
	unit := "MiB"
	if total >= 1024 {
		used /= 1024
		total /= 1024
		unit = "GiB"
	}
	return fmt.Sprintf("%.1f / %.1f %s", used, total, unit)
}
func formatUptime(seconds float64) string {
	days := int64(seconds / 86400)
	hours := int64(seconds/3600) % 24
	minutes := int64(seconds/60) % 60
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%d 小时 %d 分钟", hours, minutes)
	}
	return fmt.Sprintf("%d 分钟", minutes)
}
func eventKind(kind string) string {
	names := map[string]string{"login_new_ip": "新登录", "offline": "失联", "recovered": "恢复", "bin_changed": "二进制变化", "resource": "资源告警", "billing": "续费", "traffic": "流量", "traffic_reset": "流量"}
	if label, ok := names[kind]; ok {
		return label
	}
	return kind
}
func (h *Handler) base(sess session) page {
	heartbeat := "未配置"
	if h.Config.HeartbeatStatus != nil {
		heartbeat = h.Config.HeartbeatStatus(h.Now())
	}
	return page{PublicDir: h.Config.PublicDir, Heartbeat: heartbeat, HeartbeatConfigured: h.Config.HeartbeatURL != "", User: sess.User, CSRF: sess.CSRF, Channels: h.Config.Channels, Interval: fmt.Sprintf("%.0f 秒", h.Config.Interval.Seconds())}
}
func (h *Handler) latest(name string) (metric, error) {
	var m metric
	err := h.Store.DB.QueryRow(`SELECT coalesce(cpu,0),coalesce(load1,0),coalesce(load5,0),coalesce(load15,0),coalesce(mem_used,0),coalesce(mem_total,0),coalesce(swap_used,0),coalesce(swap_total,0),coalesce(disk_used,0),coalesce(disk_total,0),coalesce(net_tx,0),coalesce(net_rx,0),coalesce(tcp,0),coalesce(udp,0),coalesce(uptime,0) FROM metrics WHERE node=? ORDER BY ts DESC LIMIT 1`, name).Scan(&m.CPU, &m.Load1, &m.Load5, &m.Load15, &m.MemUsed, &m.MemTotal, &m.SwapUsed, &m.SwapTotal, &m.DiskUsed, &m.DiskTotal, &m.TX, &m.RX, &m.TCP, &m.UDP, &m.Up)
	if err == sql.ErrNoRows {
		err = nil
	}
	return m, err
}
func (h *Handler) view(n store.Node) (nodeView, error) {
	if n.MutedUntil <= h.Now().Unix() {
		n.MutedUntil = 0
	}
	v := nodeView{Node: n, Status: "正常", Tone: "ok"}
	var err error
	v.Metric, err = h.latest(n.Name)
	if err != nil {
		return v, err
	}
	var active bool
	err = h.Store.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM resource_alerts WHERE node=? AND active=1)`, n.Name).Scan(&active)
	if err != nil {
		return v, err
	}
	v.Active = active
	if active {
		v.Status = "告警"
		v.Tone = "warn"
	}
	if n.LastSeen != 0 && h.Now().Unix()-n.LastSeen > int64(3*h.Config.Interval/time.Second) {
		v.Status = "失联"
		v.Tone = "danger"
	}
	if n.LastSeen == 0 {
		v.Status = "从未上报"
		v.Tone = "muted"
	}
	if n.RevokedAt != 0 {
		v.Status = "已吊销"
		v.Tone = "muted"
	}
	return v, nil
}
func points(values []float64, width, height, maxValue float64) string {
	var b strings.Builder
	for i, value := range values {
		x := float64(i) * width / float64(max(1, len(values)-1))
		y := height - min(height, max(0, value/maxValue*height))
		fmt.Fprintf(&b, "%.2f,%.2f ", x, y)
	}
	return b.String()
}
func (h *Handler) overview(w http.ResponseWriter, r *http.Request, sess session) {
	data := h.base(sess)
	nodes, err := h.Store.Nodes()
	if err != nil {
		h.serverError(w, err)
		return
	}
	data.Billing, err = h.billingData()
	if err != nil {
		h.serverError(w, err)
		return
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].RevokedAt == 0 && nodes[j].RevokedAt != 0 })
	for _, n := range nodes {
		v, err := h.view(n)
		if n.RevokedAt == 0 {
			for _, b := range data.Billing.Rows {
				if b.Name == n.Name {
					if b.HasExpiry && b.Days <= 7 {
						label := fmt.Sprintf("%d 天后到期", b.Days)
						if b.Days < 0 {
							label = "已过期"
						}
						v.Tags = append(v.Tags, tag{label, b.DueTone})
					}
					if b.Pct >= 80 {
						v.Tags = append(v.Tags, tag{fmt.Sprintf("流量 %d%%", b.Pct), b.Tone})
					}
					break
				}
			}
		}
		if err != nil {
			h.serverError(w, err)
			return
		}
		rows, err := h.Store.DB.Query(`SELECT cpu FROM (SELECT cpu,ts FROM metrics WHERE node=? AND ts>=? ORDER BY ts DESC LIMIT 30) ORDER BY ts`, n.Name, h.Now().Add(-150*time.Second).Unix())
		if err != nil {
			h.serverError(w, err)
			return
		}
		var values []float64
		for rows.Next() {
			var cpu float64
			if err = rows.Scan(&cpu); err != nil {
				break
			}
			values = append(values, cpu)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			h.serverError(w, err)
			return
		}
		v.Spark = points(values, 120, 28, 100)
		if len(values) > 0 {
			v.SparkArea = "0,28 " + v.Spark + "120,28"
		}
		data.Nodes = append(data.Nodes, v)
		data.Total++
		if n.RevokedAt == 0 && n.LastSeen != 0 {
			if v.Status == "失联" {
				data.Offline++
			} else {
				data.Online++
			}
			if v.Active {
				data.Alerting++
			}
		}
	}
	if len(nodes) > 0 {
		data.NodeLink = "/nodes/" + nodes[0].Name
	}
	data.Events, err = h.events(false)
	if err == nil {
		data.Banners, err = h.events(true)
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	var count int
	if err = h.Store.DB.QueryRow(`SELECT count(*) FROM events WHERE kind='login_new_ip' AND acked_at=0`).Scan(&count); err != nil {
		h.serverError(w, err)
		return
	}
	data.More = max(0, count-5)
	if h.Ingest != nil {
		data.Stats = h.Ingest.Stats()
	}
	h.render(w, r, "overview", data, 200)
}
func (h *Handler) events(banner bool) ([]store.Event, error) {
	query := `SELECT id,ts,node,kind,detail,notified FROM events ORDER BY id DESC LIMIT 20`
	if banner {
		query = `SELECT id,ts,node,kind,detail,notified FROM events WHERE kind='login_new_ip' AND acked_at=0 ORDER BY id DESC LIMIT 5`
	}
	rows, err := h.Store.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		var event store.Event
		if err = rows.Scan(&event.ID, &event.Time, &event.Node, &event.Kind, &event.Detail, &event.Notified); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

type historyPoint struct {
	Time                   int64
	CPU, Mem, Disk, TX, RX float64
}

func (h *Handler) history(name string, duration time.Duration) ([]historyPoint, error) {
	now := h.Now().Unix()
	start := now - int64(duration/time.Second)
	width := (int64(duration/time.Second) + 360) / 360
	rows, err := h.Store.DB.Query(`SELECT min(ts),avg(cpu),avg(CASE WHEN mem_total>0 THEN mem_used*100.0/mem_total ELSE 0 END),avg(CASE WHEN disk_total>0 THEN disk_used*100.0/disk_total ELSE 0 END),avg(net_tx),avg(net_rx) FROM metrics WHERE node=? AND ts>=? AND ts<=? GROUP BY (ts-?)/? ORDER BY min(ts)`, name, start, now, start, width)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []historyPoint
	for rows.Next() {
		var p historyPoint
		if err = rows.Scan(&p.Time, &p.CPU, &p.Mem, &p.Disk, &p.TX, &p.RX); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (h *Handler) node(w http.ResponseWriter, r *http.Request, sess session) {
	n, err := h.Store.Node(r.PathValue("name"))
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	data := h.base(sess)
	data.Node, err = h.view(n)
	if err != nil {
		h.serverError(w, err)
		return
	}
	data.NodeLink = "/nodes/" + n.Name
	data.Range = r.URL.Query().Get("range")
	duration := time.Hour
	switch data.Range {
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	default:
		data.Range = "1h"
	}
	history, err := h.history(n.Name, duration)
	if err != nil {
		h.serverError(w, err)
		return
	}
	for _, title := range []string{"CPU", "内存", "磁盘", "网络 ↑ / ↓"} {
		var values, other []float64
		ceiling := 100.0
		for _, p := range history {
			switch title {
			case "CPU":
				values = append(values, p.CPU)
			case "内存":
				values = append(values, p.Mem)
			case "磁盘":
				values = append(values, p.Disk)
			default:
				values = append(values, p.RX)
				other = append(other, p.TX)
			}
		}
		top := "100%"
		mid := "50%"
		summary := "平均值 · %"
		zero := "0"
		if title == "网络 ↑ / ↓" {
			ceiling = 1
			for i := range values {
				ceiling = max(ceiling, values[i], other[i])
			}
			top = formatRate(ceiling)
			mid = formatRate(ceiling / 2)
			zero = formatRate(0)
			summary = "下行（蓝） / 上行（橙）"
		}
		var line, line2 strings.Builder
		start := h.Now().Add(-duration).Unix()
		for i, p := range history {
			x := 84 + float64(p.Time-start)/duration.Seconds()*508
			y := 160 - min(146, max(0, values[i]/ceiling*146))
			fmt.Fprintf(&line, "%.2f,%.2f ", x, y)
			if len(other) > 0 {
				fmt.Fprintf(&line2, "%.2f,%.2f ", x, 160-min(146, max(0, other[i]/ceiling*146)))
			}
		}
		area := ""
		if len(history) > 0 {
			area = "84,160 " + line.String() + "592,160"
		}
		data.Charts = append(data.Charts, chart{Area: area, Title: title, Line: line.String(), Line2: line2.String(), Top: top, Mid: mid, Zero: zero, Start: time.Unix(start, 0).Format("01-02 15:04"), End: h.Now().Format("01-02 15:04"), Summary: summary})
	}
	rows, err := h.Store.DB.Query(`SELECT ts,user,from_ip,known FROM logins WHERE node=? ORDER BY ts DESC LIMIT 50`, n.Name)
	if err != nil {
		h.serverError(w, err)
		return
	}
	for rows.Next() {
		var login loginRecord
		if err = rows.Scan(&login.Time, &login.User, &login.IP, &login.Known); err != nil {
			break
		}
		data.Logins = append(data.Logins, login)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.render(w, r, "node", data, 200)
}
