// Package public renders a deliberately limited static status document.
package public

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"wanglou/internal/server/format"
	"wanglou/internal/server/store"
)

//go:embed web/*
var assets embed.FS
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

type Fields struct{ Specs, Usage, Net, Uptime, Availability, Reason bool }
type Selection struct {
	Node   string
	Public bool
	Name   string
}
type Announcement struct {
	ID                              int64
	Title, Node, Status, Time, Body string
}
type PublicConfig struct {
	Title         string
	Interval      int
	Access, Token string
	Fields        Fields
	Nodes         []Selection
	Announcements []Announcement
}

func Token() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func DefaultConfig() PublicConfig {
	return PublicConfig{Title: "服务器状态", Interval: 30, Access: "public", Token: Token(), Fields: Fields{true, true, true, true, true, true}, Nodes: []Selection{}, Announcements: []Announcement{}}
}
func (c PublicConfig) Validate() error {
	if !utf8.ValidString(c.Title) || len([]rune(c.Title)) > 40 || strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("页面标题须为 1 到 40 个字符")
	}
	if !slices.Contains([]int{30, 60, 300}, c.Interval) || !slices.Contains([]string{"public", "token"}, c.Access) || !tokenPattern.MatchString(c.Token) {
		return fmt.Errorf("导出间隔或访问方式无效")
	}
	seen := map[string]bool{}
	for _, n := range c.Nodes {
		if seen[n.Node] || !utf8.ValidString(n.Name) || len([]rune(n.Name)) > 32 || n.Public && strings.TrimSpace(n.Name) == "" {
			return fmt.Errorf("公开显示名必填，最多 32 个字符")
		}
		seen[n.Node] = true
	}
	if len(c.Announcements) > 100 {
		return fmt.Errorf("最多 100 条公告")
	}
	ids := map[int64]bool{}
	for _, a := range c.Announcements {
		if err := a.Validate(); err != nil {
			return err
		}
		if a.ID <= 0 || ids[a.ID] {
			return fmt.Errorf("公告编号无效")
		}
		ids[a.ID] = true
	}
	return nil
}
func (a Announcement) Validate() error {
	if strings.TrimSpace(a.Title) == "" || strings.TrimSpace(a.Body) == "" {
		return fmt.Errorf("填写标题和内容后才能添加。")
	}
	if !utf8.ValidString(a.Title) || !utf8.ValidString(a.Body) || len([]rune(a.Title)) > 80 || len([]rune(a.Body)) > 1000 {
		return fmt.Errorf("标题最多 80 个字符，内容最多 1000 个字符")
	}
	if !slices.Contains([]string{"investigating", "monitoring", "resolved", "scheduled", "done"}, a.Status) {
		return fmt.Errorf("公告状态无效")
	}
	if _, err := time.Parse(time.RFC3339, a.Time); err != nil {
		return fmt.Errorf("公告时间无效")
	}
	return nil
}
func Load(s *store.Store, key string) (PublicConfig, error) {
	value, err := s.KV(key)
	if err != nil {
		return PublicConfig{}, err
	}
	if value == "" {
		return DefaultConfig(), nil
	}
	var c PublicConfig
	err = json.Unmarshal([]byte(value), &c)
	return c, err
}
func Save(s *store.Store, c PublicConfig, publish bool, now time.Time, user, ip, action string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.Transaction(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO kv VALUES('public.draft',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(data)); err != nil {
			return err
		}
		if publish {
			if _, err := tx.Exec(`INSERT INTO kv VALUES('public.published',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(data)); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,'public_publish','')`, now.Unix(), user, ip); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?, '')`, now.Unix(), user, ip, action)
		return err
	})
}

// Only these export types may reach the HTML renderer or JSON encoder.
type Specs struct {
	MemGB  float64 `json:"mem_gb"`
	DiskGB int     `json:"disk_gb"`
}
type Usage struct {
	CPU  int `json:"cpu"`
	Mem  int `json:"mem"`
	Disk int `json:"disk"`
}
type Net struct {
	TX float64 `json:"tx"`
	RX float64 `json:"rx"`
}

func (n Net) MarshalJSON() ([]byte, error) {
	sig := func(n float64) float64 {
		if n <= 0 {
			return 0
		}
		rounded, _ := strconv.ParseFloat(strconv.FormatFloat(n, 'g', 2, 64), 64)
		return rounded
	}
	type netJSON Net
	return json.Marshal(netJSON{sig(n.TX), sig(n.RX)})
}

type Day struct {
	Date  string `json:"date"`
	State string `json:"state"`
	Down  int64  `json:"down_s"`
}
type Availability struct {
	Pct  string `json:"pct"`
	Days []Day  `json:"days"`
}
type Node struct {
	OfflineDuration string        `json:"-"`
	Name            string        `json:"name"`
	Status          string        `json:"status"`
	Specs           *Specs        `json:"specs,omitempty"`
	Usage           *Usage        `json:"usage,omitempty"`
	Net             *Net          `json:"net,omitempty"`
	UptimeDays      *int          `json:"uptime_days,omitempty"`
	OfflineSince    string        `json:"offline_since,omitempty"`
	Availability    *Availability `json:"availability,omitempty"`
}
type News struct {
	Time   string `json:"time"`
	Title  string `json:"title"`
	Node   string `json:"node,omitempty"`
	Status string `json:"status"`
	Body   string `json:"body"`
}
type Summary struct {
	OK      int `json:"ok"`
	Offline int `json:"offline"`
}
type Document struct {
	V             int     `json:"v"`
	Title         string  `json:"title"`
	Generated     string  `json:"generated"`
	Interval      int     `json:"interval"`
	Summary       Summary `json:"summary"`
	Nodes         []Node  `json:"nodes"`
	Announcements []News  `json:"announcements,omitempty"`
}

func Build(s *store.Store, c PublicConfig, now time.Time) (Document, error) {
	now = now.In(s.Location)
	generated := now.Truncate(time.Duration(c.Interval) * time.Second)
	out := Document{V: 1, Title: c.Title, Generated: generated.Format(time.RFC3339), Interval: c.Interval, Nodes: []Node{}}
	nodes, err := s.Nodes()
	if err != nil {
		return out, err
	}
	names := map[string]string{}
	pct := func(used, total float64) int {
		if total <= 0 {
			return 0
		}
		return int(math.Round(min(100, max(0, used/total*100))))
	}
	for _, selection := range c.Nodes {
		if !selection.Public {
			continue
		}
		idx := slices.IndexFunc(nodes, func(n store.Node) bool { return n.Name == selection.Node && n.RevokedAt == 0 })
		if idx < 0 {
			continue
		}
		source := nodes[idx]
		n := Node{Name: selection.Name, Status: "ok"}
		names[source.Name] = n.Name
		offline := source.LastSeen == 0 || now.Unix()-source.LastSeen > int64(3*s.Interval/time.Second)
		if offline {
			n.Status = "offline"
			out.Summary.Offline++
			if c.Fields.Reason && source.LastSeen > 0 {
				n.OfflineSince = time.Unix(source.LastSeen, 0).In(s.Location).Format(time.RFC3339)
			}
		} else {
			out.Summary.OK++
		}
		var cpu, mu, mt, du, dt, tx, rx, up float64
		err = s.DB.QueryRow(`SELECT cpu,mem_used,mem_total,disk_used,disk_total,net_tx,net_rx,uptime FROM metrics WHERE node=? ORDER BY ts DESC,rowid DESC LIMIT 1`, source.Name).Scan(&cpu, &mu, &mt, &du, &dt, &tx, &rx, &up)
		if err != nil && err != sql.ErrNoRows {
			return out, err
		}
		if c.Fields.Uptime && n.OfflineSince != "" {
			minutes := max(int64(0), (now.Unix()-source.LastSeen)/60)
			n.OfflineDuration = fmt.Sprintf("离线 %d 分钟", minutes)
			if minutes >= 60 {
				n.OfflineDuration = fmt.Sprintf("离线 %d 小时", minutes/60)
			}
		}
		if c.Fields.Specs {
			mem := mt / 1024
			if mem < 4 {
				mem = math.Round(mem*2) / 2
			} else {
				mem = math.Round(mem)
			}
			n.Specs = &Specs{mem, int(math.Round(dt))}
		}
		if c.Fields.Usage && !offline {
			n.Usage = &Usage{pct(cpu, 100), pct(mu, mt), pct(du, dt)}
		}
		if c.Fields.Net && !offline {
			n.Net = &Net{tx, rx}
		}
		if c.Fields.Uptime && !offline {
			days := int(up / 86400)
			n.UptimeDays = &days
		}
		if c.Fields.Availability {
			t, err := s.Traffic(source.Name)
			if err != nil {
				return out, err
			}
			days, err := s.Days(source.Name, now.AddDate(0, 0, -44).Format("2006-01-02"))
			if err != nil {
				return out, err
			}
			a := store.Availability45(t.FirstSeen, days, now)
			n.Availability = &Availability{Pct: a.Pct, Days: []Day{}}
			for _, d := range a.Days {
				n.Availability.Days = append(n.Availability.Days, Day{d.Date, d.State, d.Down})
			}
		}
		out.Nodes = append(out.Nodes, n)
	}
	sort.SliceStable(out.Nodes, func(i, j int) bool { return out.Nodes[i].Name < out.Nodes[j].Name })
	for _, a := range c.Announcements {
		out.Announcements = append(out.Announcements, News{a.Time, a.Title, names[a.Node], a.Status, a.Body})
	}
	sort.SliceStable(out.Announcements, func(i, j int) bool { return out.Announcements[i].Time > out.Announcements[j].Time })
	return out, nil
}
func CSS() []byte { b, _ := assets.ReadFile("web/status.css"); return b }

var tmpl = template.Must(template.New("status.html").Funcs(template.FuncMap{
	"clock":    func(s string) string { t, _ := time.Parse(time.RFC3339, s); return t.Format("15:04") },
	"newsTime": func(s string) string { t, _ := time.Parse(time.RFC3339, s); return t.Format("01-02 15:04") },
	"status": func(s string) string {
		if s == "offline" {
			return "离线"
		}
		return "正常"
	},
	"annStatus": AnnouncementStatus,
	"rate":      format.Rate,
	"uptime": func(days int) string {
		if days == 0 {
			return "已运行不到 1 天"
		}
		return "已运行 " + strconv.Itoa(days) + " 天"
	},
	"barX": func(i int) int { return i * 10 },
	"dayTitle": func(d Day) string {
		date := strings.TrimPrefix(d.Date, d.Date[:5])
		switch d.State {
		case "ok":
			return date + " 全天在线"
		case "partial":
			return fmt.Sprintf("%s 短暂中断（%d 分钟）", date, d.Down/60)
		case "down":
			return fmt.Sprintf("%s 中断 %d 小时 %d 分", date, d.Down/3600, d.Down/60%60)
		}
		return date + " 无数据"
	},
}).ParseFS(assets, "web/status.html"))

func AnnouncementStatus(s string) string {
	return map[string]string{"investigating": "排查中", "monitoring": "已修复，观察中", "resolved": "已恢复", "scheduled": "计划维护", "done": "维护完成"}[s]
}
func Render(d Document, preview bool) ([]byte, error) {
	var b bytes.Buffer
	css := "status.css"
	if preview {
		css = "/static/status.css"
	}
	err := tmpl.Execute(&b, struct {
		Document
		Preview bool
		CSS     string
	}{d, preview, css})
	return b.Bytes(), err
}

type Exporter struct {
	Store *store.Store
	Dir   string
	mu    sync.Mutex
}

func (e *Exporter) Export(now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Dir == "" {
		return nil
	}
	raw, err := e.Store.KV("public.published")
	if err != nil || raw == "" {
		return err
	}
	var c PublicConfig
	if err = json.Unmarshal([]byte(raw), &c); err != nil {
		return err
	}
	if err = c.Validate(); err != nil {
		return err
	}
	d, err := Build(e.Store, c, now)
	if err != nil {
		return err
	}
	html, err := Render(d, false)
	if err != nil {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	dir := e.Dir
	if c.Access == "token" {
		dir = filepath.Join(dir, c.Token)
	}
	if err = os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{{"status.css", CSS()}, {"status.json", data}, {"index.html", html}}
	temps := []string{}
	defer func() {
		for _, p := range temps {
			_ = os.Remove(p)
		}
	}()
	for _, file := range files {
		f, err := os.CreateTemp(dir, ".wanglou-*")
		if err != nil {
			return err
		}
		temps = append(temps, f.Name())
		if err = f.Chmod(0644); err == nil {
			_, err = f.Write(file.data)
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	for i, file := range files {
		if err = os.Rename(temps[i], filepath.Join(dir, file.name)); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(e.Dir)
	if err != nil {
		return err
	}
	old := []string{}
	if c.Access == "token" {
		old = append(old, e.Dir)
	}
	for _, entry := range entries {
		if entry.IsDir() && tokenPattern.MatchString(entry.Name()) && !(c.Access == "token" && entry.Name() == c.Token) {
			old = append(old, filepath.Join(e.Dir, entry.Name()))
		}
	}
	for _, path := range old {
		for _, file := range files {
			if err = os.Remove(filepath.Join(path, file.name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if path != e.Dir {
			remaining, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			if len(remaining) == 0 {
				if err = os.Remove(path); err != nil {
					return err
				}
			}
		}
	}
	return e.Store.SetKV("public.exported_at", strconv.FormatInt(now.Unix(), 10))
}

func (e *Exporter) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last time.Time
	for {
		now := time.Now()
		raw, err := e.Store.KV("public.published")
		if err == nil && raw != "" {
			var c PublicConfig
			err = json.Unmarshal([]byte(raw), &c)
			if err == nil && now.Sub(last) >= time.Duration(max(30, c.Interval))*time.Second {
				last = now
				err = e.Export(now)
			}
		}
		if err != nil {
			log.Printf("public export: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
