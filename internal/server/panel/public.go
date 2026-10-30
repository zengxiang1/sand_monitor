package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/requestip"
	"wanglou/internal/server/store"
)

type publicNode struct {
	status.Selection
	State, Tone string
}
type publicPage struct {
	Count                                     int
	Config                                    status.PublicConfig
	Nodes                                     []publicNode
	Published, Dirty                          bool
	Exported, URL, TokenURL, AnnouncementTime string
	Announcement                              status.Announcement
}

func (h *Handler) publishedPublic() (string, status.PublicConfig, error) {
	raw, err := h.Store.KV("public.published")
	if err != nil {
		return "", status.PublicConfig{}, err
	}
	var c status.PublicConfig
	if raw == "" || json.Unmarshal([]byte(raw), &c) != nil || c.Validate() != nil || c.Access != "public" {
		return raw, status.PublicConfig{}, nil
	}
	return raw, c, nil
}

func (h *Handler) publicHome() ([]byte, error) {
	h.publicMu.Lock()
	defer h.publicMu.Unlock()
	raw, c, err := h.publishedPublic()
	if err != nil {
		return nil, err
	}
	if c.Access != "public" {
		h.publicHTML = nil
		return nil, nil
	}
	now := h.Now()
	if raw == h.publicRaw && h.publicHTML != nil && now.Before(h.publicExpires) {
		return h.publicHTML, nil
	}
	d, err := status.Build(h.Store, c, now)
	if err != nil {
		return nil, err
	}
	html, err := status.Render(d, status.RenderOptions{Login: true})
	if err != nil {
		return nil, err
	}
	h.publicRaw, h.publicHTML, h.publicExpires = raw, html, now.Add(time.Duration(c.Interval)*time.Second)
	return html, nil
}

func (h *Handler) public(w http.ResponseWriter, r *http.Request, sess session, action string) {
	c, err := status.Load(h.Store, "public.draft")
	if err != nil {
		h.serverError(w, err)
		return
	}
	if action == "public-preview" {
		d, err := status.Build(h.Store, c, h.Now())
		if err != nil {
			h.serverError(w, err)
			return
		}
		html, err := status.Render(d, status.RenderOptions{Preview: true})
		if err != nil {
			h.serverError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(html)
		return
	}
	nodes, err := h.Store.Nodes()
	if err != nil {
		h.serverError(w, err)
		return
	}
	nodes = slices.DeleteFunc(nodes, func(n store.Node) bool { return n.RevokedAt != 0 })
	code := 200
	ann := status.Announcement{Status: "investigating", Time: h.Now().In(h.Store.Location).Format(time.RFC3339)}
	if r.Method == "POST" {
		f := r.PostForm
		publish := false
		audit := "public_draft"
		switch action {
		case "public":
			c.Title = f.Get("title")
			c.Interval, err = strconv.Atoi(f.Get("interval"))
			c.Access = f.Get("access")
			c.Fields = status.Fields{Specs: f.Get("specs") == "true", Usage: f.Get("usage") == "true", Net: f.Get("net") == "true", Uptime: f.Get("uptime") == "true", Availability: f.Get("availability") == "true", Reason: f.Get("reason") == "true", Probes: f.Get("probes") == "true"}
			for _, key := range []string{"specs", "usage", "net", "uptime", "availability", "reason", "probes"} {
				if value := f.Get(key); value != "" && value != "true" {
					err = fmt.Errorf("字段开关无效")
				}
			}
			c.Nodes = []status.Selection{}
			for _, n := range nodes {
				c.Nodes = append(c.Nodes, status.Selection{Node: n.Name, Public: f.Get("public_"+n.Name) == "true", Name: f.Get("name_" + n.Name)})
			}
			publish = f.Get("publish") == "1"
		case "public-token":
			c.Token = status.Token()
			audit = "public_token"
		case "announcement":
			audit = "public_announcement_add"
			id := int64(0)
			if f.Get("id") != "" {
				id, err = strconv.ParseInt(f.Get("id"), 10, 64)
				audit = "public_announcement_edit"
			}
			ann = status.Announcement{ID: id, Title: f.Get("title"), Node: f.Get("node"), Status: f.Get("status"), Body: f.Get("body"), Time: f.Get("time")}
			at, e := time.ParseInLocation("2006-01-02T15:04", ann.Time, h.Store.Location)
			if e != nil {
				err = fmt.Errorf("公告时间无效")
			} else {
				ann.Time = at.Format(time.RFC3339)
			}
			if err == nil && ann.Node != "" && (!slices.ContainsFunc(c.Nodes, func(n status.Selection) bool { return n.Node == ann.Node && n.Public }) || !slices.ContainsFunc(nodes, func(n store.Node) bool { return n.Name == ann.Node })) {
				err = fmt.Errorf("请选择公开节点")
			}
			if err == nil {
				if id != 0 {
					idx := slices.IndexFunc(c.Announcements, func(a status.Announcement) bool { return a.ID == id })
					if idx < 0 {
						err = fmt.Errorf("公告不存在")
					} else {
						c.Announcements[idx] = ann
					}
				} else if len(c.Announcements) >= 100 {
					err = fmt.Errorf("最多 100 条公告")
				} else {
					for _, a := range c.Announcements {
						ann.ID = max(ann.ID, a.ID)
					}
					ann.ID++
					c.Announcements = append(c.Announcements, ann)
				}
			}
		case "announcement-delete":
			audit = "public_announcement_delete"
			var id int64
			id, err = strconv.ParseInt(r.PathValue("id"), 10, 64)
			if err == nil {
				idx := slices.IndexFunc(c.Announcements, func(a status.Announcement) bool { return a.ID == id })
				if idx < 0 {
					err = fmt.Errorf("公告不存在")
				} else {
					c.Announcements = append(c.Announcements[:idx], c.Announcements[idx+1:]...)
				}
			}
		}
		if err == nil {
			err = c.Validate()
		}
		if err == nil {
			err = status.Save(h.Store, c, publish, h.Now(), sess.User, requestip.ClientIP(r, h.Config.TrustedProxies), audit)
		}
		if err == nil && publish && h.Config.Exporter != nil {
			err = h.Config.Exporter.Export(h.Now())
			if err != nil {
				h.Logf("public export: %v", err)
				h.serverError(w, err)
				return
			}
		}
		if err == nil {
			location := "/public?saved=1"
			if publish {
				location = "/public?published=1"
			}
			http.Redirect(w, r, location, 303)
			return
		}
		code = 400
	}
	if id, e := strconv.ParseInt(r.URL.Query().Get("edit_ann"), 10, 64); e == nil {
		idx := slices.IndexFunc(c.Announcements, func(a status.Announcement) bool { return a.ID == id })
		if idx >= 0 {
			ann = c.Announcements[idx]
		}
	}
	data := h.base(sess)
	if err != nil {
		data.Error = err.Error()
	}
	published, e := h.Store.KV("public.published")
	if e != nil {
		h.serverError(w, e)
		return
	}
	draft, e := h.Store.KV("public.draft")
	if e != nil {
		h.serverError(w, e)
		return
	}
	p := publicPage{Config: c, Published: published != "", Dirty: draft != published, URL: h.Config.PublicURL, Exported: "从未导出", Announcement: ann}
	if p.URL == "" {
		p.URL = "未配置 public_url"
	} else {
		p.TokenURL = strings.TrimRight(p.URL, "/") + "/" + c.Token + "/"
	}
	raw, e := h.Store.KV("public.exported_at")
	if e != nil {
		h.serverError(w, e)
		return
	}
	if ts, e := strconv.ParseInt(raw, 10, 64); e == nil {
		p.Exported = "上次导出 " + time.Unix(ts, 0).In(h.Store.Location).Format("15:04")
	}
	if at, e := time.Parse(time.RFC3339, ann.Time); e == nil {
		p.AnnouncementTime = at.In(h.Store.Location).Format("2006-01-02T15:04")
	} else {
		p.AnnouncementTime = ann.Time
	}
	for _, n := range nodes {
		v, err := h.view(n)
		if err != nil {
			h.serverError(w, err)
			return
		}
		selection := status.Selection{Node: n.Name}
		if idx := slices.IndexFunc(c.Nodes, func(x status.Selection) bool { return x.Node == n.Name }); idx >= 0 {
			selection = c.Nodes[idx]
		}
		state, tone := v.Status, v.Tone
		if state == "告警" {
			state = "注意"
		}
		if selection.Public {
			p.Count++
		}
		p.Nodes = append(p.Nodes, publicNode{Selection: selection, State: state, Tone: tone})
	}
	sort.SliceStable(p.Config.Announcements, func(i, j int) bool { return p.Config.Announcements[i].Time > p.Config.Announcements[j].Time })
	data.Public = p
	if r.Method == "GET" && r.URL.Query().Get("published") == "1" && p.Published {
		data.Success = fmt.Sprintf("已发布。公开页会在 %d 秒内更新。", c.Interval)
	}
	h.render(w, r, "public", data, code)
}
