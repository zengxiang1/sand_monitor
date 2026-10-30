package panel

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"
	"wanglou/internal/server/mainland"
	"wanglou/internal/server/requestip"
	"wanglou/internal/server/store"
)

type mainlandCity struct {
	Name     string
	Count    int
	Retained bool
}

type mainlandPage struct {
	Saved, Selected store.MainlandSource
	Carriers        []option
	Cities          []mainlandCity
	DirectoryReady  bool
	DirectoryError  string
	Online          int
}

func (h *Handler) mainlandSettings(w http.ResponseWriter, r *http.Request, sess session) {
	saved, err := h.Store.MainlandSource()
	if err != nil {
		h.serverError(w, err)
		return
	}
	data := h.base(sess)
	p := mainlandPage{Saved: saved, Selected: saved}
	code := http.StatusOK
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		values = r.PostForm
	}
	if values.Has("asn") || r.Method == http.MethodPost {
		asn, err := strconv.Atoi(values.Get("asn"))
		source := store.MainlandSource{ASN: asn}
		if err != nil || source.Validate() != nil {
			data.Error, code = "请选择联通、电信或移动。", http.StatusBadRequest
		} else if asn != saved.ASN {
			p.Selected = source
		}
	}
	if r.Method == http.MethodPost {
		p.Selected.City = values.Get("city")
		if err := p.Selected.Validate(); err != nil {
			data.Error, code = "城市格式无效，请重新选择。", http.StatusBadRequest
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	locations, directoryErr := h.Config.MainlandLocations(ctx)
	p.DirectoryReady = directoryErr == nil
	if directoryErr != nil {
		h.Logf("panel mainland locations: %v", directoryErr)
		locations = nil
		p.DirectoryError = "Globalping 在线目录暂时不可用。可保持已保存的组合，或选择自动匹配。"
	}
	for _, asn := range []int{4837, 4134, 9808} {
		source := store.MainlandSource{ASN: asn}
		count := 0
		for _, location := range locations {
			if location.ASN == asn {
				count += location.Count
			}
		}
		label := source.Carrier()
		if p.DirectoryReady {
			label += fmt.Sprintf(" · %d 个在线探针", count)
		}
		p.Carriers = append(p.Carriers, option{strconv.Itoa(asn), label})
		if asn == p.Selected.ASN {
			p.Online = count
		}
	}
	for _, location := range locations {
		if location.ASN == p.Selected.ASN && location.Count > 0 {
			p.Cities = append(p.Cities, mainlandCity{Name: location.City, Count: location.Count})
		}
	}
	sort.Slice(p.Cities, func(i, j int) bool { return p.Cities[i].Name < p.Cities[j].Name })
	if saved.ASN == p.Selected.ASN && saved.City != "" && !slices.ContainsFunc(p.Cities, func(city mainlandCity) bool { return city.Name == saved.City }) {
		p.Cities = append(p.Cities, mainlandCity{Name: saved.City, Retained: true})
	}
	if r.Method == http.MethodPost && data.Error == "" {
		listed := p.DirectoryReady && slices.ContainsFunc(locations, func(location mainland.LocationOption) bool {
			return location.ASN == p.Selected.ASN && location.City == p.Selected.City && location.Count > 0
		})
		if p.Selected.City != "" && p.Selected != saved && !listed {
			data.Error, code = "请选择所选运营商当前在线目录中的城市，或使用自动匹配。", http.StatusBadRequest
		} else {
			if err := h.Store.SetMainlandSource(p.Selected); err != nil {
				h.serverError(w, err)
				return
			}
			detail := fmt.Sprintf("asn=%d city=%q", p.Selected.ASN, p.Selected.City)
			if err := h.audit(sess.User, requestip.ClientIP(r, h.Config.TrustedProxies), "mainland_source_set", detail); err != nil {
				h.serverError(w, err)
				return
			}
			h.publicMu.Lock()
			h.publicHTML = nil
			h.publicMu.Unlock()
			http.Redirect(w, r, "/mainland?saved=1", http.StatusSeeOther)
			return
		}
	}
	data.MainlandSettings = p
	if r.Method == http.MethodGet && r.URL.Query().Get("saved") == "1" {
		data.Success = "已保存，将在下一个到期的每小时轮次生效。"
	}
	h.render(w, r, "mainland", data, code)
}
