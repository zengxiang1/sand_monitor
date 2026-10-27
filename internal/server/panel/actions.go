package panel

import (
	"database/sql"
	"net/http"
	"net/netip"
	"strconv"
	"time"
	"wanglou/internal/server/requestip"
)

func (h *Handler) mutate(w http.ResponseWriter, r *http.Request, sess session, action string) {
	name := r.PathValue("name")
	now := h.Now()
	target := "/nodes/" + name
	ip := requestip.ClientIP(r, h.Config.TrustedProxies)
	if action == "ack" {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}
		err = h.Store.Transaction(func(tx *sql.Tx) error {
			result, err := tx.Exec(`UPDATE events SET acked_at=? WHERE id=? AND kind='login_new_ip'`, now.Unix(), id)
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if count == 0 {
				return sql.ErrNoRows
			}
			_, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now.Unix(), sess.User, ip, "event_ack", strconv.FormatInt(id, 10))
			return err
		})
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			h.serverError(w, err)
			return
		}
		http.Redirect(w, r, "/", 303)
		return
	}
	if _, err := h.Store.Node(name); err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			h.serverError(w, err)
		}
		return
	}
	if action == "revoke" {
		if r.PostForm.Get("confirm") != "yes" {
			http.Error(w, "请确认吊销", 400)
			return
		}
		if err := h.Store.Revoke(name, now); err != nil {
			h.serverError(w, err)
			return
		}
		if err := h.audit(sess.User, ip, "node_revoke", name); err != nil {
			h.serverError(w, err)
			return
		}
		http.Redirect(w, r, target, 303)
		return
	}
	var query string
	var value string
	switch action {
	case "note":
		note := r.PostForm.Get("note")
		if !safeNote(note) {
			http.Error(w, "备注最多 64 个字符", 400)
			return
		}
		query = `UPDATE nodes SET note=? WHERE name=?`
		value = note
	case "mute":
		hours, err := strconv.Atoi(r.PostForm.Get("hours"))
		if err != nil || (hours != 0 && hours != 1 && hours != 8 && hours != 24) {
			http.Error(w, "Bad request", 400)
			return
		}
		until := int64(0)
		if hours > 0 {
			until = now.Add(time.Duration(hours) * time.Hour).Unix()
		}
		query = `UPDATE nodes SET muted_until=? WHERE name=?`
		value = strconv.FormatInt(until, 10)
	case "known-ip":
		_, err := netip.ParseAddr(r.PostForm.Get("ip"))
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}
		value = r.PostForm.Get("ip")
		query = `INSERT OR IGNORE INTO known_ips(from_ip,node) SELECT ?,? WHERE EXISTS(SELECT 1 FROM logins WHERE node=? AND from_ip=?)`
	default:
		http.NotFound(w, r)
		return
	}
	err := h.Store.Transaction(func(tx *sql.Tx) error {
		var err error
		if action == "known-ip" {
			result, e := tx.Exec(query, value, name, name, value)
			if e != nil {
				return e
			}
			count, e := result.RowsAffected()
			if e != nil {
				return e
			}
			if count == 0 {
				var known int
				if e = tx.QueryRow(`SELECT count(*) FROM known_ips WHERE node=? AND from_ip=?`, name, value).Scan(&known); e != nil {
					return e
				}
				if known == 0 {
					return sql.ErrNoRows
				}
			}
			_, err = tx.Exec(`UPDATE logins SET known=1 WHERE node=? AND from_ip=?`, name, value)
		} else {
			_, err = tx.Exec(query, value, name)
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now.Unix(), sess.User, ip, action, name)
		return err
	})
	if err == sql.ErrNoRows {
		http.Error(w, "Bad request", 400)
		return
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	http.Redirect(w, r, target, 303)
}
