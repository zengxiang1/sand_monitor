package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/requestip"
)

type notifyPage struct {
	Enabled, ReadOnly, Webhook     bool
	TokenSuffix, ChatID, UpdatedBy string
	APIBase                        string
	UpdatedAt                      int64
}

func (h *Handler) notify(w http.ResponseWriter, r *http.Request, sess session, action string) {
	c := h.Config.Channels
	if c == nil {
		http.Error(w, "通知配置不可用", 503)
		return
	}
	data := h.base(sess)
	render := func(status int) {
		s := c.Settings()
		data.Channels = c.Names()
		data.Notify = notifyPage{Enabled: s.Token != "", ReadOnly: c.ReadOnly(), Webhook: slices.Contains(data.Channels, "Webhook"), TokenSuffix: s.TokenSuffix(), ChatID: s.ChatID, UpdatedBy: s.UpdatedBy, UpdatedAt: s.UpdatedAt, APIBase: c.APIBase()}
		h.render(w, r, "notify", data, status)
	}
	if r.Method == "GET" {
		render(200)
		return
	}
	if c.ReadOnly() {
		http.Error(w, "由服务器配置文件设置，面板不能修改", 403)
		return
	}
	if !h.notifyMu.TryLock() {
		http.Error(w, "通知操作进行中，请稍后再试", 429)
		return
	}
	defer h.notifyMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	now := h.Now()
	old := c.Settings()
	ip := requestip.ClientIP(r, h.Config.TrustedProxies)
	detail := fmt.Sprintf("chat_id=%s token=%s old_notified=none", old.ChatID, old.TokenSuffix())
	if action == "notify-test" {
		if old.Token == "" {
			data.Error = "请先保存 Telegram 配置"
			render(400)
			return
		}
		if !h.notifyTestAt.IsZero() && now.Sub(h.notifyTestAt) < 10*time.Second {
			data.Error = "测试通知每 10 秒最多发送一次，请稍后再试"
			render(429)
			return
		}
		h.notifyTestAt = now
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		err := c.Telegram(old).SendText(attempt, "测试通知：收到这条消息说明配置正确")
		stop()
		data.Success = "测试通知已发出"
		if err != nil {
			data.Success = "测试通知发送失败：" + err.Error()
		}
		if err := h.audit(sess.User, ip, "notify_telegram_test", detail+fmt.Sprintf(" sent=%t", err == nil)); err != nil {
			h.serverError(w, err)
			return
		}
		render(200)
		return
	}
	limit := h.notifyFailures[sess.User]
	if limit.since+900 <= now.Unix() {
		limit = failures{since: now.Unix()}
	}
	if limit.count >= 5 {
		data.Error = "验证码失败次数过多，请稍后再试"
		render(429)
		return
	}
	settings := alert.TelegramSettings{Token: r.PostForm.Get("token"), ChatID: r.PostForm.Get("chat_id"), UpdatedAt: now.Unix(), UpdatedBy: sess.User}
	if action == "notify-set" {
		if settings.Token == "" {
			settings.Token = old.Token
		}
		if err := settings.Validate(); err != nil {
			data.Error = err.Error()
			render(400)
			return
		}
	}
	var secret string
	var last int64
	if err := h.Store.DB.QueryRowContext(ctx, `SELECT totp_secret,totp_last_step FROM admins WHERE user=?`, sess.User).Scan(&secret, &last); err != nil {
		h.serverError(w, err)
		return
	}
	code := r.PostForm.Get("totp")
	step, valid := totpStep(secret, code, now.Unix(), last)
	if !valid {
		limit.count++
		h.notifyFailures[sess.User] = limit
		data.Error = "验证码错误，请重新输入"
		if used, ok := totpStep(secret, code, now.Unix(), -1); ok && used <= last {
			data.Error = "这个验证码已经用过，请等下一个"
		}
		render(400)
		return
	}
	result, err := h.Store.DB.ExecContext(ctx, `UPDATE admins SET totp_last_step=? WHERE user=? AND totp_secret=? AND totp_last_step<?`, step, sess.User, secret, step)
	if err != nil {
		h.serverError(w, err)
		return
	}
	count, err := result.RowsAffected()
	if err != nil {
		h.serverError(w, err)
		return
	}
	if count != 1 {
		limit.count++
		h.notifyFailures[sess.User] = limit
		data.Error = "这个验证码已经用过，请等下一个"
		render(400)
		return
	}
	oldResult := "none"
	warning := ""
	if old.Token != "" {
		message := fmt.Sprintf("通知渠道已被 %s 从 %s 修改，新的 chat id 为 %s", sess.User, ip, settings.ChatID)
		if action == "notify-disable" {
			message = fmt.Sprintf("Telegram 通知已被 %s 从 %s 停用", sess.User, ip)
		}
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		err := c.Telegram(old).SendText(attempt, message)
		stop()
		oldResult = "true"
		if err != nil {
			oldResult = "false"
			warning = "；旧渠道通知发送失败：" + err.Error()
		}
	}
	value, _ := json.Marshal(settings)
	auditAction := "notify_telegram_set"
	if action == "notify-disable" {
		auditAction = "notify_telegram_disable"
		settings = old
	}
	detail = fmt.Sprintf("chat_id=%s token=%s old_notified=%s", settings.ChatID, settings.TokenSuffix(), oldResult)
	tx, err := h.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		h.serverError(w, err)
		return
	}
	defer tx.Rollback()
	if action == "notify-disable" {
		_, err = tx.ExecContext(ctx, `DELETE FROM kv WHERE key='notify.telegram'`)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO kv VALUES('notify.telegram',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(value))
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now.Unix(), sess.User, ip, auditAction, detail)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		h.serverError(w, err)
		return
	}
	if err := c.Reload(); err != nil {
		h.serverError(w, err)
		return
	}
	data.Success = "已停用" + warning
	if action == "notify-set" {
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		err := c.Telegram(settings).SendText(attempt, "已开始向这里发送告警通知")
		stop()
		data.Success = "已保存，确认消息已发出"
		if err != nil {
			data.Success = "已保存，但确认消息发送失败：" + err.Error()
		}
		data.Success += warning
	}
	render(200)
}
