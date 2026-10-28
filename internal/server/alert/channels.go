package alert

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"slices"
	"sync"
	"wanglou/internal/server/store"
)

type TelegramSettings struct {
	Token     string `json:"token"`
	ChatID    string `json:"chat_id"`
	UpdatedAt int64  `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

var errInvalidTelegram = errors.New("Telegram 通知配置无效")
var telegramToken = regexp.MustCompile(`^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$`)
var telegramChat = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)

func (s TelegramSettings) Validate() error {
	if !telegramToken.MatchString(s.Token) {
		return fmt.Errorf("机器人 token 格式错误")
	}
	if !telegramChat.MatchString(s.ChatID) {
		return fmt.Errorf("chat id 格式错误")
	}
	return nil
}
func (s TelegramSettings) TokenSuffix() string {
	return "…" + s.Token[max(0, len(s.Token)-4):]
}

type Channels struct {
	store     *store.Store
	telegram  Telegram
	webhook   Webhook
	mu        sync.RWMutex
	settings  TelegramSettings
	notifiers []Notifier
}

func NewChannels(s *store.Store, telegram Telegram, webhook Webhook) (*Channels, error) {
	if telegram.BaseURL == "" {
		telegram.BaseURL = "https://api.telegram.org"
	}
	c := &Channels{store: s, telegram: telegram, webhook: webhook}
	err := c.Reload()
	if errors.Is(err, errInvalidTelegram) {
		// A damaged stored setting must not stop the server or the other channels.
		log.Printf("ignoring invalid panel Telegram settings")
		c.mu.Lock()
		if c.webhook.URL != "" {
			c.notifiers = []Notifier{c.webhook}
		}
		c.mu.Unlock()
		return c, nil
	}
	return c, err
}
func (c *Channels) Reload() error {
	settings := TelegramSettings{Token: c.telegram.Token, ChatID: c.telegram.ChatID}
	if !c.ReadOnly() {
		raw, err := c.store.KV("notify.telegram")
		if err != nil {
			return fmt.Errorf("读取 Telegram 通知配置失败")
		}
		if raw != "" {
			if json.Unmarshal([]byte(raw), &settings) != nil || settings.Validate() != nil {
				return errInvalidTelegram
			}
		}
	}
	notifiers := []Notifier{}
	if settings.Token != "" {
		notifiers = append(notifiers, c.Telegram(settings))
	}
	if c.webhook.URL != "" {
		notifiers = append(notifiers, c.webhook)
	}
	c.mu.Lock()
	c.settings, c.notifiers = settings, notifiers
	c.mu.Unlock()
	return nil
}
func (c *Channels) Notifiers() []Notifier {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Clone(c.notifiers)
}
func (c *Channels) Settings() TelegramSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.settings
}
func (c *Channels) ReadOnly() bool  { return c.telegram.Token != "" }
func (c *Channels) APIBase() string { return c.telegram.BaseURL }
func (c *Channels) Telegram(s TelegramSettings) Telegram {
	t := c.telegram
	t.Token, t.ChatID = s.Token, s.ChatID
	return t
}
func (c *Channels) Names() []string {
	names := []string{}
	if c == nil {
		return names
	}
	for _, n := range c.Notifiers() {
		if n.Kind() == "telegram" {
			names = append(names, "Telegram")
		} else if n.Kind() == "webhook" {
			names = append(names, "Webhook")
		}
	}
	return names
}
