package alert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"wanglou/internal/server/eventtext"
	"wanglou/internal/server/store"
)

type Notifier interface {
	ID() string
	Kind() string
	Notify(context.Context, store.Event) error
}
type Webhook struct {
	Instance string
	URL      string
	Client   *http.Client
}

func (w Webhook) Kind() string { return "webhook" }
func (w Webhook) ID() string   { return fmt.Sprintf("webhook:%x", sha256.Sum256([]byte(w.URL))) }
func (w Webhook) Notify(ctx context.Context, e store.Event) error {
	instance := w.Instance
	if instance == "" {
		instance = "望楼"
	}
	return post(ctx, w.Client, w.URL, struct {
		store.Event
		Instance string `json:"instance"`
	}{e, instance})
}

type Telegram struct {
	Token, ChatID string
	Instance      string
	Client        *http.Client
	BaseURL       string
	Location      *time.Location
}

func (t Telegram) Kind() string { return "telegram" }
func (t Telegram) ID() string {
	return fmt.Sprintf("telegram:%x", sha256.Sum256([]byte(t.BaseURL+"\n"+t.Token+"\n"+t.ChatID)))
}
func (t Telegram) Notify(ctx context.Context, e store.Event) error {
	text := fmt.Sprintf("%s · %s：%s", e.Label(), eventtext.Kind(e.Kind), e.Detail)
	if e.Kind == "flapping" {
		text = e.Label() + " " + e.Detail
	}
	if e.Kind == "peer" {
		text = e.Detail
	}
	// Delayed deliveries may arrive out of order, so they carry the event time.
	if e.Time > 0 && time.Now().Unix()-e.Time > 60 {
		loc := t.Location
		if loc == nil {
			loc = time.Local
		}
		text += "（发生于 " + time.Unix(e.Time, 0).In(loc).Format("01-02 15:04") + "）"
	}
	return t.SendText(ctx, text)
}
func (t Telegram) SendText(ctx context.Context, text string) error {
	instance := t.Instance
	if instance == "" {
		instance = "望楼"
	}
	text = instance + " · " + text
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	return post(ctx, t.Client, base+"/bot"+url.PathEscape(t.Token)+"/sendMessage", map[string]string{"chat_id": t.ChatID, "text": text})
}
func post(ctx context.Context, client *http.Client, target string, payload any) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if e != nil {
		return fmt.Errorf("notification request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("notification transport failed")
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); err != nil {
		return fmt.Errorf("notification response failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification status %d", resp.StatusCode)
	}
	return nil
}

// Dispatcher uses the events table as a durable queue, with per-channel receipts.
type Dispatcher struct {
	mu        sync.Mutex
	Store     *store.Store
	Scope     string
	Cooldown  time.Duration
	Now       func() time.Time
	Notifiers func() []Notifier
	retries   map[deliveryKey]deliveryRetry
	active    map[int64]bool
}
type deliveryKey struct {
	event   int64
	channel string
}
type deliveryRetry struct {
	next  time.Time
	delay time.Duration
}

func (d *Dispatcher) pendingNotifiers(event store.Event, notifiers []Notifier) ([]Notifier, error) {
	pending := []Notifier{}
	for _, n := range notifiers {
		if event.Targets != "" && !slices.Contains(strings.Split(event.Targets, ","), n.Kind()) {
			continue
		}
		delivered, err := d.Store.Delivered(event.ID, n.ID())
		if err != nil {
			return nil, err
		}
		if !delivered {
			pending = append(pending, n)
		}
	}
	return pending, nil
}
func (d *Dispatcher) Deliver(ctx context.Context, event store.Event) error {
	d.mu.Lock()
	if d.active[event.ID] {
		d.mu.Unlock()
		return nil
	}
	if d.active == nil {
		d.active = map[int64]bool{}
		d.retries = map[deliveryKey]deliveryRetry{}
	}
	d.active[event.ID] = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); delete(d.active, event.ID); d.mu.Unlock() }()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if event.Notified {
		return nil
	}
	notifiers := []Notifier{}
	if d.Notifiers != nil {
		notifiers = d.Notifiers()
	}
	var err error
	event, err = d.prepare(event, notifiers)
	if err != nil || event.Notified {
		return err
	}
	pending, err := d.pendingNotifiers(event, notifiers)
	if err != nil {
		return err
	}
	results := make(chan error, len(pending))
	for _, n := range pending {
		go func() {
			key := deliveryKey{event.ID, n.ID()}
			d.mu.Lock()
			retry := d.retries[key]
			d.mu.Unlock()
			if time.Now().Unix()-event.Time > 24*60*60 {
				log.Printf("notification expired: event %d channel %s", event.ID, n.ID())
				results <- nil
				return
			}
			if time.Now().Before(retry.next) {
				results <- errors.New("notification in backoff")
				return
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := n.Notify(attemptCtx, event)
			cancel()
			if err != nil {
				delay := min(10*time.Minute, max(30*time.Second, retry.delay*2))
				d.mu.Lock()
				d.retries[key] = deliveryRetry{time.Now().Add(delay), delay}
				d.mu.Unlock()
				results <- err
				return
			}
			results <- d.Store.MarkDelivered(event.ID, n.ID())
		}()
	}
	var failures []error
	for range pending {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if err = d.Store.MarkNotified(event.ID); err == nil {
		d.mu.Lock()
		for _, n := range notifiers {
			delete(d.retries, deliveryKey{event.ID, n.ID()})
		}
		d.mu.Unlock()
	}
	return err
}
func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	for ctx.Err() == nil {
		var after int64
		launched := 0
		for launched < 32 && ctx.Err() == nil {
			events, err := d.Store.Pending(32, after)
			if err != nil {
				log.Printf("notification queue: %v", err)
				break
			}
			for _, event := range events {
				after = event.ID
				notifiers := []Notifier{}
				if d.Notifiers != nil {
					notifiers = d.Notifiers()
				}
				event, err = d.prepare(event, notifiers)
				if err != nil {
					log.Printf("notification queue: %v", err)
					continue
				}
				if event.Notified {
					continue
				}
				pending, err := d.pendingNotifiers(event, notifiers)
				if err != nil {
					log.Printf("notification queue: %v", err)
					continue
				}
				d.mu.Lock()
				ready := len(pending) == 0 || time.Now().Unix()-event.Time > 24*60*60
				for _, n := range pending {
					ready = ready || !time.Now().Before(d.retries[deliveryKey{event.ID, n.ID()}].next)
				}
				ready = ready && !d.active[event.ID]
				d.mu.Unlock()
				if !ready {
					continue
				}
				workers.Go(func() {
					if err := d.Deliver(ctx, event); err != nil && ctx.Err() == nil {
						log.Printf("notification failed for event %d", event.ID)
					}
				})
				launched++
				if launched == 32 {
					break
				}
			}
			if len(events) < 32 {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
