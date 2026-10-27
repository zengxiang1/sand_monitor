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
	"sync"
	"time"
	"wanglou/internal/server/store"
)

type Notifier interface {
	ID() string
	Notify(context.Context, store.Event) error
}
type Webhook struct {
	URL    string
	Client *http.Client
}

func (w Webhook) ID() string { return fmt.Sprintf("webhook:%x", sha256.Sum256([]byte(w.URL))) }
func (w Webhook) Notify(ctx context.Context, e store.Event) error {
	return post(ctx, w.Client, w.URL, e)
}

type Telegram struct {
	Token, ChatID string
	Client        *http.Client
	BaseURL       string
}

func (t Telegram) ID() string {
	return fmt.Sprintf("telegram:%x", sha256.Sum256([]byte(t.BaseURL+"\n"+t.Token+"\n"+t.ChatID)))
}
func (t Telegram) Notify(ctx context.Context, e store.Event) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	return post(ctx, t.Client, base+"/bot"+url.PathEscape(t.Token)+"/sendMessage", map[string]string{"chat_id": t.ChatID, "text": fmt.Sprintf("wanglou %s: %s %s", e.Node, e.Kind, e.Detail)})
}
func post(ctx context.Context, client *http.Client, target string, payload any) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if e != nil {
		return e
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification status %d", resp.StatusCode)
	}
	return nil
}

// Dispatcher uses the events table as a durable queue. No network call occurs
// on the ingest goroutine; a batch remains pending after exhausted retries.
type Dispatcher struct {
	mu         sync.Mutex
	Store      *store.Store
	Notifiers  []Notifier
	RetryDelay time.Duration
}

func (d *Dispatcher) Deliver(ctx context.Context, event store.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var failures []error
	for _, n := range d.Notifiers {
		delivered, err := d.Store.Delivered(event.ID, n.ID())
		if err != nil {
			return err
		}
		if delivered {
			continue
		}
		err = nil
		for attempt := 0; attempt < 4; attempt++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = n.Notify(attemptCtx, event)
			cancel()
			if err == nil {
				break
			}
			if attempt < 3 {
				delay := d.RetryDelay
				if delay <= 0 {
					delay = time.Second
				}
				timer := time.NewTimer(delay * time.Duration(1<<attempt))
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if err = d.Store.MarkDelivered(event.ID, n.ID()); err != nil {
			return err
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if len(d.Notifiers) == 0 {
		return nil
	}
	return d.Store.MarkNotified(event.ID)
}
func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if len(d.Notifiers) > 0 {
			events, e := d.Store.Pending(32)
			if e != nil {
				log.Printf("notification queue: %v", e)
			} else {
				for _, event := range events {
					if e = d.Deliver(ctx, event); e != nil {
						log.Printf("notification failed for event %d", event.ID)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
