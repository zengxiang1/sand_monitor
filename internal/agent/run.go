package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
	"wanglou/internal/agent/collect"
	"wanglou/internal/proto"
)

func ExecutableHash() (string, error) {
	path, e := os.Executable()
	if e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
func Backoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	if failures >= 7 {
		return 60 * time.Second
	}
	return time.Second * time.Duration(1<<uint(failures-1))
}
func Run(ctx context.Context, c Config) error {
	key, e := LoadKey(c.Key)
	if e != nil {
		return e
	}
	client, e := NewClient(c, key)
	if e != nil {
		return e
	}
	hash, e := ExecutableHash()
	if e != nil {
		return e
	}
	backupState := []string{}
	if c.BackupServer != "" {
		backupState = append(backupState, c.StateFile+".backup.logins.json")
	}
	collector, e := collect.NewWithState(hash, c.StateFile+".logins.json", collect.Options{ProcRoot: c.ProcRoot, RootFS: c.RootFS, WtmpPath: c.WtmpPath}, backupState...)
	if e != nil {
		return e
	}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	return runLoop(ctx, c, client, collector, ticker.C, Backoff)
}

type sampler interface {
	Sample() (proto.Report, error)
	Logins(string) ([]proto.Login, error)
	Acknowledge(string) error
}

func runLoop(ctx context.Context, c Config, client *Client, collector sampler, ticks <-chan time.Time, backoff func(int) time.Duration) error {
	type sender struct {
		name      string
		busy      bool
		failures  int
		ready     time.Time
		lastError string
		logged    time.Time
	}
	targets := []*sender{{name: "primary"}}
	if c.BackupServer != "" {
		targets = append(targets, &sender{name: "backup"})
	}
	type result struct {
		sender *sender
		err    error
		at     time.Time
	}
	results := make(chan result, len(targets))
	var wg sync.WaitGroup
	defer wg.Wait()
	sample := func(now time.Time) {
		r, err := collector.Sample()
		if err != nil {
			log.Printf("sample failed: %v", err)
			return
		}
		for _, target := range targets {
			if target.busy || now.Before(target.ready) {
				continue
			}
			target.busy = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				report := r
				logins, err := collector.Logins(target.name)
				report.Login = logins
				if err == nil {
					err = client.SendTo(ctx, target.name, report)
				}
				if err == nil {
					err = collector.Acknowledge(target.name)
				}
				results <- result{target, err, time.Now()}
			}()
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	sample(time.Now())
	for {
		select {
		case <-ctx.Done():
			return nil
		case done := <-results:
			target := done.sender
			target.busy = false
			if done.err == nil {
				target.failures, target.lastError = 0, ""
				target.ready = time.Time{}
				continue
			}
			target.failures++
			target.ready = done.at.Add(backoff(target.failures))
			message := done.err.Error()
			if message != target.lastError || done.at.Sub(target.logged) >= 10*time.Minute {
				log.Printf("report to %s failed: %s", target.name, message)
				target.lastError, target.logged = message, done.at
			}
		case now := <-ticks:
			if ctx.Err() == nil {
				sample(now)
			}
		}
	}
}
