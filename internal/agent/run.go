package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"wanglou/internal/agent/collect"
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
	collector, e := collect.NewWithState(hash, c.StateFile+".logins.json", collect.Options{ProcRoot: c.ProcRoot, RootFS: c.RootFS, WtmpPath: c.WtmpPath})
	if e != nil {
		return e
	}
	failures := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		r, e := collector.Sample()
		if e == nil {
			e = client.Send(ctx, r)
		}
		if e == nil {
			e = collector.Acknowledge(r)
		}
		delay := c.Interval
		if e != nil {
			failures++
			delay = Backoff(failures)
			log.Printf("report failed: %v", e)
		} else {
			failures = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
