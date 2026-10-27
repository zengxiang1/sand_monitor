//go:build !linux

package collect

import (
	"runtime"
	"time"
	"wanglou/internal/proto"
)

// The portable stub deliberately returns zero measurements, never synthetic
// readings which could be mistaken for real host telemetry.
type Collector struct {
	options Options
	hash    string
	start   time.Time
}

func New(hash string) *Collector { return &Collector{hash: hash, start: time.Now()} }
func (c *Collector) Sample() (proto.Report, error) {
	return proto.Report{Version: 1, Bin: c.hash, OS: runtime.GOOS, Arch: runtime.GOARCH, Up: time.Since(c.start).Seconds(), Login: []proto.Login{}}, nil
}
func (c *Collector) Acknowledge(proto.Report) error { return nil }
func NewWithState(hash, statePath string, options Options) (*Collector, error) {
	c := New(hash)
	c.options = options.defaults()
	return c, nil
}
