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
	loginCollectors
	hash  string
	start time.Time
}

func New(hash string) *Collector { c, _ := NewWithState(hash, "", Options{}); return c }
func (c *Collector) Sample() (proto.Report, error) {
	return proto.Report{Version: 1, Bin: c.hash, OS: runtime.GOOS, Arch: runtime.GOARCH, Up: time.Since(c.start).Seconds(), Login: []proto.Login{}}, nil
}

func NewWithState(hash, statePath string, options Options, backupState ...string) (*Collector, error) {
	c := &Collector{hash: hash, start: time.Now()}
	c.options = options.defaults()
	readers, err := newLoginCollectors(c.options.WtmpPath, statePath, backupState)
	if err != nil {
		return nil, err
	}
	c.loginCollectors = readers
	return c, nil
}
