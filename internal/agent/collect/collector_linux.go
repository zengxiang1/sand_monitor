//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"wanglou/internal/proto"
)

type Collector struct {
	options Options
	loginCollectors
	hash    string
	cpu     CPU
	net     [2]uint64
	at      time.Time
	sampled bool
}

func New(hash string) *Collector { c, _ := NewWithState(hash, "", Options{}); return c }
func NewWithState(hash, statePath string, options Options, backupState ...string) (*Collector, error) {
	options = options.defaults()
	r, err := newLoginCollectors(options.WtmpPath, statePath, backupState)
	if err != nil {
		return nil, err
	}
	return &Collector{hash: hash, loginCollectors: r, options: options}, nil
}
func (c *Collector) Sample() (proto.Report, error) {
	r := proto.Report{Version: 1, Bin: c.hash, OS: runtime.GOOS, Arch: runtime.GOARCH, Login: []proto.Login{}}
	read := func(path string) (string, error) {
		b, e := os.ReadFile(filepath.Join(c.options.ProcRoot, path))
		return string(b), e
	}
	text, e := read("stat")
	if e != nil {
		return r, e
	}
	cpu, e := ParseCPU(text)
	if e != nil {
		return r, e
	}
	text, e = read("meminfo")
	if e != nil {
		return r, e
	}
	r.Mem, r.Swap, e = ParseMem(text)
	if e != nil {
		return r, e
	}
	text, e = read("loadavg")
	if e != nil {
		return r, e
	}
	r.Load, e = ParseLoad(text)
	if e != nil {
		return r, e
	}
	text, e = read("uptime")
	if e != nil {
		return r, e
	}
	r.Up, e = ParseUptime(text)
	if e != nil {
		return r, e
	}
	text, e = read("net/dev")
	if e != nil {
		return r, e
	}
	r.NetTotal, e = ParseNet(text)
	if e != nil {
		return r, e
	}
	for i, paths := range [2][2]string{{"net/tcp", "net/tcp6"}, {"net/udp", "net/udp6"}} {
		for _, path := range paths {
			text, e = read(path)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return r, e
			}
			n, e := ParseConnections(text)
			if e != nil {
				return r, e
			}
			r.Conn[i] += n
		}
	}
	var st syscall.Statfs_t
	if e = syscall.Statfs(c.options.RootFS, &st); e != nil {
		return r, e
	}
	if st.Bfree > st.Blocks {
		return r, fmt.Errorf("invalid statfs counters")
	}
	r.Disk = [2]float64{float64(st.Blocks-st.Bfree) * float64(st.Bsize) / (1 << 30), float64(st.Blocks) * float64(st.Bsize) / (1 << 30)}
	now := time.Now()
	if c.sampled {
		r.CPU = CPUPercent(c.cpu, cpu)
		r.Net = NetRate(c.net, r.NetTotal, now.Sub(c.at).Seconds())
	}
	c.cpu = cpu
	c.net = r.NetTotal
	c.at = now
	c.sampled = true
	return r, r.Validate()
}
