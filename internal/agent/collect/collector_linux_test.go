//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountedHostCollection(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	for target, source := range map[string]string{"stat": "stat", "meminfo": "meminfo", "loadavg": "loadavg", "uptime": "uptime", "net/dev": "net_dev", "net/tcp": "tcp", "net/tcp6": "tcp6", "net/udp": "udp", "net/udp6": "udp6"} {
		if err := os.WriteFile(filepath.Join(proc, target), []byte(fixture(t, source)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wtmp := filepath.Join(dir, "wtmp")
	appendRecords(t, wtmp, loginRecord("baseline", 100))
	c, err := NewWithState("sha256:"+strings.Repeat("a", 64), filepath.Join(dir, "cursor"), Options{ProcRoot: proc, RootFS: dir, WtmpPath: wtmp})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if r.Mem != ([2]float64{812, 2048}) || r.NetTotal != ([2]uint64{1532, 8841}) || r.Up != 864000.25 || r.Conn != ([2]uint64{3, 3}) || r.Disk[1] <= 0 || len(r.Login) != 0 {
		t.Fatal(r)
	}
	if err = c.Acknowledge("primary"); err != nil {
		t.Fatal(err)
	}
	appendRecords(t, wtmp, loginRecord("mounted-login", 101))
	logins, err := c.Logins("primary")
	if err != nil || len(logins) != 1 || logins[0].User != "mounted-login" {
		t.Fatal(logins, err)
	}
	r, err = c.Sample()
	if err != nil || len(r.Login) != 0 {
		t.Fatal("metrics included logins", r, err)
	}
	c.options.RootFS = filepath.Join(dir, "missing-root")
	if _, err = c.Sample(); err == nil {
		t.Fatal("ignored configured root_fs")
	}
}
