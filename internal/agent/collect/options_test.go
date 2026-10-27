package collect

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectorOptions(t *testing.T) {
	defaults := Options{}.defaults()
	if defaults.ProcRoot != "/proc" || defaults.RootFS != "/" || defaults.WtmpPath != "/var/log/wtmp" {
		t.Fatal(defaults)
	}
	options := Options{ProcRoot: "/host/proc", RootFS: "/host/root", WtmpPath: "/host/wtmp"}
	c, err := NewWithState("sha256:"+strings.Repeat("a", 64), filepath.Join(t.TempDir(), "cursor"), options)
	if err != nil || c.options != options {
		t.Fatal(c, err)
	}
}
