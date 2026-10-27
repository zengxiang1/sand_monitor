package collect

const (
	DefaultProcRoot = "/proc"
	DefaultRootFS   = "/"
	DefaultWtmpPath = "/var/log/wtmp"
)

// Options selects local host mounts when the collector runs in a container.
// Empty fields retain the native host paths.
type Options struct {
	ProcRoot, RootFS, WtmpPath string
}

func (o Options) defaults() Options {
	if o.ProcRoot == "" {
		o.ProcRoot = DefaultProcRoot
	}
	if o.RootFS == "" {
		o.RootFS = DefaultRootFS
	}
	if o.WtmpPath == "" {
		o.WtmpPath = DefaultWtmpPath
	}
	return o
}
