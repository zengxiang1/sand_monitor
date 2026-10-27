//go:build !linux && !darwin

package collect

import "os"

// Non-Linux collectors do not read wtmp. This fallback keeps helpers portable.
func fileIdentity(info os.FileInfo) string { return info.Name() }
