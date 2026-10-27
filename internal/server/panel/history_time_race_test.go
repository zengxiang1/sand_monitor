//go:build race

package panel

import "time"

// Race instrumentation adds substantial overhead to pure Go SQLite.
const historyTimeLimit = 4 * time.Second
