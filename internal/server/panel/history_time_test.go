//go:build !race

package panel

import "time"

const historyTimeLimit = 200 * time.Millisecond
