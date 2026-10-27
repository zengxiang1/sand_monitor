package format

import (
	"fmt"
	"strings"
)

func Rate(value float64) string {
	units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%.0f B/s", value)
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", value), ".0") + " " + units[unit]
}
