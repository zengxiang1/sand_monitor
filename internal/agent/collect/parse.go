package collect

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"wanglou/internal/proto"
)

type CPU struct{ Total, Idle uint64 }

func ParseCPU(text string) (CPU, error) {
	f := strings.Fields(strings.SplitN(text, "\n", 2)[0])
	if len(f) < 5 || f[0] != "cpu" {
		return CPU{}, fmt.Errorf("missing cpu counters")
	}
	var c CPU
	for i, s := range f[1:] {
		v, e := strconv.ParseUint(s, 10, 64)
		if e != nil {
			return c, e
		}
		if i < 8 {
			c.Total += v
		}
		if i == 3 || i == 4 {
			c.Idle += v
		}
	}
	return c, nil
}
func CPUPercent(prev, cur CPU) float64 {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0
	}
	total := cur.Total - prev.Total
	idle := cur.Idle - prev.Idle
	if idle >= total {
		return 0
	}
	return 100 * float64(total-idle) / float64(total)
}
func ParseMem(text string) (mem, swap [2]float64, err error) {
	values := map[string]uint64{}
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 0 {
			continue
		}
		k := strings.TrimSuffix(f[0], ":")
		switch k {
		case "MemTotal", "MemAvailable", "SwapTotal", "SwapFree":
			if len(f) != 3 || f[2] != "kB" {
				return mem, swap, fmt.Errorf("invalid memory unit")
			}
			v, e := strconv.ParseUint(f[1], 10, 64)
			if e != nil {
				return mem, swap, e
			}
			values[k] = v
		}
	}
	for _, k := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
		if _, ok := values[k]; !ok {
			return mem, swap, fmt.Errorf("missing %s", k)
		}
	}
	if values["MemAvailable"] > values["MemTotal"] || values["SwapFree"] > values["SwapTotal"] {
		return mem, swap, fmt.Errorf("invalid memory counters")
	}
	mem = [2]float64{float64(values["MemTotal"]-values["MemAvailable"]) / 1024, float64(values["MemTotal"]) / 1024}
	swap = [2]float64{float64(values["SwapTotal"]-values["SwapFree"]) / 1024, float64(values["SwapTotal"]) / 1024}
	return mem, swap, s.Err()
}
func ParseLoad(text string) (out [3]float64, err error) {
	f := strings.Fields(text)
	if len(f) < 3 {
		return out, fmt.Errorf("missing load")
	}
	for i := range out {
		out[i], err = strconv.ParseFloat(f[i], 64)
		if err != nil || out[i] < 0 || math.IsNaN(out[i]) || math.IsInf(out[i], 0) {
			return out, fmt.Errorf("invalid load")
		}
	}
	return
}
func ParseUptime(text string) (float64, error) {
	f := strings.Fields(text)
	if len(f) < 1 {
		return 0, fmt.Errorf("missing uptime")
	}
	n, e := strconv.ParseFloat(f[0], 64)
	if e != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("invalid uptime")
	}
	return n, nil
}
func virtual(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"veth", "docker", "br", "vxlan", "flannel", "cni", "kube", "podman", "virbr", "tun", "tap", "wg", "tailscale", "zt", "dummy", "ifb"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
func ParseNet(text string) (total [2]uint64, err error) {
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		name, rest, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		if virtual(strings.TrimSpace(name)) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 16 {
			return total, fmt.Errorf("invalid net counters")
		}
		rx, e := strconv.ParseUint(f[0], 10, 64)
		if e != nil {
			return total, e
		}
		tx, e := strconv.ParseUint(f[8], 10, 64)
		if e != nil {
			return total, e
		}
		total[0] += tx
		total[1] += rx
	}
	return total, s.Err()
}
func NetRate(prev, cur [2]uint64, seconds float64) (rate [2]float64) {
	if seconds <= 0 {
		return
	}
	for i := range rate {
		if cur[i] >= prev[i] {
			rate[i] = float64(cur[i]-prev[i]) / seconds
		}
	}
	return
}
func ParseConnections(text string) (uint64, error) {
	s := bufio.NewScanner(strings.NewReader(text))
	if !s.Scan() || !strings.Contains(s.Text(), "local_address") {
		return 0, fmt.Errorf("invalid connection header")
	}
	var n uint64
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") || !strings.Contains(f[1], ":") || !strings.Contains(f[2], ":") {
			return 0, fmt.Errorf("invalid connection")
		}
		if _, e := strconv.ParseUint(f[3], 16, 8); e != nil {
			return 0, e
		}
		n++
	}
	return n, s.Err()
}

// decodeWTMP parses one Linux glibc record independently of file IO.
func decodeWTMP(b []byte) (proto.Login, bool) {
	if len(b) != wtmpRecordSize || binary.LittleEndian.Uint16(b[:2]) != 7 {
		return proto.Login{}, false
	}
	ts := int64(int32(binary.LittleEndian.Uint32(b[340:344])))
	addrOffset := 348
	if wtmpRecordSize == 400 {
		ts = int64(binary.LittleEndian.Uint64(b[344:352]))
		addrOffset = 360
	}
	user := strings.TrimRight(string(b[44:76]), "\x00")
	host := strings.TrimRight(string(b[76:332]), "\x00")
	ip := net.ParseIP(host)
	if ip == nil {
		addr := b[addrOffset : addrOffset+16]
		if binary.LittleEndian.Uint32(addr[4:8]) == 0 && binary.LittleEndian.Uint64(addr[8:]) == 0 {
			ip = net.IP(addr[:4])
		} else {
			ip = net.IP(addr)
		}
	}
	if ts < 0 || user == "" || ip.IsUnspecified() {
		return proto.Login{}, false
	}
	return proto.Login{User: user, From: ip.String(), Time: ts}, true
}

// ParseWTMP includes the timestamp boundary and deduplicates by (ts,user,ip).
// Incremental collection persists its boundary identities and byte offset.
func ParseWTMP(r io.Reader, since int64) ([]proto.Login, error) {
	out := []proto.Login{}
	seen := map[proto.Login]bool{}
	var raw [wtmpRecordSize]byte
	for {
		_, err := io.ReadFull(r, raw[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		l, ok := decodeWTMP(raw[:])
		if ok && l.Time >= since && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
}
