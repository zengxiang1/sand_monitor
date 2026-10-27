package requestip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func remoteIP(addr string) string {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}

// Only trusted direct peers can supply forwarding information. Walking right
// to left stops at the first untrusted address, so a client cannot spoof an
// earlier hop. Invalid chains and all-trusted chains fall back to the peer.
func ClientIP(r *http.Request, proxies []netip.Prefix) string {
	peer := remoteIP(r.RemoteAddr)
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range proxies {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !trusted(addr.Unmap()) {
		return peer
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil || ip.Zone() != "" {
			return peer
		}
		ip = ip.Unmap()
		if !trusted(ip) {
			return ip.String()
		}
	}
	return peer
}
