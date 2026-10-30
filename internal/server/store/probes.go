package store

import (
	"database/sql"
	"time"
	"wanglou/internal/proto"
)

// ProbeHistory returns retained raw samples; probe retention is seven days.
func (s *Store) ProbeHistory(node string, since time.Time) ([]proto.Probe, error) {
	rows, err := s.DB.Query(`SELECT target,ts,ip,dns_ms,tcp_ms,tls_ms,ttfb_ms,total_ms,status,error FROM probe_samples WHERE node=? AND ts>=? ORDER BY target,ts`, node, since.Unix())
	if err != nil {
		return nil, err
	}
	return scanProbes(rows)
}

func (s *Store) LatestProbes(node string) ([]proto.Probe, error) {
	rows, err := s.DB.Query(`SELECT p.target,p.ts,p.ip,p.dns_ms,p.tcp_ms,p.tls_ms,p.ttfb_ms,p.total_ms,p.status,p.error FROM probe_samples p JOIN (SELECT target,max(ts) AS ts FROM probe_samples WHERE node=? GROUP BY target) latest ON p.target=latest.target AND p.ts=latest.ts WHERE p.node=? ORDER BY p.target`, node, node)
	if err != nil {
		return nil, err
	}
	return scanProbes(rows)
}

func scanProbes(rows *sql.Rows) ([]proto.Probe, error) {
	defer rows.Close()
	out := []proto.Probe{}
	for rows.Next() {
		var p proto.Probe
		if err := rows.Scan(&p.Target, &p.Time, &p.IP, &p.DNSMS, &p.TCPMS, &p.TLSMS, &p.TTFBMS, &p.TotalMS, &p.Status, &p.Error); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
