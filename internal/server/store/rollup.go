package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

func migrateRollup(tx *sql.Tx) error {
	for _, table := range []string{"metrics_1m", "metrics_1h"} {
		if _, err := tx.Exec(`CREATE TABLE ` + table + `(
   node TEXT NOT NULL REFERENCES nodes(name), ts INTEGER NOT NULL, samples INTEGER NOT NULL,
   cpu REAL, cpu_max REAL, load1 REAL, mem_used REAL, mem_total REAL, swap_used REAL, swap_total REAL,
   disk_used REAL, disk_total REAL, net_tx REAL, net_rx REAL, net_tx_max REAL, net_rx_max REAL,
   tcp REAL, udp REAL, PRIMARY KEY(node,ts)); CREATE INDEX ` + table + `_ts ON ` + table + `(ts);`); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`CREATE INDEX IF NOT EXISTS metrics_ts ON metrics(ts); PRAGMA user_version=5;`)
	return err
}

type rollupLevel struct {
	source, target, key string
	width, span         int64
}

var rollupLevels = []rollupLevel{
	{"metrics", "metrics_1m", "rollup.1m", 60, 6 * 3600},
	{"metrics_1m", "metrics_1h", "rollup.1h", 3600, 7 * 86400},
}

func (s *Store) Rollup(ctx context.Context, now time.Time) error {
	for _, level := range rollupLevels {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			done, err := s.rollupBatch(level, now)
			if err != nil {
				return err
			}
			if done {
				break
			}
		}
	}
	return nil
}

func (s *Store) rollupBatch(level rollupLevel, now time.Time) (bool, error) {
	done := false
	err := s.Transaction(func(tx *sql.Tx) error {
		var start int64
		err := tx.QueryRow(`SELECT CAST(value AS INTEGER) FROM kv WHERE key=?`, level.key).Scan(&start)
		if err == sql.ErrNoRows {
			if err = tx.QueryRow(`SELECT coalesce(min(ts),?) / ? * ? FROM `+level.source, now.Unix(), level.width, level.width).Scan(&start); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		limit := (now.Unix() - 60) / level.width * level.width
		if level.source == "metrics_1m" {
			var minute int64
			if err = tx.QueryRow(`SELECT CAST(value AS INTEGER) FROM kv WHERE key='rollup.1m'`).Scan(&minute); err != nil {
				return err
			}
			limit = min(limit, minute/3600*3600)
		}
		end := min(start+level.span, limit)
		if end > start {
			samples := "count(*)"
			maximum := map[string]string{"cpu_max": "cpu", "net_tx_max": "net_tx", "net_rx_max": "net_rx"}
			if level.source == "metrics_1m" {
				samples = "sum(samples)"
				maximum = map[string]string{"cpu_max": "cpu_max", "net_tx_max": "net_tx_max", "net_rx_max": "net_rx_max"}
			}
			columns := []string{"cpu", "cpu_max", "load1", "mem_used", "mem_total", "swap_used", "swap_total", "disk_used", "disk_total", "net_tx", "net_rx", "net_tx_max", "net_rx_max", "tcp", "udp"}
			values, updates := []string{}, []string{"samples=excluded.samples"}
			for _, column := range columns {
				value := "avg(" + column + ")"
				if level.source == "metrics_1m" {
					value = "sum(" + column + "*samples)*1.0/sum(samples)"
				}
				if source, ok := maximum[column]; ok {
					value = "max(" + source + ")"
				}
				values = append(values, value)
				updates = append(updates, column+"=excluded."+column)
			}
			if _, err = tx.Exec(`INSERT INTO `+level.target+`(node,ts,samples,`+strings.Join(columns, ",")+`) SELECT node,ts/?*?,`+samples+`,`+strings.Join(values, ",")+` FROM `+level.source+` WHERE ts>=? AND ts<? GROUP BY node,ts/? ON CONFLICT(node,ts) DO UPDATE SET `+strings.Join(updates, ","), level.width, level.width, start, end, level.width); err != nil {
				return err
			}
			start = end
		}
		_, err = tx.Exec(`INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, level.key, start)
		done = start >= limit
		return err
	})
	return done, err
}
