package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestV4MigrationAndRollupValues(t *testing.T) {
	s := billingStore(t)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix()
	for _, item := range []struct {
		offset int64
		value  float64
	}{{0, 10}, {5, 30}, {60, 80}, {3600, 99}} {
		if _, err := s.DB.Exec(`INSERT INTO metrics(node,ts,cpu,load1,mem_used,mem_total,swap_used,swap_total,disk_used,disk_total,net_tx,net_rx,tcp,udp) VALUES('node',?,?,?,?,?,?,?,?,?,?,?,?,?)`, base+item.offset, item.value, item.value, item.value, 100, item.value, 200, item.value, 300, item.value, item.value*2, item.value, item.value*2); err != nil {
			t.Fatal(err)
		}
	}
	var fileNumber int
	var name, path string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&fileNumber, &name, &path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(downgradeV7 + `DROP TABLE metrics_1m;DROP TABLE metrics_1h;ALTER TABLE billing DROP COLUMN anchor_day;PRAGMA user_version=4;INSERT INTO events(ts,node,kind,detail) VALUES(1,'node','offline','last seen 0')`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	up, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	var version, count int
	if err = up.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 7 {
		t.Fatal(version, err)
	}
	if err = up.DB.QueryRow(`SELECT count(*) FROM metrics`).Scan(&count); err != nil || count != 4 {
		t.Fatal(count, err)
	}
	if err = up.DB.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	now := time.Unix(base+3660, 0)
	if err = up.Rollup(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	read := func(table string, ts int64) []float64 {
		t.Helper()
		values := make([]float64, 16)
		err := up.DB.QueryRow(`SELECT samples,cpu,cpu_max,load1,mem_used,mem_total,swap_used,swap_total,disk_used,disk_total,net_tx,net_rx,net_tx_max,net_rx_max,tcp,udp FROM `+table+` WHERE node='node' AND ts=?`, ts).Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8], &values[9], &values[10], &values[11], &values[12], &values[13], &values[14], &values[15])
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	wantMinute := []float64{2, 20, 30, 20, 20, 100, 20, 200, 20, 300, 20, 40, 30, 60, 20, 40}
	wantHour := []float64{3, 40, 80, 40, 40, 100, 40, 200, 40, 300, 40, 80, 80, 160, 40, 80}
	if got := read("metrics_1m", base); !reflect.DeepEqual(got, wantMinute) {
		t.Fatal(got)
	}
	if got := read("metrics_1h", base); !reflect.DeepEqual(got, wantHour) {
		t.Fatal(got)
	}
	for _, table := range []string{"metrics_1m", "metrics_1h"} {
		if err = up.DB.QueryRow(`SELECT count(*) FROM `+table+` WHERE ts>=?`, base+3600).Scan(&count); err != nil || count != 0 {
			t.Fatal("unfinished", table, count, err)
		}
	}
	if _, err = up.DB.Exec(`UPDATE kv SET value=? WHERE key IN ('rollup.1m','rollup.1h')`, base); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = up.Rollup(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		if got := read("metrics_1m", base); !reflect.DeepEqual(got, wantMinute) {
			t.Fatal("not idempotent", got)
		}
		if got := read("metrics_1h", base); !reflect.DeepEqual(got, wantHour) {
			t.Fatal("not idempotent", got)
		}
	}
	// At the exact margin the preceding bucket becomes eligible.
	if err = up.Rollup(context.Background(), time.Unix(base+3720, 0)); err != nil {
		t.Fatal(err)
	}
	if got := read("metrics_1m", base+3600); got[0] != 1 || got[1] != 99 {
		t.Fatal(got)
	}
}

func TestRollupBatchesAndEmptyWatermarks(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Unix()
	now := time.Unix(base+20*86400+3600+60, 0)
	snapshots := []string{}
	for _, batched := range []bool{true, false} {
		s := billingStore(t)
		if _, err := s.DB.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<480) INSERT INTO metrics(node,ts,cpu,net_tx,net_rx) SELECT 'node',?+i*3600,i%100,i*2,i*3 FROM n`, base); err != nil {
			t.Fatal(err)
		}
		for _, level := range rollupLevels {
			if !batched {
				level.span = 100 * 86400
			}
			done, err := s.rollupBatch(level, now)
			if err != nil {
				t.Fatal(err)
			}
			var watermark int64
			if err = s.DB.QueryRow(`SELECT CAST(value AS INTEGER) FROM kv WHERE key=?`, level.key).Scan(&watermark); err != nil {
				t.Fatal(err)
			}
			if batched && (done || watermark != base+level.span) {
				t.Fatal("batch was not committed at limit", level, done, watermark)
			}
			for !done {
				done, err = s.rollupBatch(level, now)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		var snapshot string
		if err := s.DB.QueryRow(`SELECT group_concat(ts||':'||samples||':'||cpu||':'||cpu_max||':'||net_tx_max) FROM (SELECT * FROM metrics_1m UNION ALL SELECT * FROM metrics_1h ORDER BY ts,samples)`).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if snapshots[0] != snapshots[1] {
		t.Fatal("batch results differ")
	}
	s := billingStore(t)
	if err := s.Rollup(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	for _, level := range rollupLevels {
		var watermark int64
		if err := s.DB.QueryRow(`SELECT CAST(value AS INTEGER) FROM kv WHERE key=?`, level.key).Scan(&watermark); err != nil || watermark != now.Unix()/level.width*level.width {
			t.Fatal(level, watermark, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Rollup(ctx, now); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestCleanupWatermarksAndLifetimes(t *testing.T) {
	s := billingStore(t)
	s.RetentionDays = 30
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		table string
		days  int
	}{{"metrics", 2}, {"metrics_1m", 14}, {"metrics_1h", 30}, {"events", 30}, {"logins", 30}} {
		cutoff := now.AddDate(0, 0, -item.days).Unix()
		for _, ts := range []int64{cutoff - 100, cutoff - 1, cutoff} {
			query := `INSERT INTO ` + item.table + `(node,ts) VALUES('node',?)`
			switch item.table {
			case "metrics_1m", "metrics_1h":
				query = `INSERT INTO ` + item.table + `(node,ts,samples) VALUES('node',?,12)`
			case "events":
				query = `INSERT INTO events(node,ts,kind,detail) VALUES('node',?,'offline','test')`
			case "logins":
				query = `INSERT INTO logins(node,ts,known) VALUES('node',?,1)`
			}
			if _, err := s.DB.Exec(query, ts); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"metrics", "metrics_1m"} {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 3 {
			t.Fatal("missing watermark deleted data", table, count, err)
		}
	}
	for _, item := range []struct {
		key  string
		days int
	}{{"rollup.1m", 2}, {"rollup.1h", 14}} {
		if _, err := s.DB.Exec(`INSERT INTO kv VALUES(?,?)`, item.key, now.AddDate(0, 0, -item.days).Unix()-50); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		table string
		want  int
	}{{"metrics", 2}, {"metrics_1m", 2}, {"metrics_1h", 1}, {"events", 1}, {"logins", 1}} {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM ` + item.table).Scan(&count); err != nil || count != item.want {
			t.Fatal(item, count, err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE kv SET value=? WHERE key LIKE 'rollup.%'`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"metrics", "metrics_1m"} {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 1 {
			t.Fatal(table, count, err)
		}
	}
}

func TestRetentionDatabaseSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "size.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.DB.Exec(`INSERT INTO nodes(name,pubkey,fingerprint,created_at) VALUES('node',zeroblob(32),'sample',0)`); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix()
	if err = s.Transaction(func(tx *sql.Tx) error {
		_, err := tx.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<34559)
   INSERT INTO metrics SELECT 'node',?-i*5,(i%1000)/10.0,(i%100)/31.0,(i%100)/37.0,(i%100)/41.0,500+(i%500)/3.0,2048,0,512,18+(i%100)/13.0,40,1000+i*7.3,2000+i*11.7,CAST(1000000000+i*10000 AS TEXT),CAST(2000000000+i*20000 AS TEXT),41+i%50,6+i%10,864000+i*5 FROM n`, base)
		if err != nil {
			return err
		}
		for _, item := range []struct {
			table               string
			rows, step, samples int
		}{{"metrics_1m", 14*1440 - 1, 60, 12}, {"metrics_1h", 90 * 24, 3600, 720}} {
			if _, err = tx.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO `+item.table+` SELECT 'node',?-i*?, ?, (i%1000)/10.0,(i%1000)/10.0+5,(i%100)/31.0,500+(i%500)/3.0,2048,0,512,18+(i%100)/13.0,40,1000+i*7.3,2000+i*11.7,2000+i*7.3,4000+i*11.7,41+i%50,6+i%10 FROM n`, item.rows, base, item.step, item.samples); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`VACUUM; PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one node, 5s cadence, 90d retention: %d bytes = %.2f MB (compacted DB; 34560 raw, 20159 minute, 2160 hour rows; no event/login volume)", info.Size(), float64(info.Size())/1e6)
}
