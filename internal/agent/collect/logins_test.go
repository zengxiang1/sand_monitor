package collect

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"wanglou/internal/proto"
)

func loginRecord(user string, ts int64) []byte {
	b := make([]byte, wtmpRecordSize)
	binary.LittleEndian.PutUint16(b, 7)
	copy(b[44:76], user)
	copy(b[76:332], "203.0.113.7")
	binary.LittleEndian.PutUint32(b[340:344], uint32(ts))
	return b
}
func appendRecords(t *testing.T, path string, records ...[]byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, r := range records {
		if _, err = f.Write(r); err != nil {
			t.Fatal(err)
		}
	}
}
func reader(t *testing.T, path, state string) *loginReader {
	t.Helper()
	r, err := newLoginReader(path, state)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func loginSample(t *testing.T, r *loginReader) []proto.Login {
	t.Helper()
	got, err := r.sample()
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func ack(t *testing.T, r *loginReader) {
	t.Helper()
	if err := r.acknowledge(); err != nil {
		t.Fatal(err)
	}
}
func TestBigWTMPBaselineAndIncrementalRead(t *testing.T) {
	dir := t.TempDir()
	path, state := filepath.Join(dir, "wtmp"), filepath.Join(dir, "agent.seq.logins.json")
	// Expand the checked-in ABI fixture well beyond the report body limit.
	raw := []byte(fixture(t, "wtmp"))
	var big []byte
	for range 3000 {
		big = append(big, raw...)
	}
	if err := os.WriteFile(path, big, 0600); err != nil {
		t.Fatal(err)
	}
	r := reader(t, path, state)
	if got := loginSample(t, r); len(got) != 0 {
		t.Fatal("uploaded history", len(got))
	}
	if r.cursor.Offset != int64(len(big)) || r.cursor.Timestamp != 1761551991 {
		t.Fatal(r.cursor)
	}
	info, err := os.Stat(state)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	// Overwrite history without changing the inode/size. An incremental reader
	// must not see this deliberately newer timestamp before its saved offset.
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt(loginRecord("old-record", 1761552999), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	appendRecords(t, path, loginRecord("new-record", 1761551992))
	got := loginSample(t, r)
	if len(got) != 1 || got[0].User != "new-record" {
		t.Fatal(got)
	}
	ack(t, r)
	if got = loginSample(t, reader(t, path, state)); len(got) != 0 {
		t.Fatal("replayed history", got)
	}
}
func TestLoginCapCarryOverAndRestart(t *testing.T) {
	dir := t.TempDir()
	path, state := filepath.Join(dir, "wtmp"), filepath.Join(dir, "agent.seq.logins.json")
	appendRecords(t, path, loginRecord("baseline", 100))
	r := reader(t, path, state)
	loginSample(t, r)
	for i := 0; i < 75; i++ {
		appendRecords(t, path, loginRecord(fmt.Sprintf("session-%d", i), 101))
	}
	first := loginSample(t, r)
	if len(first) != MaxLogins {
		t.Fatal(len(first))
	}
	if retry := loginSample(t, r); !reflect.DeepEqual(first, retry) {
		t.Fatal("failed send advanced batch")
	}
	// A crash before ACK resumes the same uncommitted batch.
	r = reader(t, path, state)
	if got := loginSample(t, r); !reflect.DeepEqual(first, got) {
		t.Fatal("restart lost pending records")
	}
	ack(t, r)
	// A new login while stopped, in the same second as all previous records.
	appendRecords(t, path, loginRecord("during-downtime", 101))
	r = reader(t, path, state)
	second := loginSample(t, r)
	if len(second) != 32 || second[0].User != "session-32" {
		t.Fatal(second)
	}
	ack(t, r)
	third := loginSample(t, r)
	if len(third) != 12 || third[11].User != "during-downtime" {
		t.Fatal(third)
	}
	ack(t, r)
	if got := loginSample(t, r); len(got) != 0 {
		t.Fatal(got)
	}
	ack(t, r)
	body, _ := json.Marshal(proto.Report{Login: first})
	if len(body) > 64*1024 {
		t.Fatal("batch exceeds report limit")
	}
	// Exact duplicates appended later are suppressed, distinct same-second tuples survive.
	appendRecords(t, path, loginRecord("session-0", 101), loginRecord("another-session", 101))
	got := loginSample(t, r)
	if len(got) != 1 || got[0].User != "another-session" {
		t.Fatal(got)
	}
}
func TestLoginRotationAndTruncation(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(fmt.Sprint(rotate), func(t *testing.T) {
			dir := t.TempDir()
			path, state := filepath.Join(dir, "wtmp"), filepath.Join(dir, "agent.seq.logins.json")
			appendRecords(t, path, loginRecord("baseline", 100))
			r := reader(t, path, state)
			loginSample(t, r)
			appendRecords(t, path, loginRecord("accepted", 101), loginRecord("accepted-2", 101))
			loginSample(t, r)
			ack(t, r)
			if rotate {
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			}
			appendRecords(t, path, loginRecord("accepted", 101), loginRecord("new-same-second", 101))
			r = reader(t, path, state)
			got := loginSample(t, r)
			if len(got) != 1 || got[0].User != "new-same-second" {
				t.Fatal(got)
			}
			ack(t, r)
			appendRecords(t, path, loginRecord("next", 102))
			if got = loginSample(t, r); len(got) != 1 || got[0].User != "next" {
				t.Fatal(got)
			}
		})
	}
}
func TestLoginPartialRecordAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	path, state := filepath.Join(dir, "wtmp"), filepath.Join(dir, "agent.seq.logins.json")
	r := reader(t, path, state)
	if got := loginSample(t, r); len(got) != 0 {
		t.Fatal(got)
	}
	appendRecords(t, path, loginRecord("baseline", 100))
	loginSample(t, r)
	b := loginRecord("partial", 101)
	appendRecords(t, path, b[:100])
	if got := loginSample(t, r); len(got) != 0 {
		t.Fatal(got)
	}
	ack(t, r)
	appendRecords(t, path, b[100:])
	if got := loginSample(t, r); len(got) != 1 {
		t.Fatal(got)
	}
}
