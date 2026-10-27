package collect

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"wanglou/internal/proto"
)

const MaxLogins = 32

// The acknowledged offset never advances before a successful report. Seen
// retains identities at the timestamp boundary, including across rotations.
type loginCursor struct {
	Initialized bool          `json:"initialized"`
	Identity    string        `json:"identity"`
	Offset      int64         `json:"offset"`
	Timestamp   int64         `json:"timestamp"`
	Seen        []proto.Login `json:"seen"`
}
type loginReader struct {
	path, statePath string
	cursor          loginCursor
	pending         *loginCursor
	batch           []proto.Login
}

func newLoginReader(path, statePath string) (*loginReader, error) {
	r := &loginReader{path: path, statePath: statePath}
	if statePath == "" {
		return r, nil
	}
	data, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &r.cursor); err != nil || !r.cursor.Initialized || r.cursor.Offset < 0 || r.cursor.Offset%wtmpRecordSize != 0 || r.cursor.Timestamp < 0 {
		r.cursor = loginCursor{}
		log.Printf("invalid login cursor %s: rebuilding baseline at current wtmp end", statePath)
	}
	return r, nil
}
func (c *loginCursor) observe(l proto.Login) bool {
	if l.Time < c.Timestamp {
		return false
	}
	if l.Time > c.Timestamp {
		c.Timestamp = l.Time
		c.Seen = nil
	}
	if slices.Contains(c.Seen, l) {
		return false
	}
	c.Seen = append(c.Seen, l)
	return true
}
func (r *loginReader) sample() ([]proto.Login, error) {
	if r.pending != nil {
		return slices.Clone(r.batch), nil
	}
	f, err := os.Open(r.path)
	if err != nil {
		return []proto.Login{}, nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return []proto.Login{}, nil
	}
	next := r.cursor
	next.Seen = slices.Clone(next.Seen)
	identity := fileIdentity(info)
	if next.Identity != identity || info.Size() < next.Offset {
		next.Offset = 0
	}
	next.Identity = identity
	if _, err = f.Seek(next.Offset, io.SeekStart); err != nil {
		return []proto.Login{}, nil
	}
	// A snapshot bound avoids following a continuously growing file forever.
	records := (info.Size() - next.Offset) / wtmpRecordSize
	batch := []proto.Login{}
	for i := int64(0); i < records; i++ {
		var raw [wtmpRecordSize]byte
		if _, err = io.ReadFull(f, raw[:]); err != nil {
			return []proto.Login{}, nil
		}
		next.Offset += wtmpRecordSize
		l, ok := decodeWTMP(raw[:])
		if !ok || !next.observe(l) {
			continue
		}
		if r.cursor.Initialized {
			batch = append(batch, l)
			if len(batch) == MaxLogins {
				break
			}
		}
	}
	if !next.Initialized {
		// First installation establishes a durable baseline without uploading history.
		next.Initialized = true
		if err = r.save(next); err != nil {
			return nil, err
		}
		r.cursor = next
		return batch, nil
	}
	r.pending = &next
	r.batch = batch
	return slices.Clone(batch), nil
}
func (r *loginReader) acknowledge() error {
	if r.pending == nil {
		return nil
	}
	if err := r.save(*r.pending); err != nil {
		return err
	}
	r.cursor = *r.pending
	r.pending = nil
	r.batch = nil
	return nil
}
func (r *loginReader) save(c loginCursor) error {
	if r.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(r.statePath), ".login-cursor-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(c)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), r.statePath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(r.statePath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type loginCollectors map[string]*loginReader

func newLoginCollectors(path, state string, backup []string) (loginCollectors, error) {
	paths := map[string]string{"primary": state}
	if len(backup) > 0 {
		paths["backup"] = backup[0]
	}
	readers := loginCollectors{}
	for target, statePath := range paths {
		r, err := newLoginReader(path, statePath)
		if err != nil {
			return nil, err
		}
		if _, err = r.sample(); err != nil {
			return nil, err
		}
		readers[target] = r
	}
	return readers, nil
}
func (c loginCollectors) Logins(target string) ([]proto.Login, error) {
	r := c[target]
	if r == nil {
		return nil, fmt.Errorf("unknown login target %q", target)
	}
	return r.sample()
}
func (c loginCollectors) Acknowledge(target string) error {
	r := c[target]
	if r == nil {
		return fmt.Errorf("unknown login target %q", target)
	}
	return r.acknowledge()
}
