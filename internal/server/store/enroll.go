package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"wanglou/internal/proto"
)

func TokenHash(token string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(token))) }

func (s *Store) SubmitEnrollment(code, line string, now time.Time) error {
	key, err := proto.ParsePublicKey(line)
	if err != nil {
		return err
	}
	name := strings.Fields(line)[2]
	result, err := s.DB.Exec(`UPDATE enroll_codes SET pubkey=?,used_at=? WHERE code_hash=? AND name=? AND expires_at>? AND used_at=0 AND pubkey=''`, proto.PublicKeyLine(key, name), now.Unix(), TokenHash(code), name, now.Unix())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return fmt.Errorf("invalid enrollment")
	}
	return err
}

func (s *Store) ConfirmEnrollment(name, note, line, codeHash string, now time.Time, user, ip string) error {
	key, err := proto.ParsePublicKey(line)
	if err != nil || strings.Fields(line)[2] != name {
		return fmt.Errorf("invalid enrollment")
	}
	return s.Transaction(func(tx *sql.Tx) error {
		if codeHash != "" {
			result, err := tx.Exec(`DELETE FROM enroll_codes WHERE code_hash=? AND name=? AND note=? AND pubkey=? AND expires_at>? AND used_at>0`, codeHash, name, note, line, now.Unix())
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("invalid enrollment")
			}
		}
		if err := addNode(tx, name, key, note, now); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now.Unix(), user, ip, "node_enable", name)
		return err
	})
}
