package store

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"wanglou/internal/proto"
)

var ErrRevokedKey = errors.New("不能复用已吊销的公钥")

func TokenHash(token string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(token))) }

func (s *Store) SubmitEnrollment(code, line string, now time.Time) error {
	key, err := proto.ParsePublicKey(line)
	if err != nil {
		return err
	}
	name := strings.Fields(line)[2]
	return s.Transaction(func(tx *sql.Tx) error {
		if err := checkRevokedKey(tx, proto.Fingerprint(key)); err != nil {
			return err
		}
		result, err := tx.Exec(`UPDATE enroll_codes SET pubkey=?,used_at=? WHERE code_hash=? AND name=? AND expires_at>? AND used_at=0 AND pubkey=''`, proto.PublicKeyLine(key, name), now.Unix(), TokenHash(code), name, now.Unix())
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err == nil && count != 1 {
			return fmt.Errorf("invalid enrollment")
		}
		return err
	})
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
		action := "node_enable"
		old, err := scanNode(tx.QueryRow(`SELECT `+columns+` FROM nodes WHERE name=?`, name))
		switch {
		case err == sql.ErrNoRows:
			if err = addNode(tx, name, key, note, now); err != nil {
				return err
			}
		case err != nil:
			return err
		case old.RevokedAt == 0:
			return fmt.Errorf("节点名已被占用")
		default:
			if err := checkRevokedKey(tx, proto.Fingerprint(key)); err != nil {
				return err
			}
			if _, err = tx.Exec(`UPDATE nodes SET pubkey=?,fingerprint=?,revoked_at=0,note=? WHERE name=?`, []byte(key), proto.Fingerprint(key), note, name); err != nil {
				return err
			}
			action = "node_reenable"
		}
		_, err = tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now.Unix(), user, ip, action, name)
		return err
	})
}

func checkRevokedKey(tx *sql.Tx, fingerprint string) error {
	var revoked bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE fingerprint=?)`, fingerprint).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return ErrRevokedKey
	}
	return nil
}

func (s *Store) CheckRevokedKey(fingerprint string) error {
	return s.Transaction(func(tx *sql.Tx) error { return checkRevokedKey(tx, fingerprint) })
}
