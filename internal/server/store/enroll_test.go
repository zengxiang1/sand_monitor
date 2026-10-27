package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"testing"
	"time"
	"wanglou/internal/proto"
)

func TestConfirmEnrollmentReturnsScanError(t *testing.T) {
	s := billingStore(t)
	now := time.Unix(2000000000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	line := proto.PublicKeyLine(key, "node")
	if _, err := s.DB.Exec(`UPDATE nodes SET last_seq='invalid' WHERE name='node'; INSERT INTO enroll_codes VALUES('pending','node','',1,? ,?,1)`, now.Add(time.Minute).Unix(), line); err != nil {
		t.Fatal(err)
	}
	var parseError *strconv.NumError
	if err := s.ConfirmEnrollment("node", "", line, "pending", now, "admin", "192.0.2.1"); err == nil || !errors.As(err, &parseError) {
		t.Fatal("scan error swallowed", err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&count); err != nil || count != 0 {
		t.Fatal("false success audit", count, err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM enroll_codes WHERE code_hash='pending'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed confirmation committed", count, err)
	}
}

func TestRevokedKeysCannotBeReused(t *testing.T) {
	s := billingStore(t)
	now := time.Unix(2000000000, 0)
	original, err := s.Node("node")
	if err != nil {
		t.Fatal(err)
	}
	replacement, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = s.Revoke("node", now); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmEnrollment("node", "new", proto.PublicKeyLine(replacement, "node"), "", now, "admin", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err = s.Revoke("node", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PublicKey{original.Pubkey, replacement} {
		if err = s.CheckRevokedKey(proto.Fingerprint(key)); !errors.Is(err, ErrRevokedKey) {
			t.Fatal(err)
		}
		for _, name := range []string{"node", "fresh"} {
			if err = s.ConfirmEnrollment(name, "", proto.PublicKeyLine(key, name), "", now, "admin", "192.0.2.1"); !errors.Is(err, ErrRevokedKey) {
				t.Fatal(name, err)
			}
			if err = s.AddNode(name, key, now); !errors.Is(err, ErrRevokedKey) {
				t.Fatal("CLI enrollment", name, err)
			}
			code := proto.Fingerprint(key) + name
			if _, err = s.DB.Exec(`INSERT INTO enroll_codes(code_hash,name,note,created_at,expires_at) VALUES(?,?,'',?,?)`, TokenHash(code), name, now.Unix(), now.Add(time.Minute).Unix()); err != nil {
				t.Fatal(err)
			}
			if err = s.SubmitEnrollment(code, proto.PublicKeyLine(key, name), now); !errors.Is(err, ErrRevokedKey) {
				t.Fatal("ingest enrollment", name, err)
			}
			var line string
			var used int64
			if err = s.DB.QueryRow(`SELECT pubkey,used_at FROM enroll_codes WHERE code_hash=?`, TokenHash(code)).Scan(&line, &used); err != nil || line != "" || used != 0 {
				t.Fatal("rejected submission consumed code", line, used, err)
			}
		}
	}
	var count int
	if err = s.DB.QueryRow(`SELECT count(*) FROM revoked_keys`).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	if err = s.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='node_reenable'`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestRevokeRegistryFailureRollsBack(t *testing.T) {
	s := billingStore(t)
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_revoked BEFORE INSERT ON revoked_keys BEGIN SELECT RAISE(ABORT,'forced failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke("node", time.Unix(2000000000, 0)); err == nil {
		t.Fatal("registry failure ignored")
	}
	node, err := s.Node("node")
	if err != nil || node.RevokedAt != 0 {
		t.Fatal(node, err)
	}
}
