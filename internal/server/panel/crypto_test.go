package panel

import (
	"encoding/base32"
	"testing"
)

func TestRFC6238SHA1(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		timestamp int64
		code      string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := totp(secret, tc.timestamp/30, 8); got != tc.code {
			t.Fatalf("%d: %s != %s", tc.timestamp, got, tc.code)
		}
	}
	now := int64(2000000000)
	for _, offset := range []int64{-2, -1, 0, 1, 2} {
		step, ok := totpStep(secret, totp(secret, now/30+offset, 6), now, -1)
		want := offset >= -1 && offset <= 1
		if ok != want || ok && step != now/30+offset {
			t.Fatal(offset, step, ok)
		}
	}
	for _, step := range []int64{now/30 - 1, now / 30, now/30 + 1} {
		if _, ok := totpStep(secret, totp(secret, step, 6), now, step); ok {
			t.Fatal("replay accepted")
		}
	}
	for _, code := range []string{"", "abcdef", "12345", "1234567"} {
		if _, ok := totpStep(secret, code, now, -1); ok {
			t.Fatal(code)
		}
	}
}
func TestPasswordHash(t *testing.T) {
	hash, err := HashPassword("example-password")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(hash, "example-password") || CheckPassword(hash, "wrong") {
		t.Fatal("password comparison")
	}
	second, err := HashPassword("example-password")
	if err != nil || hash == second {
		t.Fatal("salt not random", err)
	}
	if _, err = HashPassword("short"); err == nil {
		t.Fatal("short password")
	}
	for _, bad := range []string{"", "pbkdf2-sha256$1$bad$bad", "pbkdf2-sha256$600000$bad$bad"} {
		if CheckPassword(bad, "example-password") {
			t.Fatal("bad hash")
		}
	}
}
