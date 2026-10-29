package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"v":1}`)
	sig := Sign(key, "node", 18446744073709551615, 1700000000, body)
	expected := fmt.Sprintf("wanglou-v1\nnode\n18446744073709551615\n1700000000\n%x", sha256.Sum256(body))
	if Canonical("node", 18446744073709551615, 1700000000, body) != expected {
		t.Fatal("canonical mismatch")
	}
	for _, tc := range []struct {
		name string
		node string
		seq  uint64
		ts   int64
		body []byte
		sig  string
		want bool
	}{{"valid", "node", 18446744073709551615, 1700000000, body, sig, true}, {"tampered", "node", 18446744073709551615, 1700000000, []byte(`{}`), sig, false}, {"wrong key", "node", 18446744073709551615, 1700000000, body, Sign(other, "node", 18446744073709551615, 1700000000, body), false}, {"node", "other", 18446744073709551615, 1700000000, body, sig, false}, {"seq", "node", 1, 1700000000, body, sig, false}, {"time", "node", 18446744073709551615, 1700000001, body, sig, false}, {"bad base64", "node", 1, 1, body, "!", false}} {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(pub, tc.node, tc.seq, tc.ts, tc.body, tc.sig) != tc.want {
				t.Fatal("unexpected verification")
			}
		})
	}
	if Verify(nil, "node", 1, 1, body, sig) {
		t.Fatal("invalid key")
	}
	line := PublicKeyLine(pub, "node")
	parsed, e := ParsePublicKey(line)
	if e != nil || !pub.Equal(parsed) {
		t.Fatal(e)
	}
	if !strings.HasPrefix(Fingerprint(pub), "SHA256:") || strings.Contains(Fingerprint(pub), "=") {
		t.Fatal("fingerprint format")
	}
	h := sha256.Sum256(pub)
	if Fingerprint(pub) != "SHA256:"+base64.RawStdEncoding.EncodeToString(h[:]) {
		t.Fatal("fingerprint")
	}
	for _, bad := range []string{"", "ssh-ed25519 x node", "wanglou-ed25519 eA== node", line + " extra"} {
		if _, e = ParsePublicKey(bad); e == nil {
			t.Fatal("accepted bad key")
		}
	}
}

func TestOutageValidation(t *testing.T) {
	for _, tc := range []struct {
		outage *Outage
		valid  bool
	}{{nil, true}, {&Outage{Since: 1, Failures: 1}, true}, {&Outage{Since: 0, Failures: 1}, false}, {&Outage{Since: -1, Failures: 1}, false}, {&Outage{Since: 1, Failures: 0}, false}, {&Outage{Since: 1, Failures: -1}, false}} {
		r := Report{Version: 1, Bin: "sha256:" + strings.Repeat("a", 64), OS: "linux", Arch: "amd64", Outage: tc.outage}
		if err := r.Validate(); (err == nil) != tc.valid {
			t.Fatal(tc, err)
		}
	}
}
