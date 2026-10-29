// Package proto defines the version-one wire format and its authentication.
package proto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxBody    = 64 * 1024
	NodeHeader = "X-Wanglou-Node"
	SeqHeader  = "X-Wanglou-Seq"
	TsHeader   = "X-Wanglou-Ts"
	SigHeader  = "X-Wanglou-Sig"
)

type Login struct {
	User string `json:"u"`
	From string `json:"from"`
	Time int64  `json:"t"`
}

type Outage struct {
	Since    int64 `json:"since"`
	Failures int   `json:"failures"`
}

type Report struct {
	Outage   *Outage    `json:"outage,omitempty"`
	Version  int        `json:"v"`
	CPU      float64    `json:"cpu"` // percent, sampled delta
	Load     [3]float64 `json:"load"`
	Mem      [2]float64 `json:"mem"`       // used, total MiB
	Swap     [2]float64 `json:"swap"`      // used, total MiB
	Disk     [2]float64 `json:"disk"`      // used, total GiB
	Net      [2]float64 `json:"net"`       // TX, RX bytes/second
	NetTotal [2]uint64  `json:"net_total"` // TX, RX since boot
	Conn     [2]uint64  `json:"conn"`      // TCP, UDP
	Up       float64    `json:"up"`        // seconds
	Login    []Login    `json:"login"`
	Bin      string     `json:"bin"`
	OS       string     `json:"os"`
	Arch     string     `json:"arch"`
}

var nodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func ValidNode(s string) bool { return nodePattern.MatchString(s) }
func Canonical(node string, seq uint64, ts int64, body []byte) string {
	h := sha256.Sum256(body)
	return "wanglou-v1\n" + node + "\n" + strconv.FormatUint(seq, 10) + "\n" + strconv.FormatInt(ts, 10) + "\n" + hex.EncodeToString(h[:])
}
func Sign(key ed25519.PrivateKey, node string, seq uint64, ts int64, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(Canonical(node, seq, ts, body))))
}
func Verify(key ed25519.PublicKey, node string, seq uint64, ts int64, body []byte, sig string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(sig)
	return err == nil && len(key) == ed25519.PublicKeySize && len(b) == ed25519.SignatureSize && ed25519.Verify(key, []byte(Canonical(node, seq, ts, body)), b)
}
func Fingerprint(key ed25519.PublicKey) string {
	h := sha256.Sum256(key)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
func PublicKeyLine(key ed25519.PublicKey, node string) string {
	return "wanglou-ed25519 " + base64.StdEncoding.EncodeToString(key) + " " + node
}
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	f := strings.Fields(s)
	if len(f) != 3 || f[0] != "wanglou-ed25519" || !ValidNode(f[2]) {
		return nil, fmt.Errorf("invalid public key line")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(f[1])
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key")
	}
	return ed25519.PublicKey(b), nil
}
func (r Report) Validate() error {
	if r.Outage != nil && (r.Outage.Since <= 0 || r.Outage.Failures < 1) {
		return fmt.Errorf("invalid outage")
	}
	if r.Version != 1 || !strings.HasPrefix(r.Bin, "sha256:") || len(r.Bin) != 71 || r.OS == "" || r.Arch == "" {
		return fmt.Errorf("invalid report metadata")
	}
	if _, err := hex.DecodeString(r.Bin[7:]); err != nil {
		return err
	}
	values := []float64{r.CPU, r.Up}
	values = append(values, r.Load[:]...)
	for _, p := range [][2]float64{r.Mem, r.Swap, r.Disk, r.Net} {
		values = append(values, p[:]...)
	}
	for _, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return fmt.Errorf("invalid measurement")
		}
	}
	if r.CPU > 100 {
		return fmt.Errorf("invalid cpu")
	}
	for _, p := range [][2]float64{r.Mem, r.Swap, r.Disk} {
		if p[0] > p[1] {
			return fmt.Errorf("used exceeds total")
		}
	}
	for _, l := range r.Login {
		if len(l.User) == 0 || len(l.User) > 256 || net.ParseIP(l.From) == nil || l.Time < 0 {
			return fmt.Errorf("invalid login")
		}
	}
	return nil
}
