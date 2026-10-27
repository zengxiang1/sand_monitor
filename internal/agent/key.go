package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateKey never follows an existing key path, including in force mode.
func GenerateKey(path string, force bool) (ed25519.PrivateKey, error) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if force {
		if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
			return nil, e
		}
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if e != nil {
		return nil, e
	}
	if e = f.Chmod(0400); e != nil {
		f.Close()
		os.Remove(path)
		return nil, e
	}
	if _, e = f.Write(key); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		_ = os.Remove(path)
		return nil, e
	}
	return key, nil
}
func LoadKey(path string) (ed25519.PrivateKey, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
		return nil, fmt.Errorf("private key must be a regular file with mode 0400")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length")
	}
	key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	if !key.Equal(ed25519.PrivateKey(b)) {
		return nil, fmt.Errorf("invalid private key")
	}
	return key, nil
}
