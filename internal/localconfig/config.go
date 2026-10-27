// Package localconfig reads the deliberately small flat TOML configuration
// used by both binaries: quoted strings, numbers, booleans and a string array
// for trusted_proxies.
// Unsupported syntax and unknown keys are rejected, never silently ignored.
package localconfig

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Read(path string, apply func(string, string) error) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	seen := map[string]bool{}
	line := 0
	for s.Scan() {
		line++
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, val, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if !ok || key == "" || seen[key] {
			return fmt.Errorf("%s:%d: invalid or duplicate key", path, line)
		}
		seen[key] = true
		// Strip comments outside quoted strings.
		quote := byte(0)
		escaped := false
		for i := 0; i < len(val); i++ {
			c := val[i]
			if quote != 0 {
				if c == quote && !escaped {
					quote = 0
				}
				if quote == '"' && c == '\\' && !escaped {
					escaped = true
				} else {
					escaped = false
				}
			} else if c == '"' || c == '\'' {
				quote = c
			} else if c == '#' {
				val = strings.TrimSpace(val[:i])
				break
			}
		}
		if quote != 0 {
			return fmt.Errorf("%s:%d: unterminated string", path, line)
		}
		if e := apply(key, val); e != nil {
			return fmt.Errorf("%s:%d: %w", path, line, e)
		}
	}
	return s.Err()
}
func String(v string) (string, error) {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1], nil
	}
	if len(v) < 2 || v[0] != '"' {
		return "", fmt.Errorf("expected quoted string")
	}
	return strconv.Unquote(v)
}

// Strings supports the one flat string-array setting (trusted proxy CIDRs).
// Values cannot contain commas; no other array syntax is accepted.
func Strings(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return nil, fmt.Errorf("expected quoted string array")
	}
	inner := strings.TrimSpace(value[1 : len(value)-1])
	if inner == "" {
		return []string{}, nil
	}
	parts := strings.Split(inner, ",")
	out := []string{}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" && i == len(parts)-1 {
			continue
		}
		s, err := String(p)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
