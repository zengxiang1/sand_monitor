package localconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestScalarConfig(t *testing.T) {
	for _, tc := range []struct {
		text string
		ok   bool
	}{{"# comment\nname = \"a#b\" # comment\nother = 'literal'\n", true}, {"name = \"a\"\nname = \"b\"", false}, {"[section]", false}, {"name = \"unterminated", false}, {"unknown = 1", false}} {
		p := filepath.Join(t.TempDir(), "config")
		if e := os.WriteFile(p, []byte(tc.text), 0600); e != nil {
			t.Fatal(e)
		}
		e := Read(p, func(k, v string) error {
			if k != "name" && k != "other" {
				return fmt.Errorf("unknown key")
			}
			_, e := String(v)
			return e
		})
		if (e == nil) != tc.ok {
			t.Fatal(tc.text, e)
		}
	}
}

func TestStringArray(t *testing.T) {
	for _, tc := range []struct {
		text  string
		count int
		ok    bool
	}{
		{`["172.30.0.0/24", '2001:db8::/32']`, 2, true},
		{`[]`, 0, true}, {`["172.30.0.0/24",]`, 1, true},
		{`"172.30.0.0/24"`, 0, false}, {`[172.30.0.0/24]`, 0, false},
		{`[,"172.30.0.0/24"]`, 0, false}, {`["unterminated]`, 0, false},
	} {
		got, err := Strings(tc.text)
		if (err == nil) != tc.ok || (tc.ok && len(got) != tc.count) {
			t.Fatal(tc.text, got, err)
		}
	}
}
