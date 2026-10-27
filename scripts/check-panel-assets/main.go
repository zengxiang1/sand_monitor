package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	external := regexp.MustCompile(`https?://[^\s"'<>]+`)
	inline := regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script\s*>`)
	attributes := regexp.MustCompile(`(?i)\s(?:on[a-z]+|style)\s*=`)
	err := filepath.WalkDir("internal/server/panel/web", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		source := string(data)
		for _, link := range external.FindAllString(source, -1) {
			if link != "http://www.w3.org/2000/svg" {
				return fmt.Errorf("%s: external URL", path)
			}
		}
		if strings.HasSuffix(path, ".html") {
			if attributes.MatchString(source) {
				return fmt.Errorf("%s: inline style or event", path)
			}
			for _, match := range inline.FindAllStringSubmatch(source, -1) {
				if strings.TrimSpace(match[1]) != "" {
					return fmt.Errorf("%s: inline script", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("panel assets: PASS")
}
