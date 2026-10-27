// check-agent-surface consumes go list -deps -json output. net/http itself
// necessarily contains server definitions; inspect use sites in all nonstandard
// dependencies, and forbid os/exec anywhere in the dependency closure.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

type pkg struct {
	ImportPath, Dir   string
	Standard          bool
	GoFiles, CgoFiles []string
}

func forbidden(path, name string) bool {
	switch path {
	case "net":
		return name == "Listen" || name == "ListenPacket" || name == "ListenTCP" || name == "ListenUDP" || name == "ListenUnix" || name == "ListenUnixgram" || name == "ListenConfig"
	case "net/http":
		// Allow client API use; everything else must be reviewed explicitly.
		switch name {
		case "Client", "Request", "Response", "RoundTripper", "Transport", "DefaultTransport", "DefaultClient", "Header", "Cookie", "CookieJar", "NewRequest", "NewRequestWithContext", "NoBody", "ErrUseLastResponse", "MethodPost", "MethodGet", "MethodHead", "MethodPut", "MethodDelete", "MethodPatch", "MethodOptions", "StatusNoContent", "ProxyFromEnvironment", "ProxyURL", "Get", "Head", "Post", "PostForm":
			return false
		default:
			return true
		}
	case "syscall":
		return name == "Exec" || name == "ForkExec" || name == "StartProcess"
	case "os":
		return name == "StartProcess"
	}
	return false
}
func inspect(path string) error {
	f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if e != nil {
		return e
	}
	aliases := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p == "os/exec" {
			return fmt.Errorf("%s imports os/exec", path)
		}
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." && (p == "net" || p == "net/http" || p == "syscall" || p == "os") {
			return fmt.Errorf("%s: dot import obscures surface", path)
		}
		aliases[name] = p
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if ok && forbidden(aliases[id.Name], sel.Sel.Name) {
			e = fmt.Errorf("%s: forbidden %s.%s", path, aliases[id.Name], sel.Sel.Name)
		}
		return true
	})
	return e
}
func check(r io.Reader) error {
	dec := json.NewDecoder(r)
	count := 0
	for {
		var p pkg
		e := dec.Decode(&p)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		count++
		if p.ImportPath == "os/exec" {
			return fmt.Errorf("dependency closure contains os/exec")
		}
		if p.Standard {
			continue
		}
		for _, file := range append(p.GoFiles, p.CgoFiles...) {
			if e = inspect(filepath.Join(p.Dir, file)); e != nil {
				return e
			}
		}
	}
	if count == 0 {
		return fmt.Errorf("empty dependency closure")
	}
	return nil
}
func main() {
	if e := check(os.Stdin); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("agent surface: PASS (dependency closure and AST use sites)")
}
