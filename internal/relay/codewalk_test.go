package relay

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every code relayapi declares is one this relay writes (ruling 68): a code
// that no route sends is a branch in a client that nothing reaches. The walk
// reads relayapi's source for its Code constants and its Refusal values, and
// this package's shipped source for the ones it names, directly or through a
// Refusal that carries the code.
func TestEveryCodeIsWrittenByTheRelay(t *testing.T) {
	apiFset := token.NewFileSet()
	api, err := parser.ParseFile(apiFset, filepath.Join("..", "relayapi", "relayapi.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}         // Code constant names
	refusalCode := map[string]string{} // Refusal value name -> its Code constant
	ast.Inspect(api, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			switch {
			case strings.HasPrefix(name.Name, "Code") && i < len(spec.Values):
				if lit, ok := spec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if _, err := strconv.Unquote(lit.Value); err == nil {
						codes[name.Name] = true
					}
				}
			case strings.HasPrefix(name.Name, "Refusal") && i < len(spec.Values):
				if lit, ok := spec.Values[i].(*ast.CompositeLit); ok && len(lit.Elts) > 0 {
					if id, ok := lit.Elts[0].(*ast.Ident); ok {
						refusalCode[name.Name] = id.Name
					}
				}
			}
		}
		return true
	})
	if len(codes) < 19 || len(refusalCode) < 11 {
		t.Fatalf("read %d codes and %d refusals from relayapi; it is not reading the file", len(codes), len(refusalCode))
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	written := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "relayapi" {
					return true
				}
				if codes[sel.Sel.Name] {
					written[sel.Sel.Name] = true
				}
				if code, ok := refusalCode[sel.Sel.Name]; ok {
					written[code] = true
				}
				return true
			})
		}
	}
	var never []string
	for code := range codes {
		if !written[code] {
			never = append(never, code)
		}
	}
	sort.Strings(never)
	for _, code := range never {
		t.Errorf("relayapi.%s is written by no route of this relay", code)
	}
}
