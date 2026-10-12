package client

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryBodyReadIsCapped is the source scan for the rule that a read of
// a network body in this package is held: it goes through readCapped, or
// it reads an io.LimitReader. A call that reads a body whole with no hold
// (io.ReadAll on the body itself, io.Copy to io.Discard from it, a raw
// Read on it) is a hole in the hold and fails this test by name, so a
// drain or a retry path written later cannot bypass what the answer's
// hold promises. At 30f93dd the one such site is Blob's retry drain
// (G16); the test fails there until it is held.
//
// The scan is syntactic: the first argument of io.ReadAll and the second
// of io.Copy must be a call to io.LimitReader, or the call must sit in
// readCapped, whose declared-length branch is the one place that reads a
// body to a length the relay named, held to the hold before a byte.
func TestEveryBodyReadIsCapped(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	sites := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s does not parse: %v", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				pkg, fn := selector(call.Fun)
				var read ast.Expr
				switch {
				case pkg == "io" && fn == "ReadAll" && len(call.Args) == 1:
					read = call.Args[0]
				case pkg == "io" && fn == "Copy" && len(call.Args) == 2:
					if p, f := selector(call.Args[0]); p == "io" && f == "Discard" {
						read = call.Args[1]
					}
				case pkg == "io" && fn == "ReadFull" && len(call.Args) == 2:
					read = call.Args[0]
				default:
					return true
				}
				if read == nil {
					return true
				}
				sites++
				if fd.Name.Name == "readCapped" {
					return true
				}
				if p, f := selector(callFun(read)); p == "io" && f == "LimitReader" {
					return true
				}
				pos := fset.Position(call.Pos())
				problems = append(problems, fmt.Sprintf("%s:%d %s reads a body with no hold: read an io.LimitReader at the route's hold, or go through readCapped",
					filepath.Base(pos.Filename), pos.Line, fd.Name.Name))
				return true
			})
		}
	}
	if sites < 5 {
		t.Fatalf("found %d body reads; the sweep that wrote this test found 6 at 30f93dd, so the parse is not reaching the package", sites)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// selector returns the package and name of a selector expression such as
// io.ReadAll, or two empty strings.
func selector(e ast.Expr) (string, string) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", ""
	}
	return id.Name, sel.Sel.Name
}

// callFun is the function expression of a call, or nil for anything else.
func callFun(e ast.Expr) ast.Expr {
	if call, ok := e.(*ast.CallExpr); ok {
		return call.Fun
	}
	return nil
}
