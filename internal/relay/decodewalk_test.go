package relay

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// Every request body is read through decodeRequest (D37, ruling 66): the
// strict decode and the sections rule in one place, so a route added later
// cannot read its body leniently or forget a critical section. The walk
// reads this package's own source and fails on any decode, json.Unmarshal,
// wire.Decode or a Decode method, outside the functions below, each of which
// decodes something that is not a request body and says what.
func TestEveryRequestBodyIsReadThroughDecodeRequest(t *testing.T) {
	allowed := map[string]string{
		"decodeRequest":     "the one door for every request body",
		"hasOldKey":         "the presence of one key, for the old shapes' sentences (R2)",
		"parseCarried":      "the outer envelope inside a forward request, frozen at four fields (D38)",
		"handleGetChannels": "the relay's own stored directory, verified when it was pushed, read for its names",
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, _ := decl.(*ast.FuncDecl)
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					what := ""
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "json" && (sel.Sel.Name == "Unmarshal" || sel.Sel.Name == "NewDecoder") {
						what = "json." + sel.Sel.Name
					}
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "wire" && sel.Sel.Name == "Decode" {
						what = "wire.Decode"
					}
					if sel.Sel.Name == "Decode" && what == "" {
						what = "a Decode method"
					}
					if what == "" {
						return true
					}
					if fn == nil || allowed[fn.Name.Name] == "" {
						t.Errorf("%s: %s outside decodeRequest; a request body is read through decodeRequest, and anything else decoded here is named in this test with its reason",
							fset.Position(call.Pos()), what)
						return true
					}
					seen[fn.Name.Name] = true
					return true
				})
			}
		}
	}
	var stale []string
	for name := range allowed {
		if !seen[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		t.Errorf("%s decodes nothing now; take it out of the list", name)
	}
}
