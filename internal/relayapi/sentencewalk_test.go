package relayapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// No client reads a refusal by its sentence (ruling 68): a refusal it acts
// on is known by its code and its status, and its sentence is only shown.
// The walk reads the shipped source of every package that acts on a relay's
// answers, internal/auu, internal/client and everything under cmd, and
// refuses three things:
//
//   - a comparison, == or != or a switch case, one of whose operands is a
//     .Message selector or a relayapi Msg constant, other than with the
//     empty string, which asks whether there is a sentence to show;
//   - a strings function that matches (Contains, HasPrefix, HasSuffix,
//     Index, LastIndex, EqualFold, Cut and their kin) given either;
//   - a .Message selector passed to any function but identity.PrintableText
//     and the fmt and errors constructors, so that nothing parses one.
//
// It keys on .Message and Msg constants, so an error's own text matched
// against what the standard library or the platform says, or the agent's
// sentences, which are this machine's and not a relay's, are not its
// business.
func TestNoRefusalIsReadByItsSentence(t *testing.T) {
	root := filepath.Join("..", "..")
	var dirs []string
	for _, top := range []string{"internal/auu", "internal/client", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				dirs = append(dirs, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	matchers := map[string]bool{
		"Contains": true, "ContainsAny": true, "ContainsRune": true, "HasPrefix": true, "HasSuffix": true,
		"Index": true, "IndexAny": true, "LastIndex": true, "LastIndexAny": true, "EqualFold": true,
		"Cut": true, "CutPrefix": true, "CutSuffix": true, "TrimPrefix": true, "TrimSuffix": true,
		"Split": true, "SplitN": true, "Fields": true, "Count": true,
	}
	// Where a .Message may go: shown, never read.
	shown := map[string]bool{
		"identity.PrintableText": true, "identity.PrintableLines": true,
		"fmt.Errorf": true, "fmt.Sprintf": true, "fmt.Fprintf": true, "fmt.Printf": true,
		"fmt.Sprint": true, "fmt.Sprintln": true, "fmt.Fprintln": true, "fmt.Println": true,
		"errors.New": true,
	}
	// sentence reports whether an expression is, or holds, a .Message
	// selector or a relayapi Msg constant.
	sentence := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Message" {
				found = true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "relayapi" && strings.HasPrefix(sel.Sel.Name, "Msg") {
				found = true
			}
			return true
		})
		return found
	}
	message := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Message" {
				found = true
			}
			return true
		})
		return found
	}
	callee := func(call *ast.CallExpr) string {
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			if x, ok := f.X.(*ast.Ident); ok {
				return x.Name + "." + f.Sel.Name
			}
			return "." + f.Sel.Name
		case *ast.Ident:
			return f.Name
		}
		return ""
	}

	files := 0
	for _, dir := range dirs {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, pkg := range pkgs {
			for _, file := range pkg.Files {
				files++
				ast.Inspect(file, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.BinaryExpr:
						// Whether there is a sentence to show at all is not
						// a reading of it.
						empty := func(e ast.Expr) bool {
							lit, ok := e.(*ast.BasicLit)
							return ok && lit.Value == `""`
						}
						if (n.Op == token.EQL || n.Op == token.NEQ) && (sentence(n.X) || sentence(n.Y)) && !empty(n.X) && !empty(n.Y) {
							t.Errorf("%s: a refusal compared by its sentence; compare its code", fset.Position(n.Pos()))
						}
					case *ast.SwitchStmt:
						if n.Tag != nil && sentence(n.Tag) {
							t.Errorf("%s: a switch on a refusal's sentence; switch on its code", fset.Position(n.Pos()))
						}
						for _, stmt := range n.Body.List {
							for _, e := range stmt.(*ast.CaseClause).List {
								if sentence(e) {
									t.Errorf("%s: a case on a refusal's sentence; use its code", fset.Position(e.Pos()))
								}
							}
						}
					case *ast.CallExpr:
						name := callee(n)
						if pkg, fn, ok := strings.Cut(name, "."); ok && pkg == "strings" && matchers[fn] {
							for _, arg := range n.Args {
								if sentence(arg) {
									t.Errorf("%s: %s reads a refusal's sentence; read its code", fset.Position(n.Pos()), name)
								}
							}
							return true
						}
						if shown[name] {
							return true
						}
						for _, arg := range n.Args {
							if message(arg) {
								t.Errorf("%s: a .Message handed to %s, which may read it; only show it", fset.Position(arg.Pos()), name)
							}
						}
					}
					return true
				})
			}
		}
	}
	if files < 50 {
		t.Fatalf("the walk read %d files; it is not reading the tree", files)
	}
}
