package sqlshape

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The query-shape test. Every call of Query, QueryRow, Exec, Prepare or
// their Context forms on a database, a transaction or a connection passes
// a query whose text is a constant expression: a string literal, a name
// bound by a const declaration, a + of those, a local whose every
// assignment in the function is one of those or a += of one, or a
// parameter for which every call of the function in its package passes
// one. A value goes in the args, never in the text. The test parses every
// non-test .go file under internal/ and cmd/ with go/parser, as the
// file-open ledger's does, and fails with the site and the expression on
// any query that is not constant, except the sites allowlisted below by
// key and reason. A SQL call is told from url.Values.Query and the like
// by its receiver: the expression is, or ends in, an identifier named db,
// tx or conn, which is every database handle in this tree; a prepared
// statement's Exec and Query take values alone, its text having been
// checked at the Prepare.

// queryMethods are the methods whose first string argument is a query.
// The Context forms take the context first.
var queryMethods = map[string]int{
	"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 0,
	"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1, "PrepareContext": 1,
}

// handles are the names a database handle goes by in this tree, as the
// last identifier of the receiver expression.
var handles = map[string]bool{"db": true, "tx": true, "conn": true}

// allowed are the sites whose query is not a constant expression on
// purpose, keyed as the ledger keys a site, each with why. PRAGMA takes
// no placeholder, and the number formatted is the schema version the
// store itself owns, never a value from the wire.
var allowed = map[string]string{
	`internal/relay/migrate.go setVersionTx tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v))`: "PRAGMA takes no placeholder; v is the store's own schema version",
}

// TestEveryQueryIsAConstant is the rule against the tree as it stands.
func TestEveryQueryIsAConstant(t *testing.T) {
	root := moduleRoot(t)
	problems, sites := check(root, allowed)
	if sites < 80 {
		t.Fatalf("found %d query sites; the tree has more than 80, so the parse is not reaching it", sites)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAQueryBuiltFromAValueIsNamed plants a Sprintf query and a query
// from a parameter and asserts each is named with its site and its
// expression.
func TestAQueryBuiltFromAValueIsNamed(t *testing.T) {
	root := plant(t, `package planted

import (
	"database/sql"
	"fmt"
)

const base = "SELECT 1"

type Store struct{ db *sql.DB }

func (s *Store) bad(name string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM t WHERE name = '%s'", name))
	return err
}

func fromParameter(tx *sql.Tx, query string) error {
	_, err := tx.Exec(query)
	return err
}

func caller(tx *sql.Tx, table string) error {
	return fromParameter(tx, "DELETE FROM "+table)
}

func rows(db *sql.DB, query string, args ...any) error {
	_, err := db.Query(query, args...)
	return err
}

func listAll(db *sql.DB) error   { return rows(db, base+" WHERE live = 1") }
func listOne(db *sql.DB, id int64) error {
	q := base
	q += " WHERE id = ?"
	return rows(db, q, id)
}

func good(db *sql.DB, id int64) error {
	q := base
	q += " WHERE id = ?"
	if id > 0 {
		q += " AND live = 1"
	}
	_, err := db.Exec(q, id)
	return err
}
`)
	problems, sites := check(root, nil)
	if sites != 4 {
		t.Fatalf("found %d sites, want 4", sites)
	}
	want := []string{
		`internal/planted/planted.go (*Store).bad s.db.Exec(fmt.Sprintf("DELETE FROM t WHERE name = '%s'", name)): the query is not a constant expression; a value goes in the args, never in the text`,
		`internal/planted/planted.go fromParameter tx.Exec(query): the query is not a constant expression; a value goes in the args, never in the text`,
	}
	if len(problems) != len(want) {
		t.Fatalf("problems %q, want %q", problems, want)
	}
	for i := range want {
		if problems[i] != want[i] {
			t.Errorf("problem %d is %q, want %q", i, problems[i], want[i])
		}
	}
}

// TestAnAllowlistedSiteMustExist: a row for a site that is gone is a
// problem of its own, so the allowlist cannot outlive what it excuses.
func TestAnAllowlistedSiteMustExist(t *testing.T) {
	root := plant(t, `package planted

import "database/sql"

func fine(db *sql.DB) error {
	_, err := db.Exec("PRAGMA user_version")
	return err
}
`)
	problems, _ := check(root, map[string]string{
		`internal/planted/planted.go gone db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v))`: "PRAGMA takes no placeholder",
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "has no call site in the tree; remove it from the allowlist") {
		t.Fatalf("problems %q", problems)
	}
}

// check is the rule against a tree: the problems, sorted, and how many
// query sites were found.
func check(root string, allowed map[string]string) (problems []string, sites int) {
	fset := token.NewFileSet()
	consts := map[string]map[string]bool{} // package -> const names
	type call struct {
		key   string
		query ast.Expr
		fn    *ast.FuncDecl
	}
	var calls []call
	var files []*ast.File
	rels := map[*ast.File]string{}
	for _, dir := range []string{"internal", "cmd"} {
		filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				rel, _ := filepath.Rel(root, path)
				problems = append(problems, fmt.Sprintf("%s does not parse: %v", filepath.ToSlash(rel), err))
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rels[f] = filepath.ToSlash(rel)
			files = append(files, f)
			pkg := f.Name.Name
			if consts[pkg] == nil {
				consts[pkg] = map[string]bool{}
			}
			for _, decl := range f.Decls {
				if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
					for _, spec := range gd.Specs {
						for _, name := range spec.(*ast.ValueSpec).Names {
							consts[pkg][name.Name] = true
						}
					}
				}
			}
			return nil
		})
	}
	byPkg := map[string][]*ast.File{}
	for _, f := range files {
		byPkg[f.Name.Name] = append(byPkg[f.Name.Name], f)
	}
	for _, f := range files {
		pkg := f.Name.Name
		scope := &scope{consts: consts[pkg], files: byPkg[pkg]}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				at, ok := queryMethods[sel.Sel.Name]
				if !ok || !isHandle(sel.X) || at >= len(ce.Args) {
					return true
				}
				key := fmt.Sprintf("%s %s %s(%s)", rels[f], funcName(fd), types.ExprString(sel), types.ExprString(ce.Args[at]))
				calls = append(calls, call{key: key, query: ce.Args[at], fn: fd})
				sites++
				if _, ok := allowed[key]; ok {
					return true
				}
				if !constant(ce.Args[at], fd, scope, map[string]bool{}) {
					problems = append(problems, key+": the query is not a constant expression; a value goes in the args, never in the text")
				}
				return true
			})
		}
	}
	seen := map[string]bool{}
	for _, c := range calls {
		seen[c.key] = true
	}
	for key := range allowed {
		if !seen[key] {
			problems = append(problems, fmt.Sprintf("allowlisted %s has no call site in the tree; remove it from the allowlist", key))
		}
	}
	sort.Strings(problems)
	return problems, sites
}

// isHandle reports whether a receiver expression is, or ends in, a
// database handle by name.
func isHandle(x ast.Expr) bool {
	switch e := x.(type) {
	case *ast.Ident:
		return handles[e.Name]
	case *ast.SelectorExpr:
		return handles[e.Sel.Name]
	case *ast.ParenExpr:
		return isHandle(e.X)
	}
	return false
}

// scope is what constant reads beside the function: the package's const
// names, and its files, for the callers of a function whose parameter is
// the query.
type scope struct {
	consts map[string]bool
	files  []*ast.File
}

// constant reports whether e is a constant expression as the rule defines
// it, within fd: a string literal, a const, a + of those, a parenthesis,
// a local whose every assignment in fd is one of those or a += of one, or
// a parameter of fd for which every call of fd in the package passes one.
// visiting stops a name defined in terms of itself.
func constant(e ast.Expr, fd *ast.FuncDecl, sc *scope, visiting map[string]bool) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.ParenExpr:
		return constant(x.X, fd, sc, visiting)
	case *ast.BinaryExpr:
		return x.Op == token.ADD && constant(x.X, fd, sc, visiting) && constant(x.Y, fd, sc, visiting)
	case *ast.Ident:
		if sc.consts[x.Name] {
			return true
		}
		key := funcName(fd) + "." + x.Name
		if visiting[key] {
			return true
		}
		visiting[key] = true
		defer delete(visiting, key)
		if i, isParam := paramIndex(fd, x.Name); isParam {
			return callersPassConstant(fd, i, sc, visiting)
		}
		return localIsConstant(x.Name, fd, sc, visiting)
	}
	return false
}

// paramIndex is the position of name among fd's parameters, when it is
// one.
func paramIndex(fd *ast.FuncDecl, name string) (int, bool) {
	i := 0
	for _, field := range fd.Type.Params.List {
		for _, id := range field.Names {
			if id.Name == name {
				return i, true
			}
			i++
		}
		if len(field.Names) == 0 {
			i++
		}
	}
	return 0, false
}

// callersPassConstant finds every call of fd by name in the package —
// f(...) for a function, x.f(...) for a method — and requires the
// argument at i to be constant in the caller. A function nobody calls
// has no constant to show.
func callersPassConstant(fd *ast.FuncDecl, i int, sc *scope, visiting map[string]bool) bool {
	called, ok := false, true
	for _, f := range sc.files {
		for _, decl := range f.Decls {
			caller, isFunc := decl.(*ast.FuncDecl)
			if !isFunc {
				continue
			}
			ast.Inspect(caller, func(n ast.Node) bool {
				ce, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				var name string
				switch fn := ce.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if name != fd.Name.Name || (fd.Recv == nil) != isIdentCall(ce.Fun) {
					return true
				}
				called = true
				if i >= len(ce.Args) || !constant(ce.Args[i], caller, sc, visiting) {
					ok = false
				}
				return true
			})
		}
	}
	return called && ok
}

// isIdentCall reports whether a call is f(...) rather than x.f(...).
func isIdentCall(fn ast.Expr) bool {
	_, ok := fn.(*ast.Ident)
	return ok
}

// localIsConstant finds every assignment to name in fd and requires each
// to be constant: name := c, name = c, var name = c, name += c. A name
// with no assignment at all is neither a local nor a parameter, and is
// not constant.
func localIsConstant(name string, fd *ast.FuncDecl, sc *scope, visiting map[string]bool) bool {
	assigned, ok := false, true
	ast.Inspect(fd, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				id, isIdent := lhs.(*ast.Ident)
				if !isIdent || id.Name != name {
					continue
				}
				assigned = true
				switch s.Tok {
				case token.DEFINE, token.ASSIGN:
					if i >= len(s.Rhs) || !constant(s.Rhs[i], fd, sc, visiting) {
						ok = false
					}
				case token.ADD_ASSIGN:
					if !constant(s.Rhs[0], fd, sc, visiting) {
						ok = false
					}
				default:
					ok = false
				}
			}
		case *ast.ValueSpec:
			for i, id := range s.Names {
				if id.Name != name {
					continue
				}
				assigned = true
				if i >= len(s.Values) || !constant(s.Values[i], fd, sc, visiting) {
					ok = false
				}
			}
		}
		return true
	})
	return assigned && ok
}

// funcName is a function as the ledger names it: receiver-qualified for a
// method.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + types.ExprString(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}

// moduleRoot is the directory holding go.mod above this test.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

// plant writes one source file under internal/planted in a directory of
// its own, for the self-tests.
func plant(t *testing.T, src string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "planted")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
