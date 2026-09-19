package fileopens

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
	"strconv"
	"strings"
	"testing"
)

// The ledger test. Every call site in the non-test tree of a function
// that takes a path — the list in pathArg — has one row in ledger.txt,
// keyed by the file, the enclosing function, the callee and the source
// text of the path argument, and the row says where the path came from:
// local, operator, derived, or network with the rule and the point that
// checks it. The test parses every .go file under internal/ and cmd/,
// whatever its build tag, so a site in a _windows.go file is covered as
// one in a _unix.go file is, and it fails with its own sentence on a site
// with no row, a row with no site, a key written twice, rows out of
// order, and a network row whose rule is not a function declared in the
// tree or one of the two standard-library functions a type-level rule may
// name. A new call that opens something by a path fails this test until
// its row is written, which is the point: the row is where somebody has
// to say what the path is.

// pathArg is which argument of each callee is the path, by the callee's
// package and name. A callee with two paths, such as os.Rename, has a
// row for each.
var pathArg = map[string][]int{
	"os.Open": {0}, "os.OpenFile": {0}, "os.Create": {0}, "os.CreateTemp": {0},
	"os.MkdirTemp": {0}, "os.ReadFile": {0}, "os.WriteFile": {0}, "os.Mkdir": {0},
	"os.MkdirAll": {0}, "os.Remove": {0}, "os.RemoveAll": {0}, "os.Rename": {0, 1},
	"os.Stat": {0}, "os.Lstat": {0}, "os.ReadDir": {0}, "os.Chmod": {0},
	"os.Chown": {0}, "os.Symlink": {0, 1}, "os.Link": {0, 1}, "os.Truncate": {0},
	"os.Chdir": {0}, "os.DirFS": {0},
	"filepath.Walk": {0}, "filepath.WalkDir": {0},
	"sql.Open":   {1},
	"net.Listen": {1}, "net.Dial": {1}, "net.DialTimeout": {1},
	"exec.Command": {0}, "exec.CommandContext": {1},
}

// importPaths is the import path each callee package is known by, so an
// import under another name is still found.
var importPaths = map[string]string{
	"os": "os", "path/filepath": "filepath", "database/sql": "sql", "net": "net", "os/exec": "exec",
}

// site is one call of a path-taking function.
type site struct {
	key string
	pos token.Position
}

// row is one ledger line.
type row struct {
	key, provenance, test string
	line                  int
}

// shownFloor is how many rows named a test when the ledger was written;
// a count under it means rows lost their tests, not that the tree shrank.
const shownFloor = 153

// absolutePath is the operator form for a whole path used as given, alone
// or followed by a comma and a note, and environmentsPath the ending of
// the derived form for the environment's and the OS's own paths; neither
// names a test, since nothing is joined.
const (
	absolutePath     = "operator's absolute path"
	environmentsPath = "the environment's own path"
)

// usedAsGiven reports whether a provenance is one of the two forms that
// name no test: the operator's whole path, or a derived row that is the
// environment's own; a network row cannot borrow the phrase.
func usedAsGiven(prov string) bool {
	return prov == absolutePath || strings.HasPrefix(prov, absolutePath+", ") ||
		(strings.HasPrefix(prov, "derived: ") && strings.HasSuffix(prov, ", "+environmentsPath))
}

// TestEveryFileOpenHasItsProvenanceInTheLedger is the ledger against the
// tree as it stands.
func TestEveryFileOpenHasItsProvenanceInTheLedger(t *testing.T) {
	root := moduleRoot(t)
	ledger, err := os.ReadFile(filepath.Join(root, "internal", "fileopens", "ledger.txt"))
	if err != nil {
		t.Fatal(err)
	}
	problems, sites := check(root, string(ledger))
	if len(sites) < 200 {
		t.Fatalf("found %d call sites; the sweep that wrote the ledger found more than 250, so the parse is not reaching the tree", len(sites))
	}
	for _, p := range problems {
		t.Error(p)
	}
	rows, _ := parseLedger(string(ledger))
	shown := 0
	for _, r := range rows {
		if r.test != "" {
			shown++
		}
	}
	if shown < shownFloor {
		t.Errorf("%d rows name a test; the ledger was written with %d, so rows have lost theirs", shown, shownFloor)
	}
}

// TestALedgerFindsACallWithNoRow plants one call in a module of its own
// and asserts the sentence that names the row to add.
func TestALedgerFindsACallWithNoRow(t *testing.T) {
	root := plantModule(t, `package planted

import "os"

type Box struct{}

func (b *Box) Take(name string) error {
	_, err := os.ReadFile(name)
	return err
}
`)
	problems, _ := check(root, "")
	want := "internal/planted/planted.go (*Box).Take os.ReadFile(name) has no row in ledger.txt; add one saying where the path comes from"
	if len(problems) != 1 || problems[0] != want {
		t.Fatalf("problems %q, want the one sentence %q", problems, want)
	}
}

// TestALedgerRefusesARuleThatIsNotInTheTree plants a network row whose
// rule is not a function anywhere, which names no test either, and a row
// for a site that is gone.
func TestALedgerRefusesARuleThatIsNotInTheTree(t *testing.T) {
	root := plantModule(t, `package planted

import "os"

func take(name string) error {
	_, err := os.ReadFile(name)
	return err
}
`)
	ledger := "internal/planted/planted.go take os.ReadFile(name) = network: a name, planted.ValidName at take\n" +
		"internal/planted/planted.go take os.Stat(name) = local\n"
	problems, _ := check(root, ledger)
	sort.Strings(problems)
	want := []string{
		"ledger.txt:1: internal/planted/planted.go take os.ReadFile(name) is network and names no test; a row that is not local names the TestLimit that drives the traversal set through its rule, or says \"operator's absolute path\", or for the environment's own path says so",
		"ledger.txt:1: the rule planted.ValidName is not a function declared in the tree; a network row names the function that checks the path",
		"ledger.txt:2: internal/planted/planted.go take os.Stat(name) has no call site in the tree; remove the row",
	}
	if len(problems) != len(want) {
		t.Fatalf("problems %q, want %q", problems, want)
	}
	for i := range want {
		if problems[i] != want[i] {
			t.Errorf("problem %d is %q, want %q", i, problems[i], want[i])
		}
	}
	// A key twice, and rows out of order.
	ledger = "internal/planted/planted.go take os.ReadFile(name) = local\n" +
		"internal/planted/planted.go take os.ReadFile(name) = " + absolutePath + "\n"
	problems, _ = check(root, ledger)
	if len(problems) != 1 || !strings.Contains(problems[0], "written twice") {
		t.Errorf("a key twice: %q", problems)
	}
	ledger = "z.go f os.Stat(x) = local\ninternal/planted/planted.go take os.ReadFile(name) = local\n"
	problems, _ = check(root, ledger)
	found := false
	for _, p := range problems {
		found = found || strings.Contains(p, "rows are sorted")
	}
	if !found {
		t.Errorf("rows out of order: %q", problems)
	}
}

// TestALedgerHoldsEveryRowThatIsNotLocalToATest plants one call and
// writes its row every way the shown-by column can go wrong: operator
// alone, a derived row with no test, a local row with a test, a whole
// path with a test, a test that is not a TestLimit, one no file declares,
// and one two packages declare; then the ways it is right: local, the
// operator's whole path with and without a note, the environment's own,
// and a derived row naming the one test the planted tree declares.
func TestALedgerHoldsEveryRowThatIsNotLocalToATest(t *testing.T) {
	root := plantModule(t, `package planted

import "os"

func take(name string) error {
	_, err := os.ReadFile(name)
	return err
}
`)
	testFile := "package planted\n\nimport \"testing\"\n\nfunc TestLimitPlanted(t *testing.T) {}\nfunc TestPlanted(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(root, "internal", "planted", "planted_test.go"), []byte(testFile), 0o600); err != nil {
		t.Fatal(err)
	}
	// A second package declaring the same test name.
	other := filepath.Join(root, "internal", "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "other_test.go"), []byte("package other\n\nimport \"testing\"\n\nfunc TestLimitTwice(t *testing.T) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "planted", "twice_test.go"), []byte("package planted\n\nimport \"testing\"\n\nfunc TestLimitTwice(t *testing.T) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := "internal/planted/planted.go take os.ReadFile(name)"
	wrong := []struct{ prov, want string }{
		{"operator", "says operator alone"},
		{"derived: an entry of its own directory", "names no test"},
		{"operator: a name, planted.take at take", "names no test"},
		{"local shown by TestLimitPlanted", "is local and names a test"},
		{absolutePath + " shown by TestLimitPlanted", "is used as given and names a test"},
		{absolutePath + ", --out as given shown by TestLimitPlanted", "is used as given and names a test"},
		{"derived: this program's own path from os.Executable, " + environmentsPath + " shown by TestLimitPlanted", "is used as given and names a test"},
		{"derived: an entry shown by TestPlanted", "does not start with TestLimit"},
		{"derived: an entry shown by TestLimitNowhere", "which no _test.go file in the tree declares"},
		{"derived: an entry shown by TestLimitTwice", "which 2 packages declare"},
		{"derived: an entry shown by TestLimitPlanted and TestLimitTwice", "is not one test"},
		{"network: a name, take at take, " + environmentsPath, "names no test"},
		{"operator: a name, take at take, " + environmentsPath, "names no test"},
	}
	for _, tc := range wrong {
		problems, _ := check(root, key+" = "+tc.prov+"\n")
		found := false
		for _, p := range problems {
			found = found || strings.Contains(p, tc.want)
		}
		if !found {
			t.Errorf("%q: problems %q, want one saying %q", tc.prov, problems, tc.want)
		}
	}
	right := []string{
		"local",
		absolutePath,
		absolutePath + ", --out as the record holds it",
		"derived: this program's own path from os.Executable, " + environmentsPath,
		"derived: an entry of its own directory shown by TestLimitPlanted",
		"operator: a name, planted.take at take shown by TestLimitPlanted",
		"network: a name, take at take shown by TestLimitPlanted",
	}
	for _, prov := range right {
		if problems, _ := check(root, key+" = "+prov+"\n"); len(problems) != 0 {
			t.Errorf("%q: problems %q, want none", prov, problems)
		}
	}
}

// check is the ledger against a tree: the problems, each a sentence, and
// the sites found.
func check(root, ledger string) (problems []string, sites []site) {
	fset := token.NewFileSet()
	funcs := map[string]map[string]bool{} // package name -> declared funcs
	byKey := map[string][]site{}
	for _, dir := range []string{"internal", "cmd"} {
		filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s does not parse: %v", rel, err))
				return nil
			}
			pkg := f.Name.Name
			if funcs[pkg] == nil {
				funcs[pkg] = map[string]bool{}
			}
			for _, decl := range f.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					funcs[pkg][fd.Name.Name] = true
				}
			}
			for _, s := range sitesIn(fset, f, rel) {
				byKey[s.key] = append(byKey[s.key], s)
				sites = append(sites, s)
			}
			return nil
		})
	}

	tests := limitTests(root)
	rows, rowProblems := parseLedger(ledger)
	problems = append(problems, rowProblems...)
	have := map[string]bool{}
	for _, r := range rows {
		have[r.key] = true
		if _, ok := byKey[r.key]; !ok {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s has no call site in the tree; remove the row", r.line, r.key))
		}
		if strings.HasPrefix(r.provenance, "network:") {
			rule := ruleOf(r.provenance)
			if !declared(funcs, rule) {
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: the rule %s is not a function declared in the tree; a network row names the function that checks the path", r.line, rule))
			}
		}
		// Every row that is not local names the limit test that drives
		// the traversal set through its rule, or says why nothing is
		// joined: a whole path the operator gave, or the environment's own.
		switch {
		case r.provenance == "local":
			if r.test != "" {
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is local and names a test; a local path has no rule to show", r.line, r.key))
			}
		case usedAsGiven(r.provenance):
			if r.test != "" {
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is used as given and names a test; nothing is joined, so there is nothing to show", r.line, r.key))
			}
		case r.test == "":
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is %s and names no test; a row that is not local names the TestLimit that drives the traversal set through its rule, or says %q, or for the environment's own path says so", r.line, r.key, kindOf(r.provenance), absolutePath))
		case !strings.HasPrefix(r.test, "TestLimit"):
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which does not start with TestLimit", r.line, r.key, r.test))
		case tests[r.test] == 0:
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which no _test.go file in the tree declares", r.line, r.key, r.test))
		case tests[r.test] > 1:
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which %d packages declare; give it a name of its own", r.line, r.key, r.test, tests[r.test]))
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !have[k] {
			problems = append(problems, fmt.Sprintf("%s has no row in ledger.txt; add one saying where the path comes from", k))
		}
	}
	return problems, sites
}

// sitesIn finds the path-taking calls in one file.
func sitesIn(fset *token.FileSet, f *ast.File, rel string) []site {
	// The local name of each callee package in this file.
	alias := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		short, ok := importPaths[path]
		if !ok {
			continue
		}
		name := short
		if imp.Name != nil {
			name = imp.Name.Name
		}
		alias[name] = short
	}
	if len(alias) == 0 {
		return nil
	}
	var out []site
	enclosing := "<package>"
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		short, ok := alias[id.Name]
		if !ok {
			return true
		}
		callee := short + "." + sel.Sel.Name
		args, ok := pathArg[callee]
		if !ok {
			return true
		}
		for _, i := range args {
			if i >= len(call.Args) {
				continue
			}
			out = append(out, site{
				key: fmt.Sprintf("%s %s %s(%s)", rel, enclosing, callee, types.ExprString(call.Args[i])),
				pos: fset.Position(call.Pos()),
			})
		}
		return true
	}
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			enclosing = funcName(fd)
			ast.Inspect(fd, walk)
			enclosing = "<package>"
			continue
		}
		ast.Inspect(decl, walk)
	}
	return out
}

// funcName is a function as the ledger names it: receiver-qualified for a
// method, as (*T).Name or T.Name.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + types.ExprString(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}

// parseLedger reads the rows: "<key> = <provenance>", comments with #,
// blank lines between. It reports a key twice and rows out of order.
func parseLedger(ledger string) (rows []row, problems []string) {
	seen := map[string]int{}
	var keys []string
	for i, line := range strings.Split(ledger, "\n") {
		n := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := strings.LastIndex(line, " = ")
		if at < 0 {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: not a row: a row is \"<key> = <provenance>\"", n))
			continue
		}
		key, rest := line[:at], line[at+3:]
		prov, test, _ := strings.Cut(rest, " shown by ")
		if strings.ContainsAny(test, " \t") {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %q, which is not one test", n, key, test))
			continue
		}
		switch {
		case prov == "local", usedAsGiven(prov), strings.HasPrefix(prov, "operator: "),
			strings.HasPrefix(prov, "derived: "), strings.HasPrefix(prov, "network: "):
		case prov == "operator":
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says operator alone; an operator row is one of %q, \"operator: <setting> in <file>, resolved against <base>\" or \"operator: <name>, <rule> at <point>\"", n, key, absolutePath))
		default:
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: provenance %q is none of local, %s, operator: ..., derived: ..., network: <component>, <rule> at <point>", n, prov, absolutePath))
		}
		if first, dup := seen[key]; dup {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is written twice (first at line %d)", n, key, first))
			continue
		}
		seen[key] = n
		keys = append(keys, key)
		rows = append(rows, row{key: key, provenance: prov, test: test, line: n})
	}
	if !sort.StringsAreSorted(keys) {
		problems = append(problems, "ledger.txt: rows are sorted by key, and these are not")
	}
	return rows, problems
}

// kindOf is the word a sentence uses for a row's provenance.
func kindOf(prov string) string {
	kind, _, _ := strings.Cut(prov, ":")
	return kind
}

// limitTests counts, by name, every Test function declared in a _test.go
// file under the tree, for a row's test to be held to.
func limitTests(root string) map[string]int {
	out := map[string]int{}
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return nil
			}
			for _, decl := range f.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") {
					out[fd.Name.Name]++
				}
			}
			return nil
		})
	}
	return out
}

// ruleOf is the rule a network row names: the last comma-separated part
// before " at ", so a component may be described with commas of its own.
func ruleOf(prov string) string {
	rest := strings.TrimPrefix(prov, "network: ")
	if before, _, ok := strings.Cut(rest, " at "); ok {
		rest = before
	}
	if at := strings.LastIndex(rest, ", "); at >= 0 {
		rest = rest[at+2:]
	}
	return strings.TrimSpace(rest)
}

// typeRules are the standard-library functions a network row may name as
// its rule, for a component whose rule is its type: a number the JSON
// decoder held to a number and strconv.FormatInt writes as digits, a name
// filepath.Base cuts to one segment.
var typeRules = map[string]bool{"strconv.FormatInt": true, "filepath.Base": true}

// declared reports whether rule, as pkg.Func or Func, is a function
// declared in the tree, or one of typeRules.
func declared(funcs map[string]map[string]bool, rule string) bool {
	if typeRules[rule] {
		return true
	}
	pkg, name, ok := strings.Cut(rule, ".")
	if !ok {
		for _, fs := range funcs {
			if fs[rule] {
				return true
			}
		}
		return false
	}
	return funcs[pkg][name]
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

// plantModule writes one source file under internal/planted in a
// directory of its own, for the self-tests.
func plantModule(t *testing.T, src string) string {
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
