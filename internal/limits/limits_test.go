package limits

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The limit ledger test. Every place in the non-test tree where an
// integer from outside enters the program has one row in ledger.txt,
// keyed by the file, the enclosing function or struct, the kind and the
// site as written, and the row says the range the code holds it to, or
// that it is open, and names the TestLimit test that shows it. The test
// type-checks every package under internal/ and cmd/ so that a field's
// type, a flag's receiver and a decoder's target are known rather than
// guessed, and fails with its own sentence on a site with no row, a row
// with no site, a key written twice, a range of no known shape, a test
// that is not declared exactly once in the tree's _test.go files, a test
// whose name does not start with TestLimit, an output row for a struct
// the program decodes, a site in a file the host's build constraints
// leave out, a non-test import of internal/testutil, and a count under
// the floor. A new integer from outside fails this test until its row
// and its test exist, which is the point. A third kind of site is a cap:
// a reader bounded by http.MaxBytesReader or io.LimitReader, or a header
// cap set on an http.Server or an http.Transport; its row says the
// bound, held to the tree where the bound is a constant, and the
// TestLimit test that shows it at the bound and one over.

// floor is what the sweep that wrote the ledger found. A walk that finds
// fewer is not reaching the tree.
const floor = 297

// flagMethods are the *flag.FlagSet methods that define an integer or
// duration flag; the tree has no package-level flag.Int.
var flagMethods = map[string]bool{
	"Int": true, "IntVar": true, "Int64": true, "Int64Var": true,
	"Uint": true, "UintVar": true, "Uint64": true, "Uint64Var": true,
	"Duration": true, "DurationVar": true,
}

// ranges is every shape a row's range may take for an integer: a closed
// interval, one bound, a set, open, or output for a struct that is only
// written; a duration's bound carries its unit, and "0 or" in front says
// zero is a sentinel the range does not otherwise hold.
var ranges = regexp.MustCompile(`^(0 or )?(\[-?\d+[a-z]*, -?\d+[a-z]*\]|>= -?\d+[a-z]*|> -?\d+[a-z]*|<= -?\d+[a-z]*|< -?\d+[a-z]*|one of -?\d+(, -?\d+)+|open|output)$`)

// capRanges is every shape a cap row's bound may take: "<= n" for one
// bound, or "one of a, b" where the site's bound is a parameter and the
// callers give it more than one; a bound is a number, or a name with the
// arithmetic that reaches it, as "max_bytes + 65536" or "hold + 1". A
// cap whose bound the program's own arithmetic fixes says "local: <why>"
// instead, and may name a test.
var capRanges = regexp.MustCompile(`^(<= |one of )(([a-z_]+|\d+)( [+*] ([a-z_]+|\d+))*)(, ([a-z_]+|\d+)( [+*] ([a-z_]+|\d+))*)*$`)

// capFields are the net/http fields whose value caps a header block: the
// server's, and the transport's for a response.
var capFields = map[string]bool{"MaxHeaderBytes": true, "MaxResponseHeaderBytes": true}

// localRule is the form of a string row that names the rule which fixed
// the operand's length and the point it ran: "local: ValidFingerprint at
// checkMailbox". Such a row names a test as well, one per rule and shared
// by every slice the rule guards, which feeds the operand one byte short
// at the rule's point. A local row of any other form is the operand's
// own arithmetic, "local: len(s)-1 of s", and names no function and no
// test.
var localRule = regexp.MustCompile(`^local: ([A-Za-z_][A-Za-z0-9_.]*) at (\S.*)$`)

// site is one place a value from outside enters: an integer, or a string
// cut by a slice expression.
type site struct {
	key      string // <file> <enclosing> <kind> <as written>
	kind     string // int, string or cap
	pos      token.Position
	typeName string // for a field, the struct's type by full path; "" otherwise
	bound    int64  // for a cap whose bound is a constant, its value
	constant bool   // whether bound is known
}

// row is one ledger line.
type row struct {
	key, rng, test string
	line           int
}

// TestEveryIntegerFromOutsideHasItsLimitTest is the ledger against the
// tree as it stands.
func TestEveryIntegerFromOutsideHasItsLimitTest(t *testing.T) {
	root := moduleRoot(t)
	ledger, err := os.ReadFile(filepath.Join(root, "internal", "limits", "ledger.txt"))
	if err != nil {
		t.Fatal(err)
	}
	problems, sites := check(t, root, string(ledger))
	if len(sites) < floor {
		t.Fatalf("found %d sites; the sweep that wrote the ledger found %d, so the walk is not reaching the tree", len(sites), floor)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestALedgerFindsASiteWithNoRow plants one struct, one parse and one
// flag in a module of its own and asserts the three sentences.
func TestALedgerFindsASiteWithNoRow(t *testing.T) {
	root := plantModule(t, `package planted

import (
	"flag"
	"strconv"
)

type Shape struct {
	Name string `+"`json:\"name\"`"+`
	Size int64  `+"`json:\"size\"`"+`
	Left *int64 `+"`json:\"left\"`"+`
}

func parse(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

func flags(fs *flag.FlagSet) *int { return fs.Int("n", 1, "a number") }

func short(fp string) string { return fp[:16] }

func tail(xs []int, n int) []int { return xs[n:] }

func rest(b []byte, n int) []byte { return b[n:] }

func fixed(xs []string) []string { return xs[:2] }
`)
	problems, sites := check(t, root, "")
	if len(sites) != 7 {
		t.Fatalf("found %d sites, want 7: %+v", len(sites), sites)
	}
	want := []string{
		"internal/planted/planted.go Shape int Left *int64 has no row in ledger.txt; add one saying the range the code holds it to, or open, and the TestLimit test that shows it",
		"internal/planted/planted.go Shape int Size int64 has no row in ledger.txt; add one saying the range the code holds it to, or open, and the TestLimit test that shows it",
		"internal/planted/planted.go flags int fs.Int(\"n\") has no row in ledger.txt; add one saying the range the code holds it to, or open, and the TestLimit test that shows it",
		"internal/planted/planted.go parse int strconv.ParseInt(s) has no row in ledger.txt; add one saying the range the code holds it to, or open, and the TestLimit test that shows it",
		"internal/planted/planted.go rest string b[n:] has no row in ledger.txt; add one naming the rule that fixed the operand's length and the point it ran, or the operand's own arithmetic, as local:, or the TestLimit test that cuts it short",
		"internal/planted/planted.go short string fp[:16] has no row in ledger.txt; add one naming the rule that fixed the operand's length and the point it ran, or the operand's own arithmetic, as local:, or the TestLimit test that cuts it short",
		"internal/planted/planted.go tail string xs[n:] has no row in ledger.txt; add one naming the rule that fixed the operand's length and the point it ran, or the operand's own arithmetic, as local:, or the TestLimit test that cuts it short",
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

// TestALedgerRefusesWhatItCannotStandBehind plants rows that name a test
// that is not declared, a test not named TestLimit, a range of no known
// shape, an output row for a struct the program decodes, and a row for a
// site that is gone, and asserts each sentence.
func TestALedgerRefusesWhatItCannotStandBehind(t *testing.T) {
	root := plantModule(t, `package planted

import "encoding/json"

type Shape struct {
	Size int64 `+"`json:\"size\"`"+`
}

type View struct {
	Count int `+"`json:\"count\"`"+`
}

type Wrap struct {
	Inner []Shape
}

func read(b []byte) (Wrap, error) {
	var w Wrap
	err := json.Unmarshal(b, &w)
	return w, err
}

func probe(b []byte) (int, error) {
	var p struct {
		N int `+"`json:\"n\"`"+`
	}
	err := json.Unmarshal(b, &p)
	return p.N, err
}

func local(b []byte) (int, error) {
	type inner struct {
		M int `+"`json:\"m\"`"+`
	}
	var i inner
	err := json.Unmarshal(b, &i)
	return i.M, err
}

func short(fp string) string { return fp[:16] }

func valid(fp string) bool { return len(fp) == 64 }
`)
	if err := os.WriteFile(filepath.Join(root, "internal", "planted", "planted_test.go"), []byte(`package planted

import "testing"

func TestLimitShape(t *testing.T) {}
func TestShapeSize(t *testing.T) {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := strings.Join([]string{
		"internal/planted/planted.go Shape int Size int64 = output",
		"internal/planted/planted.go View int Count int = >= 0 shown by TestLimitNowhere",
		"internal/planted/planted.go Gone int Size int64 = open shown by TestLimitShape",
		"internal/planted/planted.go View int Count int = >= 0 shown by TestShapeSize",
		"internal/planted/planted.go View int Count int = sometimes shown by TestLimitShape",
		"internal/planted/planted.go probe.struct int N int = output",
		"internal/planted/planted.go local.inner int M int = output",
		"internal/planted/planted.go short string fp[:16] = local: nowhere at valid shown by TestLimitShape",
		"internal/planted/planted.go short string fp[:16] = local: valid at short",
		"internal/planted/planted.go short string fp[:16] = local: len(fp) is 64 shown by TestLimitShape",
		"internal/planted/planted.go short string fp[:16] = a cut",
		"internal/planted/planted.go short string fp[:16] = local: valid at short shown by TestLimitShape",
	}, "\n")
	problems, _ := check(t, root, ledger)
	want := []string{
		"ledger.txt:11: internal/planted/planted.go short string fp[:16] has no \"shown by\"",
		"ledger.txt:1: internal/planted/planted.go Shape int Size int64 says output, but planted.Shape is decoded: it is reached from json.Unmarshal at internal/planted/planted.go read through planted.Wrap; give the row a range and a test",
		"ledger.txt:2: internal/planted/planted.go View int Count int names TestLimitNowhere, which no _test.go file in the tree declares",
		"ledger.txt:3: internal/planted/planted.go Gone int Size int64 has no site in the tree; remove the row",
		"ledger.txt:4: internal/planted/planted.go View int Count int is written twice",
		"ledger.txt:4: internal/planted/planted.go View int Count int names TestShapeSize, which does not start with TestLimit",
		"ledger.txt:5: internal/planted/planted.go View int Count int is written twice",
		"ledger.txt:5: internal/planted/planted.go View int Count int has the range \"sometimes\", which is not [lo, hi], >= n, > n, <= n, < n, one of a, b, open or output, with 0 or in front where zero is a sentinel",
		"ledger.txt:6: internal/planted/planted.go probe.struct int N int says output, but struct{N int \"json:\\\"n\\\"\"} is decoded: it is reached from json.Unmarshal at internal/planted/planted.go probe; give the row a range and a test",
		"ledger.txt:7: internal/planted/planted.go local.inner int M int says output, but planted.inner is decoded: it is reached from json.Unmarshal at internal/planted/planted.go local; give the row a range and a test",
		"ledger.txt:8: internal/planted/planted.go short string fp[:16] names the rule nowhere, which is not a function in the tree",
		"ledger.txt:9: internal/planted/planted.go short string fp[:16] is written twice",
		"ledger.txt:9: internal/planted/planted.go short string fp[:16] names the rule valid and no test; the rule's test feeds the operand one byte short at short",
		"ledger.txt:10: internal/planted/planted.go short string fp[:16] is written twice",
		"ledger.txt:10: internal/planted/planted.go short string fp[:16] is the operand's own arithmetic and names a test; a rule's row names one, this one does not",
		"ledger.txt:12: internal/planted/planted.go short string fp[:16] is written twice",
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

// TestALedgerFindsACapAndHoldsItsBoundToTheTree plants the four forms of
// a cap — a MaxBytesReader, a LimitReader, a server's MaxHeaderBytes in a
// literal and a transport's MaxResponseHeaderBytes by assignment, one more
// LimitReader with a good row — and asserts the sentence for a cap with
// no row, and then, row by row, a number that is not the constant in the
// tree, a name where the bound is a constant, a one of where it is a
// constant, a number where it is not a constant, and a bound of no known
// shape; the good row draws no sentence.
func TestALedgerFindsACapAndHoldsItsBoundToTheTree(t *testing.T) {
	root := plantModule(t, `package planted

import (
	"io"
	"net/http"
)

const hold = 1 << 16

func serve(w http.ResponseWriter, r *http.Request) { r.Body = http.MaxBytesReader(w, r.Body, 1<<20) }

func read(r io.Reader, n int64) ([]byte, error) { return io.ReadAll(io.LimitReader(r, n+1)) }

func server() *http.Server { return &http.Server{MaxHeaderBytes: hold} }

func transport(t *http.Transport) { t.MaxResponseHeaderBytes = hold }

func small(r io.Reader) io.Reader { return io.LimitReader(r, 512) }
`)
	if err := os.WriteFile(filepath.Join(root, "internal", "planted", "planted_test.go"), []byte(`package planted

import "testing"

func TestLimitCap(t *testing.T) {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	problems, sites := check(t, root, "")
	if len(sites) != 5 {
		t.Fatalf("found %d sites, want 5: %+v", len(sites), sites)
	}
	const add = " has no row in ledger.txt; add one saying the bound it reads under, as <= n, and the TestLimit test that shows it at the bound and one over, or the program's own arithmetic as local:"
	want := []string{
		"internal/planted/planted.go read cap io.LimitReader(r, n + 1)" + add,
		"internal/planted/planted.go serve cap http.MaxBytesReader(r.Body, 1 << 20)" + add,
		"internal/planted/planted.go server cap MaxHeaderBytes: hold" + add,
		"internal/planted/planted.go small cap io.LimitReader(r, 512)" + add,
		"internal/planted/planted.go transport cap t.MaxResponseHeaderBytes: hold" + add,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
	ledger := strings.Join([]string{
		"internal/planted/planted.go serve cap http.MaxBytesReader(r.Body, 1 << 20) = <= 1048575 shown by TestLimitCap",
		"internal/planted/planted.go server cap MaxHeaderBytes: hold = <= hold shown by TestLimitCap",
		"internal/planted/planted.go transport cap t.MaxResponseHeaderBytes: hold = one of 65536, 1 shown by TestLimitCap",
		"internal/planted/planted.go read cap io.LimitReader(r, n + 1) = <= 65537 shown by TestLimitCap",
		"internal/planted/planted.go read cap io.LimitReader(r, n + 1) = about n shown by TestLimitCap",
		"internal/planted/planted.go small cap io.LimitReader(r, 512) = <= 512 shown by TestLimitCap",
	}, "\n")
	problems, _ = check(t, root, ledger)
	want = []string{
		"ledger.txt:1: internal/planted/planted.go serve cap http.MaxBytesReader(r.Body, 1 << 20) says <= 1048575, but the bound in the tree is 1048576",
		"ledger.txt:2: internal/planted/planted.go server cap MaxHeaderBytes: hold says \"<= hold\", but the bound in the tree is the constant 65536; say <= 65536",
		"ledger.txt:3: internal/planted/planted.go transport cap t.MaxResponseHeaderBytes: hold says one of, but the bound in the tree is the constant 65536; say <= 65536",
		"ledger.txt:4: internal/planted/planted.go read cap io.LimitReader(r, n + 1) says <= 65537, but the bound in the tree is not a constant; name it",
		"ledger.txt:5: internal/planted/planted.go read cap io.LimitReader(r, n + 1) is written twice",
		"ledger.txt:5: internal/planted/planted.go read cap io.LimitReader(r, n + 1) has the bound \"about n\", which is not <= n, one of a, b or local:, a bound being a number or a name with its arithmetic",
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

// TestADecodeTargetIsFollowedThroughAHelper plants the client's shape, a
// helper that takes any and unmarshals into it, and asserts that the
// struct its caller passes counts as decoded.
func TestADecodeTargetIsFollowedThroughAHelper(t *testing.T) {
	root := plantModule(t, `package planted

import "encoding/json"

type Answer struct {
	N int `+"`json:\"n\"`"+`
}

func into(b []byte, out any) error { return json.Unmarshal(b, out) }

func twice(b []byte, out any) error { return into(b, out) }

func ask(b []byte) (Answer, error) {
	var a Answer
	err := twice(b, &a)
	return a, err
}
`)
	problems, _ := check(t, root, "internal/planted/planted.go Answer int N int = output")
	want := "ledger.txt:1: internal/planted/planted.go Answer int N int says output, but planted.Answer is decoded: it is reached from json.Unmarshal at internal/planted/planted.go into through the any parameter of into through the any parameter of twice; give the row a range and a test"
	if len(problems) != 1 || problems[0] != want {
		t.Fatalf("problems %q\nwant the one sentence %q", problems, want)
	}
}

// check walks the tree under root, reads the ledger, and returns every
// problem in ledger order and the sites it found.
func check(t *testing.T, root, ledger string) (problems []string, sites []site) {
	t.Helper()
	tree := load(t, root)
	sites = tree.sites()
	decoded := tree.decoded()
	tests := tree.limitTests()

	byKey := map[string]site{}
	for _, s := range sites {
		if _, dup := byKey[s.key]; dup {
			problems = append(problems, fmt.Sprintf("%s: two sites share the key %s; make them distinct", s.pos, s.key))
		}
		byKey[s.key] = s
	}
	problems = append(problems, tree.problems...)

	funcs := tree.functions()
	rows, rowProblems := parseLedger(ledger)
	problems = append(problems, rowProblems...)
	seen := map[string]bool{}
	for _, r := range rows {
		s, ok := byKey[r.key]
		if !ok {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s has no site in the tree; remove the row", r.line, r.key))
			continue
		}
		if seen[r.key] {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is written twice", r.line, r.key))
		}
		seen[r.key] = true
		if s.kind == "string" {
			// A string row is local by the operand's own arithmetic and
			// names no test; or local by a rule, held to the tree, and
			// names the rule's test; or names the test that cuts it short.
			if strings.HasPrefix(r.rng, "local:") {
				m := localRule.FindStringSubmatch(r.rng)
				if m == nil {
					if r.test != "" {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is the operand's own arithmetic and names a test; a rule's row names one, this one does not", r.line, r.key))
					}
					continue
				}
				if !funcs[m[1]] {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names the rule %s, which is not a function in the tree", r.line, r.key, m[1]))
					continue
				}
				if r.test == "" {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names the rule %s and no test; the rule's test feeds the operand one byte short at %s", r.line, r.key, m[1], m[2]))
					continue
				}
			} else if r.test == "" {
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s is a cut with no local reason and no test", r.line, r.key))
				continue
			}
		} else if s.kind == "cap" {
			// A cap row says the bound as the site reads it: a constant
			// bound as its number, held to the tree; a bound that is a
			// parameter or a sum by name; or the program's own arithmetic
			// as local:, which may name a test and need not.
			if strings.HasPrefix(r.rng, "local:") {
				if r.test == "" {
					continue
				}
			} else {
				m := capRanges.FindStringSubmatch(r.rng)
				if m == nil {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s has the bound %q, which is not <= n, one of a, b or local:, a bound being a number or a name with its arithmetic", r.line, r.key, r.rng))
					continue
				}
				n, isNumber := parseBound(m[2])
				switch {
				case s.constant && m[1] == "one of ":
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says one of, but the bound in the tree is the constant %d; say <= %d", r.line, r.key, s.bound, s.bound))
					continue
				case s.constant && !isNumber:
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says %q, but the bound in the tree is the constant %d; say <= %d", r.line, r.key, r.rng, s.bound, s.bound))
					continue
				case s.constant && n != s.bound:
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says <= %d, but the bound in the tree is %d", r.line, r.key, n, s.bound))
					continue
				case !s.constant && isNumber && m[1] == "<= ":
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says <= %d, but the bound in the tree is not a constant; name it", r.line, r.key, n))
					continue
				}
			}
		} else if !ranges.MatchString(r.rng) {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s has the range %q, which is not [lo, hi], >= n, > n, <= n, < n, one of a, b, open or output, with 0 or in front where zero is a sentinel", r.line, r.key, r.rng))
			continue
		}
		if r.rng == "output" {
			if s.typeName == "" {
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says output, but only a struct's field can be output", r.line, r.key))
			} else if why, is := decoded[s.typeName]; is {
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says output, but %s is decoded: it is reached from %s; give the row a range and a test", r.line, r.key, short(s.typeName), why))
			}
			continue
		}
		if !strings.HasPrefix(r.test, "TestLimit") {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which does not start with TestLimit", r.line, r.key, r.test))
			continue
		}
		switch n := tests[r.test]; n {
		case 0:
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which no _test.go file in the tree declares", r.line, r.key, r.test))
		case 1:
		default:
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which %d packages declare; give it a name of its own", r.line, r.key, r.test, n))
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].key < sites[j].key })
	for _, s := range sites {
		if seen[s.key] {
			continue
		}
		if s.kind == "string" {
			problems = append(problems, fmt.Sprintf("%s has no row in ledger.txt; add one naming the rule that fixed the operand's length and the point it ran, or the operand's own arithmetic, as local:, or the TestLimit test that cuts it short", s.key))
			continue
		}
		if s.kind == "cap" {
			problems = append(problems, fmt.Sprintf("%s has no row in ledger.txt; add one saying the bound it reads under, as <= n, and the TestLimit test that shows it at the bound and one over, or the program's own arithmetic as local:", s.key))
			continue
		}
		problems = append(problems, fmt.Sprintf("%s has no row in ledger.txt; add one saying the range the code holds it to, or open, and the TestLimit test that shows it", s.key))
	}
	return problems, sites
}

// parseBound reads a bound written as a number; a bound written by
// name is not one.
func parseBound(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// functions is every function and method declared in the non-test tree,
// by bare name, for a local row's rule to be held to.
func (tr *tree) functions() map[string]bool {
	out := map[string]bool{}
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			for _, decl := range f.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					out[fd.Name.Name] = true
				}
			}
		}
	}
	return out
}

// pkg is one type-checked package of the tree.
type pkg struct {
	dir   string // relative to root
	files []*ast.File
	types *types.Package
	info  *types.Info
}

// tree is the type-checked non-test tree.
type tree struct {
	root     string
	fset     *token.FileSet
	pkgs     []*pkg
	problems []string
}

// load parses and type-checks every package under internal/ and cmd/
// with the host's build constraints, the way the compiler would, and
// looks at the files those constraints leave out for a site the walk
// would then miss.
func load(t *testing.T, root string) *tree {
	t.Helper()
	tr := &tree{root: root, fset: token.NewFileSet()}
	ctxt := build.Default
	ctxt.Dir = root
	saved := build.Default
	build.Default = ctxt
	t.Cleanup(func() { build.Default = saved })
	imp := importer.ForCompiler(tr.fset, "source", nil)

	byDir := map[string]*pkg{}
	var dirs []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "internal/testutil/") {
				return nil
			}
			dir := filepath.Dir(path)
			ok, err := ctxt.MatchFile(dir, d.Name())
			if err != nil {
				return err
			}
			if !ok {
				tr.leftOut(path, rel)
				return nil
			}
			f, err := parser.ParseFile(tr.fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) == "github.com/tropeforce7/agentuucp/internal/testutil" {
					tr.problems = append(tr.problems, fmt.Sprintf("%s imports internal/testutil, which the walk skips as test-only; it is not", rel))
				}
			}
			p := byDir[dir]
			if p == nil {
				p = &pkg{dir: filepath.ToSlash(mustRel(root, dir))}
				byDir[dir] = p
				dirs = append(dirs, dir)
			}
			p.files = append(p.files, f)
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	sort.Strings(dirs)
	modulePath := modulePathOf(t, root)
	for _, dir := range dirs {
		p := byDir[dir]
		p.info = &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		cfg := types.Config{Importer: imp, Error: func(err error) { t.Logf("type-checking %s: %v", p.dir, err) }}
		tp, err := cfg.Check(modulePath+"/"+p.dir, tr.fset, p.files, p.info)
		if err != nil {
			t.Fatalf("type-checking %s: %v", p.dir, err)
		}
		p.types = tp
		tr.pkgs = append(tr.pkgs, p)
	}
	return tr
}

// leftOut looks, without types, at a file the host's build constraints
// exclude, and reports a site there: the walk would not see it, so it
// must be moved or the walk extended.
func (tr *tree) leftOut(path, rel string) {
	f, err := parser.ParseFile(tr.fset, path, nil, 0)
	if err != nil {
		tr.problems = append(tr.problems, fmt.Sprintf("%s: %v", rel, err))
		return
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.StructType:
			for _, fl := range x.Fields.List {
				if fl.Tag != nil && strings.Contains(fl.Tag.Value, "json:") {
					tr.problems = append(tr.problems, fmt.Sprintf("%s has a struct with a json tag, and the host's build constraints leave the file out; the walk does not see it", rel))
					return false
				}
			}
		case *ast.CallExpr:
			s := types.ExprString(x.Fun)
			if strings.HasPrefix(s, "strconv.Atoi") || strings.HasPrefix(s, "strconv.Parse") || strings.HasPrefix(s, "binary.") || strings.HasPrefix(s, "flag.") ||
				s == "http.MaxBytesReader" || s == "io.LimitReader" {
				tr.problems = append(tr.problems, fmt.Sprintf("%s calls %s, and the host's build constraints leave the file out; the walk does not see it", rel, s))
			}
		case *ast.KeyValueExpr:
			if key, ok := x.Key.(*ast.Ident); ok && capFields[key.Name] {
				tr.problems = append(tr.problems, fmt.Sprintf("%s sets %s, and the host's build constraints leave the file out; the walk does not see it", rel, key.Name))
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && capFields[sel.Sel.Name] {
					tr.problems = append(tr.problems, fmt.Sprintf("%s sets %s, and the host's build constraints leave the file out; the walk does not see it", rel, sel.Sel.Name))
				}
			}
		}
		return true
	})
}

// sites finds every integer from outside: a field of integer or duration
// type in a struct with a json tag, wherever the struct is declared (at
// package level, inside a function, or as a literal's anonymous type), a
// strconv.Atoi or Parse*, a binary.*.Uint* read, and an integer or
// duration flag on a FlagSet.
func (tr *tree) sites() []site {
	var out []site
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			rel := filepath.ToSlash(mustRel(tr.root, tr.fset.Position(f.Pos()).Filename))
			// The path from the file down to the node, so that a struct
			// knows the function and the type declaration it sits in.
			var stack []ast.Node
			anon := map[string]int{}
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				switch x := n.(type) {
				case *ast.StructType:
					if !jsonTagged(x) {
						return true
					}
					enclosing := ""
					if fd := enclosingFunc(stack); fd != nil {
						enclosing = funcName(fd) + "."
					}
					typeName := types.TypeString(p.info.TypeOf(x), nil)
					if ts := declaring(stack, x); ts != nil {
						enclosing += ts.Name.Name
						if obj := p.info.Defs[ts.Name]; obj != nil {
							typeName = fullName(obj)
						}
					} else {
						// An anonymous struct: named by its function and its order there.
						anon[enclosing]++
						enclosing += "struct"
						if k := anon[strings.TrimSuffix(enclosing, "struct")]; k > 1 {
							enclosing += fmt.Sprintf("#%d", k)
						}
					}
					for _, fl := range x.Fields.List {
						// An integer field, a pointer to one, or a map or slice
						// whose values are integers, which the decoder fills
						// with numbers all the same.
						if !integerType(p.info.TypeOf(fl.Type)) && !integerElems(p.info.TypeOf(fl.Type)) {
							continue
						}
						for _, name := range fl.Names {
							out = append(out, site{
								key:      fmt.Sprintf("%s %s int %s %s", rel, enclosing, name.Name, types.ExprString(fl.Type)),
								kind:     "int",
								pos:      tr.fset.Position(name.Pos()),
								typeName: typeName,
							})
						}
					}
				case *ast.CallExpr:
					if text, is := tr.integerCall(p, x); is {
						enclosing := "a package-level declaration"
						if fd := enclosingFunc(stack); fd != nil {
							enclosing = funcName(fd)
						}
						out = append(out, site{
							key:  fmt.Sprintf("%s %s int %s", rel, enclosing, text),
							kind: "int",
							pos:  tr.fset.Position(x.Pos()),
						})
					}
					if text, bound, is := tr.capCall(p, x); is {
						out = append(out, tr.capSite(p, rel, stack, x.Pos(), text, bound))
					}
				case *ast.KeyValueExpr:
					// A header cap set in a composite literal: MaxHeaderBytes
					// on an http.Server, MaxResponseHeaderBytes on a Transport.
					if key, ok := x.Key.(*ast.Ident); ok && capField(p.info.Uses[key]) {
						out = append(out, tr.capSite(p, rel, stack, x.Pos(), key.Name+": "+types.ExprString(x.Value), x.Value))
					}
				case *ast.AssignStmt:
					// The same caps set by assignment, written as the literal's
					// form with the receiver, t.MaxResponseHeaderBytes: n, since
					// " = " is what parts a row's key from its range.
					for i, lhs := range x.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						if sn := p.info.Selections[sel]; sn == nil || !capField(sn.Obj()) {
							continue
						}
						rhs := x.Rhs[0]
						if len(x.Rhs) == len(x.Lhs) {
							rhs = x.Rhs[i]
						}
						out = append(out, tr.capSite(p, rel, stack, x.Pos(), types.ExprString(sel)+": "+types.ExprString(rhs), rhs))
					}
				case *ast.SliceExpr:
					// A slice expression on a string or a byte slice, whatever
					// its bound: the second trace's panic was a constant [:16] on
					// a two-byte fingerprint. On another slice, one with a bound
					// that is not a constant.
					if !tr.stringCut(p, x) {
						return true
					}
					enclosing := "a package-level declaration"
					if fd := enclosingFunc(stack); fd != nil {
						enclosing = funcName(fd)
					}
					out = append(out, site{
						key:  fmt.Sprintf("%s %s string %s", rel, enclosing, types.ExprString(x)),
						kind: "string",
						pos:  tr.fset.Position(x.Pos()),
					})
				}
				return true
			})
		}
	}
	// Two calls that read as one in one function are told apart by order.
	count := map[string]int{}
	for i := range out {
		count[out[i].key]++
		if n := count[out[i].key]; n > 1 {
			out[i].key += fmt.Sprintf(" #%d", n)
		}
	}
	return out
}

// enclosingFunc is the nearest function declaration on the path.
func enclosingFunc(stack []ast.Node) *ast.FuncDecl {
	for i := len(stack) - 1; i >= 0; i-- {
		if fd, ok := stack[i].(*ast.FuncDecl); ok {
			return fd
		}
	}
	return nil
}

// declaring is the type declaration whose type is exactly st, when the
// struct is a named type's, and nil for an anonymous struct.
func declaring(stack []ast.Node, st *ast.StructType) *ast.TypeSpec {
	if len(stack) < 2 {
		return nil
	}
	if ts, ok := stack[len(stack)-2].(*ast.TypeSpec); ok && ts.Type == st {
		return ts
	}
	return nil
}

// stringCut says whether a slice expression is a site: any slice of a
// string or a byte slice, or a slice of anything else with a bound that
// is not a constant. An array is not a slice: its bounds are checked at
// compile time.
func (tr *tree) stringCut(p *pkg, se *ast.SliceExpr) bool {
	t := p.info.TypeOf(se.X)
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0
	case *types.Slice:
		if b, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic); ok && b.Kind() == types.Uint8 {
			return true
		}
	default:
		return false
	}
	for _, ix := range []ast.Expr{se.Low, se.High, se.Max} {
		if ix == nil {
			continue
		}
		if tv, ok := p.info.Types[ix]; !ok || tv.Value == nil {
			return true
		}
	}
	return false
}

// integerElems is a map or a slice whose values are integers, a byte
// slice excepted: []byte is a string of bytes, not a list of numbers.
func integerElems(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Pointer:
		// A pointer to an integer, which a field takes so that absent is
		// not zero: the decoder fills it with a number all the same.
		return integerType(u.Elem())
	case *types.Map:
		return integerType(u.Elem())
	case *types.Slice:
		if b, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic); ok && b.Kind() == types.Uint8 {
			return false
		}
		return integerType(u.Elem())
	}
	return false
}

// integerCall says whether a call is one of the integer sites, and how
// the ledger writes it: the callee and its first argument.
func (tr *tree) integerCall(p *pkg, call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	obj := p.info.Uses[sel.Sel]
	if obj == nil {
		return "", false
	}
	is := false
	switch fn := obj.(type) {
	case *types.Func:
		if fn.Pkg() == nil {
			break
		}
		switch fn.Pkg().Path() {
		case "strconv":
			is = fn.Name() == "Atoi" || strings.HasPrefix(fn.Name(), "Parse")
		case "time":
			is = fn.Name() == "ParseDuration"
		case "encoding/binary":
			// binary.BigEndian.Uint32 is a method on ByteOrder; a Put* is a write.
			is = strings.HasPrefix(fn.Name(), "Uint") || fn.Name() == "Read"
		case "flag":
			if recv := fn.Type().(*types.Signature).Recv(); recv != nil && flagMethods[fn.Name()] {
				is = strings.HasSuffix(types.TypeString(recv.Type(), nil), "flag.FlagSet")
			}
		}
	}
	if !is {
		return "", false
	}
	if len(call.Args) == 0 {
		return types.ExprString(call.Fun) + "()", true
	}
	return types.ExprString(call.Fun) + "(" + types.ExprString(call.Args[0]) + ")", true
}

// capCall says whether a call bounds a reader — http.MaxBytesReader or
// io.LimitReader — and how the ledger writes it: the callee, the reader
// and the bound; and returns the bound's expression.
func (tr *tree) capCall(p *pkg, call *ast.CallExpr) (string, ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", nil, false
	}
	fn, ok := p.info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return "", nil, false
	}
	var reader, bound ast.Expr
	switch {
	case fn.Pkg().Path() == "net/http" && fn.Name() == "MaxBytesReader" && len(call.Args) == 3:
		reader, bound = call.Args[1], call.Args[2]
	case fn.Pkg().Path() == "io" && fn.Name() == "LimitReader" && len(call.Args) == 2:
		reader, bound = call.Args[0], call.Args[1]
	default:
		return "", nil, false
	}
	return types.ExprString(call.Fun) + "(" + types.ExprString(reader) + ", " + types.ExprString(bound) + ")", bound, true
}

// capField says whether an object is one of net/http's header caps.
func capField(obj types.Object) bool {
	v, ok := obj.(*types.Var)
	return ok && v.IsField() && v.Pkg() != nil && v.Pkg().Path() == "net/http" && capFields[v.Name()]
}

// capSite is a cap's site, with its bound's value when the bound is a
// constant, so that the row's number is held to the tree.
func (tr *tree) capSite(p *pkg, rel string, stack []ast.Node, pos token.Pos, text string, bound ast.Expr) site {
	s := site{
		key:  fmt.Sprintf("%s %s cap %s", rel, enclosingName(enclosingFunc(stack)), text),
		kind: "cap",
		pos:  tr.fset.Position(pos),
	}
	if tv, ok := p.info.Types[bound]; ok && tv.Value != nil {
		if n, exact := constant.Int64Val(constant.ToInt(tv.Value)); exact {
			s.bound, s.constant = n, true
		}
	}
	return s
}

// decoded is every named type the program decodes JSON into, directly
// or through a helper whose parameter of interface type reaches
// json.Unmarshal or Decoder.Decode, and every type reachable from one
// through fields, slices, arrays, maps and pointers; the value says how.
func (tr *tree) decoded() map[string]string {
	// A decoding parameter: a function object and the index of a
	// parameter that reaches a decoder. Found to a fixpoint, since a
	// helper may call a helper.
	type param struct {
		fn    *types.Func
		index int
	}
	reaches := map[param]string{}
	direct := map[string]bool{} // a concrete argument already taken, by type and route
	var targets []struct {
		typ types.Type
		why string
	}
	record := func(p *pkg, fd *ast.FuncDecl, arg ast.Expr, why string) {
		// A parameter of the enclosing function of interface type is a
		// decoding parameter; anything else is a target now.
		if id, ok := arg.(*ast.Ident); ok {
			if v, ok := p.info.Uses[id].(*types.Var); ok && fd != nil {
				if fn, ok := p.info.Defs[fd.Name].(*types.Func); ok {
					sig := fn.Type().(*types.Signature)
					for i := 0; i < sig.Params().Len(); i++ {
						if sig.Params().At(i) == v && types.IsInterface(v.Type()) {
							reaches[param{fn, i}] = why
							return
						}
					}
				}
			}
		}
		targets = append(targets, struct {
			typ types.Type
			why string
		}{p.info.TypeOf(arg), why})
	}
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			rel := filepath.ToSlash(mustRel(tr.root, tr.fset.Position(f.Pos()).Filename))
			for _, decl := range f.Decls {
				fd, _ := decl.(*ast.FuncDecl)
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					fn, ok := p.info.Uses[sel.Sel].(*types.Func)
					if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "encoding/json" {
						return true
					}
					where := rel + " " + enclosingName(fd)
					switch {
					case fn.Name() == "Unmarshal" && len(call.Args) == 2:
						record(p, fd, call.Args[1], "json.Unmarshal at "+where)
					case fn.Name() == "Decode" && len(call.Args) == 1:
						record(p, fd, call.Args[0], "Decoder.Decode at "+where)
					}
					return true
				})
			}
		}
	}
	// Callers of a decoding parameter, to a fixpoint.
	for changed := true; changed; {
		changed = false
		for _, p := range tr.pkgs {
			for _, f := range p.files {
				for _, decl := range f.Decls {
					fd, _ := decl.(*ast.FuncDecl)
					ast.Inspect(decl, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok {
							return true
						}
						var id *ast.Ident
						switch fun := call.Fun.(type) {
						case *ast.Ident:
							id = fun
						case *ast.SelectorExpr:
							id = fun.Sel
						default:
							return true
						}
						callee, ok := p.info.Uses[id].(*types.Func)
						if !ok {
							return true
						}
						for pr, why := range reaches {
							if pr.fn != callee || pr.index >= len(call.Args) {
								continue
							}
							arg := call.Args[pr.index]
							through := why + " through the any parameter of " + callee.Name()
							if aid, ok := arg.(*ast.Ident); ok {
								if v, ok := p.info.Uses[aid].(*types.Var); ok && fd != nil {
									if fn, ok := p.info.Defs[fd.Name].(*types.Func); ok {
										sig := fn.Type().(*types.Signature)
										for i := 0; i < sig.Params().Len(); i++ {
											if sig.Params().At(i) == v && types.IsInterface(v.Type()) {
												if _, known := reaches[param{fn, i}]; !known {
													reaches[param{fn, i}] = through
													changed = true
												}
												return true
											}
										}
									}
								}
							}
							typ := p.info.TypeOf(arg)
							if typ == nil {
								continue
							}
							key := types.TypeString(typ, nil) + " at " + through
							if !direct[key] {
								direct[key] = true
								targets = append(targets, struct {
									typ types.Type
									why string
								}{typ, through})
								changed = true
							}
						}
						return true
					})
				}
			}
		}
	}
	out := map[string]string{}
	for _, tg := range targets {
		reach(tg.typ, tg.why, out, map[string]bool{})
	}
	return out
}

// reach adds every named type reachable from t.
func reach(t types.Type, why string, out map[string]string, seen map[string]bool) {
	if t == nil {
		return
	}
	t = types.Unalias(t)
	switch x := t.(type) {
	case *types.Pointer:
		reach(x.Elem(), why, out, seen)
	case *types.Slice:
		reach(x.Elem(), why, out, seen)
	case *types.Array:
		reach(x.Elem(), why, out, seen)
	case *types.Map:
		reach(x.Key(), why, out, seen)
		reach(x.Elem(), why, out, seen)
	case *types.Named:
		key := typeKey(x)
		if seen[key] {
			return
		}
		seen[key] = true
		if _, ok := out[key]; !ok {
			out[key] = why
		}
		reach(x.Underlying(), why+" through "+short(key), out, seen)
	case *types.Struct:
		// An anonymous struct is known by its spelling, which is how a
		// site names it too.
		key := types.TypeString(x, nil)
		if !seen[key] {
			seen[key] = true
			if _, ok := out[key]; !ok {
				out[key] = why
			}
		}
		for i := 0; i < x.NumFields(); i++ {
			reach(x.Field(i).Type(), why, out, seen)
		}
	}
}

// limitTests counts, by name, every TestLimit function declared in a
// _test.go file anywhere under the tree.
func (tr *tree) limitTests() map[string]int {
	out := map[string]int{}
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		filepath.WalkDir(filepath.Join(tr.root, top), func(path string, d os.DirEntry, err error) error {
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

// parseLedger reads the rows: a line that is not blank or a comment is
//
//	<file> <enclosing> <kind> <site as written> = <range> shown by <Test>
//
// or ends at "= output".
func parseLedger(ledger string) (rows []row, problems []string) {
	for i, line := range strings.Split(ledger, "\n") {
		n := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rest, ok := strings.Cut(line, " = ")
		if !ok {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: no \" = \" in the row", n))
			continue
		}
		if len(strings.Fields(key)) < 4 {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: the key %q is not <file> <enclosing> <kind> <site>", n, key))
			continue
		}
		rng, test, has := strings.Cut(rest, " shown by ")
		if !has && rng != "output" && !strings.HasPrefix(rng, "local:") {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s has no \"shown by\"", n, key))
			continue
		}
		if has && strings.ContainsAny(test, " \t") {
			problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %q, which is not one test", n, key, test))
			continue
		}
		rows = append(rows, row{key: key, rng: rng, test: test, line: n})
	}
	return rows, problems
}

func jsonTagged(st *ast.StructType) bool {
	for _, fl := range st.Fields.List {
		if fl.Tag != nil && strings.Contains(fl.Tag.Value, "json:") {
			return true
		}
	}
	return false
}

// integerType is a basic integer, or time.Duration.
func integerType(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if b, ok := t.(*types.Basic); ok {
		return b.Info()&types.IsInteger != 0
	}
	return typeKey(t) == "time.Duration"
}

func typeKey(t types.Type) string {
	if t == nil {
		return ""
	}
	if n, ok := types.Unalias(t).(*types.Named); ok {
		return fullName(n.Obj())
	}
	return ""
}

func fullName(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

// short is a type's name as a sentence says it: the package's last
// element and the type.
func short(full string) string {
	i := strings.LastIndex(full, "/")
	return full[i+1:]
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + types.ExprString(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}

func enclosingName(fd *ast.FuncDecl) string {
	if fd == nil {
		return "a package-level declaration"
	}
	return funcName(fd)
}

func mustRel(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}

// modulePathOf is the module line of go.mod under root.
func modulePathOf(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	t.Fatal("no module line in go.mod")
	return ""
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

// plantModule writes one source file under internal/planted in a module
// of its own, for the self-tests.
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
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module planted\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
