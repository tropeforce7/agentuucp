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
// cap set on an http.Server or an http.Transport. Its row says the bound
// and names the TestLimit test that shows it at the bound and one over.
// A constant bound is held to the tree. A bound the row names is held to
// the tree's spelling of it, and may not read a parameter or a local,
// including a function literal's parameter, unless a named exception says
// why. A bound the row gives as one of a set must be a parameter, and the
// set is held to what every caller passes.

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

	// For a cap, the bound as written, the function the site sits in
	// and its package, so that a bound that is not a constant can be
	// held to the tree: by its spelling, or through its callers.
	boundExpr ast.Expr
	fd        *ast.FuncDecl
	p         *pkg
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
	problems, sites, unused := checkWith(t, root, string(ledger), capBounds, capSettings, spelledBounds)
	if len(sites) < floor {
		t.Fatalf("found %d sites; the sweep that wrote the ledger found %d, so the walk is not reaching the tree", len(sites), floor)
	}
	for _, p := range problems {
		t.Error(p)
	}
	// An entry of the table no one-of row's walk reaches is a reading
	// nothing holds to the tree, and an exception no <= row takes excuses
	// nothing. Only the tree itself can say so, since a planted module has
	// tables of its own.
	for _, u := range unused {
		t.Error(u)
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
// no row. Then, row by row, it asserts a number that is not the constant
// in the tree, a name where the bound is a constant, a one of where it is
// a constant, a number where the bound is not a constant, and a bound of
// no known shape. The good row draws no sentence.
//
// It plants as well a body cap whose bound is a parameter. That bound is
// given by a function literal's call of it, whose own function's callers
// pass a constant and a method the planted table reads, and by a direct call
// passing a constant expression. The row naming that set in another order
// draws no sentence, and so does one that lists a value twice. A row short
// of a value is told to add it, and a row with a value no caller passes is
// told to remove it. A row that says the parameter by name is told to say
// the set. A generic function called once as an explicit instance and once
// by inference is read as the function, and its row draws no sentence; so is
// a method of a generic type called on an instance, which only its origin
// names. A method whose constant the planted table renders gives that
// constant's value, not another's.
//
// Each a sentence of its own: a caller passing a local and a call the
// table does not read, an exported method, a method value, a method whose
// body is not the table's, a method whose body is not a setting plus a
// constant, a function nobody calls, a bound that is not a parameter, a
// number where that bound is not a constant, a bound by name that is not
// the tree's spelling, a method called through an interface, one named in
// a file the build leaves out, a call that spreads another call's results,
// and a method expression; a table entry whose body adds to another value
// than its setting's; and a <= row of a bound that reads a local copy of
// a parameter or a function literal's parameter. A <= row of a bound that
// reads a parameter passes only where the planted spelled bounds excuse
// it. The table's
// entry nothing reaches and the spelled bound nothing takes are reported
// apart.
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

type Server struct{ max int64 }

func (s *Server) postCap() int64 { return s.max + hold }

func (s *Server) knockCap() int64 { return s.max * 2 }

func (s *Server) other() int64 { return 7 }

func (s *Server) readBody(w http.ResponseWriter, r *http.Request, limit int64) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

func (s *Server) authed(limit int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.readBody(w, r, limit) }
}

func (s *Server) local(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) Exported(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) valued(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) knocked(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func orphan(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) field(r io.Reader) io.Reader { return io.LimitReader(r, s.max) }

func held(r io.Reader, size int64) io.Reader { return io.LimitReader(r, size+1) }

func (s *Server) routes() {
	s.authed(512)
	s.authed(s.postCap())
	s.readBody(nil, nil, 1<<20)
	size := int64(9)
	s.local(nil, nil, size)
	s.local(nil, nil, s.other())
	s.Exported(nil, nil, 1)
	f := s.valued
	f(nil, nil, 1)
	s.valued(nil, nil, 2)
	s.knocked(nil, nil, s.knockCap())
	s.tiny(nil, nil, s.tinyCap())
	s.shaped(nil, nil, s.shapeCap())
	s.viaface(nil, nil, 3)
	s.hidden(nil, nil, 5)
	s.spread(three())
	(*Server).exprd(s, nil, nil, 777)
	gen[string](nil, nil, 4096, "")
	gen(nil, nil, 8192, 1)
	(&boxed[int]{}).take(nil, nil, 2048)
}

const little = 1 << 10

func (s *Server) tinyCap() int64 { return s.max + little }

func (s *Server) shapeCap() int64 { return s.max * 2 }

func (s *Server) tiny(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) shaped(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

type facer interface {
	viaface(w http.ResponseWriter, r *http.Request, n int64)
}

func (s *Server) viaface(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func callFace(f facer) { f.viaface(nil, nil, 3) }

func (s *Server) hidden(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) spread(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func three() (http.ResponseWriter, *http.Request, int64) { return nil, nil, 4 }

func (s *Server) exprd(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func gen[T any](w http.ResponseWriter, r *http.Request, n int64, _ T) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

type boxed[T any] struct{}

func (b *boxed[T]) take(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func aliased(r io.Reader, limit int64) io.Reader {
	n := limit
	return io.LimitReader(r, n)
}

func literal(r io.Reader) io.Reader {
	f := func(n int64) io.Reader { return io.LimitReader(r, n) }
	return f(1 << 40)
}

func (s *Server) doubleCap() int64 { return s.max*2 + hold }

func (s *Server) doubled(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

func (s *Server) more() {
	aliased(nil, 1<<40)
	s.doubled(nil, nil, s.doubleCap())
}
`)
	dir := filepath.Join(root, "internal", "planted")
	if err := os.WriteFile(filepath.Join(dir, "planted_test.go"), []byte(`package planted

import "testing"

func TestLimitCap(t *testing.T) {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file no host builds, which names hidden: the walk cannot type it,
	// so it cannot tell a caller there from another use of the name.
	if err := os.WriteFile(filepath.Join(dir, "never.go"), []byte(`//go:build planted_never

package planted

func never(s *Server) { s.hidden(nil, nil, 6) }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	problems, sites := check(t, root, "")
	if len(sites) != 24 {
		t.Fatalf("found %d sites, want 24: %+v", len(sites), sites)
	}
	const add = " has no row in ledger.txt; add one saying the bound it reads under, as <= n, and the TestLimit test that shows it at the bound and one over, or the program's own arithmetic as local:"
	want := []string{
		"internal/planted/planted.go (*Server).Exported cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).doubled cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).exprd cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).field cap io.LimitReader(r, s.max)" + add,
		"internal/planted/planted.go (*Server).hidden cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).knocked cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).local cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).readBody cap http.MaxBytesReader(r.Body, limit)" + add,
		"internal/planted/planted.go (*Server).shaped cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).spread cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).tiny cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).valued cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*Server).viaface cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go (*boxed[T]).take cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go aliased cap io.LimitReader(r, n)" + add,
		"internal/planted/planted.go gen cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go held cap io.LimitReader(r, size + 1)" + add,
		"internal/planted/planted.go literal cap io.LimitReader(r, n)" + add,
		"internal/planted/planted.go orphan cap http.MaxBytesReader(r.Body, n)" + add,
		"internal/planted/planted.go read cap io.LimitReader(r, n + 1)" + add,
		"internal/planted/planted.go serve cap http.MaxBytesReader(r.Body, 1 << 20)" + add,
		"internal/planted/planted.go server cap MaxHeaderBytes: hold" + add,
		"internal/planted/planted.go small cap io.LimitReader(r, 512)" + add,
		"internal/planted/planted.go transport cap t.MaxResponseHeaderBytes: hold" + add,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
	// The planted table of bounds: postCap and tinyCap read as the tree
	// has them, knockCap from a body the tree does not have, shapeCap from
	// a body that is not a setting plus a constant, and an entry for a
	// method nothing calls.
	bounds := map[string]capBound{
		"internal/planted (*Server).postCap":   {body: "s.max + hold", name: "max"},
		"internal/planted (*Server).tinyCap":   {body: "s.max + little", name: "max"},
		"internal/planted (*Server).knockCap":  {body: "s.max + 1", name: "max"},
		"internal/planted (*Server).shapeCap":  {body: "s.max * 2", name: "max"},
		"internal/planted (*Server).doubleCap": {body: "s.max * 2 + hold", name: "max"},
		"internal/planted (*Server).gone":      {body: "s.max + hold", name: "max"},
	}
	// The planted spelled bounds: held's size + 1, which its row says by
	// name, and a site that is not in the tree.
	spelled := map[string]string{
		"internal/planted/planted.go held cap io.LimitReader(r, size + 1)": "the planted exception",
		"internal/planted/planted.go gone cap io.LimitReader(r, n)":        "a site that is gone",
	}
	ledger := strings.Join([]string{
		"internal/planted/planted.go serve cap http.MaxBytesReader(r.Body, 1 << 20) = <= 1048575 shown by TestLimitCap",
		"internal/planted/planted.go server cap MaxHeaderBytes: hold = <= hold shown by TestLimitCap",
		"internal/planted/planted.go transport cap t.MaxResponseHeaderBytes: hold = one of 65536, 1 shown by TestLimitCap",
		"internal/planted/planted.go read cap io.LimitReader(r, n + 1) = <= 65537 shown by TestLimitCap",
		"internal/planted/planted.go read cap io.LimitReader(r, n + 1) = about n shown by TestLimitCap",
		"internal/planted/planted.go small cap io.LimitReader(r, 512) = <= 512 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).readBody cap http.MaxBytesReader(r.Body, limit) = one of 1048576, max + 65536, 512 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).readBody cap http.MaxBytesReader(r.Body, limit) = one of 512, max + 65536 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).readBody cap http.MaxBytesReader(r.Body, limit) = one of 512, 512, max + 65536, 1048576, 4096 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).local cap http.MaxBytesReader(r.Body, n) = one of 9, 7 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).Exported cap http.MaxBytesReader(r.Body, n) = one of 1 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).valued cap http.MaxBytesReader(r.Body, n) = one of 1, 2 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).knocked cap http.MaxBytesReader(r.Body, n) = one of max + 1 shown by TestLimitCap",
		"internal/planted/planted.go orphan cap http.MaxBytesReader(r.Body, n) = one of 1 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).field cap io.LimitReader(r, s.max) = one of 1, 2 shown by TestLimitCap",
		"internal/planted/planted.go held cap io.LimitReader(r, size + 1) = <= size + 1 shown by TestLimitCap",
		"internal/planted/planted.go held cap io.LimitReader(r, size + 1) = <= size + 2 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).readBody cap http.MaxBytesReader(r.Body, limit) = <= limit shown by TestLimitCap",
		"internal/planted/planted.go (*Server).field cap io.LimitReader(r, s.max) = <= 4096 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).tiny cap http.MaxBytesReader(r.Body, n) = one of max + 1024 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).tiny cap http.MaxBytesReader(r.Body, n) = one of max + 65536 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).shaped cap http.MaxBytesReader(r.Body, n) = one of max shown by TestLimitCap",
		"internal/planted/planted.go (*Server).viaface cap http.MaxBytesReader(r.Body, n) = one of 3 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).hidden cap http.MaxBytesReader(r.Body, n) = one of 5 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).spread cap http.MaxBytesReader(r.Body, n) = one of 4 shown by TestLimitCap",
		"internal/planted/planted.go (*Server).exprd cap http.MaxBytesReader(r.Body, n) = one of 777 shown by TestLimitCap",
		"internal/planted/planted.go gen cap http.MaxBytesReader(r.Body, n) = one of 8192, 4096 shown by TestLimitCap",
		"internal/planted/planted.go (*boxed[T]).take cap http.MaxBytesReader(r.Body, n) = one of 2048 shown by TestLimitCap",
		"internal/planted/planted.go aliased cap io.LimitReader(r, n) = <= n shown by TestLimitCap",
		"internal/planted/planted.go literal cap io.LimitReader(r, n) = <= n shown by TestLimitCap",
		"internal/planted/planted.go (*Server).doubled cap http.MaxBytesReader(r.Body, n) = one of max + 65536 shown by TestLimitCap",
	}, "\n")
	problems, _, unused := checkWith(t, root, ledger, bounds, map[string]string{"max": "s.max"}, spelled)
	const readBody = "internal/planted/planted.go (*Server).readBody cap http.MaxBytesReader(r.Body, limit)"
	const tableless = ", which is not a constant, a parameter followed to its callers, or a method the table of bounds reads; pass one of those, or say the bound as local: with why"
	const unseen = ", so its callers are not all visible; say the bound as local: with why"
	want = []string{
		"ledger.txt:1: internal/planted/planted.go serve cap http.MaxBytesReader(r.Body, 1 << 20) says <= 1048575, but the bound in the tree is 1048576",
		"ledger.txt:2: internal/planted/planted.go server cap MaxHeaderBytes: hold says \"<= hold\", but the bound in the tree is the constant 65536; say <= 65536",
		"ledger.txt:3: internal/planted/planted.go transport cap t.MaxResponseHeaderBytes: hold says one of, but the bound in the tree is the constant 65536; say <= 65536",
		"ledger.txt:4: internal/planted/planted.go read cap io.LimitReader(r, n + 1) says <= 65537, but its bound reads the parameter n of read; pass the parameter alone as the bound and say one of the set its callers pass, or say the bound as local: with why",
		"ledger.txt:5: internal/planted/planted.go read cap io.LimitReader(r, n + 1) is written twice",
		"ledger.txt:5: internal/planted/planted.go read cap io.LimitReader(r, n + 1) has the bound \"about n\", which is not <= n, one of a, b or local:, a bound being a number or a name with its arithmetic",
		"ledger.txt:8: " + readBody + " is written twice",
		"ledger.txt:8: " + readBody + " says one of 512, max + 65536, but its callers pass 512, max + 65536, 1048576; add 1048576",
		"ledger.txt:9: " + readBody + " is written twice",
		"ledger.txt:9: " + readBody + " says one of 512, 512, max + 65536, 1048576, 4096, but no caller passes 4096; remove it",
		"ledger.txt:10: internal/planted/planted.go (*Server).local cap http.MaxBytesReader(r.Body, n) says one of, but internal/planted/planted.go:65 passes size" + tableless,
		"ledger.txt:10: internal/planted/planted.go (*Server).local cap http.MaxBytesReader(r.Body, n) says one of, but internal/planted/planted.go:66 passes s.other()" + tableless,
		"ledger.txt:11: internal/planted/planted.go (*Server).Exported cap http.MaxBytesReader(r.Body, n) says one of, but its bound is a parameter of (*Server).Exported, which is exported" + unseen,
		"ledger.txt:12: internal/planted/planted.go (*Server).valued cap http.MaxBytesReader(r.Body, n) says one of, but (*Server).valued is used at internal/planted/planted.go:68 other than in a call" + unseen,
		"ledger.txt:13: internal/planted/planted.go (*Server).knocked cap http.MaxBytesReader(r.Body, n) says one of, but the table of bounds has internal/planted (*Server).knockCap's body as s.max + 1, and its body in the tree is s.max * 2; read the method again and change its entry in the table",
		"ledger.txt:14: internal/planted/planted.go orphan cap http.MaxBytesReader(r.Body, n) says one of, but orphan has no caller to give its bound; give it a caller, or say the bound as local: with why",
		"ledger.txt:15: internal/planted/planted.go (*Server).field cap io.LimitReader(r, s.max) says one of, but its bound s.max is not a parameter of (*Server).field, so it has no callers to read the set from; say it by its name, as <= s.max",
		"ledger.txt:17: internal/planted/planted.go held cap io.LimitReader(r, size + 1) is written twice",
		"ledger.txt:17: internal/planted/planted.go held cap io.LimitReader(r, size + 1) says <= size + 2, but the bound in the tree is size + 1",
		"ledger.txt:18: " + readBody + " is written twice",
		"ledger.txt:18: " + readBody + " says <= limit, but its bound reads the parameter limit of (*Server).readBody; say one of the set its callers pass",
		"ledger.txt:19: internal/planted/planted.go (*Server).field cap io.LimitReader(r, s.max) is written twice",
		"ledger.txt:19: internal/planted/planted.go (*Server).field cap io.LimitReader(r, s.max) says <= 4096, but the bound in the tree is not a constant; name it, as <= s.max",
		"ledger.txt:21: internal/planted/planted.go (*Server).tiny cap http.MaxBytesReader(r.Body, n) is written twice",
		"ledger.txt:21: internal/planted/planted.go (*Server).tiny cap http.MaxBytesReader(r.Body, n) says one of max + 65536, but its callers pass max + 1024; add max + 1024",
		"ledger.txt:21: internal/planted/planted.go (*Server).tiny cap http.MaxBytesReader(r.Body, n) says one of max + 65536, but no caller passes max + 65536; remove it",
		"ledger.txt:22: internal/planted/planted.go (*Server).shaped cap http.MaxBytesReader(r.Body, n) says one of, but the table of bounds reads internal/planted (*Server).shapeCap, whose body s.max * 2 is not a setting plus a constant; make it one, or say the bound as local: with why",
		"ledger.txt:23: internal/planted/planted.go (*Server).viaface cap http.MaxBytesReader(r.Body, n) says one of, but (*Server).viaface is called through the interface facer at internal/planted/planted.go:105" + unseen,
		"ledger.txt:24: internal/planted/planted.go (*Server).hidden cap http.MaxBytesReader(r.Body, n) says one of, but (*Server).hidden is named in internal/planted/never.go, which the host's build leaves out" + unseen,
		"ledger.txt:25: internal/planted/planted.go (*Server).spread cap http.MaxBytesReader(r.Body, n) says one of, but internal/planted/planted.go:76 passes its bound through a call it spreads, s.spread(three()), which the walk cannot read; pass the values one by one, or say the bound as local: with why",
		"ledger.txt:26: internal/planted/planted.go (*Server).exprd cap http.MaxBytesReader(r.Body, n) says one of, but (*Server).exprd is called as a method expression at internal/planted/planted.go:77, which the walk does not read; call it as a method, or say the bound as local: with why",
		"ledger.txt:29: internal/planted/planted.go aliased cap io.LimitReader(r, n) says <= n, but its bound reads the local n of aliased; the walk cannot follow it to a caller, so say the bound as local: with why, or pass a parameter alone as the bound and say one of the set its callers pass",
		"ledger.txt:30: internal/planted/planted.go literal cap io.LimitReader(r, n) says <= n, but its bound reads the local n of literal; the walk cannot follow it to a caller, so say the bound as local: with why, or pass a parameter alone as the bound and say one of the set its callers pass",
		"ledger.txt:31: internal/planted/planted.go (*Server).doubled cap http.MaxBytesReader(r.Body, n) says one of, but the table of bounds names internal/planted (*Server).doubleCap's setting max, which is s.max, and its body adds to something else: s.max * 2 + hold; say the setting it adds to, or say the bound as local: with why",
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
	wantUnused := []string{
		"the table of bounds has an entry for internal/planted (*Server).gone, which no one-of row's walk reached; remove it, or mend the row whose callers call it",
		"the spelled bounds excuse internal/planted/planted.go gone cap io.LimitReader(r, n), which no <= row of a bound that is not a constant says; remove it",
	}
	if strings.Join(unused, "\n") != strings.Join(wantUnused, "\n") {
		t.Fatalf("unused:\n%s\nwant:\n%s", strings.Join(unused, "\n"), strings.Join(wantUnused, "\n"))
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

// capBound is how the table of bounds reads one method whose call a
// caller passes as a cap's bound. The body is the method's one return of
// one expression, held to the tree as written. It must be a setting plus
// a constant. The name is the setting as the ledger says it, held by the
// table of settings to the code's spelling of the setting the body adds
// to, and the bound is rendered as the name plus the constant's value in
// the tree.
type capBound struct {
	body, name string
}

// capSettings is the setting each name in the table of bounds stands
// for, by the code's spelling of it. A table entry's body is that setting
// plus a constant, and the name is given here once, so that an entry whose
// body adds to some other value cannot keep a setting's name. What the
// setting's own accessor returns is not held here: knockMax is read as
// knock_max_bytes on the strength of its comment and its test.
var capSettings = map[string]string{
	"max_bytes":       "s.cfg.MaxBytes",
	"knock_max_bytes": "s.knockMax()",
}

// capBounds is the table of bounds for the tree, keyed by the method's
// package directory and its name as the ledger writes a function. Each
// entry is held to the tree when a one-of row's walk reaches it. The test
// of the tree as it stands fails on an entry no one-of row's walk
// reaches.
var capBounds = map[string]capBound{
	"internal/relay (*Server).postCap":    {body: "s.cfg.MaxBytes + relayapi.FramingAllowance", name: "max_bytes"},
	"internal/relay (*Server).forwardCap": {body: "s.cfg.MaxBytes + relayapi.FramingAllowance", name: "max_bytes"},
	"internal/relay (*Server).knockCap":   {body: "s.knockMax() + relayapi.FramingAllowance", name: "knock_max_bytes"},
}

// spelledBounds are the cap sites whose <= row may name a bound that
// reads a parameter, keyed by the site's key, each with the reason. Any
// other such row is refused: a parameter's value is its callers', and the
// row says the set they pass. The test of the tree as it stands fails on
// an entry no <= row takes.
var spelledBounds = map[string]string{
	"internal/client/client.go (*Client).attempt cap io.LimitReader(resp.Body, hold + 1)": "its callers pass locals read from the relay's health answer (client.go listingCap), which no walk can render, and the row names the hold each caller computes",
}

// check walks the tree under root, reads the ledger, and returns every
// problem in ledger order and the sites it found. It reads a caller's
// method by the tree's table of bounds and takes the tree's spelled
// bounds. An entry nothing takes is the tree's test to report, not a
// planted module's.
func check(t *testing.T, root, ledger string) (problems []string, sites []site) {
	t.Helper()
	problems, sites, _ = checkWith(t, root, ledger, capBounds, capSettings, spelledBounds)
	return problems, sites
}

// checkWith is check with the table of bounds and the spelled bounds
// given. It returns as well a sentence for every entry of the table no
// one-of row's walk reached, and for every spelled bound no <= row took.
func checkWith(t *testing.T, root, ledger string, bounds map[string]capBound, settings, spelled map[string]string) (problems []string, sites []site, unused []string) {
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
	reached, taken := map[string]bool{}, map[string]bool{}
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
			// A cap row says the bound the site reads under. A row that
			// says a number is held to the constant in the tree. A row
			// that says a name is held to the tree's spelling. A row that
			// says one of a set is held to what the callers pass. A row
			// that says local: is the program's own arithmetic, the row's
			// own word, and may name a test or not.
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
				case !s.constant && m[1] == "<= ":
					// A row that says <= of a bound that is not a constant
					// says the bound by its name, as the tree spells it. A
					// bound that reads a parameter has the value its callers
					// give, so its row says the set they pass; one that reads
					// a local or a function literal's parameter has a value
					// no walk can follow, so its row says local: with why. A
					// row may say the name instead only where spelledBounds
					// says why.
					if _, excused := spelled[r.key]; excused {
						taken[r.key] = true
					} else if param, declParam, isParam, reads := readsLocal(s); reads {
						what, remedy := "the parameter", "say one of the set its callers pass"
						if !isParam {
							remedy = "pass the parameter alone as the bound and say one of the set its callers pass, or say the bound as local: with why"
						}
						if !declParam {
							what, remedy = "the local", "the walk cannot follow it to a caller, so say the bound as local: with why, or pass a parameter alone as the bound and say one of the set its callers pass"
						}
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says <= %s, but its bound reads %s %s of %s; %s", r.line, r.key, m[2], what, param, enclosingName(s.fd), remedy))
						continue
					}
					spelling := types.ExprString(s.boundExpr)
					if isNumber {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says <= %d, but the bound in the tree is not a constant; name it, as <= %s", r.line, r.key, n, spelling))
						continue
					}
					if m[2] != spelling {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says <= %s, but the bound in the tree is %s", r.line, r.key, m[2], spelling))
						continue
					}
				case !s.constant && m[1] == "one of ":
					if bad := tree.capCallers(r, s, bounds, settings, reached); len(bad) > 0 {
						problems = append(problems, bad...)
						continue
					}
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
	var names []string
	for name := range bounds {
		if !reached[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		unused = append(unused, fmt.Sprintf("the table of bounds has an entry for %s, which no one-of row's walk reached; remove it, or mend the row whose callers call it", name))
	}
	var keys []string
	for key := range spelled {
		if !taken[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		unused = append(unused, fmt.Sprintf("the spelled bounds excuse %s, which no <= row of a bound that is not a constant says; remove it", key))
	}
	return problems, sites, unused
}

// parseBound reads a bound written as a number; a bound written by
// name is not one.
func parseBound(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// capCallers holds a cap row that says "one of" a set, where the bound is
// not a constant, to the callers that give it. The bound must be a parameter
// of the function the site sits in, a function literal counting as part of
// its declaration. Every caller of that function in its package is found by
// the function's object, whether it is called by its name or by a selector,
// and a generic function's instance counts as the function. Each argument is
// read as a constant's value, as a parameter of the caller followed to its
// own callers in turn, or as a call of a method the table of bounds reads.
// The set read must be the row's set, both ways. A value the row lists twice
// draws no sentence. The walk refuses a function whose callers may be
// elsewhere: an exported one, one used other than in a call, one called
// through an interface, one named in a file the host's build leaves out, and
// one nobody calls. It refuses as well a call it cannot line up with the
// parameters: a method expression, and a call whose arguments are another
// call's results, where the bound falls past the call's own arguments; where
// it falls among them, that argument is a call the table does not read and
// is refused as one. A local: row is the row's own word and never comes
// here, and a row that says <= is held to the bound's spelling instead.
func (tr *tree) capCallers(r row, s site, bounds map[string]capBound, settings map[string]string, reached map[string]bool) []string {
	lead := fmt.Sprintf("ledger.txt:%d: %s", r.line, r.key)
	fn, i, ok := paramOf(s.p, s.fd, s.boundExpr)
	if !ok {
		spelling := types.ExprString(s.boundExpr)
		remedy := "say it by its name, as <= " + spelling
		if _, _, reads := readsParam(s); reads {
			remedy = "pass a parameter alone as the bound, or say the bound as local: with why"
		}
		return []string{fmt.Sprintf("%s says one of, but its bound %s is not a parameter of %s, so it has no callers to read the set from; %s", lead, spelling, enclosingName(s.fd), remedy)}
	}
	w := &capWalk{tr: tr, lead: lead, bounds: bounds, settings: settings, reached: reached, visiting: map[capParam]bool{}, seen: map[string]bool{}}
	w.callers(fn, i)
	if len(w.problems) > 0 {
		return w.problems
	}
	var listed []string
	inList := map[string]bool{}
	for _, v := range strings.Split(strings.TrimPrefix(r.rng, "one of "), ", ") {
		if !inList[v] {
			inList[v] = true
			listed = append(listed, v)
		}
	}
	var problems, missing []string
	for _, v := range w.values {
		if !inList[v] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		problems = append(problems, fmt.Sprintf("%s says %s, but its callers pass %s; add %s", lead, r.rng, strings.Join(w.values, ", "), strings.Join(missing, ", ")))
	}
	for _, v := range listed {
		if !w.seen[v] {
			problems = append(problems, fmt.Sprintf("%s says %s, but no caller passes %s; remove it", lead, r.rng, v))
		}
	}
	return problems
}

// readsParam says whether a cap's bound reads a value its function was
// given or made: a parameter of the declaration it sits in, a function
// literal's parameter, or a local. It names the first such value and
// says whether the bound is one of the declaration's parameters alone. A
// receiver, a field, a constant and a package-level variable, of this
// package or another, are not such values: the row may name them.
func readsParam(s site) (name string, alone, reads bool) {
	name, _, alone, reads = readsLocal(s)
	return name, alone, reads
}

// readsLocal is readsParam, saying as well whether the value it names is
// one of the declaration's own parameters.
func readsLocal(s site) (name string, declParam, alone, reads bool) {
	if s.fd == nil || s.p == nil {
		return "", false, false, false
	}
	fn, ok := s.p.info.Defs[s.fd.Name].(*types.Func)
	if !ok {
		return "", false, false, false
	}
	sig := fn.Type().(*types.Signature)
	params := sig.Params()
	isParam := func(v *types.Var) bool {
		for i := 0; i < params.Len(); i++ {
			if params.At(i) == v {
				return true
			}
		}
		return false
	}
	local := func(id *ast.Ident) (*types.Var, bool) {
		v, ok := s.p.info.Uses[id].(*types.Var)
		if !ok || v.IsField() || (v.Pkg() != nil && v.Parent() == v.Pkg().Scope()) || v == sig.Recv() {
			return nil, false
		}
		return v, true
	}
	ast.Inspect(s.boundExpr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && !reads {
			if v, ok := local(id); ok {
				name, declParam, reads = id.Name, isParam(v), true
			}
		}
		return !reads
	})
	if id, ok := ast.Unparen(s.boundExpr).(*ast.Ident); ok && reads && declParam {
		v, _ := local(id)
		alone = isParam(v)
	}
	return name, declParam, alone, reads
}

// capParam is one parameter of one function, by its object and position.
type capParam struct {
	fn *types.Func
	i  int
}

// capWalk is one walk from a cap's bound up through its callers: the
// values read, in the order the walk met them and once each, and the
// sentences for whatever could not be read.
type capWalk struct {
	tr       *tree
	lead     string
	bounds   map[string]capBound
	settings map[string]string
	reached  map[string]bool
	visiting map[capParam]bool
	values   []string
	seen     map[string]bool
	problems []string
}

// localWhy ends every sentence that says the walk cannot give the set: the
// row then says why the bound holds instead.
const localWhy = "say the bound as local: with why"

// callers reads the argument every caller of fn passes at i. A parameter
// already walked is not walked again. That ends a cycle, and a parameter
// reached by two paths is read once.
func (w *capWalk) callers(fn *types.Func, i int) {
	if w.visiting[capParam{fn, i}] {
		return
	}
	w.visiting[capParam{fn, i}] = true
	p, fd := w.tr.declOf(fn)
	if p == nil {
		w.fail("%s says one of, but its bound is passed through %s, which is not declared in the tree, so its callers are not all visible; %s", w.lead, objName(fn), localWhy)
		return
	}
	name := enclosingName(fd)
	if fn.Exported() {
		w.fail("%s says one of, but its bound is a parameter of %s, which is exported, so its callers are not all visible; %s", w.lead, name, localWhy)
		return
	}
	w.throughInterface(p, fn, name)
	w.namedLeftOut(p, fn, name)
	calls, others := 0, 0
	for _, f := range p.files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if used, ok := p.info.Uses[id].(*types.Func); !ok || used.Origin() != fn {
				return true
			}
			call := callOf(stack)
			if call == nil {
				others++
				w.fail("%s says one of, but %s is used at %s other than in a call, so its callers are not all visible; %s", w.lead, name, w.tr.at(id), localWhy)
				return true
			}
			calls++
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && p.info.Types[sel.X].IsType() {
				w.fail("%s says one of, but %s is called as a method expression at %s, which the walk does not read; call it as a method, or %s", w.lead, name, w.tr.at(call), localWhy)
				return true
			}
			if i < len(call.Args) {
				w.arg(p, enclosingFunc(stack), call.Args[i])
			} else {
				w.fail("%s says one of, but %s passes its bound through a call it spreads, %s, which the walk cannot read; pass the values one by one, or %s", w.lead, w.tr.at(call), types.ExprString(call), localWhy)
			}
			return true
		})
	}
	if calls == 0 && others == 0 {
		w.fail("%s says one of, but %s has no caller to give its bound; give it a caller, or %s", w.lead, name, localWhy)
	}
}

// throughInterface refuses a method that a use in its package may reach
// through an interface. A call there resolves to the interface's method,
// not to fn, so the walk would not see it.
func (w *capWalk) throughInterface(p *pkg, fn *types.Func, name string) {
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return
	}
	t := recv.Type()
	if pt, ok := t.(*types.Pointer); ok {
		t = pt.Elem()
	}
	for _, f := range p.files {
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || id.Name != fn.Name() {
				return true
			}
			m, ok := p.info.Uses[id].(*types.Func)
			if !ok {
				return true
			}
			mr := m.Type().(*types.Signature).Recv()
			if mr == nil {
				return true
			}
			iface, ok := mr.Type().Underlying().(*types.Interface)
			if !ok {
				return true
			}
			if types.Implements(t, iface) || types.Implements(types.NewPointer(t), iface) {
				w.fail("%s says one of, but %s is called through the interface %s at %s, so its callers are not all visible; %s", w.lead, name, types.TypeString(mr.Type(), types.RelativeTo(p.types)), w.tr.at(id), localWhy)
			}
			return true
		})
	}
}

// namedLeftOut refuses a function whose name appears in a file of its
// package that the host's build constraints leave out. That file has no
// types, so any identifier of the name counts: a caller there would be
// one the walk does not see.
func (w *capWalk) namedLeftOut(p *pkg, fn *types.Func, name string) {
	for _, lf := range w.tr.excluded[p.dir] {
		found := false
		ast.Inspect(lf.file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == fn.Name() {
				found = true
			}
			return !found
		})
		if found {
			w.fail("%s says one of, but %s is named in %s, which the host's build leaves out, so its callers are not all visible; %s", w.lead, name, lf.rel, localWhy)
		}
	}
}

// arg reads one argument a caller passes: a constant as its value, a
// parameter of the caller's declaration by that function's callers, or a
// call of a method in the table of bounds as the table renders it, the
// method's body held to the table. Anything else draws a sentence saying
// it could not be read.
func (w *capWalk) arg(p *pkg, fd *ast.FuncDecl, e ast.Expr) {
	e = ast.Unparen(e)
	if tv, ok := p.info.Types[e]; ok && tv.Value != nil {
		if n, exact := constant.Int64Val(constant.ToInt(tv.Value)); exact {
			w.add(strconv.FormatInt(n, 10))
			return
		}
	}
	if caller, j, ok := paramOf(p, fd, e); ok {
		w.callers(caller, j)
		return
	}
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 0 {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if m, ok := p.info.Uses[sel.Sel].(*types.Func); ok {
				if key, ok := w.tr.methodKey(m); ok {
					if b, listed := w.bounds[key]; listed {
						w.reached[key] = true
						body, ret, mp := w.tr.returns(m)
						if body != b.body {
							w.fail("%s says one of, but the table of bounds has %s's body as %s, and its body in the tree is %s; read the method again and change its entry in the table", w.lead, key, b.body, body)
							return
						}
						v, ok := rendered(mp, ret, b.name)
						if !ok {
							w.fail("%s says one of, but the table of bounds reads %s, whose body %s is not a setting plus a constant; make it one, or %s", w.lead, key, body, localWhy)
							return
						}
						if want, known := w.settings[b.name]; known && !addsTo(ret, want) {
							w.fail("%s says one of, but the table of bounds names %s's setting %s, which is %s, and its body adds to something else: %s; say the setting it adds to, or %s", w.lead, key, b.name, want, body, localWhy)
							return
						} else if !known {
							w.fail("%s says one of, but the table of bounds names %s's setting %s, which the table of settings does not have; add it, with the code's spelling of it", w.lead, key, b.name)
							return
						}
						w.add(v)
						return
					}
				}
			}
		}
	}
	w.fail("%s says one of, but %s passes %s, which is not a constant, a parameter followed to its callers, or a method the table of bounds reads; pass one of those, or %s", w.lead, w.tr.at(e), types.ExprString(e), localWhy)
}

// addsTo says whether a body is the setting spelled want plus something.
func addsTo(e ast.Expr, want string) bool {
	be, ok := e.(*ast.BinaryExpr)
	return ok && be.Op == token.ADD && types.ExprString(be.X) == want
}

// rendered is a table entry's bound: the setting's name plus the value of
// the constant the body adds, read from the tree's types.
func rendered(p *pkg, e ast.Expr, name string) (string, bool) {
	be, ok := e.(*ast.BinaryExpr)
	if p == nil || !ok || be.Op != token.ADD {
		return "", false
	}
	tv, ok := p.info.Types[be.Y]
	if !ok || tv.Value == nil {
		return "", false
	}
	n, exact := constant.Int64Val(constant.ToInt(tv.Value))
	if !exact {
		return "", false
	}
	return name + " + " + strconv.FormatInt(n, 10), true
}

func (w *capWalk) add(v string) {
	if !w.seen[v] {
		w.seen[v] = true
		w.values = append(w.values, v)
	}
}

func (w *capWalk) fail(format string, args ...any) {
	w.problems = append(w.problems, fmt.Sprintf(format, args...))
}

// paramOf says whether e is an identifier naming a parameter of fd, a use
// inside a function literal of fd counting, and which function and
// position it is.
func paramOf(p *pkg, fd *ast.FuncDecl, e ast.Expr) (*types.Func, int, bool) {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok || fd == nil {
		return nil, 0, false
	}
	v, ok := p.info.Uses[id].(*types.Var)
	if !ok {
		return nil, 0, false
	}
	fn, ok := p.info.Defs[fd.Name].(*types.Func)
	if !ok {
		return nil, 0, false
	}
	params := fn.Type().(*types.Signature).Params()
	for i := 0; i < params.Len(); i++ {
		if params.At(i) == v {
			return fn, i, true
		}
	}
	return nil, 0, false
}

// callOf is the call whose callee is the identifier at the top of the
// stack, f(...), x.f(...) or an instance f[T](...), or nil when the
// identifier is used another way, as a method value or a function value.
func callOf(stack []ast.Node) *ast.CallExpr {
	k := len(stack) - 1
	var fun ast.Expr = stack[k].(*ast.Ident)
	if k >= 1 {
		if sel, ok := stack[k-1].(*ast.SelectorExpr); ok && sel.Sel == fun {
			fun, k = sel, k-1
		}
	}
	if k >= 1 {
		switch ix := stack[k-1].(type) {
		case *ast.IndexExpr:
			if ix.X == fun {
				fun, k = ix, k-1
			}
		case *ast.IndexListExpr:
			if ix.X == fun {
				fun, k = ix, k-1
			}
		}
	}
	if k >= 1 {
		if call, ok := stack[k-1].(*ast.CallExpr); ok && call.Fun == fun {
			return call
		}
	}
	return nil
}

// declOf is the package and the declaration of a function of the tree,
// found by its object.
func (tr *tree) declOf(fn *types.Func) (*pkg, *ast.FuncDecl) {
	for _, p := range tr.pkgs {
		if p.types != fn.Pkg() {
			continue
		}
		for _, f := range p.files {
			for _, decl := range f.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && p.info.Defs[fd.Name] == types.Object(fn) {
					return p, fd
				}
			}
		}
	}
	return nil, nil
}

// objName is a function's name as the ledger writes one, for a function
// with no declaration in the tree to read it from.
func objName(fn *types.Func) string {
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return fn.Name()
	}
	return "(" + types.TypeString(recv.Type(), types.RelativeTo(fn.Pkg())) + ")." + fn.Name()
}

// methodKey is a method's key in the table of bounds: its package's
// directory and its name as the ledger writes a function.
func (tr *tree) methodKey(m *types.Func) (string, bool) {
	recv := m.Type().(*types.Signature).Recv()
	if recv == nil || m.Pkg() == nil {
		return "", false
	}
	t, star := recv.Type(), ""
	if pt, ok := t.(*types.Pointer); ok {
		t, star = pt.Elem(), "*"
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return "", false
	}
	dir := strings.TrimPrefix(m.Pkg().Path(), tr.modulePath+"/")
	return dir + " (" + star + named.Obj().Name() + ")." + m.Name(), true
}

// returns is a method's body as the table of bounds holds it: the one
// expression of its one return statement, with the expression and its
// package. A body of another shape is a sentence saying so, with no
// expression.
func (tr *tree) returns(m *types.Func) (string, ast.Expr, *pkg) {
	p, fd := tr.declOf(m)
	if fd == nil || fd.Body == nil || len(fd.Body.List) != 1 {
		return "not one return of one expression", nil, nil
	}
	ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "not one return of one expression", nil, nil
	}
	return types.ExprString(ret.Results[0]), ret.Results[0], p
}

// at is a node's place as a sentence gives it, the file from the root and
// the line.
func (tr *tree) at(n ast.Node) string {
	pos := tr.fset.Position(n.Pos())
	return fmt.Sprintf("%s:%d", filepath.ToSlash(mustRel(tr.root, pos.Filename)), pos.Line)
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
	root       string
	modulePath string
	fset       *token.FileSet
	pkgs       []*pkg
	problems   []string

	// excluded is, by package directory, every file the host's build
	// constraints leave out, parsed without types.
	excluded map[string][]leftFile
}

// leftFile is one file the host's build leaves out, by its path from the
// root.
type leftFile struct {
	rel  string
	file *ast.File
}

// load parses and type-checks every package under internal/ and cmd/
// with the host's build constraints, the way the compiler would, and
// looks at the files those constraints leave out for a site the walk
// would then miss.
func load(t *testing.T, root string) *tree {
	t.Helper()
	tr := &tree{root: root, fset: token.NewFileSet(), excluded: map[string][]leftFile{}}
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
	tr.modulePath = modulePath
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
	dir := filepath.ToSlash(filepath.Dir(rel))
	tr.excluded[dir] = append(tr.excluded[dir], leftFile{rel: rel, file: f})
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

		boundExpr: bound,
		fd:        enclosingFunc(stack),
		p:         p,
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
