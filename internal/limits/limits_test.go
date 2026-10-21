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
	"slices"
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
// and its test exist, which is the point. A string cut is a site of its
// own, held to the rule that fixed its operand's length. A third kind of
// site is a cap: a reader bounded by http.MaxBytesReader or
// io.LimitReader, or a header cap set on an http.Server or an
// http.Transport. Its row says the bound
// and names the TestLimit test that shows it at the bound and one over.
// A constant bound is held to the tree. A bound the row names is held to
// the tree's spelling of it, and may not read a parameter or a local,
// including a function literal's parameter, unless a named exception says
// why. A bound the row gives as one of a set must be a parameter, and the
// set is held to what every caller passes. A fourth kind is a time: a
// field of a type that holds a time in a json-tagged struct, or in any
// struct a decode reaches, tagged or not, embedded or not, a generic
// struct's by the type argument it is given; a decode straight into a
// time; an UnmarshalText, UnmarshalJSON or UnmarshalBinary called on one;
// and a time.Parse, time.ParseInLocation, time.Unix, time.UnixMilli or
// time.UnixMicro. Its row says how far ahead the code takes it, or its
// window, deadline, display, output or local; the test refuses a display
// row on a field that reaches anything but a format, a print, a marshal,
// a field whose own row is display or output, or a helper that only shows
// it; a deadline or bound with no test, or with a test that does not feed
// the grammar's values through testutil.TimeEdges; local: on a time made
// of an integer whose own row says it is from outside; and local: on a
// field a decode fills unless it names the rule that holds it, the rule's
// test and every function of the tree that writes the field. json.Unmarshal, a Decoder's Decode, or a helper that
// reaches one, taken as a value rather than called, is refused.

// floor is what the walk finds, every kind together, raised with each row
// added: 542 when the time kind was added, 572 when it was made to see
// every decoded time and every time.Unix, 574 when a field a display
// field is copied into became a site of its own (HTTPError.At and
// Loaded.Issued), 576 when a channel gained max_bytes and a directory's
// decode a probe of v, 575 when that probe became a strict decode of the
// object's keys asked only after the document was refused (R18), 578
// when the owner's --max-bytes, its listing and the health answer's
// channel ceiling were added, 577 when quarantine trust's branch for a
// sent message, which a quarantined one never is, went (G31), 578 when
// the owed acknowledgement's refusal named its message (G32), 579 when a
// stream's sources were hashed as they were sealed (G34), 580 when the
// courier's queue said when it is next due (G40), 582 when a drop the
// outbox would not take named its copy in its two refusals (G43), 581
// when a sent record's change said its read and its save in one warning
// (G45), 586 when a program's line over the cap was cut and the lines after
// it copied (G49), 588 when serve read git's version for the oldest it
// takes (F1), 590 when a resume named the drop for a record never opened
// on a relay (57c), 591 when a stalled attempt was read on after its
// answer only while its body arrived (58e), 602 when handle.json's
// numbers and durations were read, 617 when handle's ledger was, 628 when
// handle ran its first jobs, 630 when it replied to them, 631 when the
// replies carried files, 640 when the operator's commands read the ledger.
// A walk that finds fewer is not reaching the tree.
const floor = 640

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

// timeRanges is every shape a time row's range may take that names no
// prose: "<= now + 5m", a stamp held to no more than relayapi.MaxSkew
// ahead of the reader's clock, the bound of a document an owner posts and
// of a relay's own stamps; "<= now + 42m", a sealed stamp held to
// relayapi.MaxStampAhead, the chain of clocks it crossed; "[lo, hi]", a
// window with both edges, named as the code names them or written as
// numbers, as a token's dates are (G26); "display", shown
// and never compared or ordered, which the walk holds by the field's uses
// as far as compared says it can see them; and "output", as for an
// integer. The rest take a reason after a colon: "local: <why>", this
// program's own clock or its user's input read back, or a value a check
// already held; "deadline: <its use>", a time that names a moment to
// come, compared with now, with the other edge of its own window or with
// an earlier copy of itself, or for the earliest to show, never ordered
// across records, and written to a file only as a record of it, whose
// test feeds the extremes.
var timeRanges = regexp.MustCompile(`^(<= now \+ 5m|<= now \+ 42m|\[(-?\d+|[A-Za-z_.]+), (-?\d+|[A-Za-z_.]+)\]|display|output)$`)

// timeOperators are the time.Time methods that compare or order: a
// display field is an operand of none of them.
var timeOperators = map[string]bool{"Before": true, "After": true, "Equal": true, "Sub": true, "Compare": true}

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

// site is one place a value from outside enters: an integer, a time, or
// a string cut by a slice expression.
type site struct {
	key      string // <file> <enclosing> <kind> <as written>
	kind     string // int, time, string or cap
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

	// For a time made of an integer, time.Unix and its kin, the position
	// of every struct field its arguments read: the int site it comes
	// from, whose row says where the integer is from.
	from []string
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

// TestALedgerFindsATimeWithNoRow plants, in a json-tagged struct, a time
// field, a pointer to one, an untagged unexported one, a slice and an
// array of times, a map with times for values and one with times for
// keys, an embedded time.Time, a field of a type defined over time.Time,
// of a named slice of times and of a named pointer to one, one of a
// struct embedding a time and one of a struct embedding a pointer to it,
// with a time.Parse and a time.ParseInLocation, and asserts the fifteen
// sentences; a time field of a
// struct with no json tag that no decode reaches is not a site, and
// neither is a field of a struct with no time inside.
func TestALedgerFindsATimeWithNoRow(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import "time"

type Stamp time.Time

type Wrapped struct{ time.Time }

type WrappedPtr struct{ *time.Time }

type Stamps []time.Time

type StampPtr *time.Time

type Named struct{ S string }

type Record struct {
	At    time.Time            'json:"at"'
	Until *time.Time           'json:"until"'
	seen  time.Time
	List  []time.Time          'json:"list"'
	ByKey map[string]time.Time 'json:"by_key"'
	time.Time
	Mark  Stamp   'json:"mark"'
	Wrap  Wrapped 'json:"wrap"'
	WrapP WrappedPtr 'json:"wrap_p"'
	Keys  map[time.Time]string 'json:"keys"'
	Many  Stamps 'json:"many"'
	Ptr   StampPtr 'json:"ptr"'
	Arr   [2]time.Time 'json:"arr"'
	Name  Named   'json:"name"'
}

type Plain struct {
	When time.Time
}

func parse(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

func parseIn(s string) (time.Time, error) { return time.ParseInLocation(time.RFC3339, s, time.UTC) }
`})
	problems, sites := check(t, root, "")
	if len(sites) != 15 {
		t.Fatalf("found %d sites, want 15: %+v", len(sites), sites)
	}
	for _, s := range sites {
		if strings.Contains(s.key, "Plain") {
			t.Fatalf("a time field of a struct with no json tag is a site: %s", s.key)
		}
		if strings.HasSuffix(s.key, " Name") {
			t.Fatalf("a field of a struct with no time inside is a site: %s", s.key)
		}
	}
	const noRow = " has no row in ledger.txt; add one saying how far ahead the code takes it, <= now + 5m, or its window, with the TestLimit test that shows it, or a deadline with its use and its test, or display, output or local: with why"
	want := []string{
		"internal/planted/planted.go Record time Arr" + noRow,
		"internal/planted/planted.go Record time At" + noRow,
		"internal/planted/planted.go Record time ByKey" + noRow,
		"internal/planted/planted.go Record time Keys" + noRow,
		"internal/planted/planted.go Record time List" + noRow,
		"internal/planted/planted.go Record time Many" + noRow,
		"internal/planted/planted.go Record time Mark" + noRow,
		"internal/planted/planted.go Record time Ptr" + noRow,
		"internal/planted/planted.go Record time Time" + noRow,
		"internal/planted/planted.go Record time Until" + noRow,
		"internal/planted/planted.go Record time Wrap" + noRow,
		"internal/planted/planted.go Record time WrapP" + noRow,
		"internal/planted/planted.go Record time seen" + noRow,
		"internal/planted/planted.go parse time time.Parse(s)" + noRow,
		"internal/planted/planted.go parseIn time time.ParseInLocation(s)" + noRow,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

// TestALedgerHoldsATimeRowToItsField plants a struct of time fields and
// a row for each. A display row is refused, by name and with the place,
// on a field that is an operand of Before, either side of After, a side
// of ==, read in a comparator handed to sort.Slice or slices.SortFunc or
// in a Less method, or compared in another package; and on one compared
// through what still holds the same time: a method answering a time,
// x.F.UTC() or x.F.Add(d), parentheses, a dereference on either side of
// Before or ==, an element of a slice, and time.Since or time.Until. It
// is refused too when it names a test, and taken on a pointer only held
// against nil, on a field only shown, and on one read only in a function
// handed to slices.ContainsFunc or slices.IndexFunc, which order nothing.
// Sub is counted with either side the field, Compare with the field its
// receiver, and comparators handed to sort.SliceStable and slices.MinFunc
// as well; a display row on a time.Parse, which is no field, is refused.
// An unbounded row, a range R21 of the time rules removed, is refused as a
// range of no known shape for every commit, 2, 3 or 4, and one with no
// "shown by" by the reading of the ledger. A
// deadline with no "shown by" is refused by the reading of the ledger,
// and one with no reason as a range of no known shape, as is <= now + 1h;
// a <= now + 5m row naming a test that is not TestLimit is refused, and
// an output row on a time of a decoded struct. A bound, a window, a
// deadline with its reason and its test, local: and output on a struct
// nothing decodes draw no sentence.
func TestALedgerHoldsATimeRowToItsField(t *testing.T) {
	root := plantFiles(t, map[string]string{
		"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"slices"
	"sort"
	"time"
)

type Event struct {
	A time.Time  'json:"a"'
	B time.Time  'json:"b"'
	C time.Time  'json:"c"'
	D time.Time  'json:"d"'
	E time.Time  'json:"e"'
	F time.Time  'json:"f"'
	G *time.Time 'json:"g"'
	H time.Time  'json:"h"'
	I time.Time  'json:"i"'
	J time.Time  'json:"j"'
	K time.Time  'json:"k"'
	L time.Time  'json:"l"'
	M time.Time  'json:"m"'
	N time.Time  'json:"n"'
	O time.Time  'json:"o"'
	P time.Time  'json:"p"'
	Q time.Time  'json:"q"'
	R time.Time  'json:"r"'
	S time.Time  'json:"s"'
	T time.Time  'json:"t"'
}

type Wire struct {
	At time.Time 'json:"at"'
}

type Shown struct {
	When time.Time 'json:"when"'
}

type Out struct {
	Sent time.Time 'json:"sent"'
}

func read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return w, err
}

func before(x Event, y time.Time) bool { return x.A.Before(y) }

func after(x Event, y time.Time) bool { return y.After(x.B) }

func same(x, y Event) bool { return x.C == y.C }

func bySort(es []Event) {
	sort.Slice(es, func(i, j int) bool { return es[i].D.Unix() < es[j].D.Unix() })
}

func bySlices(es []Event) {
	slices.SortFunc(es, func(a, b Event) int { return int(a.E.Unix() - b.E.Unix()) })
}

type byF []Event

func (s byF) Less(i, j int) bool { return s[i].F.Unix() < s[j].F.Unix() }

func present(x Event) bool { return x.G != nil }

func show(x Event, s Shown) string { return x.I.String() + s.When.String() }

type More struct {
	U  time.Time   'json:"u"'
	V  time.Time   'json:"v"'
	W  time.Time   'json:"w"'
	X  *time.Time  'json:"x"'
	Y  *time.Time  'json:"y"'
	Z  []time.Time 'json:"z"'
	AA time.Time   'json:"aa"'
	AB time.Time   'json:"ab"'
	AC time.Time   'json:"ac"'
	AD time.Time   'json:"ad"'
}

func utc(x More, y time.Time) bool { return x.U.UTC().Before(y) }

func added(x More, d time.Duration) bool { return x.V.Add(d).After(time.Now()) }

func paren(x More, y time.Time) bool { return (x.W).Equal(y) }

func deref(x More, y time.Time) bool { return y.Before(*x.X) }

func derefEq(x More, y time.Time) bool { return *x.Y == y }

func index(x More, y time.Time) bool { return x.Z[0].Before(y) }

func since(x More) time.Duration { return time.Since(x.AA) }

func until(x More) time.Duration { return time.Until(x.AB) }

func contains(ms []More) bool {
	return slices.ContainsFunc(ms, func(m More) bool { return m.AC.String() != "" })
}

func find(ms []More) int {
	return slices.IndexFunc(ms, func(m More) bool { return m.AD.String() != "" })
}

type Most struct {
	F time.Time 'json:"f"'
	G time.Time 'json:"g"'
	H time.Time 'json:"h"'
	K time.Time 'json:"k"'
	N time.Time 'json:"n"'
}

func sub(x Most, y time.Time) time.Duration { return x.F.Sub(y) }

func subArg(x Most, y time.Time) time.Duration { return y.Sub(x.G) }

func cmp(x Most, y time.Time) int { return x.H.Compare(y) }

func stable(ms []Most) {
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].K.Unix() < ms[j].K.Unix() })
}

func least(ms []Most) Most {
	return slices.MinFunc(ms, func(a, b Most) int { return int(a.N.Unix() - b.N.Unix()) })
}

func parsed(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

type Late struct {
	V time.Time 'json:"v"'
}
`,
		"internal/planted/planted_test.go": `package planted

import (
	"testing"
	"time"

	"planted/internal/testutil"
)

func TestLimitStamp(t *testing.T) { testutil.TimeEdges(time.Time{}) }
func TestStamp(t *testing.T)      {}
`,
		"internal/testutil/testutil.go": plantedTestutil,
		"internal/other/other.go": `package other

import (
	"time"

	"planted/internal/planted"
)

func Late(e planted.Event, t time.Time) bool { return e.H.After(t) }
`,
	})
	const ev = "internal/planted/planted.go Event time "
	const mo = "internal/planted/planted.go More time "
	const ms = "internal/planted/planted.go Most time "
	ledger := strings.Join([]string{
		ev + "A = display",
		ev + "B = display",
		ev + "C = display",
		ev + "D = display",
		ev + "E = display",
		ev + "F = display",
		ev + "G = display",
		ev + "H = display",
		ev + "I = display shown by TestLimitStamp",
		ev + "J = unbounded: PLAN-TIME commit 4 shown by TestLimitStamp",
		ev + "K = unbounded: PLAN-TIME commit 2 shown by TestLimitStamp",
		ev + "L = unbounded: PLAN-TIME commit 3 shown by TestLimitStamp",
		ev + "M = deadline: the next retry",
		ev + "N = deadline: shown by TestLimitStamp",
		ev + "O = <= now + 5m shown by TestStamp",
		ev + "P = <= now + 1h shown by TestLimitStamp",
		"internal/planted/planted.go Wire time At = output",
		ev + "Q = <= now + 5m shown by TestLimitStamp",
		ev + "R = [not_before, not_after] shown by TestLimitStamp",
		ev + "S = deadline: when the lease ends shown by TestLimitStamp",
		ev + "T = local: this program's own file",
		"internal/planted/planted.go Shown time When = display",
		"internal/planted/planted.go Out time Sent = output",
		mo + "U = display",
		mo + "V = display",
		mo + "W = display",
		mo + "X = display",
		mo + "Y = display",
		mo + "Z = display",
		mo + "AA = display",
		mo + "AB = display",
		mo + "AC = display",
		mo + "AD = display",
		ms + "F = display",
		ms + "G = display",
		ms + "H = display",
		ms + "K = display",
		ms + "N = display",
		"internal/planted/planted.go parsed time time.Parse(s) = display",
		"internal/planted/planted.go Late time V = unbounded: PLAN-TIME commit 3",
	}, "\n")
	problems, _ := check(t, root, ledger)
	const fix = "; give the row a bound and a test"
	const shapes = ", which is not <= now + 5m, [lo, hi], display, output, local: or deadline: with its reason"
	want := []string{
		"ledger.txt:13: " + ev + "M has no \"shown by\"",
		"ledger.txt:40: internal/planted/planted.go Late time V has no \"shown by\"",
		"ledger.txt:1: " + ev + "A says display, but the field is compared or ordered at internal/planted/planted.go:51 (Before)" + fix,
		"ledger.txt:2: " + ev + "B says display, but the field is compared or ordered at internal/planted/planted.go:53 (After)" + fix,
		"ledger.txt:3: " + ev + "C says display, but the field is compared or ordered at internal/planted/planted.go:55 (==)" + fix,
		"ledger.txt:4: " + ev + "D says display, but the field is compared or ordered at internal/planted/planted.go:58 (a comparator handed to sort.Slice)" + fix,
		"ledger.txt:5: " + ev + "E says display, but the field is compared or ordered at internal/planted/planted.go:62 (a comparator handed to slices.SortFunc)" + fix,
		"ledger.txt:6: " + ev + "F says display, but the field is compared or ordered at internal/planted/planted.go:67 (a Less method)" + fix,
		"ledger.txt:8: " + ev + "H says display, but the field is compared or ordered at internal/other/other.go:9 (After)" + fix,
		"ledger.txt:9: " + ev + "I says display and names a test; a field that is only shown has none",
		"ledger.txt:10: " + ev + "J has the range \"unbounded: PLAN-TIME commit 4\"" + shapes,
		"ledger.txt:11: " + ev + "K has the range \"unbounded: PLAN-TIME commit 2\"" + shapes,
		"ledger.txt:12: " + ev + "L has the range \"unbounded: PLAN-TIME commit 3\"" + shapes,
		"ledger.txt:14: " + ev + "N has the range \"deadline:\"" + shapes,
		"ledger.txt:15: " + ev + "O names TestStamp, which does not start with TestLimit",
		"ledger.txt:16: " + ev + "P has the range \"<= now + 1h\"" + shapes,
		"ledger.txt:17: internal/planted/planted.go Wire time At says output, but planted.Wire is decoded: it is reached from json.Unmarshal at internal/planted/planted.go read; give the row a range and a test",
		"ledger.txt:24: " + mo + "U says display, but the field is compared or ordered at internal/planted/planted.go:86 (Before)" + fix,
		"ledger.txt:25: " + mo + "V says display, but the field is compared or ordered at internal/planted/planted.go:88 (After)" + fix,
		"ledger.txt:26: " + mo + "W says display, but the field is compared or ordered at internal/planted/planted.go:90 (Equal)" + fix,
		"ledger.txt:27: " + mo + "X says display, but the field is compared or ordered at internal/planted/planted.go:92 (Before)" + fix,
		"ledger.txt:28: " + mo + "Y says display, but the field is compared or ordered at internal/planted/planted.go:94 (==)" + fix,
		"ledger.txt:29: " + mo + "Z says display, but the field is compared or ordered at internal/planted/planted.go:96 (Before)" + fix,
		"ledger.txt:30: " + mo + "AA says display, but the field is compared or ordered at internal/planted/planted.go:98 (time.Since)" + fix,
		"ledger.txt:31: " + mo + "AB says display, but the field is compared or ordered at internal/planted/planted.go:100 (time.Until)" + fix,
		"ledger.txt:34: " + ms + "F says display, but the field is compared or ordered at internal/planted/planted.go:118 (Sub)" + fix,
		"ledger.txt:35: " + ms + "G says display, but the field is compared or ordered at internal/planted/planted.go:120 (Sub)" + fix,
		"ledger.txt:36: " + ms + "H says display, but the field is compared or ordered at internal/planted/planted.go:122 (Compare)" + fix,
		"ledger.txt:37: " + ms + "K says display, but the field is compared or ordered at internal/planted/planted.go:125 (a comparator handed to sort.SliceStable)" + fix,
		"ledger.txt:38: " + ms + "N says display, but the field is compared or ordered at internal/planted/planted.go:129 (a comparator handed to slices.MinFunc)" + fix,
		"ledger.txt:39: internal/planted/planted.go parsed time time.Parse(s) says display, but only a struct's field can be display",
		ev + "M has no row in ledger.txt; add one saying how far ahead the code takes it, <= now + 5m, or its window, with the TestLimit test that shows it, or a deadline with its use and its test, or display, output or local: with why",
		"internal/planted/planted.go Late time V has no row in ledger.txt; add one saying how far ahead the code takes it, <= now + 5m, or its window, with the TestLimit test that shows it, or a deadline with its use and its test, or display, output or local: with why",
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

// TestADecodeTargetIsFollowedAcrossPackages plants a decode helper in one
// package, codec.Decode, which hands its any parameter to a Decoder, a
// helper in a second, fetch.Get, which hands its own to codec.Decode, and
// two structs in a third, one passed to each. Every field of both, an
// integer and a time, counts as decoded, the sentence naming the route.
func TestADecodeTargetIsFollowedAcrossPackages(t *testing.T) {
	root := plantFiles(t, map[string]string{
		"internal/codec/codec.go": `package codec

import (
	"bytes"
	"encoding/json"
)

func Decode(data []byte, v any) error { return json.NewDecoder(bytes.NewReader(data)).Decode(v) }
`,
		"internal/fetch/fetch.go": `package fetch

import "planted/internal/codec"

func Get(b []byte, out any) error { return codec.Decode(b, out) }
`,
		"internal/answer/answer.go": `package answer

import (
	"time"

	"planted/internal/codec"
	"planted/internal/fetch"
)

type Answer struct {
	N  int       'json:"n"'
	At time.Time 'json:"at"'
}

type Later struct {
	N  int       'json:"n"'
	At time.Time 'json:"at"'
}

func ask(b []byte) (Answer, error) {
	var s Answer
	err := codec.Decode(b, &s)
	return s, err
}

func later(b []byte) (Later, error) {
	var l Later
	err := fetch.Get(b, &l)
	return l, err
}
`,
	})
	ledger := strings.Join([]string{
		"internal/answer/answer.go Answer int N int = output",
		"internal/answer/answer.go Answer time At = output",
		"internal/answer/answer.go Later int N int = output",
		"internal/answer/answer.go Later time At = output",
	}, "\n")
	problems, _ := check(t, root, ledger)
	const once = "Decoder.Decode at internal/codec/codec.go Decode through the any parameter of Decode"
	const fix = "; give the row a range and a test"
	want := []string{
		"ledger.txt:1: internal/answer/answer.go Answer int N int says output, but answer.Answer is decoded: it is reached from " + once + fix,
		"ledger.txt:2: internal/answer/answer.go Answer time At says output, but answer.Answer is decoded: it is reached from " + once + fix,
		"ledger.txt:3: internal/answer/answer.go Later int N int says output, but answer.Later is decoded: it is reached from " + once + " through the any parameter of Get" + fix,
		"ledger.txt:4: internal/answer/answer.go Later time At says output, but answer.Later is decoded: it is reached from " + once + " through the any parameter of Get" + fix,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
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
// knock_max_bytes, and inlineMax as inline_max, the smaller of max_bytes
// and relayapi.MaxPageBytes, on the strength of their comments and their
// tests.
var capSettings = map[string]string{
	"max_bytes":       "s.cfg.MaxBytes",
	"knock_max_bytes": "s.knockMax()",
	"inline_max":      "s.inlineMax()",
}

// capBounds is the table of bounds for the tree, keyed by the method's
// package directory and its name as the ledger writes a function. Each
// entry is held to the tree when a one-of row's walk reaches it. The test
// of the tree as it stands fails on an entry no one-of row's walk
// reaches.
var capBounds = map[string]capBound{
	"internal/relay (*Server).postCap":    {body: "s.inlineMax() + relayapi.FramingAllowance", name: "inline_max"},
	"internal/relay (*Server).forwardCap": {body: "s.inlineMax() + relayapi.FramingAllowance", name: "inline_max"},
	"internal/relay (*Server).knockCap":   {body: "s.knockMax() + relayapi.FramingAllowance", name: "knock_max_bytes"},
}

// spelledBounds are the cap sites whose <= row may name a bound that
// reads a parameter, keyed by the site's key, each with the reason. Any
// other such row is refused: a parameter's value is its callers', and the
// row says the set they pass. The test of the tree as it stands fails on
// an entry no <= row takes.
var spelledBounds = map[string]string{
	"internal/client/client.go readCapped cap io.LimitReader(body, hold + 1)": "attempt passes its hold, and attempt's callers pass locals read from the relay's health answer (client.go listingCap, through holdFor, never above relayapi.MaxListingHold), which no walk can render, and the row names the hold each caller computes",
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
	compared := tree.compared()
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
	// An int site of a struct's field by its position, and a row by its
	// key, so that a time made of an integer is read off the int row it
	// comes from.
	intAt := map[string]site{}
	for _, s := range sites {
		if s.kind == "int" && s.typeName != "" {
			intAt[s.pos.String()] = s
		}
	}
	rowOf := map[string]row{}
	for _, r := range rows {
		rowOf[r.key] = r
	}
	// A field's row by the field's declaration, so that a display field
	// copied into another is read against the other's row.
	rngAt := map[string]string{}
	for _, s := range sites {
		if r, ok := rowOf[s.key]; ok && s.kind == "time" && s.typeName != "" {
			rngAt[s.pos.String()] = r.rng
		}
	}
	// A field a display field is copied into holds the same time under
	// another name, and is a site of its own with a row of its own.
	var display []string
	for _, s := range sites {
		if r, ok := rowOf[s.key]; ok && s.kind == "time" && r.rng == "display" {
			display = append(display, s.pos.String())
		}
	}
	for _, s := range tree.copiedInto(display) {
		if _, dup := byKey[s.key]; dup {
			continue
		}
		sites = append(sites, s)
		byKey[s.key] = s
		if r, ok := rowOf[s.key]; ok {
			rngAt[s.pos.String()] = r.rng
		}
	}
	shown := tree.displayUses(func(pos string) string { return rngAt[pos] })
	calls := tree.testutilCalls()
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
		} else if s.kind == "time" {
			// A time row is a bound with its test, a window with its
			// test, a deadline with its use and its test, a field shown
			// and never compared, output, or this program's own clock or
			// a value a check already held.
			reason := func(prefix string) bool {
				return strings.HasPrefix(r.rng, prefix) && strings.TrimSpace(strings.TrimPrefix(r.rng, prefix)) != ""
			}
			// A time made of an integer from outside is from outside: an
			// argument that reads a field whose int row gives it a range,
			// rather than output or local:, may not be local: here.
			// A local: on a field a decode fills names the rule that holds
			// it and the test that shows it; the reason alone is prose the
			// walk cannot hold, and what a decode fills came from a file or
			// a wire whose writer it cannot see.
			if strings.HasPrefix(r.rng, "local:") && s.typeName != "" {
				if why, is := decoded[s.typeName]; is {
					m := localTimeRule.FindStringSubmatch(r.rng)
					if m == nil {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says local: with a reason the walk cannot hold, but %s is decoded: it is reached from %s; say local: held by <Rule> at <point> shown by <TestLimit...>, or give the row a bound and a test", r.line, r.key, short(s.typeName), why))
						continue
					}
					rule := m[1]
					if k := strings.LastIndex(rule, "."); k >= 0 {
						rule = rule[k+1:]
					}
					if !funcs[rule] {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names the rule %s, which is not a function in the tree", r.line, r.key, m[1]))
						continue
					}
					if r.test == "" {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names the rule %s and no test; the rule's test shows it holding the value at %s", r.line, r.key, m[1], m[2]))
						continue
					}
					// Every function of the tree that writes the field is
					// named in the row, so that what holds it is all that
					// puts a value there; a writer the row does not name is
					// another path.
					var unnamed []string
					for _, w := range tree.fieldWriters(s.pos.String()) {
						// The name as a whole word, not the tail of another
						// qualified name: Other.Stamp does not name Stamp.
						if !regexp.MustCompile(`(^|[^A-Za-z0-9_.])` + regexp.QuoteMeta(w.name) + `\b`).MatchString(r.rng) {
							unnamed = append(unnamed, w.name+" at "+w.at)
						}
					}
					if len(unnamed) > 0 {
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says it is held by %s, but the field is written in %s, which the row does not name; name every writer, or give the row a bound and a test", r.line, r.key, m[1], strings.Join(unnamed, ", ")))
						continue
					}
				}
			}
			if strings.HasPrefix(r.rng, "local:") {
				var outside []string
				for _, pos := range s.from {
					is, ok := intAt[pos]
					if !ok {
						continue
					}
					ir, ok := rowOf[is.key]
					if ok && (ir.rng == "output" || strings.HasPrefix(ir.rng, "local:")) {
						continue
					}
					outside = append(outside, is.key)
				}
				if len(outside) > 0 {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says local:, but it makes a time of an integer from outside, %s; give it a bound and a test", r.line, r.key, strings.Join(outside, ", ")))
					continue
				}
			}
			switch {
			case r.rng == "display":
				if s.typeName == "" {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says display, but only a struct's field can be display", r.line, r.key))
				} else if where := compared[s.pos.String()]; len(where) > 0 {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says display, but the field is compared or ordered at %s; give the row a bound and a test", r.line, r.key, strings.Join(where, ", ")))
				} else if where := shown[s.pos.String()]; len(where) > 0 {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says display, but the field is used other than shown at %s; a display field reaches a format, a print, a marshal, a field whose row is display or output, or a helper that only shows it, so give the row a bound and a test", r.line, r.key, strings.Join(where, ", ")))
				} else if r.test != "" {
					problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s says display and names a test; a field that is only shown has none", r.line, r.key))
				}
				continue
			case r.rng == "output":
			case reason("local:"):
				if r.test == "" {
					continue
				}
			case reason("deadline:"), timeRanges.MatchString(r.rng):
				// A bound's test feeds the values the grammar lists, and the
				// walk holds it to doing so through testutil.TimeEdges, or a
				// deadline's through each of the two it names.
				if tests[r.test] == 1 && strings.HasPrefix(r.test, "TestLimit") {
					c := calls[r.test]
					deadline := strings.HasPrefix(r.rng, "deadline:")
					if !c["TimeEdges"] && !(deadline && c["EarliestInstant"] && c["PastYear9999"]) {
						want := "testutil.TimeEdges"
						if deadline {
							want += ", or each of testutil.EarliestInstant and testutil.PastYear9999"
						}
						problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s names %s, which does not call %s; a bound's test feeds the values the grammar lists through it", r.line, r.key, r.test, want))
						continue
					}
				}
			default:
				problems = append(problems, fmt.Sprintf("ledger.txt:%d: %s has the range %q, which is not <= now + 5m, [lo, hi], display, output, local: or deadline: with its reason", r.line, r.key, r.rng))
				continue
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
		if s.kind == "time" {
			problems = append(problems, fmt.Sprintf("%s has no row in ledger.txt; add one saying how far ahead the code takes it, <= now + 5m, or its window, with the TestLimit test that shows it, or a deadline with its use and its test, or display, output or local: with why", s.key))
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

	// walk is what the decodes reach, found once (see decodes).
	walk *decodeWalk

	// candidates is, by its declaration, every time field of a named
	// struct that is no site of its own, for copiedInto.
	candidates map[string]site
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
			Instances:  map[*ast.Ident]types.Instance{},
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
				s == "time.Parse" || s == "time.ParseInLocation" ||
				s == "time.Unix" || s == "time.UnixMilli" || s == "time.UnixMicro" ||
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
// duration flag on a FlagSet; every time from outside, a field in such a
// struct, tagged or not, of a type that holds a time (see timeType), a
// field holding one in any struct a decode reaches (see decodes and
// timesIn), a decode straight into one, an UnmarshalText, UnmarshalJSON or
// UnmarshalBinary called on one, and a time.Parse, time.ParseInLocation,
// time.Unix, time.UnixMilli or time.UnixMicro; and the string cuts and
// caps.
func (tr *tree) sites() []site {
	var out []site
	decodedTimes := tr.decodes().times
	at := func(id *ast.Ident) string { return tr.fset.Position(id.Pos()).String() }
	candidates := map[string]site{}
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
					// A struct with a json tag, or one a decode reaches that
					// holds a time: untagged, embedded, or a generic struct
					// given a time for its type argument.
					tagged := jsonTagged(x)
					reached := false
					for _, fl := range x.Fields.List {
						for _, name := range fieldNames(fl) {
							if _, is := decodedTimes[at(name)]; is {
								reached = true
							}
						}
					}
					if !tagged && !reached {
						// A named struct's time field is a site too when a
						// site's time is copied into it (see copiedInto).
						if ts := declaring(stack, x); ts != nil && enclosingFunc(stack) == nil {
							if obj := p.info.Defs[ts.Name]; obj != nil {
								for _, fl := range x.Fields.List {
									if !timeType(p.info.TypeOf(fl.Type)) {
										continue
									}
									for _, name := range fieldNames(fl) {
										candidates[at(name)] = site{
											key:      fmt.Sprintf("%s %s time %s", rel, ts.Name.Name, name.Name),
											kind:     "time",
											pos:      tr.fset.Position(name.Pos()),
											typeName: fullName(obj),
										}
									}
								}
							}
						}
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
						// A type that holds a time, alone or in a pointer, a
						// slice, an array or a map (see timeType), or a field
						// a decode reaches as one.
						isTime := tagged && timeType(p.info.TypeOf(fl.Type))
						for _, name := range fieldNames(fl) {
							if _, is := decodedTimes[at(name)]; is {
								isTime = true
							}
						}
						if isTime {
							for _, name := range fieldNames(fl) {
								out = append(out, site{
									key:      fmt.Sprintf("%s %s time %s", rel, enclosing, name.Name),
									kind:     "time",
									pos:      tr.fset.Position(name.Pos()),
									typeName: typeName,
								})
							}
							continue
						}
						// An integer field, a pointer to one, or a map or slice
						// whose values are integers, which the decoder fills
						// with numbers all the same.
						if !tagged || !integerType(p.info.TypeOf(fl.Type)) && !integerElems(p.info.TypeOf(fl.Type)) {
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
					if text, is := timeCall(p, x); is {
						enclosing := "a package-level declaration"
						if fd := enclosingFunc(stack); fd != nil {
							enclosing = funcName(fd)
						}
						out = append(out, site{
							key:  fmt.Sprintf("%s %s time %s", rel, enclosing, text),
							kind: "time",
							pos:  tr.fset.Position(x.Pos()),
							from: tr.fieldsRead(p, x),
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
	tr.candidates = candidates
	// A decode straight into a time.
	out = append(out, tr.decodes().sites...)
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
// json.Unmarshal or Decoder.Decode, or a generic helper whose type
// parameter does, and every type reachable from one through fields,
// slices, arrays, maps and pointers; the value says how.
func (tr *tree) decoded() map[string]string { return tr.decodes().types }

// decodeWalk is what the program's decodes reach.
type decodeWalk struct {
	// types is decoded's answer.
	types map[string]string
	// times is every field of a type that holds a time (see timeType) in
	// a struct a decode reaches, tagged or not, embedded or not, a generic
	// struct's field by the type argument it is given, by the position of
	// its declaration; the value says how it is reached.
	times map[string]string
	// sites is every decode straight into a type that holds a time, which
	// no field names: a json.RawMessage or a []byte decoded later into a
	// *time.Time, the decode itself is the site.
	sites []site
}

// decodeTarget is one value a decode fills, and the call that fills it.
type decodeTarget struct {
	typ  types.Type
	why  string
	call *ast.CallExpr
	p    *pkg
	fd   *ast.FuncDecl
	rel  string
}

// decodes follows every decode in the tree: json.Unmarshal and
// (*json.Decoder).Decode called, a helper's parameter of interface type
// that reaches one followed to its callers, and a generic helper's type
// parameter that reaches one followed by its type argument at each call.
// Every json.RawMessage or []byte the program decodes later is decoded by
// one of these calls, so following the calls follows the bytes. A decode
// function used as a value, rather than called, is refused: the walk
// cannot follow what it holds.
func (tr *tree) decodes() *decodeWalk {
	if tr.walk != nil {
		return tr.walk
	}
	// A decoding parameter: a function, by its full name, and the index
	// of a parameter that reaches a decoder. Found to a fixpoint, since a
	// helper may call a helper. The name and not the object, since each
	// package is checked on its own and a helper seen from another
	// package, wire.Decode from everywhere, is another object for it. A
	// generic function's type parameter is one too, by its index among
	// the function's type parameters, or among its receiver's.
	type param struct {
		fn    string
		index int
		kind  string // "" a parameter, "type" a type parameter, "recv" a receiver's
	}
	reaches := map[param]string{}
	direct := map[string]bool{} // a concrete argument already taken, by type and route
	var targets []decodeTarget
	// typeParams registers every type parameter of fd that t mentions as a
	// decoding type parameter, and says whether there was one.
	typeParams := func(p *pkg, fd *ast.FuncDecl, t types.Type, why string) (found, changed bool) {
		if fd == nil {
			return false, false
		}
		fn, ok := p.info.Defs[fd.Name].(*types.Func)
		if !ok {
			return false, false
		}
		sig := fn.Type().(*types.Signature)
		mentions(t, func(tp *types.TypeParam) {
			for _, list := range []struct {
				l    *types.TypeParamList
				kind string
			}{{sig.TypeParams(), "type"}, {sig.RecvTypeParams(), "recv"}} {
				for i := 0; i < list.l.Len(); i++ {
					if list.l.At(i).Obj() == tp.Obj() {
						found = true
						k := param{fn.FullName(), i, list.kind}
						if _, known := reaches[k]; !known {
							reaches[k] = why
							changed = true
						}
					}
				}
			}
		})
		return found, changed
	}
	record := func(p *pkg, fd *ast.FuncDecl, rel string, call *ast.CallExpr, arg ast.Expr, why string) {
		// A parameter of the enclosing function of interface type is a
		// decoding parameter; anything else is a target now.
		if id, ok := arg.(*ast.Ident); ok {
			if v, ok := p.info.Uses[id].(*types.Var); ok && fd != nil {
				if fn, ok := p.info.Defs[fd.Name].(*types.Func); ok {
					sig := fn.Type().(*types.Signature)
					for i := 0; i < sig.Params().Len(); i++ {
						if sig.Params().At(i) == v && types.IsInterface(v.Type()) {
							reaches[param{fn.FullName(), i, ""}] = why
							return
						}
					}
				}
			}
		}
		// A type parameter of the enclosing function is followed to its
		// type arguments; what the target holds besides it is a target all
		// the same.
		typ := p.info.TypeOf(arg)
		typeParams(p, fd, typ, why)
		targets = append(targets, decodeTarget{typ, why, call, p, fd, rel})
	}
	jsonDecoder := func(p *pkg, id *ast.Ident) (string, bool) {
		fn, ok := p.info.Uses[id].(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "encoding/json" {
			return "", false
		}
		switch fn.FullName() {
		case "encoding/json.Unmarshal":
			return "json.Unmarshal", true
		case "(*encoding/json.Decoder).Decode":
			return "(*json.Decoder).Decode", true
		}
		return "", false
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
					name, ok := jsonDecoder(p, sel.Sel)
					if !ok {
						return true
					}
					where := rel + " " + enclosingName(fd)
					switch {
					case name == "json.Unmarshal" && len(call.Args) == 2:
						record(p, fd, rel, call, call.Args[1], "json.Unmarshal at "+where)
					case name == "(*json.Decoder).Decode" && len(call.Args) == 1:
						record(p, fd, rel, call, call.Args[0], "Decoder.Decode at "+where)
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
				rel := filepath.ToSlash(mustRel(tr.root, tr.fset.Position(f.Pos()).Filename))
				for _, decl := range f.Decls {
					fd, _ := decl.(*ast.FuncDecl)
					ast.Inspect(decl, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok {
							return true
						}
						id := calleeIdent(call.Fun)
						if id == nil {
							return true
						}
						callee, ok := p.info.Uses[id].(*types.Func)
						if !ok {
							return true
						}
						name := callee.Origin().FullName()
						for pr, why := range reaches {
							if pr.fn != name {
								continue
							}
							if pr.kind != "" {
								// A generic helper: its type argument at this
								// call is the target, or a type parameter of the
								// caller's, followed in turn.
								arg := typeArg(p, call, id, pr.kind, pr.index)
								if arg == nil {
									continue
								}
								through := why + " through the type argument of " + callee.Name()
								if generic, more := typeParams(p, fd, arg, through); generic {
									changed = changed || more
									continue
								}
								key := types.TypeString(arg, nil) + " at " + through
								if !direct[key] {
									direct[key] = true
									targets = append(targets, decodeTarget{arg, through, call, p, fd, rel})
									changed = true
								}
								continue
							}
							if pr.index >= len(call.Args) {
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
												if _, known := reaches[param{fn.FullName(), i, ""}]; !known {
													reaches[param{fn.FullName(), i, ""}] = through
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
							if generic, more := typeParams(p, fd, typ, through); generic {
								changed = changed || more
							}
							key := types.TypeString(typ, nil) + " at " + through
							if !direct[key] {
								direct[key] = true
								targets = append(targets, decodeTarget{typ, through, call, p, fd, rel})
								changed = true
							}
						}
						return true
					})
				}
			}
		}
	}
	// A decode, or a helper that reaches one, taken as a value rather than
	// called: what it holds is called where the walk cannot see it.
	helpers := map[string]bool{}
	for pr := range reaches {
		helpers[pr.fn] = true
	}
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			rel := filepath.ToSlash(mustRel(tr.root, tr.fset.Position(f.Pos()).Filename))
			called := map[*ast.Ident]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id := calleeIdent(call.Fun); id != nil {
						called[id] = true
					}
				}
				return true
			})
			for _, decl := range f.Decls {
				fd, _ := decl.(*ast.FuncDecl)
				ast.Inspect(decl, func(n ast.Node) bool {
					id, ok := n.(*ast.Ident)
					if !ok || called[id] {
						return true
					}
					name, is := jsonDecoder(p, id)
					if !is {
						fn, ok := p.info.Uses[id].(*types.Func)
						if !ok || !helpers[fn.Origin().FullName()] {
							return true
						}
						name = fn.Name()
					}
					tr.problems = append(tr.problems, fmt.Sprintf("%s:%d: %s takes %s as a value rather than calling it; the walk follows a decode only where it is called, so call it there", rel, tr.fset.Position(id.Pos()).Line, enclosingName(fd), name))
					return true
				})
			}
		}
	}
	w := &decodeWalk{types: map[string]string{}, times: map[string]string{}}
	for _, tg := range targets {
		reach(tg.typ, tg.why, w.types, map[string]bool{})
		tr.timesIn(tg.typ, tg.why, w.times, map[string]bool{})
		// A decode straight into a time, which no field of a struct names.
		if tg.call == nil || !timeType(tg.typ) {
			continue
		}
		generic := false
		mentions(tg.typ, func(*types.TypeParam) { generic = true })
		if generic {
			continue
		}
		w.sites = append(w.sites, site{
			key:  fmt.Sprintf("%s %s time %s", tg.rel, enclosingName(tg.fd), types.ExprString(tg.call)),
			kind: "time",
			pos:  tr.fset.Position(tg.call.Pos()),
		})
	}
	// One call reached by two routes is one site; the order is the tree's.
	sort.Slice(w.sites, func(i, j int) bool {
		a, b := w.sites[i].pos, w.sites[j].pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Offset < b.Offset
	})
	w.sites = slices.CompactFunc(w.sites, func(a, b site) bool { return a.pos == b.pos })
	tr.walk = w
	return w
}

// timesIn adds, by the position of its declaration, every field of a type
// that holds a time in a struct reachable from t: tagged or not, embedded
// or not, exported or not, since a type with its own UnmarshalJSON or
// UnmarshalText fills what it likes. A generic struct's field is read with
// the type argument it was given. A field that holds a time is not looked
// inside; it is the site. A type outside the module is not followed.
func (tr *tree) timesIn(t types.Type, why string, out map[string]string, seen map[string]bool) {
	if t == nil {
		return
	}
	switch x := types.Unalias(t).(type) {
	case *types.Pointer:
		tr.timesIn(x.Elem(), why, out, seen)
	case *types.Slice:
		tr.timesIn(x.Elem(), why, out, seen)
	case *types.Array:
		tr.timesIn(x.Elem(), why, out, seen)
	case *types.Map:
		tr.timesIn(x.Key(), why, out, seen)
		tr.timesIn(x.Elem(), why, out, seen)
	case *types.Named:
		pk := x.Obj().Pkg()
		if pk == nil || (pk.Path() != tr.modulePath && !strings.HasPrefix(pk.Path(), tr.modulePath+"/")) {
			return
		}
		key := types.TypeString(x, nil)
		if seen[key] {
			return
		}
		seen[key] = true
		// The instance's own underlying type, its fields given the type
		// arguments: Box[time.Time]'s V is a time where Box[T]'s is a T.
		tr.timesIn(x.Underlying(), why+" through "+short(key), out, seen)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			f := x.Field(i)
			if timeType(f.Type()) {
				pos := tr.fset.Position(f.Pos()).String()
				if _, ok := out[pos]; !ok {
					out[pos] = why
				}
				continue
			}
			tr.timesIn(f.Type(), why, out, seen)
		}
	}
}

// mentions calls f with every type parameter t is built from.
func mentions(t types.Type, f func(*types.TypeParam)) {
	if t == nil {
		return
	}
	switch x := types.Unalias(t).(type) {
	case *types.TypeParam:
		f(x)
	case *types.Pointer:
		mentions(x.Elem(), f)
	case *types.Slice:
		mentions(x.Elem(), f)
	case *types.Array:
		mentions(x.Elem(), f)
	case *types.Map:
		mentions(x.Key(), f)
		mentions(x.Elem(), f)
	case *types.Named:
		args := x.TypeArgs()
		for i := 0; i < args.Len(); i++ {
			mentions(args.At(i), f)
		}
	}
}

// calleeIdent is the name a call's function is written with: a function,
// a method or field by its selector, either with its type arguments, in
// parentheses or not.
func calleeIdent(fun ast.Expr) *ast.Ident {
	for {
		switch x := fun.(type) {
		case *ast.Ident:
			return x
		case *ast.SelectorExpr:
			return x.Sel
		case *ast.IndexExpr:
			fun = x.X
		case *ast.IndexListExpr:
			fun = x.X
		case *ast.ParenExpr:
			fun = x.X
		default:
			return nil
		}
	}
}

// typeArg is the type argument a call gives a generic function's type
// parameter, by its index, or a generic type's method's receiver's.
func typeArg(p *pkg, call *ast.CallExpr, id *ast.Ident, kind string, index int) types.Type {
	if kind == "type" {
		inst, ok := p.info.Instances[id]
		if !ok || inst.TypeArgs == nil || index >= inst.TypeArgs.Len() {
			return nil
		}
		return inst.TypeArgs.At(index)
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	sn := p.info.Selections[sel]
	if sn == nil {
		return nil
	}
	recv := sn.Recv()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	if !ok || index >= named.TypeArgs().Len() {
		return nil
	}
	return named.TypeArgs().At(index)
}

// compared is every time field that is compared or ordered somewhere in
// the tree, by the position of its declaration, with where; comparedAs
// says what counts and what it cannot see. A field is known by where it
// is declared, since each package is checked on its own and the same
// field seen from another package is another object.
func (tr *tree) compared() map[string][]string {
	out := map[string][]string{}
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			var stack []ast.Node
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				sn := p.info.Selections[sel]
				if sn == nil || sn.Kind() != types.FieldVal || !timeType(sn.Obj().Type()) {
					return true
				}
				if how := comparedAs(p, stack); how != "" {
					decl := tr.fset.Position(sn.Obj().Pos()).String()
					at := tr.fset.Position(sel.Pos())
					where := fmt.Sprintf("%s:%d (%s)", filepath.ToSlash(mustRel(tr.root, at.Filename)), at.Line, how)
					if !slices.Contains(out[decl], where) {
						out[decl] = append(out[decl], where)
					}
				}
				return true
			})
		}
	}
	return out
}

// comparedAs says how the selector at the top of the stack is compared,
// or "" when it is not. The selector is followed up through what still
// holds the same time: parentheses, a pointer's dereference, an index
// into a slice or map of times, and a method of time.Time that answers
// another time (x.F.UTC(), x.F.Add(d)); the comparison is then sought
// where that ends. This is not every way a time can be compared, and a
// display row is read against its field for the rest; among them, a copy
// into a local or into a struct with no row, a comparison through Unix or
// UnixNano, a defined type converted back to time.Time, a method promoted
// from an embedded time, a whole struct compared, reflect.DeepEqual, a
// comparator not written in the call that sorts, and a helper of the
// tree's own that compares a time it is handed.
func comparedAs(p *pkg, stack []ast.Node) string {
	i := len(stack) - 1
	cur := stack[i].(ast.Expr)
	for i >= 1 {
		switch parent := stack[i-1].(type) {
		case *ast.ParenExpr, *ast.StarExpr:
			cur, i = parent.(ast.Expr), i-1
			continue
		case *ast.IndexExpr:
			if parent.X == cur {
				cur, i = parent, i-1
				continue
			}
		case *ast.SelectorExpr:
			// A method of time.Time that answers a time, called.
			if parent.X == cur && i >= 2 && !timeOperators[parent.Sel.Name] {
				if call, ok := stack[i-2].(*ast.CallExpr); ok && call.Fun == parent && timeType(p.info.TypeOf(call)) && timeType(p.info.TypeOf(cur)) {
					cur, i = call, i-2
					continue
				}
			}
		}
		break
	}
	if i >= 1 {
		switch parent := stack[i-1].(type) {
		case *ast.SelectorExpr:
			// x.F.Before(y)
			if parent.X == cur && timeOperators[parent.Sel.Name] {
				return parent.Sel.Name
			}
		case *ast.CallExpr:
			for _, a := range parent.Args {
				if a != cur {
					continue
				}
				// y.Before(x.F)
				if fun, ok := parent.Fun.(*ast.SelectorExpr); ok && timeOperators[fun.Sel.Name] && timeType(p.info.TypeOf(fun.X)) {
					return fun.Sel.Name
				}
				// time.Since(x.F), time.Until(x.F)
				if fn := calleeFunc(p, parent); fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "time" && (fn.Name() == "Since" || fn.Name() == "Until") {
					return "time." + fn.Name()
				}
			}
		case *ast.BinaryExpr:
			// A time compared as a value; a pointer, slice or map of
			// them held against nil asks only whether it is there.
			switch types.Unalias(p.info.TypeOf(cur)).Underlying().(type) {
			case *types.Pointer, *types.Slice, *types.Map:
				return ""
			}
			switch parent.Op {
			case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
				return parent.Op.String()
			}
		}
	}
	for k := len(stack) - 2; k >= 0; k-- {
		switch x := stack[k].(type) {
		case *ast.FuncLit:
			if k == 0 {
				continue
			}
			call, ok := stack[k-1].(*ast.CallExpr)
			if !ok {
				continue
			}
			if fn := calleeFunc(p, call); fn != nil && fn.Pkg() != nil && orderingFuncs[fn.Pkg().Path()+"."+fn.Name()] {
				return "a comparator handed to " + fn.Pkg().Name() + "." + fn.Name()
			}
		case *ast.FuncDecl:
			if x.Recv != nil && x.Name.Name == "Less" {
				return "a Less method"
			}
			return ""
		}
	}
	return ""
}

// embeddedName is the identifier an embedded field is known by: the type's
// own name, through a pointer and a package.
func embeddedName(e ast.Expr) *ast.Ident {
	switch x := e.(type) {
	case *ast.StarExpr:
		return embeddedName(x.X)
	case *ast.SelectorExpr:
		return x.Sel
	case *ast.IndexExpr:
		return embeddedName(x.X)
	case *ast.IndexListExpr:
		return embeddedName(x.X)
	case *ast.Ident:
		return x
	}
	return ast.NewIdent(types.ExprString(e))
}

// orderingFuncs are the functions of sort and slices whose function
// argument orders: a time read there orders something.
var orderingFuncs = map[string]bool{
	"sort.Slice": true, "sort.SliceStable": true, "sort.SliceIsSorted": true, "sort.Search": true,
	"slices.SortFunc": true, "slices.SortStableFunc": true, "slices.IsSortedFunc": true,
	"slices.MinFunc": true, "slices.MaxFunc": true, "slices.BinarySearchFunc": true, "slices.CompareFunc": true,
}

// calleeFunc is the function a call names, or nil.
func calleeFunc(p *pkg, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	case *ast.IndexExpr:
		// slices.SortFunc[...] written with its instance
		if s, ok := fun.X.(*ast.SelectorExpr); ok {
			id = s.Sel
		}
	case *ast.IndexListExpr:
		// and with more than one type argument
		if s, ok := fun.X.(*ast.SelectorExpr); ok {
			id = s.Sel
		}
	}
	if id == nil {
		return nil
	}
	fn, _ := p.info.Uses[id].(*types.Func)
	return fn
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
		// output, local: and a time shown and never compared name no
		// test; every other row names one.
		if !has && rng != "output" && rng != "display" && !strings.HasPrefix(rng, "local:") {
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

// timeType is a type that holds a time: time.Time; a struct embedding
// one, which decodes as one through the promoted method; a type defined
// over time.Time, which does not decode from a string at all but is taken
// all the same, since it holds one; or a pointer, slice, array or map of
// these, the map by its key as well as its value, since a time key
// decodes from its text.
func timeType(t types.Type) bool {
	if t == nil {
		return false
	}
	// By the underlying type, so that a named slice or pointer of times,
	// type Stamps []time.Time, is one as its spelling would be.
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Pointer:
		return timeType(u.Elem())
	case *types.Slice:
		return timeType(u.Elem())
	case *types.Array:
		return timeType(u.Elem())
	case *types.Map:
		return timeType(u.Key()) || timeType(u.Elem())
	}
	return isTime(t, 0)
}

// isTime is time.Time, a type defined over it, or a struct embedding one,
// or a pointer to one.
func isTime(t types.Type, depth int) bool {
	if depth > 8 {
		return false
	}
	if typeKey(t) == "time.Time" {
		return true
	}
	st, ok := types.Unalias(t).Underlying().(*types.Struct)
	if !ok {
		return false
	}
	// A type defined over time.Time has its fields: wall, ext and loc,
	// declared in package time.
	if st.NumFields() == 3 && st.Field(0).Pkg() != nil && st.Field(0).Pkg().Path() == "time" && st.Field(0).Name() == "wall" {
		return true
	}
	for f := range st.Fields() {
		ft := f.Type()
		if ptr, ok := types.Unalias(ft).(*types.Pointer); ok {
			ft = ptr.Elem()
		}
		if f.Embedded() && isTime(ft, depth+1) {
			return true
		}
	}
	return false
}

// timeCall says whether a call makes a time from outside, and how the
// ledger writes it. A time.Parse or time.ParseInLocation is written as the
// callee and the value it parses, which is the second argument of both;
// the first is the layout. A time.Unix, time.UnixMilli or time.UnixMicro
// makes a time of an integer and is written whole, as is an UnmarshalText,
// UnmarshalJSON or UnmarshalBinary called on a time: the bytes it is given
// are the value.
func timeCall(p *pkg, call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	fn, ok := p.info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return "", false
	}
	if sn := p.info.Selections[sel]; sn != nil && sn.Kind() == types.MethodVal {
		switch fn.Name() {
		case "UnmarshalText", "UnmarshalJSON", "UnmarshalBinary":
			if timeType(sn.Recv()) {
				return types.ExprString(call), true
			}
		}
		return "", false
	}
	if fn.Pkg().Path() != "time" {
		return "", false
	}
	switch fn.Name() {
	case "Parse", "ParseInLocation":
		if len(call.Args) < 2 {
			return "", false
		}
		return fmt.Sprintf("time.%s(%s)", fn.Name(), types.ExprString(call.Args[1])), true
	case "Unix", "UnixMilli", "UnixMicro":
		return types.ExprString(call), true
	}
	return "", false
}

// fieldsRead is, by the position of its declaration, every struct field a
// time.Unix or its kin reads in its arguments, directly or through
// arithmetic: where the integer it makes a time of comes from, when it
// comes from a field. A local is not followed.
func (tr *tree) fieldsRead(p *pkg, call *ast.CallExpr) []string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if fn, ok := p.info.Uses[sel.Sel].(*types.Func); !ok || fn.Pkg() == nil || fn.Pkg().Path() != "time" || !strings.HasPrefix(fn.Name(), "Unix") {
		return nil
	}
	var out []string
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if se, ok := n.(*ast.SelectorExpr); ok {
				if sn := p.info.Selections[se]; sn != nil && sn.Kind() == types.FieldVal {
					out = append(out, tr.fset.Position(sn.Obj().Pos()).String())
				}
			}
			return true
		})
	}
	return out
}

// fieldNames is the names a struct field declares, an embedded field's
// being the name its type gives it.
func fieldNames(fl *ast.Field) []*ast.Ident {
	if len(fl.Names) > 0 {
		return fl.Names
	}
	return []*ast.Ident{embeddedName(fl.Type)}
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

// plantFiles writes several source files, each by its path under the
// root, in a module of its own named planted, for the self-tests that
// need more than one package. A tag in a file is written between single
// quotes and planted between backquotes, so that the source reads as Go.
func plantFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	tick := strings.NewReplacer("'", "`")
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(tick.Replace(src)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module planted\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// localTimeRule is the form of a time row's local: on a field the walk
// finds decoded: "local: held by <Rule> at <point>", the function that
// holds the value and the point it runs, as a string row's local: names
// the rule that fixed its operand's length. The rule is held to the tree
// and the row names the TestLimit test that shows it. A prose reason is
// not enough there, since what a decode fills came from a file or a wire
// whose writer the walk cannot see. What the walk holds is that much and
// no more: the rule is a function of the tree, the test exists, and the
// row names every function of the tree that writes the field (see
// fieldWriters). That the bytes the decode reads are this home's own file
// and not a wire is the row's claim, which the walk cannot see, held by
// review.
var localTimeRule = regexp.MustCompile(`^local: held by ([A-Za-z_][A-Za-z0-9_.()*]*) at (\S.*)$`)

// shownMethods are the time.Time methods a display field may be read by:
// each writes it out, or asks only whether it is there.
var shownMethods = map[string]bool{
	"Format": true, "AppendFormat": true, "String": true, "GoString": true,
	"MarshalJSON": true, "MarshalText": true, "IsZero": true,
}

// shownFuncs are the calls outside the tree a display field may be handed
// to: a format, a print, a log line or a marshal.
func shownFunc(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "fmt", "log", "log/slog":
		return true
	case "encoding/json":
		return fn.Name() == "Marshal" || fn.Name() == "MarshalIndent" || fn.Name() == "Encode"
	}
	return false
}

// displayUses is, by a time field's declaration, every use of it that is
// neither a comparison (see compared) nor a way of showing it: a display
// field may reach a format, a print, a marshal, a field whose own row is
// display or output, or a helper of the tree whose body uses the
// parameter it is handed in those ways alone, and nothing else. rowAt
// gives the row's range of a field by its declaration, "" for none.
func (tr *tree) displayUses(rowAt func(pos string) string) map[string][]string {
	out := map[string][]string{}
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			var stack []ast.Node
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				sn := p.info.Selections[sel]
				if sn == nil || sn.Kind() != types.FieldVal || !timeType(sn.Obj().Type()) {
					return true
				}
				decl := tr.fset.Position(sn.Obj().Pos()).String()
				if rowAt(decl) != "display" {
					return true
				}
				if comparedAs(p, stack) != "" {
					return true // said as compared
				}
				if how := tr.shownOnly(p, stack, rowAt, map[string]bool{}); how != "" {
					where := fmt.Sprintf("%s (%s)", tr.at(sel), how)
					if !slices.Contains(out[decl], where) {
						out[decl] = append(out[decl], where)
					}
				}
				return true
			})
		}
	}
	return out
}

// shownOnly says how the time at the top of the stack is used other than
// shown, or "" when it is only shown or written. It follows the time up
// through what still holds it, as comparedAs does, and reads where that
// ends.
func (tr *tree) shownOnly(p *pkg, stack []ast.Node, rowAt func(string) string, seen map[string]bool) string {
	i := len(stack) - 1
	cur := stack[i].(ast.Expr)
	for i >= 1 {
		switch parent := stack[i-1].(type) {
		case *ast.ParenExpr, *ast.StarExpr:
			cur, i = parent.(ast.Expr), i-1
			continue
		case *ast.UnaryExpr:
			// Its address, which holds the same time: followed to where
			// the pointer goes.
			if parent.Op == token.AND {
				cur, i = parent, i-1
				continue
			}
		case *ast.IndexExpr:
			if parent.X == cur {
				cur, i = parent, i-1
				continue
			}
		case *ast.SelectorExpr:
			if parent.X == cur && i >= 2 && !timeOperators[parent.Sel.Name] {
				if call, ok := stack[i-2].(*ast.CallExpr); ok && call.Fun == parent && timeType(p.info.TypeOf(call)) && timeType(p.info.TypeOf(cur)) {
					cur, i = call, i-2
					continue
				}
			}
		}
		break
	}
	if i < 1 {
		return "used where the walk cannot see"
	}
	fieldRow := func(obj types.Object) string {
		v, ok := obj.(*types.Var)
		if !ok || !v.IsField() {
			return "copied into something that is not a field"
		}
		decl := tr.fset.Position(v.Pos())
		owner := fmt.Sprintf("%s declared at %s:%d", v.Name(), filepath.ToSlash(mustRel(tr.root, decl.Filename)), decl.Line)
		switch rng := rowAt(tr.fset.Position(v.Pos()).String()); {
		case rng == "display" || rng == "output":
			return ""
		case rng == "":
			return "copied into the field " + owner + ", which has no row"
		default:
			return "copied into the field " + owner + ", whose row says " + rng
		}
	}
	switch parent := stack[i-1].(type) {
	case *ast.SelectorExpr:
		if parent.X != cur {
			break
		}
		switch {
		case shownMethods[parent.Sel.Name]:
			return ""
		case strings.HasPrefix(parent.Sel.Name, "Unix"):
			return "turned into a number by " + parent.Sel.Name
		default:
			return "read by its method " + parent.Sel.Name
		}
	case *ast.CallExpr:
		for k, a := range parent.Args {
			if a != cur {
				continue
			}
			if tv, ok := p.info.Types[parent.Fun]; ok && tv.IsType() {
				return "converted to " + types.ExprString(parent.Fun)
			}
			fn := calleeFunc(p, parent)
			if shownFunc(fn) {
				return ""
			}
			if fn == nil {
				return "passed to " + types.ExprString(parent.Fun) + ", which the walk cannot follow"
			}
			name := objName(fn)
			if fn.Pkg() != nil {
				name = fn.Pkg().Name() + "." + name
			}
			hp, fd := tr.declOf(fn)
			if fd == nil {
				return "passed to " + name
			}
			// A helper of the tree's own: the parameter it is handed may be
			// used there only as the field may be here.
			sig := fn.Type().(*types.Signature)
			idx := k
			if sig.Variadic() && idx >= sig.Params().Len()-1 {
				idx = sig.Params().Len() - 1
			}
			if idx >= sig.Params().Len() {
				return "passed to " + name + ", which the walk cannot follow"
			}
			param := sig.Params().At(idx)
			key := fmt.Sprintf("%s#%d", fullName(fn), idx)
			if seen[key] {
				return ""
			}
			seen[key] = true
			if fd.Body == nil {
				return "passed to " + name
			}
			why := ""
			var inner []ast.Node
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					inner = inner[:len(inner)-1]
					return true
				}
				inner = append(inner, n)
				if why != "" {
					return false
				}
				if id, ok := n.(*ast.Ident); ok && hp.info.Uses[id] == types.Object(param) {
					if how := tr.shownOnly(hp, inner, rowAt, seen); how != "" {
						why = fmt.Sprintf("passed to %s, where %s is %s at %s", name, param.Name(), how, tr.at(id))
					}
				}
				return true
			})
			return why
		}
	case *ast.KeyValueExpr:
		if parent.Value != cur || i < 2 {
			break
		}
		lit, ok := stack[i-2].(*ast.CompositeLit)
		if !ok {
			break
		}
		if _, isStruct := types.Unalias(p.info.TypeOf(lit)).Underlying().(*types.Struct); !isStruct {
			return "put in a " + types.TypeString(p.info.TypeOf(lit), nil)
		}
		if key, ok := parent.Key.(*ast.Ident); ok {
			return fieldRow(p.info.Uses[key])
		}
	case *ast.CompositeLit:
		st, ok := types.Unalias(p.info.TypeOf(parent)).Underlying().(*types.Struct)
		if !ok {
			return "put in a " + types.TypeString(p.info.TypeOf(parent), nil)
		}
		for k, e := range parent.Elts {
			if e == cur && k < st.NumFields() {
				return fieldRow(st.Field(k))
			}
		}
	case *ast.AssignStmt:
		for k, lhs := range parent.Lhs {
			if lhs == cur {
				return "" // written, not read
			}
			if k < len(parent.Rhs) && parent.Rhs[k] == cur || len(parent.Rhs) == 1 && parent.Rhs[0] == cur {
				switch l := lhs.(type) {
				case *ast.Ident:
					return "assigned to the local " + l.Name
				case *ast.SelectorExpr:
					if sn := p.info.Selections[l]; sn != nil && sn.Kind() == types.FieldVal {
						return fieldRow(sn.Obj())
					}
				}
				return "assigned to " + types.ExprString(lhs)
			}
		}
	case *ast.ValueSpec:
		for _, name := range parent.Names {
			return "assigned to the local " + name.Name
		}
	case *ast.BinaryExpr:
		other := parent.X
		if other == cur {
			other = parent.Y
		}
		if id, ok := other.(*ast.Ident); ok && id.Name == "nil" {
			return ""
		}
		return "an operand of " + parent.Op.String()
	case *ast.ReturnStmt:
		return "returned"
	case *ast.UnaryExpr:
		return "an operand of " + parent.Op.String()
	case *ast.RangeStmt:
		return "ranged over"
	}
	return fmt.Sprintf("used in a %s", strings.TrimPrefix(fmt.Sprintf("%T", stack[i-1]), "*ast."))
}

// testutilCalls is, by the name of every Test function in the tree's
// _test.go files, the functions of internal/testutil its body calls,
// written in it or in a function literal inside it.
func (tr *tree) testutilCalls() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	want := tr.modulePath + "/internal/testutil"
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
			name := ""
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) != want {
					continue
				}
				name = "testutil"
				if imp.Name != nil {
					name = imp.Name.Name
				}
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || !strings.HasPrefix(fd.Name.Name, "Test") || fd.Body == nil {
					continue
				}
				calls := out[fd.Name.Name]
				if calls == nil {
					calls = map[string]bool{}
					out[fd.Name.Name] = calls
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fun := call.Fun.(type) {
					case *ast.SelectorExpr:
						if x, ok := fun.X.(*ast.Ident); ok && name != "" && x.Name == name {
							calls[fun.Sel.Name] = true
						}
					case *ast.Ident:
						// Within internal/testutil's own tests.
						if f.Name.Name == "testutil" {
							calls[fun.Name] = true
						}
					}
					return true
				})
			}
			return nil
		})
	}
	return out
}

// copiedInto is every time field of a named struct that is no site of its
// own (tr.candidates) that a field declared at one of from is copied
// into, by an assignment or a composite literal, itself or its address:
// such a field holds a display field's time under another name, and the
// display row is held through it only if it has a row of its own. A
// field so reached is followed in turn.
func (tr *tree) copiedInto(from []string) []site {
	held := map[string]bool{}
	for _, pos := range from {
		held[pos] = true
	}
	candidates := tr.candidates
	fieldPos := func(p *pkg, e ast.Expr) string {
		for {
			switch x := e.(type) {
			case *ast.ParenExpr:
				e = x.X
				continue
			case *ast.StarExpr:
				e = x.X
				continue
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					e = x.X
					continue
				}
			case *ast.SelectorExpr:
				if sn := p.info.Selections[x]; sn != nil && sn.Kind() == types.FieldVal {
					return tr.fset.Position(sn.Obj().Pos()).String()
				}
			case *ast.Ident:
				if v, ok := p.info.Uses[x].(*types.Var); ok && v.IsField() {
					return tr.fset.Position(v.Pos()).String()
				}
			}
			return ""
		}
	}
	var out []site
	for changed := true; changed; {
		changed = false
		for _, p := range tr.pkgs {
			for _, f := range p.files {
				ast.Inspect(f, func(n ast.Node) bool {
					var pairs [][2]string
					switch x := n.(type) {
					case *ast.AssignStmt:
						if len(x.Lhs) == len(x.Rhs) {
							for i := range x.Lhs {
								pairs = append(pairs, [2]string{fieldPos(p, x.Lhs[i]), fieldPos(p, x.Rhs[i])})
							}
						}
					case *ast.KeyValueExpr:
						if key, ok := x.Key.(*ast.Ident); ok {
							pairs = append(pairs, [2]string{fieldPos(p, key), fieldPos(p, x.Value)})
						}
					}
					for _, pr := range pairs {
						to, from := pr[0], pr[1]
						if to == "" || !held[from] || held[to] {
							continue
						}
						if c, ok := candidates[to]; ok {
							held[to] = true
							out = append(out, c)
							changed = true
						}
					}
					return true
				})
			}
		}
	}
	return out
}

// plantedTestutil is a planted module's internal/testutil, for a planted
// bound row's test to call as the tree's tests call the real one.
const plantedTestutil = `package testutil

import "time"

type TimeEdge struct {
	Name string
	At   time.Time
}

func TimeEdges(edge time.Time) []TimeEdge { return nil }

func EarliestInstant() time.Time { return time.Time{} }

func PastYear9999() time.Time { return time.Time{} }
`

// fieldWriter is a function of the tree that writes a field, by the name
// a row must give it, and where. A method is named with its receiver's
// type, Store.Load, and a function of another package than the field's
// with its package, auu.deliverStream; a function of the field's own
// package by its name alone. A bare name is not unique in the tree
// ((*serveRun).settle, (*meeter).settle and regular.settle), so a row
// that names one by it would take any of them.
type fieldWriter struct{ name, at string }

// fieldWriters is every place in the non-test tree that writes the field
// declared at pos: an assignment to it, a composite literal that sets it,
// by its key or by its place, or its address taken, which lets anything
// write it. A decode fills it by none of these, and is the read the row
// is about.
func (tr *tree) fieldWriters(pos string) []fieldWriter {
	var out []fieldWriter
	var fieldPkg *types.Package
	is := func(obj types.Object) bool {
		v, ok := obj.(*types.Var)
		if ok && v.IsField() && tr.fset.Position(v.Pos()).String() == pos {
			fieldPkg = v.Pkg()
			return true
		}
		return false
	}
	qualified := func(p *pkg, fd *ast.FuncDecl) string {
		if fd == nil {
			return "a package-level declaration"
		}
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			recv := fd.Recv.List[0].Type
			for {
				switch x := recv.(type) {
				case *ast.StarExpr:
					recv = x.X
					continue
				case *ast.IndexExpr:
					recv = x.X
					continue
				case *ast.IndexListExpr:
					recv = x.X
					continue
				}
				break
			}
			return types.ExprString(recv) + "." + fd.Name.Name
		}
		if fieldPkg != nil && p.types != fieldPkg {
			return p.types.Name() + "." + fd.Name.Name
		}
		return fd.Name.Name
	}
	for _, p := range tr.pkgs {
		for _, f := range p.files {
			var stack []ast.Node
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				var hit ast.Node
				switch x := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok {
							if sn := p.info.Selections[sel]; sn != nil && sn.Kind() == types.FieldVal && is(sn.Obj()) {
								hit = sel
							}
						}
					}
				case *ast.KeyValueExpr:
					if key, ok := x.Key.(*ast.Ident); ok && is(p.info.Uses[key]) {
						hit = x
					}
				case *ast.CompositeLit:
					if st, ok := types.Unalias(p.info.TypeOf(x)).Underlying().(*types.Struct); ok {
						for k, e := range x.Elts {
							if _, kv := e.(*ast.KeyValueExpr); !kv && k < st.NumFields() && is(st.Field(k)) {
								hit = e
							}
						}
					}
				case *ast.UnaryExpr:
					if sel, ok := x.X.(*ast.SelectorExpr); ok && x.Op == token.AND {
						if sn := p.info.Selections[sel]; sn != nil && sn.Kind() == types.FieldVal && is(sn.Obj()) {
							hit = x
						}
					}
				}
				if hit != nil {
					out = append(out, fieldWriter{qualified(p, enclosingFunc(stack)), tr.at(hit)})
				}
				return true
			})
		}
	}
	return out
}
