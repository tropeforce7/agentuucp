package limits

import (
	"strings"
	"testing"
)

// The shapes of a decoded time the walk once missed, each planted in a
// module of its own (the second review's section 4). A test names the
// site it wants by its key, so a site found under another name is a
// failure as much as one not found.

// timeKeys is every time site's key, one to a line.
func timeKeys(sites []site) string {
	var ks []string
	for _, s := range sites {
		if s.kind == "time" {
			ks = append(ks, s.key)
		}
	}
	return strings.Join(ks, "\n")
}

// hasProblem says whether any problem holds sub.
func hasProblem(problems []string, sub string) bool {
	for _, p := range problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// wantTimes holds the time sites to exactly want.
func wantTimes(t *testing.T, sites []site, problems []string, want ...string) {
	t.Helper()
	if got := timeKeys(sites); got != strings.Join(want, "\n") {
		t.Errorf("time sites:\n%s\nwant:\n%s\nproblems:\n%s", got, strings.Join(want, "\n"), strings.Join(problems, "\n"))
	}
}

// TestTheWalkSeesAnUntaggedNestedStruct: a time decoded from the wire in a
// struct that carries no json tag of its own, reached as a named field of
// a tagged, decoded struct; the decoder fills From and To by name, and
// both are sites of the untagged struct. The same struct reached by no
// decode is not one.
func TestTheWalkSeesAnUntaggedNestedStruct(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"time"
)

type Window struct {
	From time.Time
	To   time.Time
}

type Unread struct {
	At time.Time
}

type Wire struct {
	N int    'json:"n"'
	W Window 'json:"w"'
}

func Read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return w, err
}

func Open(w Wire, now time.Time) bool { return w.W.From.Before(now) && now.Before(w.W.To) }
`})
	problems, sites := check(t, root, "internal/planted/planted.go Wire int N int = >= 0 shown by TestLimitX")
	wantTimes(t, sites, problems,
		"internal/planted/planted.go Window time From",
		"internal/planted/planted.go Window time To")
}

// TestTheWalkSeesAnEmbeddedStructWithATimeField: the same through an
// embedded, untagged struct that holds a time as a named field, whose
// promoted field the decoder fills by the key "At".
func TestTheWalkSeesAnEmbeddedStructWithATimeField(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"time"
)

type Stamped struct {
	At time.Time
}

type Wire struct {
	Stamped
	N int 'json:"n"'
}

func Read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return w, err
}
`})
	problems, sites := check(t, root, "internal/planted/planted.go Wire int N int = >= 0 shown by TestLimitX")
	wantTimes(t, sites, problems, "internal/planted/planted.go Stamped time At")
}

// TestTheWalkSeesAGenericField: a generic struct's field is read with the
// type argument it is given, so Box[time.Time]'s V is a time where
// Box[T]'s is a T; the same struct given an int elsewhere changes nothing.
func TestTheWalkSeesAGenericField(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"time"
)

type Box[T any] struct {
	V T 'json:"v"'
}

type Wire struct {
	B Box[time.Time] 'json:"b"'
	C Box[string]    'json:"c"'
}

func Read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return w, err
}
`})
	problems, sites := check(t, root, "")
	wantTimes(t, sites, problems, "internal/planted/planted.go Box time V")
}

// TestTheWalkSeesARawMessageAndUnmarshalText: a json.RawMessage decoded
// later straight into a time.Time, through json.Unmarshal and through a
// Decoder, and a string made a time by UnmarshalText and UnmarshalJSON;
// none is a struct's field or a time.Parse, and each is a site of its own.
func TestTheWalkSeesARawMessageAndUnmarshalText(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"bytes"
	"encoding/json"
	"time"
)

type Wire struct {
	Raw  json.RawMessage 'json:"raw"'
	Text string          'json:"text"'
}

func Later(w Wire) (time.Time, error) {
	var at time.Time
	err := json.Unmarshal(w.Raw, &at)
	return at, err
}

func Stream(w Wire) ([]time.Time, error) {
	var at []time.Time
	err := json.NewDecoder(bytes.NewReader(w.Raw)).Decode(&at)
	return at, err
}

func Text(w Wire) (time.Time, error) {
	var at time.Time
	err := at.UnmarshalText([]byte(w.Text))
	return at, err
}

func JSON(w Wire) (time.Time, error) {
	var at time.Time
	err := at.UnmarshalJSON(w.Raw)
	return at, err
}
`})
	problems, sites := check(t, root, "")
	wantTimes(t, sites, problems,
		"internal/planted/planted.go JSON time at.UnmarshalJSON(w.Raw)",
		"internal/planted/planted.go Later time json.Unmarshal(w.Raw, &at)",
		"internal/planted/planted.go Stream time json.NewDecoder(bytes.NewReader(w.Raw)).Decode(&at)",
		"internal/planted/planted.go Text time at.UnmarshalText([]byte(w.Text))")
}

// TestTheWalkSeesAUnixIntegerAsATime: a unix timestamp from the wire is
// an int site and, made a time, a time site of its own, as are
// time.UnixMilli and time.UnixMicro. The time's row is read off the int
// row it comes from: local: is refused while the int row gives a range,
// and taken when the int row says output; a bound with its test is
// taken. The int row stands throughout.
func TestTheWalkSeesAUnixIntegerAsATime(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"time"
)

type Wire struct {
	At int64 'json:"at"'
}

func When(b []byte) (time.Time, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return time.Unix(w.At, 0), err
}

func Milli(n int64) time.Time { return time.UnixMilli(n) }

func Micro(n int64) time.Time { return time.UnixMicro(n) }
`, "internal/planted/planted_test.go": "package planted\n\nimport (\n\t\"testing\"\n\n\t\"planted/internal/testutil\"\n)\n\nfunc TestLimitX(t *testing.T) { testutil.EarliestInstant(); testutil.PastYear9999() }\n",
		"internal/testutil/testutil.go": plantedTestutil})
	const intRow = "internal/planted/planted.go Wire int At int64 = >= 0 shown by TestLimitX\n"
	const others = "internal/planted/planted.go Milli time time.UnixMilli(n) = local: a constant\ninternal/planted/planted.go Micro time time.UnixMicro(n) = local: a constant\n"
	const key = "internal/planted/planted.go When time time.Unix(w.At, 0)"
	problems, sites := check(t, root, intRow+others)
	wantTimes(t, sites, problems,
		"internal/planted/planted.go Micro time time.UnixMicro(n)",
		"internal/planted/planted.go Milli time time.UnixMilli(n)",
		key)
	if len(problems) != 1 || !strings.HasPrefix(problems[0], key+" has no row in ledger.txt") {
		t.Fatalf("problems %q; want the time site's missing row alone, the int row standing", problems)
	}
	problems, _ = check(t, root, intRow+others+key+" = local: the program's own")
	want := "ledger.txt:4: " + key + " says local:, but it makes a time of an integer from outside, internal/planted/planted.go Wire int At int64; give it a bound and a test"
	if len(problems) != 1 || problems[0] != want {
		t.Errorf("a local: row on a time of a wire integer: %q\nwant %q", problems, want)
	}
	problems, _ = check(t, root, intRow+others+key+" = deadline: when it ends shown by TestLimitX")
	if len(problems) != 0 {
		t.Errorf("a deadline with its test: %q", problems)
	}

	// An integer of a struct the program writes and never decodes, made a
	// time: its int row says output, and the time's may say local:.
	root = plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import "time"

type Rec struct {
	At int64 'json:"at"'
}

func Show(r Rec) time.Time { return time.Unix(r.At, 0) }
`})
	problems, _ = check(t, root, "internal/planted/planted.go Rec int At int64 = output\ninternal/planted/planted.go Show time time.Unix(r.At, 0) = local: our own record")
	if len(problems) != 0 {
		t.Errorf("a local: row on a time of an output integer: %q", problems)
	}
}

// TestTheWalkSeesAnOutputDecodedThroughAGenericOrAFuncValue: an output
// row on a struct decoded through a generic helper, Get[A], is refused as
// decoded, through two generic helpers and through a generic type's
// method as well; json.Unmarshal, a Decoder's Decode and a helper that
// reaches one, taken as a value rather than called, are each refused
// outright, since what they hold is called where the walk cannot see.
func TestTheWalkSeesAnOutputDecodedThroughAGenericOrAFuncValue(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"io"
	"time"
)

type A struct {
	At time.Time 'json:"at"'
}

type B struct {
	At time.Time 'json:"at"'
}

type C struct {
	At time.Time 'json:"at"'
}

type D struct {
	At time.Time 'json:"at"'
}

func Get[T any](b []byte) (T, error) {
	var v T
	err := json.Unmarshal(b, &v)
	return v, err
}

func Twice[U any](b []byte) (U, error) { return Get[U](b) }

func ReadA(b []byte) (A, error) { return Get[A](b) }

func ReadC(b []byte) (C, error) { return Twice[C](b) }

type Reader[T any] struct{ v T }

func (r *Reader[T]) Read(b []byte) error { return json.Unmarshal(b, &r.v) }

func ReadD(b []byte) (D, error) {
	var r Reader[D]
	err := r.Read(b)
	return r.v, err
}

var un = json.Unmarshal

func ReadB(b []byte) (B, error) {
	var v B
	err := un(b, &v)
	return v, err
}

func decoder(r io.Reader) func(any) error { return json.NewDecoder(r).Decode }

func into(b []byte, out any) error { return json.Unmarshal(b, out) }

var helper = into
`})
	problems, _ := check(t, root, "internal/planted/planted.go A time At = output\ninternal/planted/planted.go B time At = output\ninternal/planted/planted.go C time At = output\ninternal/planted/planted.go D time At = output")
	for _, want := range []string{
		"ledger.txt:1: internal/planted/planted.go A time At says output, but planted.A is decoded: it is reached from json.Unmarshal at internal/planted/planted.go Get through the type argument of Get",
		"ledger.txt:3: internal/planted/planted.go C time At says output, but planted.C is decoded: it is reached from json.Unmarshal at internal/planted/planted.go Get through the type argument of Get through the type argument of Twice",
		"ledger.txt:4: internal/planted/planted.go D time At says output, but planted.D is decoded: it is reached from json.Unmarshal at internal/planted/planted.go (*Reader[T]).Read through the type argument of Read",
		"internal/planted/planted.go:47: a package-level declaration takes json.Unmarshal as a value rather than calling it",
		"internal/planted/planted.go:55: decoder takes (*json.Decoder).Decode as a value rather than calling it",
		"internal/planted/planted.go:59: a package-level declaration takes into as a value rather than calling it",
	} {
		if !hasProblem(problems, want) {
			t.Errorf("no problem says %q:\n%s", want, strings.Join(problems, "\n"))
		}
	}
	if hasProblem(problems, "B time At says output") {
		t.Errorf("B is decoded only through the value refused; its output row is not what is wrong:\n%s", strings.Join(problems, "\n"))
	}
}

// TestTheWalkTakesAnAliasAndAPointerOfAnEmbedded: the control the review
// kept, which the walk already handled: an alias of time.Time, a pointer
// to a struct embedding a pointer to one, and a map keyed by the alias,
// in a tagged struct nothing decodes, with a time.Parse: four sites, four
// missing rows, and the untagged struct reached by no decode none.
func TestTheWalkTakesAnAliasAndAPointerOfAnEmbedded(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import "time"

type T = time.Time

type E struct{ *time.Time }

type Wire struct {
	A T            'json:"a"'
	B *E           'json:"b"'
	C map[T]string 'json:"c"'
}

func parse(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
`})
	problems, sites := check(t, root, "")
	wantTimes(t, sites, problems,
		"internal/planted/planted.go Wire time A",
		"internal/planted/planted.go Wire time B",
		"internal/planted/planted.go Wire time C",
		"internal/planted/planted.go parse time time.Parse(s)")
	if len(problems) != 4 {
		t.Errorf("want 4 no-row problems, got %q", problems)
	}
}
