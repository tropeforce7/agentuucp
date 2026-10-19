package limits

import (
	"strings"
	"testing"
)

// The three rules by which a time row's claim is held by the walk rather
// than by convention (D86): a local: on a field a decode fills names the
// rule that holds it and its test; a display field reaches nothing but a
// format, a print, a marshal, a field whose own row is display or output,
// or a helper that only shows it; and a bound row's test feeds the
// grammar's values through testutil.TimeEdges. Each was a hole the second
// review planted (D).

// TestTheWalkRefusesALocalRowOnADecodedComparedField: a field json.Unmarshal
// fills from the wire, compared with now, is refused as display, and was
// taken when the row's prose said local:. Now a local: on a decoded field
// with a reason alone is refused, a rule that is no function of the tree
// is refused, a rule with no test is refused, and a row that does not name
// every function of the tree that writes the field, a method by its
// receiver's type and a function of another package by its package, is
// refused naming the writers it leaves out. A row that passes all of that
// is taken, and no more is shown by it: that the decode reads this home's
// own file and not a wire is the row's claim, held by review.
func TestTheWalkRefusesALocalRowOnADecodedComparedField(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"errors"
	"time"
)

type Wire struct {
	At time.Time 'json:"at"'
}

func Read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	if err == nil {
		err = held(w.At)
	}
	return w, err
}

func held(at time.Time) error {
	if at.Year() > 9999 {
		return errors.New("too late")
	}
	return nil
}

func Late(w Wire, now time.Time) bool { return w.At.After(now) }

func Stamp(w *Wire) { w.At = time.Now() }

func Fresh() Wire { return Wire{At: time.Now()} }

type Other struct{}

func (Other) Stamp(w *Wire) { w.At = time.Now() }
`, "internal/other/other.go": `package other

import (
	"time"

	"planted/internal/planted"
)

func Touch(w *planted.Wire) { w.At = time.Time{} }
`, "internal/planted/planted_test.go": "package planted\n\nimport \"testing\"\n\nfunc TestLimitHeld(t *testing.T) {}\n"})
	const key = "internal/planted/planted.go Wire time At"
	unnamed := func(rule, writers string) string {
		return "ledger.txt:1: " + key + " says it is held by " + rule + ", but the field is written in " + writers + ", which the row does not name; name every writer, or give the row a bound and a test"
	}
	problems, _ := check(t, root, key+" = display")
	if !hasProblem(problems, "says display, but the field is compared") {
		t.Fatalf("control: display should be refused: %v", problems)
	}
	for _, c := range []struct{ rng, want string }{
		{"local: this program's own clock", "ledger.txt:1: " + key + " says local: with a reason the walk cannot hold, but planted.Wire is decoded: it is reached from json.Unmarshal at internal/planted/planted.go Read; say local: held by <Rule> at <point> shown by <TestLimit...>, or give the row a bound and a test"},
		{"local: held by nowhere at Read shown by TestLimitHeld", "ledger.txt:1: " + key + " names the rule nowhere, which is not a function in the tree"},
		{"local: held by held at Read", "ledger.txt:1: " + key + " names the rule held and no test; the rule's test shows it holding the value at Read"},
		{"local: held by held at Read; Stamp, Fresh, Other.Stamp and other.Touch write it shown by TestLimitNone", "ledger.txt:1: " + key + " names TestLimitNone, which no _test.go file in the tree declares"},
		{"local: held by held at Read shown by TestLimitHeld", unnamed("held", "other.Touch at internal/other/other.go:9, Stamp at internal/planted/planted.go:31, Fresh at internal/planted/planted.go:33, Other.Stamp at internal/planted/planted.go:37")},
		// A bare name names the function of the field's package and
		// nothing else: not a method of the same name on another type,
		// nor a function of the same name in another package.
		{"local: held by Stamp at the write, and Fresh at the making, each this machine's clock shown by TestLimitHeld", unnamed("Stamp", "other.Touch at internal/other/other.go:9, Other.Stamp at internal/planted/planted.go:37")},
		{"local: held by Stamp at the write, Fresh at the making, Other.Stamp at its own, and Touch clears it shown by TestLimitHeld", unnamed("Stamp", "other.Touch at internal/other/other.go:9")},
		// And a qualified name does not name the bare one it ends with.
		{"local: held by Other.Stamp at its write, Fresh at the making and other.Touch clears it shown by TestLimitHeld", unnamed("Other.Stamp", "Stamp at internal/planted/planted.go:31")},
		// Every writer named in the form the walk asks, the rule a
		// function of the tree and its test declared: the walk takes the
		// row. That the decode reads this home's own file, and not a wire,
		// is the row's claim, which the walk does not see and review holds.
		{"local: held by Stamp at the write, Fresh at the making, Other.Stamp at its own, and other.Touch clears it shown by TestLimitHeld", ""},
	} {
		problems, _ := check(t, root, key+" = "+c.rng)
		if c.want == "" {
			if len(problems) != 0 {
				t.Errorf("%q: %q, want it to stand", c.rng, problems)
			}
			continue
		}
		if len(problems) != 1 || problems[0] != c.want {
			t.Errorf("%q: %q\nwant %q", c.rng, problems, c.want)
		}
	}
}

// TestTheWalkRefusesABoundRowTheCodeDoesNotEnforce: a bound, a window or
// a deadline named a TestLimit that tested nothing, and the walk asked only
// that the name was declared once. Now the test it names must call
// testutil.TimeEdges, or for a deadline each of testutil.EarliestInstant
// and testutil.PastYear9999, the values the grammar lists, so that a test
// that feeds nothing is refused by name.
func TestTheWalkRefusesABoundRowTheCodeDoesNotEnforce(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"time"
)

type Wire struct {
	At time.Time 'json:"at"'
}

func Read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return w, err
}
`, "internal/planted/planted_test.go": `package planted

import (
	"testing"
	"time"

	tu "planted/internal/testutil"
)

func TestLimitNothing(t *testing.T) {}

func TestLimitEdges(t *testing.T) {
	t.Run("all", func(t *testing.T) { tu.TimeEdges(time.Now()) })
}

func TestLimitDeadline(t *testing.T) { tu.EarliestInstant(); tu.PastYear9999() }

func TestLimitHalf(t *testing.T) { tu.EarliestInstant() }
`, "internal/testutil/testutil.go": plantedTestutil})
	const key = "internal/planted/planted.go Wire time At"
	for _, rng := range []string{"<= now + 5m", "<= now + 42m", "[not_before, not_after]", "deadline: whatever"} {
		want := "ledger.txt:1: " + key + " names TestLimitNothing, which does not call testutil.TimeEdges"
		if strings.HasPrefix(rng, "deadline:") {
			want += ", or each of testutil.EarliestInstant and testutil.PastYear9999"
		}
		want += "; a bound's test feeds the values the grammar lists through it"
		problems, _ := check(t, root, key+" = "+rng+" shown by TestLimitNothing")
		if len(problems) != 1 || problems[0] != want {
			t.Errorf("%q with an empty test: %q\nwant %q", rng, problems, want)
		}
		// TimeEdges called under another import name, in a function
		// literal of the test, is called.
		if problems, _ := check(t, root, key+" = "+rng+" shown by TestLimitEdges"); len(problems) != 0 {
			t.Errorf("%q with TimeEdges: %q", rng, problems)
		}
	}
	// A deadline may call the two values its grammar names one by one;
	// a bound may not, and a deadline calling one of the two is refused.
	if problems, _ := check(t, root, key+" = deadline: whatever shown by TestLimitDeadline"); len(problems) != 0 {
		t.Errorf("a deadline with each named value: %q", problems)
	}
	if problems, _ := check(t, root, key+" = <= now + 5m shown by TestLimitDeadline"); len(problems) != 1 {
		t.Errorf("a bound with the deadline's two values alone: %q, want it refused", problems)
	}
	if problems, _ := check(t, root, key+" = deadline: whatever shown by TestLimitHalf"); len(problems) != 1 {
		t.Errorf("a deadline with one of its two values: %q, want it refused", problems)
	}
}

// TestTheWalkRefusesADisplayComparedOutOfSight: a display field copied into
// a local, handed to a helper of the tree that compares it, or turned into
// a number by Unix was compared where the walk did not look. Now each use
// that is not a showing is refused, naming it, while a format, a helper
// that only formats, a copy into a field with a display row of its own and
// its address into an output struct stand.
func TestTheWalkRefusesADisplayComparedOutOfSight(t *testing.T) {
	root := plantFiles(t, map[string]string{"internal/planted/planted.go": `package planted

import (
	"encoding/json"
	"fmt"
	"time"
)

type Wire struct {
	A time.Time 'json:"a"'
	B time.Time 'json:"b"'
	C time.Time 'json:"c"'
	D time.Time 'json:"d"'
}

func Read(b []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(b, &w)
	return w, err
}

func after(x, y time.Time) bool { return x.After(y) }

func Local(w Wire, now time.Time) bool  { a := w.A; return a.After(now) }
func Helper(w Wire, now time.Time) bool { return after(w.B, now) }
func Unix(w Wire, now time.Time) bool   { return w.C.Unix() > now.Unix() }

type Err struct{ At time.Time }

type Out struct {
	At *time.Time 'json:"at"'
}

func stamp(t time.Time) string { return t.Local().Format(time.RFC3339) }

func Shown(w Wire) (string, Err, Out) {
	if w.D.IsZero() {
		return "", Err{}, Out{}
	}
	e := Err{At: w.D}
	return fmt.Sprint(w.D.UTC().Format(time.RFC3339), stamp(w.D), stamp(e.At)), e, Out{At: &w.D}
}
`})
	const w = "internal/planted/planted.go Wire time "
	ledger := w + "A = display\n" + w + "B = display\n" + w + "C = display\n" + w + "D = display\n" +
		"internal/planted/planted.go Err time At = display\ninternal/planted/planted.go Out time At = output"
	problems, _ := check(t, root, ledger)
	const shown = "; a display field reaches a format, a print, a marshal, a field whose row is display or output, or a helper that only shows it, so give the row a bound and a test"
	want := []string{
		"ledger.txt:1: " + w + "A says display, but the field is used other than shown at internal/planted/planted.go:24 (assigned to the local a)" + shown,
		"ledger.txt:2: " + w + "B says display, but the field is used other than shown at internal/planted/planted.go:25 (passed to planted.after, where x is read by its method After at internal/planted/planted.go:22)" + shown,
		"ledger.txt:3: " + w + "C says display, but the field is used other than shown at internal/planted/planted.go:26 (turned into a number by Unix)" + shown,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}

	// The field it is copied into needs a row of its own, and a row that
	// is not display is refused for the copy.
	problems, _ = check(t, root, w+"D = display\n"+"internal/planted/planted.go Out time At = output")
	if !hasProblem(problems, "internal/planted/planted.go Err time At has no row in ledger.txt") ||
		!hasProblem(problems, "D says display, but the field is used other than shown at internal/planted/planted.go:40 (copied into the field At declared at internal/planted/planted.go:28, which has no row)") {
		t.Errorf("a copy into a field with no row: %q", problems)
	}
	problems, _ = check(t, root, w+"D = display\n"+"internal/planted/planted.go Err time At = local: a copy\ninternal/planted/planted.go Out time At = output")
	if !hasProblem(problems, "(copied into the field At declared at internal/planted/planted.go:28, whose row says local: a copy)") {
		t.Errorf("a copy into a field whose row is not display: %q", problems)
	}
}
