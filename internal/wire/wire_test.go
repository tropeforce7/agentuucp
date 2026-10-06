package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func section(name string, critical bool) Section {
	return Section{Name: name, Critical: critical, Data: json.RawMessage(`{}`)}
}

// The name rule against the guide's string catalogue: every value a name
// could be that is not one, and the edges of the length.
func TestTheSectionNameRule(t *testing.T) {
	cap64 := "a" + strings.Repeat("b", MaxNameBytes-1)
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"recipients", true},
		{"a", true},
		{"a1", true},
		{"a-b", true},
		{"a--b", true},
		{"a-", true},
		{cap64, true},
		{cap64 + "c", false},
		// A name of exactly the cap whose last rune straddles it.
		{"a" + strings.Repeat("b", MaxNameBytes-2) + "é", false},
		{"", false},
		{" a", false},
		{"a ", false},
		{"A", false},
		{"aB", false},
		{"1a", false},
		{"-a", false},
		{"a_b", false},
		{"a.b", false},
		{"a/b", false},
		{"a\\b", false},
		{".", false},
		{"..", false},
		{"a%", false},
		{"a*", false},
		{"a\x00", false},
		{"a\x1b", false},
		{"a\r", false},
		{"a\n", false},
		{"a\t", false},
		{"a‮", false},
		{"a‍", false},
		{"a", false},
		{"a ", false},
		{"a\u0085", false},
		{"aK", false}, // the Kelvin sign, which folds to k
		{"a\xff", false},
		{"+1", false},
		{"0x1", false},
	} {
		err := ValidName(tc.name)
		if tc.ok && err != nil {
			t.Errorf("%q: %v; want it taken", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrForm) {
			t.Errorf("%q: %v; want ErrForm", tc.name, err)
		}
	}
}

// A refusal quotes the name, so nothing a writer put in one reaches a
// terminal as itself.
func TestARefusedNameIsQuoted(t *testing.T) {
	err := ValidName("a\x1b[31mred")
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("got %v; want the escape written as \\x1b", err)
	}
	err = Check([]Section{section("a", false), {Name: "a\nb", Data: json.RawMessage(`0`)}})
	if err == nil || strings.Contains(err.Error(), "\n") {
		t.Fatalf("got %v; want the newline quoted", err)
	}
}

// The count is held before any entry is looked at: a list one over the cap
// whose first entry is also bad is refused for its count, which is the
// check that fired first. A slice cannot claim a length it does not have;
// what bounds the allocation behind it is the cap on the bytes it was
// decoded from, which is each reader's.
func TestLimitSectionCount(t *testing.T) {
	list := func(n int) []Section {
		out := make([]Section, n)
		for i := range out {
			out[i] = section(fmt.Sprintf("s%d", i), false)
		}
		return out
	}
	for _, n := range []int{0, 1, MaxSections - 1, MaxSections} {
		if err := Check(list(n)); err != nil {
			t.Errorf("%d sections: %v; want them taken", n, err)
		}
	}
	if err := Check(nil); err != nil {
		t.Errorf("no list: %v; want it taken", err)
	}
	over := list(MaxSections + 1)
	err := Check(over)
	want := fmt.Sprintf("sections are malformed: %d sections, at most %d", MaxSections+1, MaxSections)
	if !errors.Is(err, ErrForm) || err.Error() != want {
		t.Fatalf("%d sections: %v; want %q", MaxSections+1, err, want)
	}
	over[0].Name = "Bad"
	if err := Check(over); err == nil || err.Error() != want {
		t.Fatalf("an over-long list with a bad first name: %v; want the count refused first", err)
	}
}

func TestCheckRefusesWhatIsNotAList(t *testing.T) {
	for _, tc := range []struct {
		what string
		list []Section
		want string
	}{
		{"a name twice", []Section{section("a", false), section("b", true), section("a", true)},
			`sections are malformed: section "a" appears twice`},
		{"no name", []Section{{Data: json.RawMessage(`{}`)}},
			"sections are malformed: a section has no name"},
		{"no data", []Section{{Name: "a"}},
			`sections are malformed: section "a" has no data`},
		{"a bad name after a good one", []Section{section("a", false), section("B", false)},
			`sections are malformed: section name "B" does not begin with a lowercase letter`},
	} {
		if err := Check(tc.list); !errors.Is(err, ErrForm) || err.Error() != tc.want {
			t.Errorf("%s: %v; want %q", tc.what, err, tc.want)
		}
	}
	// Data that is present and null is data: null is a value a section's
	// rule may give a meaning to.
	if err := Check([]Section{{Name: "a", Data: json.RawMessage(`null`)}}); err != nil {
		t.Errorf("null data: %v; want it taken", err)
	}
}

// Every field is written, so absence on the wire is never what a writer
// meant. Marshal the zero value to prove the tags.
func TestASectionWritesEveryField(t *testing.T) {
	out, err := json.Marshal(Section{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"name":"","critical":false,"data":null}` {
		t.Fatalf("the zero section marshals as %s", out)
	}
	// A section as it arrives, without its data, decodes to no data, which
	// Check refuses; without its critical flag, to false, which is what the
	// writer's false would be, and so has no test of its own.
	var s Section
	if err := Decode([]byte(`{"name":"a","critical":false}`), &s); err != nil {
		t.Fatal(err)
	}
	if err := Check([]Section{s}); !errors.Is(err, ErrForm) {
		t.Fatalf("a section without its data: %v; want ErrForm", err)
	}
}

// The registry is empty in this release, so every section is unknown: one
// that is not critical is ignored, and one that is stops the sort by name.
func TestSortIgnoresTheUnknownAndRefusesTheCritical(t *testing.T) {
	if len(known) != 0 {
		t.Fatalf("this release knows %d sections; it ships the door and nothing through it", len(known))
	}
	k, ign, err := Sort([]Section{section("later", false), section("other", false)})
	if err != nil || len(k) != 0 || len(ign) != 2 || ign[0].Name != "later" || ign[1].Name != "other" {
		t.Fatalf("two unknown, not critical: known %v, ignored %v, %v", k, ign, err)
	}
	k, ign, err = Sort([]Section{section("later", false), section("first", true), section("second", true)})
	var nn *NeedsNewerError
	if !errors.Is(err, ErrNeedsNewer) || !errors.As(err, &nn) || nn.Name != "first" || k != nil || ign != nil {
		t.Fatalf("an unknown critical section: known %v, ignored %v, %v; want the first named and nothing else", k, ign, err)
	}
	if err.Error() != `section "first" is critical and this build of auu does not know it; it needs a newer auu` {
		t.Fatalf("the sentence is %q", err)
	}
	if k, ign, err := Sort(nil); err != nil || k != nil || ign != nil {
		t.Fatalf("no list: %v %v %v", k, ign, err)
	}
}

// A section this build knows goes to its rule whether or not it is
// critical. The registry is empty in this release, so the test fills it.
func TestSortHandsAKnownSectionOn(t *testing.T) {
	known["recipients"] = true
	t.Cleanup(func() { delete(known, "recipients") })
	k, ign, err := Sort([]Section{section("recipients", true), section("later", false)})
	if err != nil || len(k) != 1 || k[0].Name != "recipients" || len(ign) != 1 || ign[0].Name != "later" {
		t.Fatalf("known %v, ignored %v, %v", k, ign, err)
	}
	if !Known("recipients") || Known("later") {
		t.Fatal("Known disagrees with the registry")
	}
}

// Decode is strict about fields and about what follows the value, including
// the two bytes json.Decoder.More lets through.
func TestDecodeIsStrict(t *testing.T) {
	type thing struct {
		A int `json:"a"`
	}
	for _, in := range []string{`{"a":1}`, ` {"a":1} `, "{\"a\":1}\n", "{\"a\":1}\t\r\n"} {
		var v thing
		if err := Decode([]byte(in), &v); err != nil || v.A != 1 {
			t.Errorf("%q: %+v, %v; want it taken", in, v, err)
		}
	}
	for _, in := range []string{`{"a":1}}`, `{"a":1}]`, `{"a":1}x`, `{"a":1}{}`, `{"a":1},`, `{"a":1} 2`} {
		var v thing
		if err := Decode([]byte(in), &v); err == nil || err.Error() != "trailing data after the value" {
			t.Errorf("%q: %v; want trailing data refused", in, err)
		}
	}
	var v thing
	if err := Decode([]byte(`{"a":1,"b":2}`), &v); err == nil || !strings.Contains(err.Error(), `unknown field "b"`) {
		t.Errorf("an unknown field: %v", err)
	}
	if err := Decode([]byte(``), &v); err == nil {
		t.Error("nothing at all was taken")
	}
	if err := Decode([]byte(`{"a":`), &v); err == nil {
		t.Error("a truncated value was taken")
	}
	// The list itself decodes strictly too: a field a section does not have
	// is refused, so a section cannot carry an extension of its own.
	var s []Section
	if err := Decode([]byte(`[{"name":"a","critical":false,"data":{},"extra":1}]`), &s); err == nil || !strings.Contains(err.Error(), `unknown field "extra"`) {
		t.Errorf("a section with a fourth field: %v", err)
	}
}
