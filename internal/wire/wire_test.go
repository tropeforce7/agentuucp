package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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

// The registry is empty in this package's tests, which link no feature that
// fills it, so every section is unknown: one
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
// critical, and Sort asks whether the name is known on any path: one
// registered only for requests and answers is handed on as well. The
// registry is empty in this package's tests, so the test fills it.
func TestSortHandsAKnownSectionOn(t *testing.T) {
	known["recipients"] = OnMessage
	known["asked"] = OnRequest | OnAnswer
	t.Cleanup(func() { delete(known, "recipients"); delete(known, "asked") })
	k, ign, err := Sort([]Section{section("recipients", true), section("asked", true), section("later", false)})
	if err != nil || len(k) != 2 || k[0].Name != "recipients" || k[1].Name != "asked" || len(ign) != 1 || ign[0].Name != "later" {
		t.Fatalf("known %v, ignored %v, %v", k, ign, err)
	}
	if !Known("recipients", OnMessage) || Known("later", AnyPath) {
		t.Fatal("Known disagrees with the registry")
	}
}

// Known answers for the paths asked: a name is known on a path it was
// registered on, on a set of paths any one of which it was registered on,
// and on no other (D76).
func TestKnownIsAskedPerPath(t *testing.T) {
	known["asked"] = OnRequest | OnAnswer
	t.Cleanup(func() { delete(known, "asked") })
	for _, c := range []struct {
		on   Path
		want bool
	}{
		{OnMessage, false},
		{OnManifest, false},
		{OnMessage | OnManifest, false},
		{OnRequest, true},
		{OnAnswer, true},
		{OnMessage | OnAnswer, true},
		{AnyPath, true},
		{0, false},
	} {
		if got := Known("asked", c.on); got != c.want {
			t.Errorf("Known(asked, %04b) = %v; want %v", c.on, got, c.want)
		}
	}
	if Known("never", AnyPath) {
		t.Error("an unregistered name is known")
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

// A document reads one way: a key given twice, two keys equal under case
// folding, and a key that matches a field only by case are each refused by
// name and depth, where encoding/json would keep the last or take the
// field. The same key in two objects is two keys, and is taken.
func TestDecodeRefusesAKeyThatReadsTwoWays(t *testing.T) {
	type inner struct {
		Name string `json:"name"`
		K    int    `json:"k"`
	}
	type outer struct {
		Name  string          `json:"name"`
		Inner inner           `json:"inner"`
		List  []inner         `json:"list"`
		Map   map[string]int  `json:"map"`
		Raw   json.RawMessage `json:"raw"`
	}
	for _, in := range []string{
		`{"name":"a","inner":{"name":"b","k":1},"list":[{"name":"c"},{"name":"d"}],"map":{"x":1,"y":2},"raw":{"name":1}}`,
		`{}`,
	} {
		var v outer
		if err := Decode([]byte(in), &v); err != nil {
			t.Errorf("%s: %v; want it taken", in, err)
		}
	}
	for _, tc := range []struct {
		what, in, want string
	}{
		{"a key twice at the top", `{"name":"a","name":"b"}`,
			`key "name" appears twice in an object at depth 1`},
		{"a key twice inside a nested object", `{"inner":{"k":1,"k":2}}`,
			`key "k" appears twice in an object at depth 2`},
		{"a key twice inside an object in a list", `{"list":[{"name":"a"},{"name":"b","name":"c"}]}`,
			`key "name" appears twice in an object at depth 3`},
		{"a key twice in a map", `{"map":{"x":1,"x":2}}`,
			`key "x" appears twice in an object at depth 2`},
		{"a key twice inside raw data", `{"raw":{"a":1,"a":2}}`,
			`key "a" appears twice in an object at depth 2`},
		{"a key in another case against a lowercase field", `{"Name":"a"}`,
			`key "Name" matches the field "name" only by case, in an object at depth 1`},
		{"the same, nested", `{"inner":{"NAME":"a"}}`,
			`key "NAME" matches the field "name" only by case, in an object at depth 2`},
		{"two keys equal only under folding", `{"map":{"k":1,"K":2}}`,
			"key \"k\" and key \"K\", the same under case folding, are both in an object at depth 2"},
		{"the Kelvin sign against a field k", `{"inner":{"K":1}}`,
			"key \"K\" matches the field \"k\" only by case, in an object at depth 2"},
	} {
		var v outer
		if err := Decode([]byte(tc.in), &v); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v; want %q", tc.what, err, tc.want)
		}
	}
	// The sentence names the key, never its value.
	var v outer
	err := Decode([]byte(`{"name":"secret-value","name":"other"}`), &v)
	if err == nil || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "other") {
		t.Errorf("the sentence carries a value: %v", err)
	}
	// A syntax error is the decoder's own, for a reader that reports where.
	var syn *json.SyntaxError
	if err := Decode([]byte(`{"name":"a",}`), &v); !errors.As(err, &syn) {
		t.Errorf("a syntax error: %v; want the decoder's *json.SyntaxError", err)
	}
	if err := Decode([]byte(`{"name":"a"}}`), &v); !errors.Is(err, ErrTrailing) {
		t.Errorf("trailing data: %v; want ErrTrailing", err)
	}
}

// fieldsOf follows encoding/json's naming: a tag's name, a field's own name
// with no tag, a promoted embedded struct's fields, and nothing for "-" or
// an unexported field.
func TestTheWalkKnowsTheFieldsJSONDoes(t *testing.T) {
	type Base struct {
		ID int `json:"id"`
	}
	type thing struct {
		Base
		Plain   int
		Tagged  int `json:"tagged,omitempty"`
		Skipped int `json:"-"`
		hidden  int
	}
	_ = thing{}.hidden
	got := fieldsOf(reflect.TypeFor[thing]())
	for _, want := range []string{"id", "Plain", "tagged"} {
		if _, ok := got[want]; !ok {
			t.Errorf("no field %q in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("fields %v; want id, Plain and tagged alone", got)
	}
	var v thing
	if err := Decode([]byte(`{"id":1,"Plain":2,"tagged":3}`), &v); err != nil || v.ID != 1 || v.Plain != 2 || v.Tagged != 3 {
		t.Errorf("the exact keys: %+v, %v", v, err)
	}
	if err := Decode([]byte(`{"plain":2}`), &v); err == nil || !strings.Contains(err.Error(), `matches the field "Plain" only by case`) {
		t.Errorf("an untagged field by another case: %v", err)
	}
}

// Register adds a name to what this build knows, once, on the paths given,
// and refuses a name that is not one, a name twice, no path and a bit that
// is no path by panicking, since each is the program's own mistake at init;
// none of the refused calls changes what is known.
func TestRegisterAddsANameOnce(t *testing.T) {
	unregister := Register("a-feature", OnMessage)
	if !Known("a-feature", OnMessage) || Known("a-feature", OnManifest|OnRequest|OnAnswer) {
		t.Fatal("a registered name is not known on its path alone")
	}
	t.Cleanup(func() {
		unregister()
		if Known("a-feature", AnyPath) {
			t.Error("the name is still known after its unregister ran")
		}
	})
	for _, c := range []struct {
		name string
		on   Path
		why  string
	}{
		{"a-feature", OnMessage, "a name twice"},
		{"a-feature", OnAnswer, "a name twice on another path"},
		{"Not-A-Name", OnMessage, "not a name"},
		{"", OnMessage, "no name"},
		{"no-path", 0, "no path"},
		{"unknown-bit", AnyPath + 1, "a bit that is no path"},
		{"unknown-bit", 1 << 7, "the top bit"},
		{"unknown-bit", OnMessage | 1<<4, "a path and a bit that is none"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q, %08b), %s, did not panic", c.name, c.on, c.why)
				}
			}()
			Register(c.name, c.on)
		}()
	}
	if known["a-feature"] != OnMessage {
		t.Errorf("a refused second registration changed the first: %08b", known["a-feature"])
	}
	for _, name := range []string{"no-path", "unknown-bit"} {
		if _, ok := known[name]; ok {
			t.Errorf("a refused registration of %q left an entry", name)
		}
	}
}

// CheckBody is the one rule for a body's sections at both ends (D37, R4):
// the list's shape first, then its size as this build encodes it, then the
// sort. Each edge is one step apart, and the order is shown by a list that
// breaks two rules at once.
func TestLimitCheckBody(t *testing.T) {
	sized := func(n int) []Section {
		empty, _ := json.Marshal([]Section{{Name: "later", Data: json.RawMessage(`""`)}})
		return []Section{{Name: "later", Data: json.RawMessage(`"` + strings.Repeat("a", n-len(empty)) + `"`)}}
	}
	for _, n := range []int{MaxAPISectionBytes - 1, MaxAPISectionBytes} {
		if err := CheckBody(sized(n)); err != nil {
			t.Errorf("%d bytes: %v; want them taken", n, err)
		}
	}
	var size *SizeError
	if err := CheckBody(sized(MaxAPISectionBytes + 1)); !errors.As(err, &size) || size.Bytes != MaxAPISectionBytes+1 {
		t.Errorf("%d bytes: %v; want a SizeError of that many", MaxAPISectionBytes+1, err)
	}
	if err := CheckBody(nil); err != nil {
		t.Errorf("no sections: %v", err)
	}

	count := func(n int) []Section {
		out := make([]Section, n)
		for i := range out {
			out[i] = section(fmt.Sprintf("s%d", i), false)
		}
		return out
	}
	if err := CheckBody(count(MaxSections)); err != nil {
		t.Errorf("%d sections: %v; want them taken", MaxSections, err)
	}
	if err := CheckBody(count(MaxSections + 1)); !errors.Is(err, ErrForm) {
		t.Errorf("%d sections: %v; want ErrForm", MaxSections+1, err)
	}

	// The shape before the sort: a critical section first and a bad name
	// after it is a list that is not one, never a body that needs a newer
	// build, so nothing unread is advised about.
	twoWrong := []Section{section("must-know", true), section("Bad", false)}
	if err := CheckBody(twoWrong); !errors.Is(err, ErrForm) || errors.Is(err, ErrNeedsNewer) {
		t.Errorf("a critical section then a bad name: %v; want ErrForm and not ErrNeedsNewer", err)
	}
	// The size before the sort: a critical section in a list over the size.
	big := append(sized(MaxAPISectionBytes), section("must-know", true))
	if err := CheckBody(big); !errors.As(err, &size) {
		t.Errorf("a critical section in a list over the size: %v; want a SizeError", err)
	}
	var newer *NeedsNewerError
	if err := CheckBody([]Section{section("later", false), section("must-know", true)}); !errors.As(err, &newer) || newer.Name != "must-know" {
		t.Errorf("a critical section this build does not know: %v; want NeedsNewerError naming it", err)
	}
	if err := CheckBody([]Section{section("later", false)}); err != nil {
		t.Errorf("a section this build does not know, not critical: %v; want it ignored", err)
	}
}
