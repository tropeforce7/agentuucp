package wire

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// G4 moved Decode's key walk from json.Decoder's tokens to a scan of the
// bytes, and its decode from a json.Decoder to json.Unmarshal (R13). The
// tests here hold the new Decode to the old one's answers: oldDecode below
// is Decode and its walk as they stood before the change, copied whole, the
// reference every row and every random document is compared against.

func oldDecode(data []byte, v any) error {
	if err := oldCheckKeys(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrTrailing
	}
	return nil
}

func oldCheckKeys(data []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	err := oldWalkValue(dec, t, 0)
	if errors.Is(err, errStop) {
		return nil
	}
	return err
}

func oldWalkValue(dec *json.Decoder, t reflect.Type, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return errStop
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth+1 > maxDepth {
		return errStop
	}
	t = target(t)
	if d == '[' {
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.More() {
			if err := oldWalkValue(dec, elem, depth+1); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errStop
		}
		return nil
	}
	return oldWalkObject(dec, t, depth+1)
}

func oldWalkObject(dec *json.Decoder, t reflect.Type, depth int) error {
	var fields map[string]reflect.Type
	var mapElem reflect.Type
	if t != nil {
		switch t.Kind() {
		case reflect.Struct:
			fields = fieldsOf(t)
		case reflect.Map:
			mapElem = t.Elem()
		}
	}
	seen := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errStop
		}
		key, ok := tok.(string)
		if !ok {
			return errStop
		}
		folded := foldKey(key)
		if first, ok := seen[folded]; ok {
			if first == key {
				return fmt.Errorf("key %q appears twice in an object at depth %d", key, depth)
			}
			return fmt.Errorf("key %q and key %q, the same under case folding, are both in an object at depth %d", first, key, depth)
		}
		seen[folded] = key
		var elem reflect.Type
		switch {
		case fields != nil:
			ft, exact := fields[key]
			if !exact {
				for name := range fields {
					if strings.EqualFold(name, key) {
						return fmt.Errorf("key %q matches the field %q only by case, in an object at depth %d", key, name, depth)
					}
				}
			}
			elem = ft
		case mapElem != nil:
			elem = mapElem
		}
		if err := oldWalkValue(dec, elem, depth); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errStop
	}
	return nil
}

// errClass names the kind of answer a decode gave, which is what the two
// Decodes are held to agree on; the sentences of the key refusals are held
// whole in TestDecodeRefusesAKeyThatReadsTwoWays.
func errClass(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrTrailing):
		return "trailing"
	case errors.Is(err, errUnscanned):
		return "unscanned"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.As(err, &syn):
		return "syntax"
	case errors.As(err, &typ):
		return "type"
	case strings.Contains(err.Error(), "appears twice in an object"):
		return "dup"
	case strings.Contains(err.Error(), "the same under case folding"):
		return "fold"
	case strings.Contains(err.Error(), "only by case"):
		return "case"
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown"
	}
	return "other: " + err.Error()
}

type decInner struct {
	Name string `json:"name"`
	K    int    `json:"k"`
}

type decDoc struct {
	Name  string         `json:"name"`
	N     float64        `json:"n"`
	Flag  *bool          `json:"flag"`
	Inner decInner       `json:"inner"`
	Map   map[string]int `json:"map"`
	List  []decInner     `json:"list"`
	Any   any            `json:"any"`
}

// Every row decoded into a struct with a nested struct, a map, a slice of
// structs and an interface, by the new Decode and by the old, each held to
// the class the row names. Where the two differ the row fails on the new
// one, since the old one's answer is the contract.
func TestDecodeRefusesTheSameAsBefore(t *testing.T) {
	nest := func(n int) string {
		// n levels in all: the top object is one, the arrays under "any"
		// the rest.
		return `{"any":` + strings.Repeat("[", n-1) + strings.Repeat("]", n-1) + `}`
	}
	for _, tc := range []struct {
		what, in, want string
	}{
		{"a whole document", `{"name":"a","n":1,"flag":true,"inner":{"name":"b","k":1},"map":{"x":1},"list":[{"k":2},{"name":"c"}],"any":{"Name":[1,{"NAME":2}]}}`, "ok"},
		{"an empty object", `{}`, "ok"},
		{"a key twice", `{"name":"a","name":"b"}`, "dup"},
		{"a key twice in a slice element", `{"list":[{"k":1,"k":2}]}`, "dup"},
		{"a key twice, once escaped", `{"map":{"A":1,"\u0041":2}}`, "dup"},
		{"the Kelvin sign and k in a map", "{\"map\":{\"k\":1,\"\u212a\":2}}", "fold"},
		{"the Kelvin sign escaped and k in a map", `{"map":{"k":1,"\u212a":2}}`, "fold"},
		{"a field by case alone", `{"Name":"a"}`, "case"},
		{"the Kelvin sign against the field k", "{\"inner\":{\"\u212a\":1}}", "case"},
		{"an unknown field at the top", `{"zz":1}`, "unknown"},
		{"an unknown field nested", `{"inner":{"zz":1}}`, "unknown"},
		{"an unknown field in a slice element", `{"list":[{"k":1},{"zz":1}]}`, "unknown"},
		{"a trailing }", `{"name":"a"}}`, "trailing"},
		{"a trailing ]", `{"name":"a"}]`, "trailing"},
		{"a trailing letter", `{"name":"a"}x`, "trailing"},
		{"a second value", `{"name":"a"} {"name":"b"}`, "trailing"},
		{"nesting at 10,000", nest(10000), "ok"},
		{"nesting at 10,001", nest(10001), "syntax"},
		{"every escape in a key", `{"map":{"a\"b\\c\/d\be\ff\ng\rh\ti\u0041j\ud83d\ude00":1}}`, "ok"},
		{"a lone surrogate against U+FFFD escaped", `{"map":{"\ud800":1,"\ufffd":2}}`, "dup"},
		{"a lone low surrogate against U+FFFD raw", "{\"map\":{\"\\udc00\":1,\"\ufffd\":2}}", "dup"},
		{"a key with an invalid byte", "{\"map\":{\"a\xffb\":1}}", "ok"},
		{"an invalid byte against U+FFFD", "{\"map\":{\"a\xffb\":1,\"a\\ufffdb\":2}}", "dup"},
		{"an escape the decoder refuses in a key", `{"map":{"\x":1}}`, "syntax"},
		{"a control character in a key", "{\"map\":{\"a\x01\":1}}", "syntax"},
		{"nothing at all", ``, "eof"},
		{"white space alone", " \n\t", "eof"},
		{"cut short", `{"name":"a"`, "eof"},
		{"cut inside a key", `{"na`, "eof"},
		{"cut inside a literal", `{"flag":tru`, "eof"},
		{"cut inside a literal at the top", `nul`, "eof"},
		{"cut inside a number", `{"n":1e+`, "eof"},
		{"cut after a minus", `-`, "eof"},
		{"cut inside an escape", `{"name":"\u12`, "eof"},
		{"a bad escape in a value, then cut", `{"name":"\ `, "syntax"},
		{"a bad escape in a key, then cut", `{"\x`, "syntax"},
		{"a short \\u escape, then cut", `{"name":"\u12x"`, "syntax"},
		{"a bad number, then cut", `{"n":1.e`, "syntax"},
		{"a leading zero, then cut", `{"n":01`, "syntax"},
		{"two points, then cut", `{"n":1.5.`, "syntax"},
		{"a bad escape in a value, then a quote", `{"name":"\-"}"}`, "syntax"},
		{"a bad escape in a value, then a key twice", `{"name":"\-","name":1}`, "syntax"},
		{"a short \\u escape in a value, then more", `{"name":"\u00"}"}`, "syntax"},
		{"leading and trailing white space", " \t\r\n{\"name\":\"a\"}\n\t \r", "ok"},
		{"minus zero", `{"n":-0}`, "ok"},
		{"an exponent", `{"n":1e10}`, "ok"},
		{"a fraction and a capital exponent", `{"n":1.5E-3}`, "ok"},
		{"a signed exponent", `{"n":-0.0e+5}`, "ok"},
		{"a leading plus", `{"n":+1}`, "syntax"},
		{"a leading zero", `{"n":01}`, "syntax"},
		{"a bare point", `{"n":1.}`, "syntax"},
		{"a minus alone", `{"n":-}`, "syntax"},
		{"an exponent with no digits", `{"n":1e}`, "syntax"},
		{"true", `{"flag":true}`, "ok"},
		{"false", `{"flag":false}`, "ok"},
		{"null", `{"flag":null}`, "ok"},
		{"null for the whole", `null`, "ok"},
		{"a literal cut short", `{"flag":tru}`, "syntax"},
		{"a literal run on", `{"flag":truex}`, "syntax"},
		{"braces, brackets and quotes in a string", `{"name":"{[}]\"}{\"[","map":{"}{][\"":1}}`, "ok"},
		{"a string where a number goes", `{"n":"1"}`, "type"},
		{"a non-breaking space before the value", "\u00a0{}", "syntax"},
		{"a byte order mark", "\ufeff{}", "syntax"},
		{"a trailing comma", `{"name":"a",}`, "syntax"},
		{"a key that is not a string", `{1:2}`, "syntax"},
	} {
		var nv, ov decDoc
		newErr := Decode([]byte(tc.in), &nv)
		oldErr := oldDecode([]byte(tc.in), &ov)
		what := tc.what
		if got := errClass(oldErr); got != tc.want {
			t.Errorf("%s: the old Decode gave %s (%v); the row says %s", what, got, oldErr, tc.want)
		}
		if got := errClass(newErr); got != tc.want {
			t.Errorf("%s: Decode gave %s (%v); the old Decode gave %s (%v)", what, got, newErr, errClass(oldErr), oldErr)
		}
		if newErr == nil && oldErr == nil && !reflect.DeepEqual(nv, ov) {
			t.Errorf("%s: decoded %+v; the old Decode %+v", what, nv, ov)
		}
	}

	// The unknown field is refused in DisallowUnknownFields' own words.
	var v decDoc
	if err := Decode([]byte(`{"list":[{"zz":1}]}`), &v); err == nil || err.Error() != `json: unknown field "zz"` {
		t.Errorf("an unknown field: %v; want json: unknown field \"zz\"", err)
	}
	// Every escape is read as the decoder reads it, and the surrogate pair
	// is one rune.
	v = decDoc{}
	if err := Decode([]byte(`{"map":{"a\"b\\c\/d\be\ff\ng\rh\ti\u0041j\ud83d\ude00":1}}`), &v); err != nil {
		t.Fatal(err)
	}
	if want := "a\"b\\c/d\be\ff\ng\rh\tiAj\U0001F600"; v.Map[want] != 1 || len(v.Map) != 1 {
		t.Errorf("every escape: %v; want the one key %q", v.Map, want)
	}
	// A key with an invalid byte is read with U+FFFD in its place.
	v = decDoc{}
	if err := Decode([]byte("{\"map\":{\"a\xffb\":1}}"), &v); err != nil || v.Map["a\ufffdb"] != 1 {
		t.Errorf("an invalid byte: %v, %v; want the key a\\ufffdb", v.Map, err)
	}
	// A lone surrogate is read as U+FFFD (R14), so it and U+FFFD are one
	// key, refused as given twice and not as two keys folded together.
	if err := Decode([]byte(`{"map":{"\ud800":1,"\ufffd":2}}`), &v); err == nil || err.Error() != "key \"\ufffd\" appears twice in an object at depth 2" {
		t.Errorf("a lone surrogate: %v", err)
	}
}

// selfDecoding decodes itself, so its keys are its own business.
type selfDecoding struct{ raw []byte }

func (s *selfDecoding) UnmarshalJSON(b []byte) error {
	s.raw = append([]byte(nil), b...)
	return nil
}

// Inside a map, an interface and a type with its own UnmarshalJSON there is
// no field to hold a key against: any key is taken there, a field's name
// in another case among them, as before. A key given twice is refused
// there too, as before.
func TestDecodeDoesNotHoldKeysInsideWhatHasNoFields(t *testing.T) {
	type doc struct {
		M map[string]any `json:"m"`
		I any            `json:"i"`
		S selfDecoding   `json:"s"`
		P *selfDecoding  `json:"p"`
	}
	in := `{"m":{"Unknown":1,"M":{"Deep":{"I":1}}},"i":{"Whatever":1,"S":[{"y":1}]},"s":{"Anything":1,"M":2},"p":{"zz":[1]}}`
	var nv, ov doc
	if err := Decode([]byte(in), &nv); err != nil {
		t.Fatalf("keys inside a map, an interface and a self-decoding type: %v; want them taken", err)
	}
	if err := oldDecode([]byte(in), &ov); err != nil {
		t.Fatalf("the old Decode: %v", err)
	}
	if !reflect.DeepEqual(nv, ov) {
		t.Errorf("decoded %+v; the old Decode %+v", nv, ov)
	}
	if string(nv.S.raw) != `{"Anything":1,"M":2}` || nv.P == nil || string(nv.P.raw) != `{"zz":[1]}` {
		t.Errorf("the self-decoding fields were given %q and %v", nv.S.raw, nv.P)
	}
	if nv.M["Unknown"] != float64(1) || nv.I.(map[string]any)["Whatever"] != float64(1) {
		t.Errorf("the map and the interface: %v, %v", nv.M, nv.I)
	}
	for _, in := range []string{
		`{"m":{"a":1,"a":2}}`,
		`{"i":{"x":{"a":1,"a":2}}}`,
		`{"s":{"a":1,"a":2}}`,
		`{"p":{"a":1,"A":2}}`,
	} {
		var nv, ov doc
		n, o := errClass(Decode([]byte(in), &nv)), errClass(oldDecode([]byte(in), &ov))
		if n != o || (n != "dup" && n != "fold") {
			t.Errorf("%s: Decode %s, the old Decode %s; want both refused as a key twice", in, n, o)
		}
	}
}

// errUnscanned is for a document the scan stops on that the decoder takes.
// The scan stops only where JSON's grammar does: no input, a byte that
// begins no value, a control byte or no closing quote in a string, a key
// that is not a string, a missing colon or comma, a key whose escape the
// decoder refuses, nesting past ten thousand. So no such document is known,
// and Decode builds its scan where no test can stand in for it; this holds
// the claim over every candidate below and over the random documents of
// TestDecodeAgreesWithTheOldDecodeOnRandomDocuments, and holds that
// Decode, where the scan stops, gives the decoder's own error.
func TestNoDocumentTheScanStopsOnIsOneTheDecoderTakes(t *testing.T) {
	cands := []string{
		``, ` `, "\u00a0{}", "{\u00a0}", "\ufeff{}", `+1`, `{"n":+1}`, `{"a" 1}`, `{"a":1 "b":2}`,
		`[1 2]`, `{"a`, `{"\x":1}`, "{\"\x01\":1}", "\"\x1f\"", `{,}`, `[,]`, `{"a":}`, `}`, `]`,
		`{"a":1}` + "\x00", "{\"a\":1}\v", "{\"a\":1}\f", strings.Repeat("[", 10001) + strings.Repeat("]", 10001),
		`{"\ud800":1}`, "{\"a\xff\":1}", `{'a':1}`, `{"a":'b'}`, `{a:1}`, "{\"a\":1}\u2028",
	}
	for _, in := range cands {
		checkUnscanned(t, []byte(in))
	}
}

// checkUnscanned fails if the scan stops on data and the decoder takes it,
// and, where the scan stops, if Decode's answer is not of the class the old
// Decode gave: the cut-short errors a json.Decoder gives where the input
// ended inside the value or held none, the decoder's syntax error where it
// did not.
func checkUnscanned(t *testing.T, data []byte) {
	t.Helper()
	var v any
	sc := &keyScan{data: data}
	if !errors.Is(sc.value(reflect.TypeOf(&v), 0), errStop) {
		return
	}
	var u any
	if json.Unmarshal(data, &u) == nil {
		t.Errorf("%q: the scan stopped and the decoder took it; this is the document errUnscanned is for", data)
		return
	}
	var ov any
	err, oldErr := Decode(data, &v), oldDecode(data, &ov)
	if got, want := errClass(err), errClass(oldErr); got != want || (want != "eof" && want != "syntax") {
		t.Errorf("%q: the scan stopped and Decode said %v (%s); the old Decode %v (%s)", data, err, got, oldErr, want)
	}
}

// decSeed draws a seed as testutil.Seed does, which this package cannot
// import (testutil imports wire): AUU_TEST_SEED if set, crypto/rand if not,
// logged at the top.
func decSeed(t *testing.T) (*rand.Rand, uint64) {
	t.Helper()
	var seed uint64
	if raw, ok := os.LookupEnv("AUU_TEST_SEED"); ok {
		s, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("AUU_TEST_SEED=%q: %v", raw, err)
		}
		seed = s
	} else {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		seed = binary.LittleEndian.Uint64(b[:])
	}
	t.Logf("seed %d (AUU_TEST_SEED=%d to repeat)", seed, seed)
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), seed
}

// decKeys is the pool random objects draw keys from: the fields of decDoc
// and decInner, the same in other cases, the Kelvin sign, escapes, a lone
// surrogate, U+FFFD, an invalid byte and keys nobody has.
var decKeys = []string{
	`"name"`, `"Name"`, `"NAME"`, `"k"`, `"K"`, "\"\u212a\"", `"\u212a"`, `"n"`, `"flag"`, `"inner"`,
	`"map"`, `"list"`, `"any"`, `"zz"`, `"x"`, `"\u0078"`, `"a\"b"`, `"\ud800"`, "\"\ufffd\"", "\"\xff\"",
	`"{"`, `"]"`,
}

func genValue(r *rand.Rand, depth int, b *strings.Builder) {
	n := 8
	if depth > 3 {
		n = 6
	}
	switch r.IntN(n) {
	case 0:
		b.WriteString([]string{`0`, `-0`, `1e10`, `1.5E-3`, `-12.5e+2`, `7`}[r.IntN(6)])
	case 1:
		b.WriteString([]string{`true`, `false`, `null`}[r.IntN(3)])
	case 2, 3:
		b.WriteString([]string{`"a"`, `"{[}]"`, `"\"}"`, `"\\"`, `"\u00e9"`, `""`}[r.IntN(6)])
	case 4, 5:
		b.WriteString(decKeys[r.IntN(len(decKeys))])
	case 6:
		b.WriteByte('[')
		for i := range r.IntN(3) {
			if i > 0 {
				b.WriteByte(',')
			}
			genValue(r, depth+1, b)
		}
		b.WriteByte(']')
	default:
		genObject(r, depth+1, b)
	}
}

func genObject(r *rand.Rand, depth int, b *strings.Builder) {
	b.WriteByte('{')
	for i := range r.IntN(4) {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(decKeys[r.IntN(len(decKeys))])
		b.WriteString([]string{":", " : ", ":\n"}[r.IntN(3)])
		genValue(r, depth, b)
	}
	b.WriteByte('}')
}

// mutate changes a document by one edit: a byte removed, one inserted from
// the bytes JSON's grammar turns on, a span repeated, or the document cut.
func mutate(r *rand.Rand, d []byte) []byte {
	if len(d) == 0 {
		return d
	}
	const alphabet = "{}[]\",: \t\n\\x1-e.+\x00\xa0"
	i := r.IntN(len(d))
	switch r.IntN(4) {
	case 0:
		return append(append([]byte(nil), d[:i]...), d[i+1:]...)
	case 1:
		out := append([]byte(nil), d[:i]...)
		out = append(out, alphabet[r.IntN(len(alphabet))])
		return append(out, d[i:]...)
	case 2:
		j := i + r.IntN(len(d)-i)
		out := append([]byte(nil), d[:j]...)
		out = append(out, d[i:j]...)
		return append(out, d[j:]...)
	}
	return d[:i]
}

// Random small documents from a grammar over decDoc's keys, and one-edit
// mutations of them, decoded into decDoc, a map and an interface by the
// new Decode and the old: each takes exactly what the other takes, into the
// same value, and no document the scan stops on is one the decoder takes.
func TestDecodeAgreesWithTheOldDecodeOnRandomDocuments(t *testing.T) {
	r, seed := decSeed(t)
	classes, differ := map[string]int{}, map[string]int{}
	for range 20000 {
		var b strings.Builder
		genObject(r, 0, &b)
		d := []byte(b.String())
		if r.IntN(2) == 0 {
			d = mutate(r, d)
		}
		checkUnscanned(t, d)
		for _, mk := range []func() any{
			func() any { return new(decDoc) },
			func() any { return new(map[string]any) },
			func() any { return new(any) },
		} {
			nv, ov := mk(), mk()
			newErr, oldErr := Decode(d, nv), oldDecode(d, ov)
			classes[errClass(newErr)]++
			if errClass(newErr) != errClass(oldErr) {
				differ[errClass(oldErr)+" -> "+errClass(newErr)]++
			}
			// A document the old Decode refused as malformed is refused as
			// malformed, or for an unknown field the scan now meets before
			// the fault, and never for anything the scan read past it.
			if o, n := errClass(oldErr), errClass(newErr); (o == "syntax" || o == "eof") && n != o && n != "unknown" {
				t.Errorf("seed %d: %q into %T: Decode %v (%s), the old Decode %v (%s)", seed, d, nv, newErr, n, oldErr, o)
			}
			if (newErr == nil) != (oldErr == nil) {
				t.Fatalf("seed %d: %q into %T: Decode %v, the old Decode %v", seed, d, nv, newErr, oldErr)
			}
			if newErr == nil && !reflect.DeepEqual(nv, ov) {
				t.Fatalf("seed %d: %q into %T: decoded %v, the old Decode %v", seed, d, nv, nv, ov)
			}
		}
	}
	t.Logf("answers by class: %v; where the refusal's class moved, old -> new: %v", classes, differ)
	// The grammar reaches every answer, so a pass is a comparison of each.
	for _, c := range []string{"ok", "dup", "fold", "case", "unknown", "syntax", "trailing"} {
		if classes[c] == 0 {
			t.Errorf("seed %d: no random document was answered %s", seed, c)
		}
	}
}

// breakJSON makes one edit that is likely to leave a document invalid: a
// byte dropped or inserted from the bytes the grammar turns on, a cut, a
// control character or a bad escape inside a string.
func breakJSON(r *rand.Rand, d []byte) []byte {
	if len(d) == 0 {
		return d
	}
	const alphabet = "\"{}[],:\\ a1-.eE"
	i := r.IntN(len(d))
	ins := func(b ...byte) []byte {
		out := append([]byte(nil), d[:i]...)
		out = append(out, b...)
		return append(out, d[i:]...)
	}
	// A place just inside a string, if there is one at or after i.
	inString := func() int {
		if j := bytes.IndexByte(d[i:], '"'); j >= 0 {
			return i + j + 1
		}
		return i
	}
	switch r.IntN(5) {
	case 0:
		return append(append([]byte(nil), d[:i]...), d[i+1:]...)
	case 1:
		return ins(alphabet[r.IntN(len(alphabet))])
	case 2:
		return d[:i]
	case 3:
		i = inString()
		return ins(byte(r.IntN(0x20)))
	}
	i = inString()
	bad := [][]byte{{'\\', 'x'}, {'\\', 'u', '1', '2'}, {'\\', 'u', 'g', '0', '0', '0'}, {'\\', ' '}, {'\\', '\''}}
	return ins(bad[r.IntN(len(bad))]...)
}

// firstRepeat walks data's tokens with a json.Decoder, apart from the
// scanner, and answers the class of the first key in an object that
// repeats an earlier key of that object, "dup" when the same bytes and
// "fold" when equal under strings.EqualFold, or "" for none before the
// walk ends or meets a token the decoder refuses.
func firstRepeat(data []byte) string {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func() (string, bool)
	walk = func() (string, bool) {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return "", true
		}
		var keys []string
		for dec.More() {
			if d == '{' {
				tok, err := dec.Token()
				if err != nil {
					return "", false
				}
				k, _ := tok.(string)
				for _, prev := range keys {
					if prev == k {
						return "dup", false
					}
					if strings.EqualFold(prev, k) {
						return "fold", false
					}
				}
				keys = append(keys, k)
			}
			if c, ok := walk(); c != "" || !ok {
				return c, false
			}
		}
		if _, err := dec.Token(); err != nil {
			return "", false
		}
		return "", true
	}
	c, _ := walk()
	return c
}

// Held to encoding/json itself rather than to the Decode before G4: over
// random documents from the grammar, their mutations and edits that break
// them, decoded into any so that no field is unknown, a document json.Valid
// refuses is refused, as malformed, as cut short, or as a valid value with
// more after it; and one json.Valid takes is taken unless a key in it
// repeats another of its object or equals it under case folding, found by
// a walk of the decoder's tokens, in which case it is refused for exactly
// that, and otherwise answered as json.Unmarshal answers it (a number past
// float64's range is valid JSON and a type error). The refusals that need a struct are held by hand at the end.
func TestTheScanAcceptsWhatTheStandardLibraryAccepts(t *testing.T) {
	r, seed := decSeed(t)
	counts := map[string]int{}
	for range 25000 {
		var b strings.Builder
		genObject(r, 0, &b)
		d := []byte(b.String())
		switch r.IntN(3) {
		case 1:
			d = mutate(r, d)
		case 2:
			d = breakJSON(r, d)
		}
		var v any
		err := Decode(d, &v)
		got := errClass(err)
		repeat := firstRepeat(d)
		if !json.Valid(d) {
			counts["invalid"]++
			switch {
			case repeat != "" && got == repeat:
			case got == "syntax" || got == "eof":
			case got == "trailing":
				valid := false
				for k := len(d) - 1; k > 0 && !valid; k-- {
					valid = json.Valid(d[:k])
				}
				if !valid {
					t.Errorf("seed %d: %q: refused as trailing data, but no prefix of it is a valid value", seed, d)
				}
			default:
				t.Errorf("seed %d: %q: json.Valid refuses it and Decode said %v (%s)", seed, d, err, got)
			}
			continue
		}
		if repeat == "" {
			// Valid JSON can still fail to decode for its values: a
			// number past float64's range is a type error to
			// json.Unmarshal itself, and is held to that answer.
			var u any
			uerr := json.Unmarshal(d, &u)
			counts["valid"]++
			if uerr != nil {
				counts["valid, a value the decoder refuses"]++
			}
			if errClass(err) != errClass(uerr) || (err == nil) != (uerr == nil) {
				t.Errorf("seed %d: %q: valid with no key repeated; Decode said %v and json.Unmarshal %v", seed, d, err, uerr)
			}
			continue
		}
		counts["valid, "+repeat]++
		if got != repeat {
			t.Errorf("seed %d: %q: valid with a key repeated (%s), and Decode said %v (%s)", seed, d, repeat, err, got)
		}
	}
	t.Logf("documents: %v", counts)
	for _, c := range []string{"invalid", "valid", "valid, dup", "valid, fold"} {
		if counts[c] < 100 {
			t.Errorf("seed %d: only %d documents were %s", seed, counts[c], c)
		}
	}

	// The refusals that need a struct: a valid value with more after it,
	// and a key the struct does not have.
	type small struct {
		A int `json:"a"`
	}
	for _, in := range []string{`{"a":1} {}`, `{"a":1}}`, `{"a":1}]`, `{"a":1}x`, `{"a":1} 1`} {
		var s small
		if err := Decode([]byte(in), &s); !errors.Is(err, ErrTrailing) {
			t.Errorf("%q: %v; want ErrTrailing", in, err)
		}
	}
	var s small
	if err := Decode([]byte(`{"a":1,"b":2}`), &s); err == nil || err.Error() != `json: unknown field "b"` {
		t.Errorf("an unknown field: %v; want json: unknown field \"b\"", err)
	}
}
