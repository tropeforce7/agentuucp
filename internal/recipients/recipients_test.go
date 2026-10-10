package recipients

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// fp is the i'th of a run of distinct fingerprints, by construction.
func fp(i int) string { return fmt.Sprintf("%064x", i+1) }

func fps(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fp(i)
	}
	return out
}

// listJSON writes a list as this build does, compactly.
func listJSON(t *testing.T, to []string) []byte {
	t.Helper()
	data, err := json.Marshal(List{To: to})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The rule as a table, in its own order: one and thirty-two taken, zero and
// thirty-three refused, a fingerprint twice, one a character short, one in
// upper case, the reader missing, a field the list does not have, and null.
// Each refusal is ErrForm with the sentence that names what is wrong.
func TestTheRuleTakesAListAndRefusesWhatBreaksIt(t *testing.T) {
	upper := strings.ToUpper(strings.Repeat("ab", 32))
	short := fp(1)[1:]
	rows := []struct {
		name string
		data []byte
		self string
		want string // empty: taken
	}{
		{"one, the reader", listJSON(t, fps(1)), fp(0), ""},
		{"thirty-two", listJSON(t, fps(relayapi.MaxRecipients)), fp(relayapi.MaxRecipients - 1), ""},
		{"none", listJSON(t, []string{}), fp(0), "it names nobody"},
		{"the key absent", []byte(`{}`), fp(0), "it names nobody"},
		{"null", []byte(`{"to":null}`), fp(0), "it names nobody"},
		{"thirty-three", listJSON(t, fps(relayapi.MaxRecipients+1)), fp(0), "33 recipients, at most 32"},
		{"a fingerprint twice", listJSON(t, []string{fp(0), fp(1), fp(0)}), fp(0), "is named twice"},
		{"a fingerprint one short", listJSON(t, []string{fp(0), short}), fp(0), "entry 2 is not a fingerprint"},
		{"a fingerprint in upper case", listJSON(t, []string{fp(0), upper}), fp(0), "entry 2 is not a fingerprint"},
		{"the reader not named", listJSON(t, fps(3)), fp(7), "it does not name " + fp(7)[:16]},
		{"a field the list does not have", []byte(`{"to":["` + fp(0) + `"],"role":"cc"}`), fp(0), "unknown field"},
		{"a key that matches only by case", []byte(`{"TO":["` + fp(0) + `"]}`), fp(0), "*"},
		{"trailing data", append(listJSON(t, fps(1)), '}'), fp(0), wire.ErrTrailing.Error()},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := Check(row.data, row.self)
			if row.want == "*" {
				// wire.Decode refuses it in its own words; the row is
				// here so that the rule is seen to read strictly.
				if !errors.Is(err, ErrForm) {
					t.Fatalf("taken: %v", err)
				}
				return
			}
			if row.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), row.want) {
				t.Fatalf("got %v; want ErrForm saying %q", err, row.want)
			}
		})
	}
}

// The order the rule promises: a section over its cap is refused for its
// size before a byte of it is decoded. The data is over the cap and its last
// byte is not JSON, so a decode that ran first would say so instead.
func TestTheSizeIsCheckedBeforeTheDecode(t *testing.T) {
	data := []byte(`{"to":["` + strings.Repeat("a", MaxBytes) + `x`)
	_, err := Check(data, fp(0))
	if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), fmt.Sprintf("over the %d it may be", MaxBytes)) {
		t.Fatalf("got %v; want the size refusal, which comes before the decode", err)
	}

	// The edge: a list padded with white space to the cap exactly is
	// taken, and one byte more is refused.
	base := listJSON(t, fps(1))
	at := append([]byte(strings.Repeat(" ", MaxBytes-len(base))), base...)
	if len(at) != MaxBytes {
		t.Fatalf("the padded list is %d bytes, want %d", len(at), MaxBytes)
	}
	if _, err := Check(at, fp(0)); err != nil {
		t.Fatalf("a list at the cap was refused: %v", err)
	}
	if _, err := Check(append([]byte(" "), at...), fp(0)); !errors.Is(err, ErrForm) {
		t.Fatalf("a list a byte over the cap: %v; want ErrForm", err)
	}
}

// Every number in MaxBytes's comment, asserted against the encoder.
func TestMaxBytesArithmeticIsTheEncoders(t *testing.T) {
	full := fps(relayapi.MaxRecipients)
	compact, err := json.Marshal(List{To: full})
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(List{To: full}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("the terms", func(t *testing.T) {
		if got := len(`{"to":[`); got != 7 {
			t.Errorf("the opening is %d bytes, the comment says 7", got)
		}
		if got := len(listJSON(t, fps(1))) - len(`{"to":[]}`); got != 66 {
			t.Errorf("one fingerprint is %d bytes, the comment says 66", got)
		}
		if got := len(`]}`); got != 2 {
			t.Errorf("the close is %d bytes, the comment says 2", got)
		}
	})
	t.Run("compact at the ceiling", func(t *testing.T) {
		if want := 7 + relayapi.MaxRecipients*66 + (relayapi.MaxRecipients - 1) + 2; len(compact) != want || want != 2152 {
			t.Errorf("compact list at the ceiling is %d bytes, the terms give %d, the comment says 2,152", len(compact), want)
		}
	})
	t.Run("indented at the ceiling", func(t *testing.T) {
		if len(indented) != 2320 {
			t.Errorf("indented list at the ceiling is %d bytes, the comment says 2,320", len(indented))
		}
	})
	t.Run("under the cap and under what an older reader keeps", func(t *testing.T) {
		if len(indented) > MaxBytes || len(compact) > MaxBytes {
			t.Errorf("a list at the ceiling does not fit the cap of %d", MaxBytes)
		}
		if MaxBytes > wire.MaxKeptBytes {
			t.Errorf("the cap %d is over the %d a reader that does not know the section keeps", MaxBytes, wire.MaxKeptBytes)
		}
	})
}

// The rule is never run without knowing whose copy it is, so step three
// cannot be skipped by a caller that forgot.
func TestTheRuleNeedsItsCopysRecipient(t *testing.T) {
	data := listJSON(t, fps(2))
	for _, self := range []string{"", fp(0)[:16], strings.ToUpper(strings.Repeat("ab", 32))} {
		if _, err := Check(data, self); err == nil || errors.Is(err, ErrForm) {
			t.Errorf("checked with %q for the reader: %v; want the programming error", self, err)
		}
	}
}

// The section on a message that is one envelope to one person by its own
// rules is refused, whoever is named; an ack is a reply's kind and may
// carry it; a list with no section passes as a message to one.
func TestTheSectionIsRefusedOnAOnePersonMessage(t *testing.T) {
	sec, err := Section(fps(2))
	if err != nil {
		t.Fatal(err)
	}
	list := []wire.Section{sec}
	for _, typ := range []string{message.TypeKnock, message.TypeVouch, message.TypeVouchAsk} {
		if _, err := CheckSections(list, typ, fp(0)); !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "one envelope to one person") {
			t.Errorf("a %s carrying the list: %v; want the refusal", typ, err)
		}
	}
	for _, typ := range []string{message.TypeAsk, message.TypeReply, message.TypeNote, message.TypeAck} {
		got, err := CheckSections(list, typ, fp(1))
		if err != nil || len(got.To) != 2 {
			t.Errorf("a %s carrying the list: %v, %v; want it read", typ, got, err)
		}
	}
	if got, err := CheckSections(nil, message.TypeKnock, fp(0)); err != nil || got.To != nil {
		t.Errorf("no section: %v, %v; want a message to one", got, err)
	}
}

// Section writes the list in the order given, not critical, and holds it to
// the rule but for whose copy it is.
func TestSectionWritesTheListAsGiven(t *testing.T) {
	order := []string{fp(5), fp(1), fp(3)}
	sec, err := Section(order)
	if err != nil {
		t.Fatal(err)
	}
	if sec.Name != Name || sec.Critical {
		t.Fatalf("the section is %q, critical %v; want %q, not critical", sec.Name, sec.Critical, Name)
	}
	if want := listJSON(t, order); string(sec.Data) != string(want) {
		t.Fatalf("the section's data is %s; want %s", sec.Data, want)
	}
	for _, bad := range [][]string{nil, fps(relayapi.MaxRecipients + 1), {fp(0), fp(0)}} {
		if _, err := Section(bad); !errors.Is(err, ErrForm) {
			t.Errorf("Section(%d names) = %v; want ErrForm", len(bad), err)
		}
	}
	if !wire.Known(Name, wire.OnMessage) {
		t.Fatal("the section is not registered with the wire")
	}
}

// Each of the three names is known on the paths its feature reads it on and
// on no other (D76, R13): the list in a message and a manifest, the count in
// a request alone and the maximum in an answer alone, and neither in a
// message, where they are held to wire.MaxKeptBytes as an unknown section
// is.
func TestTheSectionsAreKnownOnTheirPathsAlone(t *testing.T) {
	paths := []struct {
		on    wire.Path
		label string
	}{
		{wire.OnMessage, "a message"},
		{wire.OnManifest, "a manifest"},
		{wire.OnRequest, "a request"},
		{wire.OnAnswer, "an answer"},
	}
	for _, c := range []struct {
		name string
		on   wire.Path
	}{
		{Name, wire.OnMessage | wire.OnManifest},
		{CountName, wire.OnRequest},
		{MaxName, wire.OnAnswer},
	} {
		for _, p := range paths {
			if got, want := wire.Known(c.name, p.on), c.on&p.on != 0; got != want {
				t.Errorf("%s known on %s: %v; want %v", c.name, p.label, got, want)
			}
		}
		if !wire.Known(c.name, wire.AnyPath) {
			t.Errorf("%s is not known on any path", c.name)
		}
	}
}
