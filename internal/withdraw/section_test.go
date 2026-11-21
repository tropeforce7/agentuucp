package withdraw_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

const anID = "0123456789abcdef0123456789abcdef"

// The reason is the subject's rule at the subject's cap: the two agree on
// every value, at the cap and one past it, and on each character a line
// may not hold.
func TestTheReasonIsTheSubjectsRuleAtItsCap(t *testing.T) {
	for name, r := range map[string]string{
		"empty":            "",
		"at the cap":       strings.Repeat("a", withdraw.MaxReasonBytes),
		"one past the cap": strings.Repeat("a", withdraw.MaxReasonBytes+1),
		"an ESC":           "fine\x1b[2Jthen",
		"a bidi override":  "fine‮then",
		"U+2028":           "fine then",
		"a newline":        "fine\nthen",
		"a tab":            "fine\tthen",
		"not UTF-8":        "fine\xffthen",
		"a plain line":     "sent to the wrong person",
	} {
		got, want := withdraw.ValidReason(r), message.ValidSubject(r)
		if (got == nil) != (want == nil) {
			t.Errorf("%s: the reason's rule says %v and the subject's %v", name, got, want)
		}
	}
	if withdraw.ValidReason(strings.Repeat("a", withdraw.MaxReasonBytes)) != nil ||
		withdraw.ValidReason(strings.Repeat("a", withdraw.MaxReasonBytes+1)) == nil {
		t.Fatal("the reason's cap is not MaxReasonBytes")
	}
}

// The data's rule, in its order: over the cap is refused before any decode,
// so a body that would also fail the decode is refused for its size; then
// the strict decode; then the id; then the reason.
func TestAWithdrawalSectionIsHeldToItsRule(t *testing.T) {
	good := `{"id":"` + anID + `","reason":"a mistake"}`
	if w, err := withdraw.Check([]byte(good)); err != nil || w.ID != anID || w.Reason != "a mistake" {
		t.Fatalf("a good section: %+v, %v", w, err)
	}
	if w, err := withdraw.Check([]byte(`{"id":"` + anID + `","reason":""}`)); err != nil || w.Reason != "" {
		t.Fatalf("a section with no reason: %+v, %v", w, err)
	}
	for _, c := range []struct{ name, data, want string }{
		{"over its cap", `"` + strings.Repeat("a", withdraw.MaxSectionBytes) + `"`, "over the 25600 it may be"},
		{"a field it does not have", `{"id":"` + anID + `","reason":"","colour":"blue"}`, `unknown field "colour"`},
		{"not an object", `["` + anID + `"]`, "cannot unmarshal array"},
		{"no id", `{"reason":"x"}`, "its id is not a message id"},
		{"an id one short", `{"id":"` + anID[:31] + `"}`, "its id is not a message id"},
		{"an id one long", `{"id":"` + anID + `0"}`, "its id is not a message id"},
		{"an id in uppercase", `{"id":"` + strings.ToUpper(anID) + `"}`, "its id is not a message id"},
		{"an id not hex", `{"id":"` + "g" + anID[1:] + `"}`, "its id is not a message id"},
		{"a reason with ESC", `{"id":"` + anID + `","reason":"a\u001bb"}`, "reason"},
		{"a reason with a newline", `{"id":"` + anID + `","reason":"a\nb"}`, "reason"},
		{"a reason one byte over", `{"id":"` + anID + `","reason":"` + strings.Repeat("a", withdraw.MaxReasonBytes+1) + `"}`, "at most 4096"},
	} {
		_, err := withdraw.Check([]byte(c.data))
		if !errors.Is(err, withdraw.ErrForm) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want the form's refusal saying %q", c.name, err, c.want)
		}
	}
}

// MaxSectionBytes is above the largest section a writer can make for a
// valid reason: compactly, a reason at its cap each of whose bytes
// encoding/json writes as six, which is 24,629 bytes exactly, and the same
// indented. Section builds that largest one.
func TestMaxSectionBytesHoldsTheLargestSection(t *testing.T) {
	reason := strings.Repeat("<", withdraw.MaxReasonBytes)
	s, err := withdraw.Section(anID, reason)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Data) != 24_629 {
		t.Fatalf("the largest compact section is %d bytes, not the 24,629 the comment says", len(s.Data))
	}
	indented, err := json.MarshalIndent(withdraw.Withdrawal{ID: anID, Reason: reason}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Data) > withdraw.MaxSectionBytes || len(indented) > withdraw.MaxSectionBytes {
		t.Fatalf("compact %d and indented %d bytes; the cap is %d", len(s.Data), len(indented), withdraw.MaxSectionBytes)
	}
	if _, err := withdraw.Check(indented); err != nil {
		t.Fatalf("the indented section: %v", err)
	}
	if s.Critical || s.Name != withdraw.SectionName {
		t.Fatalf("Section built %+v", s)
	}
}

// The section on its message: never critical, on a note alone, naming the
// message the note answers, and on a note with no attachment. A list
// without it is no withdrawal.
func TestTheSectionIsHeldToTheNoteItIsOn(t *testing.T) {
	sec, err := withdraw.Section(anID, "")
	if err != nil {
		t.Fatal(err)
	}
	note := withdraw.NoteBody(anID, anID, "")
	if w, err := withdraw.CheckSections([]wire.Section{sec}, note); err != nil || w == nil || w.ID != anID {
		t.Fatalf("a note's section: %+v, %v", w, err)
	}
	if w, err := withdraw.CheckSections(nil, note); err != nil || w != nil {
		t.Fatalf("no section: %+v, %v; want no withdrawal", w, err)
	}
	critical := sec
	critical.Critical = true
	ask := note
	ask.Type = message.TypeAsk
	other := note
	other.InReplyTo = "f" + anID[1:]
	attached := note
	a, err := message.NewAttachment("x.txt", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	attached.Attachments = []message.Attachment{a}
	for _, c := range []struct {
		name string
		sec  wire.Section
		body message.Body
		want string
	}{
		{"marked critical", critical, note, "marked critical"},
		{"on an ask", sec, ask, "on a message of type ask"},
		{"in reply to another message", sec, other, "in reply to another message"},
		{"with an attachment", sec, attached, "carries an attachment"},
	} {
		if _, err := withdraw.CheckSections([]wire.Section{c.sec}, c.body); !errors.Is(err, withdraw.ErrForm) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want the form's refusal saying %q", c.name, err, c.want)
		}
	}
}

// The note's body says what an old reader reads: the subject, the
// sentence, and the reason after a blank line when there is one; it is a
// valid note, in reply to the message, on its thread.
func TestANotesBodySaysItWasWithdrawn(t *testing.T) {
	thread := "f" + anID[1:]
	for reason, text := range map[string]string{
		"":          withdraw.NoteSentence,
		"a mistake": withdraw.NoteSentence + "\n\na mistake",
	} {
		b := withdraw.NoteBody(thread, anID, reason)
		if b.Type != message.TypeNote || b.Subject != withdraw.NoteSubject || b.Thread != thread || b.InReplyTo != anID || b.Text != text {
			t.Errorf("reason %q: %+v", reason, b)
		}
		if err := b.Validate(); err != nil {
			t.Errorf("reason %q: the note's body does not validate: %v", reason, err)
		}
	}
}

// The section is known on a message and on no other path: on a manifest,
// a request or an answer it is a name this build does not know.
func TestTheSectionIsKnownOnAMessageAlone(t *testing.T) {
	for _, c := range []struct {
		path wire.Path
		name string
		want bool
	}{
		{wire.OnMessage, "a message", true},
		{wire.OnManifest, "a manifest", false},
		{wire.OnRequest, "a request", false},
		{wire.OnAnswer, "an answer", false},
	} {
		if got := wire.Known(withdraw.SectionName, c.path); got != c.want {
			t.Errorf("known on %s: %v, want %v", c.name, got, c.want)
		}
	}
}
