package envelope

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

const withdrawnID = "fedcba9876543210fedcba9876543210"

// noteRecord is a signed-to-be inner record of a withdrawal note from
// alice to bob, as raw JSON, with whatever body and sections the test
// wants and nothing held to the sealer's rules.
func noteRecord(t *testing.T, alice, bob *identity.Identity, v int, b message.Body, sections []wire.Section) []byte {
	t.Helper()
	raw, err := json.Marshal(&Inner{
		V: v, From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
		ID: "0123456789abcdef0123456789abcdef", Time: time.Now().UTC().Truncate(time.Second),
		Body: b, Sections: sections,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rawWithdrawal is a withdrawal section with the data given, unchecked.
func rawWithdrawal(data string) wire.Section {
	return wire.Section{Name: withdraw.SectionName, Data: json.RawMessage(data)}
}

// A note sealed with its section and a made-up section beside it opens to
// the same note, its section read and held, the other kept as one this
// build does not know; not critical, so it is version 1 outside and in.
func TestAWithdrawalNoteRoundTrips(t *testing.T) {
	alice, bob := pair(t)
	sec, err := withdraw.Section(withdrawnID, "sent to the wrong person")
	if err != nil {
		t.Fatal(err)
	}
	note := withdraw.NoteBody("0123456789abcdef0123456789abcdef", withdrawnID, "sent to the wrong person")
	env, sealed, err := SealSections(alice, bob.Public(), "", note, []wire.Section{sec, later(false)})
	if err != nil {
		t.Fatal(err)
	}
	if env.V != Version || sealed.V != Version {
		t.Fatalf("a note sealed as %d outside and %d inside; want %d", env.V, sealed.V, Version)
	}
	inner, _, err := Open(bob, env)
	if err != nil {
		t.Fatal(err)
	}
	w, err := withdraw.CheckSections(inner.Sections, inner.Body)
	if err != nil || w == nil || w.ID != withdrawnID || w.Reason != "sent to the wrong person" {
		t.Fatalf("the opened note's section: %+v, %v", w, err)
	}
	if inner.Body.Text != note.Text || inner.Body.InReplyTo != withdrawnID || len(inner.Sections) != 2 {
		t.Fatalf("the opened note: %+v", inner)
	}
}

// The sealer holds the section to its rule and to the note before it signs
// anything: a section naming another message, on an ask, on a note with an
// attachment, marked critical, with a reason that is not one line, over its
// cap, or with an id that is not one, is refused, and no signature is made.
func TestTheSealerHoldsAWithdrawalBeforeItSigns(t *testing.T) {
	alice, bob := pair(t)
	signed := countingSigner(t, alice, -1)
	sec, err := withdraw.Section(withdrawnID, "")
	if err != nil {
		t.Fatal(err)
	}
	note := withdraw.NoteBody("0123456789abcdef0123456789abcdef", withdrawnID, "")
	other := note
	other.InReplyTo = "0123456789abcdef0123456789abcdef"
	ask := body(t)
	ask.InReplyTo = withdrawnID
	attached := note
	a, err := message.NewAttachment("x.txt", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	attached.Attachments = []message.Attachment{a}
	critical := sec
	critical.Critical = true
	for _, row := range []struct {
		name string
		b    message.Body
		sec  wire.Section
		want string
	}{
		{"another message", other, sec, "in reply to another message"},
		{"on an ask", ask, sec, "on a message of type ask"},
		{"with an attachment", attached, sec, "carries an attachment"},
		{"marked critical", note, critical, "marked critical"},
		{"a reason with ESC", note, rawWithdrawal(`{"id":"` + withdrawnID + `","reason":"a\u001bb"}`), "reason"},
		{"a reason with a bidi override", note, rawWithdrawal(`{"id":"` + withdrawnID + `","reason":"a‮b"}`), "reason"},
		{"a reason with U+2028", note, rawWithdrawal(`{"id":"` + withdrawnID + `","reason":"a b"}`), "reason"},
		{"a reason with a newline", note, rawWithdrawal(`{"id":"` + withdrawnID + `","reason":"a\nb"}`), "reason"},
		{"a reason one byte over", note, rawWithdrawal(`{"id":"` + withdrawnID + `","reason":"` + strings.Repeat("a", withdraw.MaxReasonBytes+1) + `"}`), "at most 4096"},
		{"over its cap", note, rawWithdrawal(`"` + strings.Repeat("a", withdraw.MaxSectionBytes) + `"`), "over the 25600"},
		{"an id that is not one", note, rawWithdrawal(`{"id":"` + strings.ToUpper(withdrawnID) + `"}`), "not a message id"},
	} {
		t.Run(row.name, func(t *testing.T) {
			env, _, err := SealSections(signed.id, bob.Public(), "", row.b, []wire.Section{row.sec})
			if !errors.Is(err, withdraw.ErrForm) || !strings.Contains(err.Error(), row.want) || env != nil {
				t.Fatalf("got an envelope %v, %v; want none and the refusal saying %q", env != nil, err, row.want)
			}
		})
	}
	if n := signed.count.Load(); n != 0 {
		t.Fatalf("%d signatures were made for notes that were refused", n)
	}
}

// Open holds the section to the rule once the signature has verified: a
// signed note whose section breaks it is malformed, saying why, and the same
// note with a good section opens.
func TestAWithdrawalThatBreaksTheRuleIsMalformedAtOpen(t *testing.T) {
	alice, bob := pair(t)
	note := withdraw.NoteBody("0123456789abcdef0123456789abcdef", withdrawnID, "")
	ask := body(t)
	ask.InReplyTo = withdrawnID
	good := rawWithdrawal(`{"id":"` + withdrawnID + `","reason":""}`)
	for _, row := range []struct {
		name string
		b    message.Body
		sec  wire.Section
		want string
	}{
		{"another message", note, rawWithdrawal(`{"id":"0123456789abcdef0123456789abcdef"}`), "in reply to another message"},
		{"on an ask with attachments", ask, good, "on a message of type ask"},
		{"a reason with ESC", note, rawWithdrawal(`{"id":"` + withdrawnID + `","reason":"a\u001bb"}`), "reason"},
		{"over its cap", note, rawWithdrawal(`"` + strings.Repeat("a", withdraw.MaxSectionBytes) + `"`), "over the 25600"},
		{"a field it does not have", note, rawWithdrawal(`{"id":"` + withdrawnID + `","colour":"blue"}`), `unknown field "colour"`},
	} {
		t.Run(row.name, func(t *testing.T) {
			env := sealRecord(t, alice, bob.Public(), Version, noteRecord(t, alice, bob, Version, row.b, []wire.Section{row.sec}))
			_, _, err := Open(bob, env)
			if !errors.Is(err, ErrMalformed) || !strings.Contains(causeOf(err), row.want) {
				t.Fatalf("got %v (%s); want malformed, saying %q", err, causeOf(err), row.want)
			}
		})
	}
	env := sealRecord(t, alice, bob.Public(), Version, noteRecord(t, alice, bob, Version, note, []wire.Section{good}))
	if _, _, err := Open(bob, env); err != nil {
		t.Fatalf("a good note: %v", err)
	}
}

// The rule is read only under the signature: a section that breaks it, in
// a record whose signature does not verify, is refused for the signature.
func TestAnUnsignedWithdrawalIsRefusedForItsSignature(t *testing.T) {
	alice, bob := pair(t)
	mallory := readers(t, 1)[0]
	note := withdraw.NoteBody("0123456789abcdef0123456789abcdef", withdrawnID, "")
	broken := rawWithdrawal(`{"id":"0123456789abcdef0123456789abcdef"}`)
	env := sealRecord(t, mallory, bob.Public(), Version, noteRecord(t, alice, bob, Version, note, []wire.Section{broken}))
	if _, _, err := Open(bob, env); !errors.Is(err, ErrBadSender) {
		t.Fatalf("an unsigned withdrawal: %v; want the signature's refusal", err)
	}
}

// A signed note with a critical section this build does not know and a
// withdrawal that breaks its rule is malformed, never one that needs a
// newer auu, so nothing kept as newer carries a withdrawal nobody checked.
func TestARecordThatNeedsANewerAuuIsHeldToItsWithdrawalFirst(t *testing.T) {
	alice, bob := pair(t)
	note := withdraw.NoteBody("0123456789abcdef0123456789abcdef", withdrawnID, "")
	broken := rawWithdrawal(`{"id":"0123456789abcdef0123456789abcdef"}`)
	env := sealRecord(t, alice, bob.Public(), VersionCritical,
		noteRecord(t, alice, bob, VersionCritical, note, []wire.Section{later(true), broken}))
	inner, _, err := Open(bob, env)
	if inner != nil || !errors.Is(err, ErrMalformed) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("got %v, %v; want no record and malformed, never needs-newer", inner, err)
	}
}
