package withdraw

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// SectionName is the withdrawal note's section: under the signature of a
// note, it names the message the note withdraws and the sender's reason.
//
// A note is an ordinary message of type note, on the original's thread and
// in reply to it, so a reader that does not know the section reads a note
// that says the message was withdrawn, which is true with less said. That
// is why the section is never critical (D190): reading without it does not
// mislead. A reader that knows it holds it to its rule, Check, where a
// message is made and where one is read anew: the sealer before anything
// is signed, and Open once the signature has verified. The store does not
// hold a saved record to it (R150), since a release before this one kept
// a section of this name as one it did not know, whatever it said; so
// whatever acts on a saved record's section, the mark, runs CheckSections
// itself first.
//
// It is known on a message alone. A note is always an envelope, and the
// stream sealer refuses the section, so on a manifest it is a name this
// build does not know, kept or dropped as any other is and acted on by
// nobody.
const SectionName = "withdrawal"

// MaxReasonBytes is the reason's cap, the subject's (D188 b): the reason is
// held to the subject's rule, one line of valid UTF-8, and its length. A
// test holds the two to one number.
const MaxReasonBytes = 4096

// MaxSectionBytes caps the section's data before it is decoded. The data at
// its largest as this build encodes it, compactly, is 24,629 bytes: a reason
// at MaxReasonBytes of characters encoding/json writes as six bytes each,
// such as "<", which is the most any writer can spend on one byte of a
// valid reason, beside a 32-character id and the object's own 21. The same
// data indented as json.MarshalIndent writes it is a few bytes more. The
// cap leaves room above both. Each number is asserted against the encoder
// by a subtest.
const MaxSectionBytes = 25600

// NoteSubject and NoteSentence are a withdrawal note's subject and the
// sentence its text begins with, the reason after it when there is one:
// what a reader that does not know the section reads.
const (
	NoteSubject  = "withdrawn"
	NoteSentence = "The sender withdrew this message."
)

func init() {
	wire.Register(SectionName, wire.OnMessage)
}

// Withdrawal is the section's data. ID is the withdrawn message's id, which
// must be the note's in_reply_to. Reason may be empty, and is always
// written.
type Withdrawal struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// ErrForm is a withdrawal section that breaks the rule.
var ErrForm = errors.New("the withdrawal section is malformed")

// Check is the rule for the section's data, in its order: the size before
// anything is decoded, the strict decode, the id a message id, and the
// reason the subject's rule at its cap.
func Check(data []byte) (Withdrawal, error) {
	if len(data) > MaxSectionBytes {
		return Withdrawal{}, fmt.Errorf("%w: %d bytes, over the %d it may be", ErrForm, len(data), MaxSectionBytes)
	}
	var w Withdrawal
	if err := wire.Decode(data, &w); err != nil {
		return Withdrawal{}, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if err := message.ValidID(w.ID); err != nil {
		return Withdrawal{}, fmt.Errorf("%w: its id is not a message id", ErrForm)
	}
	if err := ValidReason(w.Reason); err != nil {
		return Withdrawal{}, fmt.Errorf("%w: %v", ErrForm, err)
	}
	return w, nil
}

// ValidReason is the reason's rule: at most MaxReasonBytes, and one line,
// as a subject is. Empty is a withdrawal with no reason given.
func ValidReason(reason string) error {
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("the reason is %d bytes, at most %d", len(reason), MaxReasonBytes)
	}
	return message.ValidOneLine("reason", reason)
}

// Section builds the section for the message id withdrawn and a reason,
// held to the rule.
func Section(id, reason string) (wire.Section, error) {
	data, err := json.Marshal(Withdrawal{ID: id, Reason: reason})
	if err != nil {
		return wire.Section{}, err
	}
	if _, err := Check(data); err != nil {
		return wire.Section{}, err
	}
	return wire.Section{Name: SectionName, Critical: false, Data: data}, nil
}

// NoteBody is a withdrawal note's body for the message id on thread: a
// note on that thread, in reply to the message, with the fixed subject and
// the sentence, and the reason after a blank line when there is one.
func NoteBody(thread, id, reason string) message.Body {
	text := NoteSentence
	if reason != "" {
		text += "\n\n" + reason
	}
	return message.Body{Type: message.TypeNote, Subject: NoteSubject, Thread: thread, InReplyTo: id, Text: text}
}

// CheckSections finds the section in a list that has passed wire.Check and
// holds it to the rule and to the message it is on: never critical, on a
// note alone, naming the message the note is in reply to, and on a note
// with no attachment. A list without it passes, and nil is returned.
func CheckSections(sections []wire.Section, body message.Body) (*Withdrawal, error) {
	for _, s := range sections {
		if s.Name != SectionName {
			continue
		}
		if s.Critical {
			return nil, fmt.Errorf("%w: it is marked critical, and a note's section never is", ErrForm)
		}
		if body.Type != message.TypeNote {
			return nil, fmt.Errorf("%w: it is on a message of type %s, and only a note carries one", ErrForm, body.Type)
		}
		w, err := Check(s.Data)
		if err != nil {
			return nil, err
		}
		if w.ID != body.InReplyTo {
			return nil, fmt.Errorf("%w: it names a message and the note is in reply to another message", ErrForm)
		}
		if len(body.Attachments) > 0 {
			return nil, fmt.Errorf("%w: the note carries an attachment", ErrForm)
		}
		return &w, nil
	}
	return nil, nil
}
