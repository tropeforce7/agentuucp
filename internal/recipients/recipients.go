// Package recipients is the first section through the door: the list of
// everybody a message to several was written to, carried under the
// signature in every copy (D45, P1).
//
// A message to several is sealed once per recipient, each copy an ordinary
// envelope or stream bound to its reader, and every copy carries the same
// section, `recipients`, naming every recipient by fingerprint in the order
// the sender gave them. It is not critical: a reader that does not know it
// reads a correct message from the sender to itself, and only loses the
// knowledge of who else was written to.
//
// The data is read strictly, so what the section says, it says for good. A
// later need is a new section name beside this one, never a field added to
// it, as a grant document changes by its format version.
//
// The rule is one function, Check, and both ends run it on every path: the
// sealer for each copy before anything is signed, the reader of an envelope
// and of a manifest once the signature has verified, and the store at Load.
// Two numbers travel beside it, each a section of its own name, since a
// name says one thing for good: recipient-count on a request, how many a
// copy's message went to, which the first relay holds to its
// max_recipients; and max-recipients on the relay's health and status
// answers, the number it holds, for a client to hold itself to on a plain
// post, whose body has nowhere to carry a count (D54).
//
// It is standard library only, and from this tree it imports only the rules
// it is built from: identity's for a fingerprint, message's for a type,
// relayapi's ceiling and the wire's decode.
package recipients

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// Name is the section's name.
const Name = "recipients"

// MaxBytes caps the section's data before it is decoded. A list at the
// ceiling as this build encodes it, compactly, is 2,152 bytes: `{"to":[`
// is 7, each of relayapi.MaxRecipients fingerprints is 64 hex characters
// and two quotes, 66, so 32 of them are 2,112, the 31 commas between them
// are 31, and `]}` is 2. The same list indented two spaces a level, as
// json.MarshalIndent writes it, is 2,320. The cap leaves room above both
// for a writer that indents more widely, and is under wire.MaxKeptBytes, so
// a reader that does not know the section keeps it whole. Each number here
// is asserted against the encoder by a subtest.
const MaxBytes = 4096

// CountName is the request's section: how many recipients the message
// this request carries a copy of was written to, so that the first relay
// can hold a sender to its max_recipients (D47, D54). It is a count and
// never the list: the relay needs the number alone, and a list on a
// forward would tell the first relay who on other relays was written to.
const CountName = "recipient-count"

// MaxName is the health answer's section, and the administrator's status
// answer's: the most recipients this relay takes, the number in force, for
// a client to hold a message to several to before it sends.
const MaxName = "max-recipients"

// MaxNumberBytes caps the data of either number's section before it is
// decoded: {"max":32} is ten bytes, and the cap leaves room for a writer
// that indents. A number a byte longer is no number this rule takes.
const MaxNumberBytes = 64

func init() {
	// The list travels in a message and in a manifest, the count on a
	// request and the maximum on answers, each read nowhere else.
	wire.Register(Name, wire.OnMessage|wire.OnManifest)
	wire.Register(CountName, wire.OnRequest)
	wire.Register(MaxName, wire.OnAnswer)
}

// List is the section's data.
type List struct {
	To []string `json:"to"`
}

// ErrForm is a recipients section that breaks the rule.
var ErrForm = errors.New("the recipients section is malformed")

// Check is the rule, in its order: the size before anything is decoded,
// the strict decode, between 1 and relayapi.MaxRecipients entries before
// any of them is looked at, each a fingerprint, none twice, and the reader
// in the list. self is the fingerprint of the copy's own recipient: the
// reader's own on the way in, the copy's on the way out. It is always
// given; nothing reads a list without knowing whose copy it is.
func Check(data []byte, self string) (List, error) {
	if !identity.ValidFingerprint(self) {
		return List{}, errors.New("recipients: the list was checked without its copy's recipient")
	}
	if len(data) > MaxBytes {
		return List{}, fmt.Errorf("%w: %d bytes, over the %d it may be", ErrForm, len(data), MaxBytes)
	}
	var l List
	if err := wire.Decode(data, &l); err != nil {
		return List{}, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if len(l.To) == 0 {
		return List{}, fmt.Errorf("%w: it names nobody", ErrForm)
	}
	if len(l.To) > relayapi.MaxRecipients {
		return List{}, fmt.Errorf("%w: %d recipients, at most %d", ErrForm, len(l.To), relayapi.MaxRecipients)
	}
	seen := make(map[string]bool, len(l.To))
	mine := false
	for i, fp := range l.To {
		if !identity.ValidFingerprint(fp) {
			return List{}, fmt.Errorf("%w: entry %d is not a fingerprint", ErrForm, i+1)
		}
		if seen[fp] {
			return List{}, fmt.Errorf("%w: %s is named twice", ErrForm, fp[:identity.ShortIDLen])
		}
		seen[fp] = true
		if fp == self {
			mine = true
		}
	}
	if !mine {
		return List{}, fmt.Errorf("%w: it does not name %s, whose copy this is", ErrForm, self[:identity.ShortIDLen])
	}
	return l, nil
}

// Section builds the section for a list of fingerprints, in the order given,
// held to everything the rule says but whose copy it is, which the sealer
// checks per copy.
func Section(fps []string) (wire.Section, error) {
	if len(fps) == 0 {
		return wire.Section{}, fmt.Errorf("%w: it names nobody", ErrForm)
	}
	data, err := json.Marshal(List{To: fps})
	if err != nil {
		return wire.Section{}, err
	}
	if _, err := Check(data, fps[0]); err != nil {
		return wire.Section{}, err
	}
	return wire.Section{Name: Name, Critical: false, Data: data}, nil
}

// onePerson says whether a message of this type is one envelope to one
// person by its own rules, and so never part of a message to several: a
// knock, a vouch and a vouch question.
func onePerson(bodyType string) bool {
	return bodyType == message.TypeKnock || bodyType == message.TypeVouch || bodyType == message.TypeVouchAsk
}

// CheckSections finds the recipients section in a list that has passed
// wire.Check and holds it to the rule for the copy addressed to self, and
// refuses it on a message of a type that is one envelope to one person. A
// list without the section is a message to one and passes. It returns the
// list, empty when there is none.
func CheckSections(sections []wire.Section, bodyType, self string) (List, error) {
	for _, s := range sections {
		if s.Name != Name {
			continue
		}
		if onePerson(bodyType) {
			return List{}, fmt.Errorf("%w: a %s message is one envelope to one person and carries no list", ErrForm, bodyType)
		}
		return Check(s.Data, self)
	}
	return List{}, nil
}

// Count is the request section's data.
type Count struct {
	N int `json:"n"`
}

// Max is the answer section's data.
type Max struct {
	Max int `json:"max"`
}

// checkNumber is the rule both numbers share: the size before the strict
// decode, then 1 to relayapi.MaxRecipients.
func checkNumber(name string, data []byte, v any, n func() int) (int, error) {
	if len(data) > MaxNumberBytes {
		return 0, fmt.Errorf("the %s section is %d bytes, over the %d it may be", name, len(data), MaxNumberBytes)
	}
	if err := wire.Decode(data, v); err != nil {
		return 0, fmt.Errorf("the %s section: %v", name, err)
	}
	if got := n(); got < 1 || got > relayapi.MaxRecipients {
		return 0, fmt.Errorf("the %s section says %d, which is not 1 to %d", name, got, relayapi.MaxRecipients)
	}
	return n(), nil
}

// CheckCount is the rule for a request's count.
func CheckCount(data []byte) (int, error) {
	var c Count
	return checkNumber(CountName, data, &c, func() int { return c.N })
}

// CheckMax is the rule for an answer's number.
func CheckMax(data []byte) (int, error) {
	var m Max
	return checkNumber(MaxName, data, &m, func() int { return m.Max })
}

// CountSection is the request's section for a message to n recipients, or
// nothing for a message to one, whose request is the bytes it always was;
// 0 is a caller with no count to give, and is a message to one too.
func CountSection(n int) ([]wire.Section, error) {
	if n == 0 || n == 1 {
		return nil, nil
	}
	return numberSection(CountName, Count{N: n}, n)
}

// MaxSection is the answer's section for a relay that takes n.
func MaxSection(n int) ([]wire.Section, error) {
	return numberSection(MaxName, Max{Max: n}, n)
}

func numberSection(name string, v any, n int) ([]wire.Section, error) {
	if n < 1 || n > relayapi.MaxRecipients {
		return nil, fmt.Errorf("recipients: %d is not 1 to %d", n, relayapi.MaxRecipients)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return []wire.Section{{Name: name, Critical: false, Data: data}}, nil
}

// Find is the data of the named section in a list, and whether there is one.
func Find(sections []wire.Section, name string) ([]byte, bool) {
	for _, s := range sections {
		if s.Name == name {
			return s.Data, true
		}
	}
	return nil, false
}
