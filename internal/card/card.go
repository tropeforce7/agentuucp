// Package card implements a mailbox's card: the owner's name, whether the
// relay may list them to every registered identity, and whether their
// mailbox takes knocks from senders its allow list does not name.
//
// A card is one JSON document signed by the owner's identity key under its
// own domain string, exactly as an allow list and a channel directory are.
// The relay verifies it against the mailbox's registered bundle before
// storing it, stores the bytes verbatim, verifies them again every time it
// lets a knock past the allow list, and serves them to every registered
// identity in its listing without verifying, since the reader is the party
// that must not trust the relay and verifies each entry with the bundle
// beside it. So a row edited in the database removes a name from the
// listing and closes a mailbox to knocks; it never adds a name or opens a
// mailbox.
//
// A mailbox with no card is not listed and takes no knocks, and so is one
// whose card says neither: that is what 'auu card clear' pushes. Nothing
// here talks to a relay or reads a file: the rules and the signature are
// what both sides share.
package card

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

const (
	// Version is the one card format this build writes and reads.
	Version = 1

	// signDomain separates a card's signature from the other six things an
	// identity key signs: requests (ccx-http-v1), messages (ccx-sig-v1),
	// enrolment tokens (ccx-token-v1), stream manifests
	// (ccx-stream-sig-v1), channel directories (ccx-channels-v1) and allow
	// lists (ccx-allow-v1). A signature made for one purpose must not
	// verify for another.
	signDomain = "ccx-card-v1"
)

// Failures a caller tells apart. The relay answers 401 for ErrSignature and
// 400, with the sentence, for everything else.
var (
	ErrSignature = errors.New("card signature does not verify")
	ErrForm      = errors.New("card is malformed")
	ErrOwner     = errors.New("card owner is not the key that signed it")
)

// Document is the signed document: what one mailbox's owner says about
// being found.
type Document struct {
	V     int    `json:"v"`
	Owner string `json:"owner"`
	// Issued orders cards from the same owner: a relay refuses one that is
	// not newer than the one it holds, so two machines of one identity
	// cannot push each other backwards in silence. It is omitted when zero
	// only so that an unsigned copy can leave it out; a signed card always
	// carries it, since Validate requires it.
	Issued time.Time `json:"issued,omitzero"`
	// Name is what the owner calls themselves, under the export line's
	// rule, signed so that a relay cannot rename anybody. It is a name from
	// the wire wherever it is read: a suggestion at a prompt and never a
	// local label until a person accepts it.
	Name string `json:"name"`
	// Listed says the relay may show this card, with the bundle, to any
	// registered identity that asks.
	Listed bool `json:"listed"`
	// Knocks says the relay may let a knock past the mailbox's allow list.
	Knocks bool `json:"knocks"`
}

// Validate applies every rule in the format to a card. The error names the
// rule, for instance
//
//	name is 65 bytes; at most 64
func (d *Document) Validate() error {
	if d.V != Version {
		return fmt.Errorf("v is %d; this build reads %d", d.V, Version)
	}
	if !identity.ValidFingerprint(d.Owner) {
		return errors.New("owner is not a fingerprint")
	}
	if d.Issued.IsZero() {
		return errors.New("issued is missing")
	}
	// A listing entry is a name, so a card without one is not a card. The
	// rule is the export line's, and its sentences begin "identity: name";
	// the prefix is dropped so the sentence reads as the card's.
	if err := identity.ValidName(d.Name); err != nil {
		return errors.New(nameSentence(err))
	}
	return nil
}

// nameSentence is identity.ValidName's sentence without its package prefix.
func nameSentence(err error) string {
	return strings.TrimPrefix(err.Error(), "identity: ")
}

// Sign fills in the owner from the identity, checks every rule, encodes the
// card once and signs the encoding under the card domain. The document
// bytes returned are what the signature covers, and what travels; nothing
// re-encodes them. The caller sets Issued, since it is the caller's clock
// that orders the owner's cards.
//
// Validation comes before signing for the reason a directory's does: an
// invalid card should not exist, rather than be refused later by a relay
// the owner has already been told holds it.
func Sign(id *identity.Identity, d *Document) (doc, sig []byte, err error) {
	if id == nil {
		return nil, nil, errors.New("card: no signing identity")
	}
	if d.V == 0 {
		d.V = Version
	}
	d.Owner = id.Fingerprint()
	if err := d.Validate(); err != nil {
		return nil, nil, err
	}
	doc, err = json.Marshal(d)
	if err != nil {
		return nil, nil, err
	}
	sig, err = id.Sign(signingBytes(doc))
	if err != nil {
		return nil, nil, err
	}
	return doc, sig, nil
}

// Verify checks a card's signature with the owner's key, then parses the
// document strictly and requires that it name that key's fingerprint as
// its owner. Nothing it returns has come from bytes the signature did not
// cover.
//
// The length is checked first, since it costs nothing and tells the
// caller nothing; then the signature, so that a caller learns nothing
// about a document's content from a refusal and the JSON decoder never
// runs on bytes nobody vouched for.
func Verify(pub *identity.Public, doc, sig []byte) (*Document, error) {
	if pub == nil {
		return nil, ErrOwner
	}
	// The length before anything else: it is the one check that costs
	// nothing and reveals nothing, and a document over the cap is not
	// verified, so a reader of the listing spends no signature check on
	// a card padded past what a page can hold.
	if err := checkLength(doc); err != nil {
		return nil, err
	}
	if !pub.Verify(signingBytes(doc), sig) {
		return nil, ErrSignature
	}
	d, err := Parse(doc)
	if err != nil {
		return nil, err
	}
	if d.Owner != pub.Fingerprint() {
		return nil, ErrOwner
	}
	return d, nil
}

// Parse reads a document strictly and applies every rule, with no
// signature: the half of Verify that comes after the signature has been
// checked. Nothing that decides on a card calls it on its own — a row with
// no signature is broken, not parsed — and it is exported for a reader,
// such as a test, that wants to see what a document says.
func Parse(doc []byte) (*Document, error) {
	if err := checkLength(doc); err != nil {
		return nil, err
	}
	d, err := decode(doc)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// checkLength holds a document's bytes to relayapi.MaxCardBytes: the
// wire's rule, run at the push and at every entry of the listing. The
// sentence says the bytes and the cap, and what to do.
func checkLength(doc []byte) error {
	if len(doc) > relayapi.MaxCardBytes {
		return fmt.Errorf("%w: the card is %d bytes; at most %d, so send it compact", ErrForm, len(doc), relayapi.MaxCardBytes)
	}
	return nil
}

// signingBytes is the exact input to the signature.
func signingBytes(doc []byte) []byte {
	out := make([]byte, 0, len(signDomain)+len(doc))
	out = append(out, signDomain...)
	return append(out, doc...)
}

// decode reads a document strictly. An unknown field is an error: a signed
// card is not a place for extensions one side understands and the other
// ignores.
func decode(doc []byte) (*Document, error) {
	var d Document
	err := wire.Decode(doc, &d)
	if errors.Is(err, wire.ErrTrailing) {
		return nil, fmt.Errorf("%w: trailing data after the document", ErrForm)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	return &d, nil
}

// CheckIssued is the rule of a pushed card that needs a clock, and so
// runs where the document is pushed and nowhere else: at the relay, on the
// verified document before it is stored, and in the owner's command before
// any request. A document issued further ahead of now than a request may
// be (relayapi.MaxSkew) was stamped by a clock no relay would have
// accepted, and would hold every later push from a right clock off as
// older; one issued outside what this program can write
// (relayapi.Writable) could not be written into an answer or a file that
// carries it (a 409's at, a --json listing). A
// stored document is read as it is, by Verify, which never asks: a bound
// at the read would close a mailbox over a clock.
func CheckIssued(d *Document, now time.Time) error {
	if d.Issued.After(now.Add(relayapi.MaxSkew)) {
		return fmt.Errorf("issued %s is more than %s %w",
			d.Issued.UTC().Format(time.RFC3339), relayapi.MaxSkew, relayapi.ErrAheadOfNow)
	}
	if !relayapi.Writable(d.Issued) {
		return fmt.Errorf("issued %s is outside the years 0000 to 9999 this program can write",
			d.Issued.UTC().Format(time.RFC3339))
	}
	return nil
}
