// Package allowlist implements a mailbox's allow list: the senders an owner
// admits, which the relay enforces on every post.
//
// An allow list is one JSON document signed by the owner's identity key under
// its own domain string, exactly as a channel directory is. The relay
// verifies it against the mailbox's registered bundle before storing it,
// stores the bytes verbatim, and verifies them again every time it enforces
// the list, so a row edited in the database refuses every sender rather
// than admitting one the owner never named. The relay can serve a stale
// list, which is the same power as refusing service; it cannot add a
// sender.
//
// A mailbox with no list takes mail from any registered sender, and so does
// a list that names nobody: that is what 'auu allow clear' pushes. The
// owner is never listed and is always admitted. Nothing here talks to a
// relay or reads a file: the rules and the signature are what both sides
// share.
package allowlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

const (
	// Version is the one allow list format this build writes and reads.
	Version = 1

	// signDomain separates an allow list's signature from the other five
	// things an identity key signs: requests (ccx-http-v1), messages
	// (ccx-sig-v1), enrolment tokens (ccx-token-v1), stream manifests
	// (ccx-stream-sig-v1) and channel directories (ccx-channels-v1). A
	// signature made for one purpose must not verify for another.
	signDomain = "ccx-allow-v1"
)

// Failures a caller tells apart. The relay answers 401 for ErrSignature and
// 400, with the sentence, for everything else.
var (
	ErrSignature = errors.New("allow list signature does not verify")
	ErrForm      = errors.New("allow list is malformed")
	ErrOwner     = errors.New("allow list owner is not the key that signed it")
)

// Document is the signed document: who may post to one mailbox.
type Document struct {
	V     int    `json:"v"`
	Owner string `json:"owner"`
	// Issued orders lists from the same owner: a relay refuses one that is
	// not newer than the one it holds, so two machines of one identity
	// cannot push each other backwards in silence. It is omitted when zero
	// only so that an unsigned copy can leave it out; a signed list always
	// carries it, since Validate requires it.
	Issued time.Time `json:"issued,omitzero"`
	// Senders is every fingerprint admitted, sorted. Empty admits every
	// registered sender, and is written as [] rather than null so that the
	// document says so in so many words.
	Senders []string `json:"senders"`
}

// Validate applies every rule in the format to a list. The error names the
// rule, and the sender where there is one, for instance
//
//	sender "abc…": is not a fingerprint
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
	if len(d.Senders) > relayapi.MaxAllowlist {
		return fmt.Errorf("the allow list has %d senders; at most %d", len(d.Senders), relayapi.MaxAllowlist)
	}
	seen := make(map[string]bool, len(d.Senders))
	for _, fp := range d.Senders {
		if !identity.ValidFingerprint(fp) {
			return fmt.Errorf("sender %q: is not a fingerprint", fp)
		}
		if fp == d.Owner {
			return fmt.Errorf("sender %q: is the owner, who is always admitted", fp)
		}
		if seen[fp] {
			return fmt.Errorf("sender %q: listed twice", fp)
		}
		seen[fp] = true
	}
	return nil
}

// Admits says whether the list lets a sender post. A list that names
// nobody admits everyone; the owner is the caller's to have admitted
// before asking, since the owner is never listed.
func (d *Document) Admits(sender string) bool {
	if len(d.Senders) == 0 {
		return true
	}
	return slices.Contains(d.Senders, sender)
}

// Sign fills in the owner from the identity, sorts the senders, checks
// every rule, encodes the list once and signs the encoding under the allow
// list domain. The document bytes returned are what the signature covers,
// and what travels; nothing re-encodes them. The caller sets Issued, since
// it is the caller's clock that orders the owner's lists.
//
// The senders are sorted so that the same peer list on two machines is the
// same bytes, and a nil list is written as [] so that a list of nobody says
// so. Validation comes before signing for the reason a directory's does:
// an invalid list should not exist, rather than be refused later by a relay
// the owner has already been told holds it.
func Sign(id *identity.Identity, d *Document) (doc, sig []byte, err error) {
	if id == nil {
		return nil, nil, errors.New("allowlist: no signing identity")
	}
	if d.V == 0 {
		d.V = Version
	}
	d.Owner = id.Fingerprint()
	if d.Senders == nil {
		d.Senders = []string{}
	}
	slices.Sort(d.Senders)
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

// Verify checks a list's signature with the owner's key, then parses the
// document strictly and requires that it name that key's fingerprint as
// its owner. Nothing it returns has come from bytes the signature did not
// cover.
//
// The signature is checked first so that a caller learns nothing about a
// document's content from a refusal, and so that the JSON decoder never runs
// on bytes nobody vouched for.
func Verify(pub *identity.Public, doc, sig []byte) (*Document, error) {
	if pub == nil {
		return nil, ErrOwner
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
// signature. It is for the one document that has none: a list the relay
// converted from the table it kept before lists were signed, which is
// honoured as it was until the owner pushes again. Everything else goes
// through Verify.
func Parse(doc []byte) (*Document, error) {
	d, err := decode(doc)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// signingBytes is the exact input to the signature.
func signingBytes(doc []byte) []byte {
	out := make([]byte, 0, len(signDomain)+len(doc))
	out = append(out, signDomain...)
	return append(out, doc...)
}

// decode reads a document strictly. An unknown field is an error: a signed
// list is not a place for extensions one side understands and the other
// ignores.
func decode(doc []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the document", ErrForm)
	}
	return &d, nil
}
