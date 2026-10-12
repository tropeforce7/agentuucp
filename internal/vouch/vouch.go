// Package vouch implements a vouch: one identity's signed statement that it
// holds another on its peer list, under a name, as of a time.
//
// It says nothing more. Not that the subject is honest, not that the
// subject may act for the voucher, and not how much: a receiver takes the
// voucher's word for the subject's key or does not. There are no chains, no
// scores and no expiry. A vouch counts at a receiver only when its voucher
// is already on the receiver's peer list and the signature verifies under
// the key the receiver holds for them; that judgement is the receiver's and
// is made where the peer list is, never here.
//
// A vouch is one JSON document signed by the voucher's identity key under
// its own domain string, as a card, an allow list and a channel directory
// are. It carries the subject's bundle, so that a receiver can add the
// subject without a lookup, and so that the subject's fingerprint is
// recomputed from the bundle and a document whose bundle is somebody else's
// is refused. It travels only inside sealed messages; nothing here talks to
// a relay or reads a file.
package vouch

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
	// Version is the one vouch format this build writes and reads.
	Version = 1

	// signDomain separates a vouch's signature from the other seven things
	// an identity key signs: requests (ccx-http-v1), messages
	// (ccx-sig-v1), enrolment tokens (ccx-token-v1), stream manifests
	// (ccx-stream-sig-v1), channel directories (ccx-channels-v1), allow
	// lists (ccx-allow-v1) and cards (ccx-card-v1). A signature made for
	// one purpose must not verify for another.
	signDomain = "ccx-vouch-v1"
)

// Failures a caller tells apart.
var (
	ErrSignature = errors.New("vouch signature does not verify")
	ErrForm      = errors.New("vouch is malformed")
	ErrOwner     = errors.New("vouch voucher is not the key that signed it")
)

// Document is the signed statement: Voucher holds Subject, whose bundle is
// Bundle, on their peer list under the name Name, as of Issued. Every
// field is always written.
type Document struct {
	V       int    `json:"v"`
	Voucher string `json:"voucher"`
	Subject string `json:"subject"`
	// Bundle is the subject's public bundle. Its fingerprint must be
	// Subject, so the document cannot name one key and carry another.
	Bundle []byte `json:"bundle"`
	// Name is the voucher's own label for the subject, under the export
	// line's rule. At a receiver it is a suggestion at the local-name
	// prompt and never a label until a person accepts it.
	Name   string    `json:"name"`
	Issued time.Time `json:"issued"`
}

// Validate applies every rule in the format that needs no clock. The error
// names the rule, for instance
//
//	name is 65 bytes; at most 64
func (d *Document) Validate() error {
	if d.V != Version {
		return fmt.Errorf("v is %d; this build reads %d", d.V, Version)
	}
	if !identity.ValidFingerprint(d.Voucher) {
		return errors.New("voucher is not a fingerprint")
	}
	if !identity.ValidFingerprint(d.Subject) {
		return errors.New("subject is not a fingerprint")
	}
	if d.Voucher == d.Subject {
		return errors.New("a voucher does not vouch for themselves")
	}
	pub, err := identity.ParseBundle(d.Bundle)
	if err != nil {
		return fmt.Errorf("bundle: %s", strings.TrimPrefix(err.Error(), "identity: "))
	}
	if pub.Fingerprint() != d.Subject {
		return errors.New("bundle is not the subject's key")
	}
	if err := identity.ValidName(d.Name); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "identity: "))
	}
	if d.Issued.IsZero() {
		return errors.New("issued is missing")
	}
	return nil
}

// fromTheFuture is the one rule that needs a clock: a vouch issued further
// ahead of now than the chain of clocks it crossed allows
// (relayapi.MaxStampAhead) was stamped by a clock further out than some
// link of that chain would take, and the sender's clock is the one thing
// about it that may be old but not ahead.
func fromTheFuture(d *Document, now time.Time) error {
	if relayapi.Ahead(d.Issued, now, relayapi.MaxStampAhead) {
		return fmt.Errorf("issued %s is more than %s ahead of this machine's clock",
			d.Issued.UTC().Format(time.RFC3339), relayapi.MaxStampAhead)
	}
	return nil
}

// Sign fills in the voucher from the identity, checks every rule, encodes
// the document once and signs the encoding under the vouch domain. The
// bytes returned are what the signature covers and what travels. The
// caller sets Issued; now is the clock it is held to.
func Sign(id *identity.Identity, d *Document, now time.Time) (doc, sig []byte, err error) {
	if id == nil {
		return nil, nil, errors.New("vouch: no signing identity")
	}
	if d.V == 0 {
		d.V = Version
	}
	d.Voucher = id.Fingerprint()
	if err := d.Validate(); err != nil {
		return nil, nil, err
	}
	if err := fromTheFuture(d, now); err != nil {
		return nil, nil, err
	}
	doc, err = json.Marshal(d)
	if err != nil {
		return nil, nil, err
	}
	if err := checkLength(doc); err != nil {
		return nil, nil, err
	}
	sig, err = id.Sign(signingBytes(doc))
	if err != nil {
		return nil, nil, err
	}
	return doc, sig, nil
}

// Verify checks a vouch with the voucher's key: the length first, which
// costs nothing and tells nothing; then the signature, so the decoder never
// runs on bytes nobody signed; then the form and the rules; then that the
// voucher named is the key that signed; then the clock. Nothing it returns
// has come from bytes the signature did not cover.
//
// It does not decide whether the vouch counts: that the voucher is on the
// receiver's list, and what the subject is to the receiver, are the
// receiver's questions, asked where the list is.
func Verify(pub *identity.Public, doc, sig []byte, now time.Time) (*Document, error) {
	if pub == nil {
		return nil, ErrOwner
	}
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
	if d.Voucher != pub.Fingerprint() {
		return nil, ErrOwner
	}
	if err := fromTheFuture(d, now); err != nil {
		return nil, err
	}
	return d, nil
}

// Parse reads a document strictly and applies every rule that needs no
// clock, with no signature. It is what a message's Validate runs on a
// carried vouch, as a shape, since Validate has no peer list to verify it
// against; nothing that decides whether a vouch counts calls it alone.
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

// checkLength holds a document to relayapi.MaxVouchBytes.
func checkLength(doc []byte) error {
	if len(doc) > relayapi.MaxVouchBytes {
		return fmt.Errorf("%w: the vouch is %d bytes; at most %d, so send it compact", ErrForm, len(doc), relayapi.MaxVouchBytes)
	}
	return nil
}

// signingBytes is the exact input to the signature.
func signingBytes(doc []byte) []byte {
	out := make([]byte, 0, len(signDomain)+len(doc))
	out = append(out, signDomain...)
	return append(out, doc...)
}

// decode reads a document strictly: an unknown field and trailing bytes are
// each an error.
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
