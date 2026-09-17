// Package channels implements a mailbox's directory of channels: the named
// sub-mailboxes an owner defines and a sender chooses between.
//
// A directory is one JSON document signed by the owner's identity key under
// its own domain string, exactly as an enrolment token is signed by an
// administrator's. The relay verifies it against the mailbox's registered
// bundle before storing it and serves the bytes back verbatim, so a sender
// verifies the same bytes against the key it holds for the peer. The relay
// can serve a stale directory, which is the same power as refusing service;
// it cannot invent a channel or edit a description.
//
// A mailbox with no directory has one channel, "default", with no period.
// Nothing here talks to a relay or reads a file: the rules, the signature and
// the period are what both sides share.
package channels

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

const (
	// Version is the one directory format this build writes and reads.
	Version = 1

	// Default is the channel a message that names none goes to. It is a
	// name like any other in a directory, and a directory may leave it out.
	Default = "default"

	// signDomain separates a directory's signature from the other five things
	// an identity key signs: requests (ccx-http-v1), messages (ccx-sig-v1),
	// enrolment tokens (ccx-token-v1), stream manifests (ccx-stream-sig-v1)
	// and allow lists (ccx-allow-v1). A signature made for one purpose must
	// not verify for another.
	signDomain = "ccx-channels-v1"
)

// Failures a caller tells apart. The relay answers 401 for ErrSignature and
// 400, with the sentence, for everything else.
var (
	ErrSignature = errors.New("directory signature does not verify")
	ErrForm      = errors.New("directory is malformed")
	ErrOwner     = errors.New("directory owner is not the key that signed it")
)

// Directory is the signed document: every channel of one mailbox.
type Directory struct {
	V     int    `json:"v"`
	Owner string `json:"owner"`
	// Issued orders directories from the same owner: a relay refuses one
	// that is not newer than the one it holds, so two machines of one
	// identity cannot push each other backwards in silence. It is omitted
	// when zero only so that the local, unsigned copy can leave it out; a
	// signed directory always carries it, since Validate requires it.
	Issued   time.Time `json:"issued,omitzero"`
	Channels []Channel `json:"channels"`
}

// Channel is one named sub-mailbox and the period in which it takes mail.
// A bound that is absent is unbounded on that side.
type Channel struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
}

// ValidName applies the rules for a channel name: valid UTF-8, 1 to
// relayapi.MaxChannelNameBytes bytes, no control, format, private-use, line
// or paragraph separator characters, no white space at either end, no "/",
// and neither "." nor "..". The last three keep a name usable as a directory
// name. Names are compared byte for byte, so "Bugs" and "bugs" are two names.
//
// The error is a sentence beginning "name", for a caller to prefix with what
// the name belongs to.
func ValidName(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if len(name) > relayapi.MaxChannelNameBytes {
		return fmt.Errorf("name is %d bytes; at most %d", len(name), relayapi.MaxChannelNameBytes)
	}
	if !utf8.ValidString(name) {
		return errors.New("name is not valid UTF-8")
	}
	if r, what := forbiddenRune(name); what != "" {
		return fmt.Errorf("name contains %U, a %s", r, what)
	}
	if first, _ := utf8.DecodeRuneInString(name); unicode.IsSpace(first) {
		return errors.New("name begins with white space")
	}
	if last, _ := utf8.DecodeLastRuneInString(name); unicode.IsSpace(last) {
		return errors.New("name ends with white space")
	}
	if strings.Contains(name, "/") {
		return errors.New(`name contains "/"`)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("name is %q", name)
	}
	return nil
}

// ValidDescription applies the rules for a description: valid UTF-8, at most
// relayapi.MaxChannelDescriptionBytes bytes, and the same forbidden
// characters as a name. A line break is a control character and is refused
// here; the command that takes a description folds line breaks to one space
// before it gets this far, so a directory never holds one.
//
// The error is a sentence beginning "description".
func ValidDescription(desc string) error {
	if len(desc) > relayapi.MaxChannelDescriptionBytes {
		return fmt.Errorf("description is %d bytes; at most %d", len(desc), relayapi.MaxChannelDescriptionBytes)
	}
	if !utf8.ValidString(desc) {
		return errors.New("description is not valid UTF-8")
	}
	if r, what := forbiddenRune(desc); what != "" {
		return fmt.Errorf("description contains %U, a %s", r, what)
	}
	return nil
}

// forbiddenRune finds the first character of a category a name or a
// description may not hold, and says which category in words.
func forbiddenRune(s string) (rune, string) {
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Cc, r):
			return r, "control character"
		case unicode.Is(unicode.Cf, r):
			return r, "format character"
		case unicode.Is(unicode.Co, r):
			return r, "private-use character"
		case unicode.Is(unicode.Zl, r):
			return r, "line separator"
		case unicode.Is(unicode.Zp, r):
			return r, "paragraph separator"
		}
	}
	return 0, ""
}

// Validate applies every rule in the format to a directory. The error names
// the channel and the rule, for instance
//
//	channel "bug reports": description is 1031 bytes; at most 1024
func (d *Directory) Validate() error {
	if d.V != Version {
		return fmt.Errorf("v is %d; this build reads %d", d.V, Version)
	}
	if !identity.ValidFingerprint(d.Owner) {
		return errors.New("owner is not a fingerprint")
	}
	if d.Issued.IsZero() {
		return errors.New("issued is missing")
	}
	if len(d.Channels) > relayapi.MaxChannels {
		return fmt.Errorf("the directory has %d channels; at most %d", len(d.Channels), relayapi.MaxChannels)
	}
	seen := make(map[string]bool, len(d.Channels))
	for _, ch := range d.Channels {
		if err := ValidName(ch.Name); err != nil {
			return fmt.Errorf("channel %q: %v", ch.Name, err)
		}
		if seen[ch.Name] {
			return fmt.Errorf("channel %q: listed twice", ch.Name)
		}
		seen[ch.Name] = true
		if err := ValidDescription(ch.Description); err != nil {
			return fmt.Errorf("channel %q: %v", ch.Name, err)
		}
		if ch.NotBefore != nil && ch.NotAfter != nil && ch.NotBefore.After(*ch.NotAfter) {
			return fmt.Errorf("channel %q: not_before %s is after not_after %s",
				ch.Name, stamp(*ch.NotBefore), stamp(*ch.NotAfter))
		}
	}
	return nil
}

// Find returns the channel of that name, or nil.
func (d *Directory) Find(name string) *Channel {
	for i := range d.Channels {
		if d.Channels[i].Name == name {
			return &d.Channels[i]
		}
	}
	return nil
}

// OpenAt says whether the channel takes mail at now, and when not, why: "opens
// T" for one whose period has not begun and "closed T" for one whose period
// has ended, with T in UTC. Both edges are inclusive: a post at not_before
// and one at not_after are both taken. The sentence is the one both sides
// print, so the sender and the relay agree word for word.
func (ch *Channel) OpenAt(now time.Time) (open bool, why string) {
	if ch.NotBefore != nil && now.Before(*ch.NotBefore) {
		return false, "opens " + stamp(*ch.NotBefore)
	}
	if ch.NotAfter != nil && now.After(*ch.NotAfter) {
		return false, "closed " + stamp(*ch.NotAfter)
	}
	return true, ""
}

// stamp renders a bound the way the sentences show it.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Sign fills in the owner from the identity, checks every rule, encodes the
// directory once and signs the encoding under the directory domain. The
// document bytes returned are what the signature covers, and what travels;
// nothing re-encodes them. The caller sets Issued, since it is the caller's
// clock that orders the owner's directories.
//
// Validation comes before signing for the same reason an enrolment token is
// checked before it is issued: an invalid directory should not exist, rather
// than be refused later by a relay the owner has already been told holds it.
func Sign(id *identity.Identity, d *Directory) (doc, sig []byte, err error) {
	if id == nil {
		return nil, nil, errors.New("channels: no signing identity")
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

// Verify checks a directory's signature with the owner's key, then decodes
// the document strictly, validates it, and requires that it name that key's
// fingerprint as its owner. Nothing it returns has come from bytes the
// signature did not cover.
//
// The signature is checked first so that a caller learns nothing about a
// document's content from a refusal, and so that the JSON decoder never runs
// on bytes nobody vouched for.
func Verify(pub *identity.Public, doc, sig []byte) (*Directory, error) {
	if pub == nil {
		return nil, ErrOwner
	}
	if !pub.Verify(signingBytes(doc), sig) {
		return nil, ErrSignature
	}
	d, err := decode(doc)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.Owner != pub.Fingerprint() {
		return nil, ErrOwner
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
// directory is not a place for extensions one side understands and the other
// ignores.
func decode(doc []byte) (*Directory, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var d Directory
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the document", ErrForm)
	}
	return &d, nil
}
