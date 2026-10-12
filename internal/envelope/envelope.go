// Package envelope seals a message for exactly one recipient.
//
// The construction is sign-then-encrypt over HPKE (RFC 9180) in single-shot
// mode, using the standard library's crypto/hpke: an MLKEM768-X25519 (X-Wing)
// KEM, HKDF-SHA256, and AES-256-GCM. Every message carries a fresh ephemeral
// encapsulation, so one compromised message does not expose the others.
//
// The sender's identity lives inside the ciphertext, so a relay sees only the
// recipient's fingerprint and an opaque blob. The recipient's fingerprint is
// bound into the HPKE info string, which means a message cannot be re-addressed
// or replayed at a different recipient.
package envelope

import (
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

const (
	// Version is the version of a message with no critical section, and
	// the one every reader since the first has understood. A reader of this
	// build takes it and VersionCritical, and refuses any other before it
	// decrypts.
	Version = 1

	// VersionCritical is the version of a message that carries a section
	// marked critical, and of no other (D30). To a reader that knows the
	// sections door it says nothing the inner record does not; it is a
	// word to a reader from before the door, which refuses any version but
	// 1 before it decrypts, and so cannot silently drop a section the
	// sender said it must not. It is not a protection against a relay: the
	// outer version is signed by nobody, and what holds for this build's
	// readers is the inner record's own v, which Open holds equal to it.
	VersionCritical = 2

	sigDomain  = "ccx-sig-v1"
	infoDomain = "ccx-envelope-v1"

	// sigLen is the signature at the front of the sealed plaintext.
	//
	// Fixed, which constrains the identity suite: the plaintext is
	// signature || inner, so a reader must know the signature's length before
	// it can find the inner record — and the inner record is the only thing
	// that says which suite signed it, in FromBundle.
	//
	// Unlike the stream format, this one can be extended without a
	// chicken-and-egg problem, because Envelope.V is outside the ciphertext
	// and is read before anything is decrypted. Version 2 is taken, by a
	// message with a critical section (VersionCritical); version 3 should
	// lay the plaintext out as inner || signature, so the JSON delimits
	// itself and whatever remains is a signature of whatever length.
	// TestSignatureLengthMatchesTheDefaultSuite is what will tell whoever
	// adds a suite that this is waiting for them.
	sigLen = 64

	messageIDLn = 16
)

// suite pins the HPKE ciphersuite. Changing any of these three is a wire
// format change and needs a new Version.
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.AES256GCM() }

// ErrOpenFailed is returned by Open for every failure. The specific cause is
// wrapped so it can be logged locally, but callers and anything on the wire see
// one indistinguishable error.
var ErrOpenFailed = errors.New("envelope: open failed")

// The classes a cause falls into, beneath ErrOpenFailed, for a receiver that
// keeps what it could not open and says why in a word: the ciphertext did
// not open under this key, the envelope names another recipient, the
// sender's bundle or signature does not hold, or the bytes are not the shape
// of an envelope at all. Cause finds which; the detail beneath each is for a
// log.
var (
	ErrNotDecrypted = errors.New("did not decrypt")
	ErrNotForUs     = errors.New("not addressed to this key")
	ErrBadSender    = errors.New("sender signature failed")
	ErrMalformed    = errors.New("malformed")
)

// Cause is the class beneath an ErrOpenFailed, or nil for any other error.
func Cause(err error) error {
	if !errors.Is(err, ErrOpenFailed) {
		return nil
	}
	for _, class := range []error{ErrNotDecrypted, ErrNotForUs, ErrBadSender, ErrMalformed} {
		if errors.Is(err, class) {
			return class
		}
	}
	return nil
}

type openError struct{ cause error }

func (e *openError) Error() string        { return ErrOpenFailed.Error() }
func (e *openError) Unwrap() error        { return e.cause }
func (e *openError) Is(target error) bool { return target == ErrOpenFailed }

func fail(class error, format string, a ...any) error {
	return &openError{cause: fmt.Errorf("%w: "+format, append([]any{class}, a...)...)}
}

// failWith keeps err in the chain beneath the class: a locked key surfaces
// from hpke.Open, and the caller must still be able to find it.
func failWith(class error, err error, context string) error {
	return &openError{cause: fmt.Errorf("%w: %s: %w", class, context, err)}
}

// Envelope is the outer, relay-visible structure. CT is the HPKE output: the
// encapsulated key followed by the ciphertext.
type Envelope struct {
	V  int    `json:"v"`
	To string `json:"to"`
	CT []byte `json:"ct"`
	// Ch is the recipient's channel the message is posted to, in the clear
	// so the relay can route by it and refuse a name the recipient has not
	// published or a period that is not open. Absent means default: the
	// sender's rule, a message for default carrying nothing. It is not
	// covered by the seal; the inner record carries the same name under
	// the signature, and a receiver treats a disagreement as a message
	// the relay misfiled.
	Ch string `json:"ch,omitempty"`
}

// Inner is the authenticated plaintext record. Only the recipient sees it.
type Inner struct {
	// V is the version, under the signature, which the outer V must equal:
	// a relay can rewrite the outer one, and what that buys it is a message
	// the recipient refuses (ruling 60).
	V          int          `json:"v"`
	From       string       `json:"from"`
	FromBundle []byte       `json:"from_bundle"`
	To         string       `json:"to"`
	ID         string       `json:"id"`
	Time       time.Time    `json:"time"`
	Body       message.Body `json:"body"`
	// Channel is the name the sender sealed the message for, absent for
	// default; the receiver checks it against the outer Ch and the channel
	// the relay listed the message under.
	Channel string `json:"channel,omitempty"`
	// Sections is the one place something new may go (internal/wire):
	// absent when there are none, the sender's to leave out as it leaves
	// out a default channel.
	Sections []wire.Section `json:"sections,omitempty"`
}

// NewID returns a fresh random message id: 32 lowercase hex characters,
// the shape message.ValidID holds every id, thread and in_reply_to to.
func NewID() (string, error) {
	buf := make([]byte, messageIDLn)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Seal encrypts body from sender to recipient. The returned Inner is the record
// that was sealed, so the caller can file its own copy of what it sent.
func Seal(sender *identity.Identity, recipient *identity.Public, body message.Body) (*Envelope, *Inner, error) {
	return SealFor(sender, recipient, "", body)
}

// SealFor is Seal for a channel of the recipient's: the name goes into the
// sealed record, under the signature, so the receiver can check it against
// what the relay says. Empty means default and writes nothing. The outer
// field is not set here; the client sets it when it posts, since that is
// the one the relay reads.
func SealFor(sender *identity.Identity, recipient *identity.Public, channel string, body message.Body) (*Envelope, *Inner, error) {
	return SealSections(sender, recipient, channel, body, nil)
}

// SealSections is SealFor with sections. They are held to wire.Check before
// anything is sealed, and the version is VersionCritical exactly when one of
// them is critical, both outside and in the inner record (D30); a reader
// refuses either version written the other way. It is SealMany for one
// recipient, which writes no recipients section of its own.
func SealSections(sender *identity.Identity, recipient *identity.Public, channel string,
	body message.Body, sections []wire.Section) (*Envelope, *Inner, error) {
	envs, inners, err := seal(sender, []*identity.Public{recipient}, channel, body, sections)
	if err != nil {
		return nil, nil, err
	}
	return envs[0], inners[0], nil
}

// SealMany seals one record for several recipients (P2): one id, one time,
// one body and one list of sections for every copy, and one seal and one
// signature per copy, each bound to its own reader as every envelope is.
// With more than one recipient it adds the recipients section, naming every
// recipient in the order given, so each reader knows who else was written
// to; with one it adds nothing, and is SealSections. The envelopes and the
// records come back in the recipients' order.
//
// It is all or nothing: a copy that cannot be sealed, a key locked after
// some copies were signed among them, returns the error and no envelope,
// so a caller never holds part of a message to several.
func SealMany(sender *identity.Identity, to []*identity.Public, channel string,
	body message.Body, sections []wire.Section) ([]*Envelope, []*Inner, error) {
	sections, err := withRecipients(to, sections)
	if err != nil {
		return nil, nil, err
	}
	return seal(sender, to, channel, body, sections)
}

// withRecipients is the caller's sections with the recipients section added
// when there is more than one recipient. The section is SealMany's to
// write: one the caller wrote would name a list nobody checked against the
// copies being sealed.
func withRecipients(to []*identity.Public, sections []wire.Section) ([]wire.Section, error) {
	if len(to) == 0 {
		return nil, errors.New("envelope: a message to nobody")
	}
	if len(to) == 1 {
		return sections, nil
	}
	for _, s := range sections {
		if s.Name == recipients.Name {
			return nil, fmt.Errorf("envelope: the %s section is written by SealMany from the recipients it is given", recipients.Name)
		}
	}
	fps := make([]string, len(to))
	for i, r := range to {
		fps[i] = r.Fingerprint()
	}
	list, err := recipients.Section(fps)
	if err != nil {
		return nil, err
	}
	return append(append([]wire.Section{}, sections...), list), nil
}

// seal is every copy of one record. Everything that can be refused is
// refused before the first signature, and every copy's list is held to the
// rule for that copy, so a list given by hand is held as SealMany's is.
func seal(sender *identity.Identity, to []*identity.Public, channel string,
	body message.Body, sections []wire.Section) ([]*Envelope, []*Inner, error) {
	if err := wire.Check(sections); err != nil {
		return nil, nil, err
	}
	if err := body.Validate(); err != nil {
		return nil, nil, err
	}
	// The sender's rule for attachment names runs here, where every
	// envelope leaves, and nowhere on the receiving path: a receiver
	// writes whatever name arrives under SafeName of it, and an honest
	// sender is told before anything leaves what a receiver would change.
	if err := message.ValidAttachmentNames(body.AttachmentNames()); err != nil {
		return nil, nil, fmt.Errorf("message: %w", err)
	}
	for _, r := range to {
		if _, err := recipients.CheckSections(sections, body.Type, r.Fingerprint()); err != nil {
			return nil, nil, err
		}
	}
	id, err := NewID()
	if err != nil {
		return nil, nil, err
	}
	v := Version
	if anyCritical(sections) {
		v = VersionCritical
	}
	now := time.Now().UTC().Truncate(time.Second)
	envs := make([]*Envelope, 0, len(to))
	inners := make([]*Inner, 0, len(to))
	for _, r := range to {
		inner := &Inner{
			V:          v,
			From:       sender.Fingerprint(),
			FromBundle: sender.Public().Bundle(),
			To:         r.Fingerprint(),
			ID:         id,
			Time:       now,
			Body:       body,
			Channel:    channel,
			Sections:   sections,
		}
		env, err := sealOne(sender, r, inner)
		if err != nil {
			return nil, nil, err
		}
		envs = append(envs, env)
		inners = append(inners, inner)
	}
	return envs, inners, nil
}

// sealOne signs and seals one copy for its recipient.
func sealOne(sender *identity.Identity, recipient *identity.Public, inner *Inner) (*Envelope, error) {
	// Marshal exactly once: the bytes that are signed are the bytes that travel.
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	sig, err := sender.Sign(sigInput(inner.To, innerBytes))
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, sigLen+len(innerBytes))
	plaintext = append(plaintext, sig...)
	plaintext = append(plaintext, innerBytes...)

	ct, err := hpke.Seal(recipient.KEM, kdf(), aead(), info(inner.To), plaintext)
	if err != nil {
		return nil, err
	}
	return &Envelope{V: inner.V, To: inner.To, CT: ct}, nil
}

// anyCritical says whether a list holds a section marked critical.
func anyCritical(sections []wire.Section) bool {
	for _, s := range sections {
		if s.Critical {
			return true
		}
	}
	return false
}

// Open decrypts and authenticates an envelope addressed to recipient. It returns
// the inner record and the sender's verified public key.
//
// Open deliberately says nothing about whether the sender is authorised. That
// is a policy question for the caller, which holds the peer list.
func Open(recipient *identity.Identity, env *Envelope) (*Inner, *identity.Public, error) {
	if env == nil {
		return nil, nil, fail(ErrMalformed, "nil envelope")
	}
	if env.V != Version && env.V != VersionCritical {
		return nil, nil, fail(ErrMalformed, "unsupported version %d", env.V)
	}
	selfFP := recipient.Fingerprint()
	if env.To != selfFP {
		return nil, nil, fail(ErrNotForUs, "envelope addressed to %s, not to us", env.To)
	}

	plaintext, err := hpke.Open(recipient.KEM(), kdf(), aead(), info(selfFP), env.CT)
	if err != nil {
		return nil, nil, failWith(ErrNotDecrypted, err, "hpke")
	}
	if len(plaintext) < sigLen {
		return nil, nil, fail(ErrMalformed, "plaintext too short")
	}
	sig := plaintext[:sigLen]
	innerBytes := plaintext[sigLen:]

	// Strictly (P1): a field the record does not have is refused, so that
	// sections are the only place something new may go.
	var inner Inner
	if err := wire.Decode(innerBytes, &inner); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "inner json")
	}
	// The outer version is signed by nobody; the inner one is under the
	// signature, and the two must agree (ruling 60).
	// A record from a build before the inner version carries none, and
	// is said so: that is what a reader meets in the window of an upgrade
	// (D43).
	if inner.V == 0 {
		return nil, nil, fail(ErrMalformed, "the sealed record carries no version; the envelope says %d", env.V)
	}
	if inner.V != env.V {
		return nil, nil, fail(ErrMalformed, "the envelope says version %d and the sealed record %d", env.V, inner.V)
	}
	// The list's shape, before the signature as the rest of the shape is;
	// what is done with each section waits for the signature (R7).
	if err := wire.Check(inner.Sections); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "sections")
	}
	// The version rule, checked by the reader both ways (P4, R6): a
	// version 1 record with a critical section, or a version 2 record
	// with none, is one no honest writer makes.
	if critical := anyCritical(inner.Sections); critical != (inner.V == VersionCritical) {
		return nil, nil, fail(ErrMalformed, "version %d with critical sections %v", inner.V, critical)
	}
	sender, err := identity.ParseBundle(inner.FromBundle)
	if err != nil {
		return nil, nil, failWith(ErrBadSender, err, "sender bundle")
	}
	// The claimed sender fingerprint must be the one its own key material
	// produces, otherwise `from` is decoration.
	if sender.Fingerprint() != inner.From {
		return nil, nil, fail(ErrBadSender, "sender fingerprint does not match bundle")
	}
	// Binding the signature to the recipient stops a peer forwarding a message
	// it received and passing it off as one written for someone else.
	if !sender.Verify(sigInput(selfFP, innerBytes), sig) {
		return nil, nil, fail(ErrBadSender, "bad signature")
	}
	if inner.To != selfFP {
		return nil, nil, fail(ErrNotForUs, "inner record addressed to %s", inner.To)
	}
	// The id becomes the record's file name. Refused here, as malformed,
	// so that a receiver keeps the message under damaged and acknowledges
	// it: left to the store's own refusal, the fetch failed on it with the
	// cursor unmoved, and the mailbox was blocked by anyone the relay let
	// post.
	if err := message.ValidID(inner.ID); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "id")
	}
	// A message can be old — it was stored and forwarded — but not from
	// the future: the stamp is the sender's word, shown as such, and one
	// past the receiver's clock by more than the chain of clocks it
	// crossed allows (relayapi.MaxStampAhead) is malformed. Nothing here
	// orders by it any more; the bound is so that what is shown is at
	// least possible.
	if relayapi.Ahead(inner.Time, time.Now(), relayapi.MaxStampAhead) {
		return nil, nil, fail(ErrMalformed, "stamped %s, in the future", inner.Time.UTC().Format(time.RFC3339))
	}
	if err := inner.Body.Validate(); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "body")
	}
	sender.Name = "" // names come from the local peer list, never from the wire
	// A known section is read now, under the signature, and before the
	// sort: the list of everybody a message to several went to, which must
	// name this reader and is never on a message that is one person's by
	// its own rules. The whole rule runs here, its size check with the
	// rest, so nothing in the section is read before the signature; and it
	// runs before the sort, so a record handed back as needing a newer auu
	// never carries a list nobody checked, as the stream's manifest must not.
	if _, err := recipients.CheckSections(inner.Sections, inner.Body.Type, selfFP); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "recipients")
	}
	// Only now, with the signature verified, is a section this build does
	// not know judged: an unsigned record is never one that needs a newer
	// auu (R7). The record and its sender come back with the error, so the
	// receiver can say whose message it is and keep it.
	if _, _, err := wire.Sort(inner.Sections); err != nil {
		return &inner, sender, &openError{cause: err}
	}
	return &inner, sender, nil
}

func sigInput(toFP string, innerBytes []byte) []byte {
	buf := make([]byte, 0, len(sigDomain)+len(toFP)+len(innerBytes))
	buf = append(buf, sigDomain...)
	buf = append(buf, toFP...)
	buf = append(buf, innerBytes...)
	return buf
}

// info is the HPKE info string. Binding the recipient's fingerprint here is
// what makes an envelope undecryptable if it is re-addressed.
func info(toFP string) []byte {
	return append([]byte(infoDomain), toFP...)
}
