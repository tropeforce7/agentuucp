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
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

const (
	// Version is the only envelope version this build understands.
	Version = 1

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
	// and is read before anything is decrypted. Version 2 should lay the
	// plaintext out as inner || signature, so the JSON delimits itself and
	// whatever remains is a signature of whatever length.
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
	id, err := NewID()
	if err != nil {
		return nil, nil, err
	}
	toFP := recipient.Fingerprint()
	inner := &Inner{
		From:       sender.Fingerprint(),
		FromBundle: sender.Public().Bundle(),
		To:         toFP,
		ID:         id,
		Time:       time.Now().UTC().Truncate(time.Second),
		Body:       body,
		Channel:    channel,
	}

	// Marshal exactly once: the bytes that are signed are the bytes that travel.
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		return nil, nil, err
	}

	sig, err := sender.Sign(sigInput(toFP, innerBytes))
	if err != nil {
		return nil, nil, err
	}
	plaintext := make([]byte, 0, sigLen+len(innerBytes))
	plaintext = append(plaintext, sig...)
	plaintext = append(plaintext, innerBytes...)

	ct, err := hpke.Seal(recipient.KEM, kdf(), aead(), info(toFP), plaintext)
	if err != nil {
		return nil, nil, err
	}
	return &Envelope{V: Version, To: toFP, CT: ct}, inner, nil
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
	if env.V != Version {
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

	var inner Inner
	if err := json.Unmarshal(innerBytes, &inner); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "inner json")
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
	// past the receiver's clock by more than the skew a relay allows a
	// request is malformed. Nothing here orders by it any more; the bound
	// is so that what is shown is at least possible.
	if inner.Time.After(time.Now().Add(relayapi.MaxSkew)) {
		return nil, nil, fail(ErrMalformed, "stamped %s, in the future", inner.Time.UTC().Format(time.RFC3339))
	}
	if err := inner.Body.Validate(); err != nil {
		return nil, nil, failWith(ErrMalformed, err, "body")
	}
	sender.Name = "" // names come from the local peer list, never from the wire
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
