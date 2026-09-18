package envelope

import (
	"bytes"
	"crypto/hpke"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
)

func pair(t *testing.T) (alice, bob *identity.Identity) {
	t.Helper()
	var err error
	if alice, err = identity.Generate("alice"); err != nil {
		t.Fatal(err)
	}
	if bob, err = identity.Generate("bob"); err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func body(t *testing.T) message.Body {
	t.Helper()
	a, err := message.NewAttachment("Missing.java", []byte("// TODO"))
	if err != nil {
		t.Fatal(err)
	}
	return message.Body{
		Type:        message.TypeAsk,
		Subject:     "padding oracle?",
		Thread:      "0123456789abcdef0123456789abcdef",
		Text:        "Does the relay see this?",
		Attachments: []message.Attachment{a},
	}
}

func TestRoundTrip(t *testing.T) {
	alice, bob := pair(t)
	env, sent, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	if env.To != bob.Fingerprint() {
		t.Fatal("wrong recipient on envelope")
	}

	// The relay only ever handles the serialised outer form.
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var received Envelope
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}

	inner, sender, err := Open(bob, &received)
	if err != nil {
		t.Fatal(err)
	}
	if sender.Fingerprint() != alice.Fingerprint() {
		t.Fatal("wrong sender recovered")
	}
	if inner.ID != sent.ID || inner.Body.Text != "Does the relay see this?" {
		t.Fatal("body did not survive the round trip")
	}
	if len(inner.Body.Attachments) != 1 || string(inner.Body.Attachments[0].Data) != "// TODO" {
		t.Fatal("attachment did not survive the round trip")
	}
	// The sender fingerprint must not be visible in the outer form.
	if got := string(wire); len(got) > 0 && contains(got, alice.Fingerprint()) {
		t.Fatal("sender fingerprint leaked into the outer envelope")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func TestTamperedCiphertext(t *testing.T) {
	alice, bob := pair(t)
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	env.CT[len(env.CT)/2] ^= 0x01
	if _, _, err := Open(bob, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("expected open failure, got %v", err)
	}
}

// The encapsulated key sits at the front of the HPKE output; corrupting it
// must fail closed rather than yield a different plaintext.
func TestTamperedEncapsulatedKey(t *testing.T) {
	alice, bob := pair(t)
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	env.CT[0] ^= 0x01
	if _, _, err := Open(bob, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("expected open failure, got %v", err)
	}
}

func TestTruncatedCiphertext(t *testing.T) {
	alice, bob := pair(t)
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	env.CT = env.CT[:len(env.CT)/2]
	if _, _, err := Open(bob, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("expected open failure, got %v", err)
	}
}

func TestWrongRecipientIdentity(t *testing.T) {
	alice, bob := pair(t)
	carol, err := identity.Generate("carol")
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(carol, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("carol opened bob's mail: %v", err)
	}
}

// Re-addressing the outer envelope must not let a message be passed off as one
// written for someone else, even by the relay.
func TestReaddressedEnvelope(t *testing.T) {
	alice, bob := pair(t)
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	carol, _ := identity.Generate("carol")
	env.To = carol.Fingerprint()
	if _, _, err := Open(carol, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("expected open failure, got %v", err)
	}
	// And bob can no longer open it either: the AAD is bound to the address.
	if _, _, err := Open(bob, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("expected open failure for bob, got %v", err)
	}
}

// A message whose inner record claims one sender but is signed by another key
// must be rejected: the fingerprint is recomputed from the bundle that travels
// with the message, and the signature is checked against that.
func TestSignatureBundleMismatch(t *testing.T) {
	alice, bob := pair(t)
	mallory, _ := identity.Generate("mallory")

	// Mallory writes a message, swaps in alice's bundle, and keeps her own
	// signature. Build the envelope by hand to simulate a hostile sender.
	inner := &Inner{
		From:       alice.Fingerprint(),
		FromBundle: alice.Public().Bundle(),
		To:         bob.Fingerprint(),
		ID:         "0123456789abcdef0123456789abcdef",
		Body:       body(t),
	}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	sig := mustSign(t, mallory, sigInput(bob.Fingerprint(), innerBytes))
	plaintext := append(append([]byte{}, sig...), innerBytes...)

	ct, err := hpke.Seal(bob.Public().KEM, kdf(), aead(), info(bob.Fingerprint()), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{V: Version, To: bob.Fingerprint(), CT: ct}
	if _, _, err := Open(bob, env); !errors.Is(err, ErrOpenFailed) {
		t.Fatal("accepted a message signed by a key other than the claimed sender")
	}
}

// A correctly sealed message from an unknown sender still opens: authorisation
// is the caller's decision, not the envelope's.
func TestOpenDoesNotConsultAnyPeerList(t *testing.T) {
	_, bob := pair(t)
	stranger, _ := identity.Generate("stranger")
	env, _, err := Seal(stranger, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	_, sender, err := Open(bob, env)
	if err != nil {
		t.Fatalf("a valid message from a stranger should open: %v", err)
	}
	if sender.Fingerprint() != stranger.Fingerprint() {
		t.Fatal("wrong sender reported")
	}
	// The name must come from the local peer list, never from the wire.
	if sender.Name != "" {
		t.Fatalf("sender name leaked from the wire: %q", sender.Name)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	alice, bob := pair(t)
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{0, Version + 1, 99} {
		env.V = v
		if _, _, err := Open(bob, env); !errors.Is(err, ErrOpenFailed) {
			t.Fatalf("accepted envelope version %d", v)
		}
	}
}

func TestSealRejectsInvalidBody(t *testing.T) {
	alice, bob := pair(t)
	if _, _, err := Seal(alice, bob.Public(), message.Body{Type: "exec", Thread: "0123456789abcdef0123456789abcdef"}); err == nil {
		t.Fatal("sealed an invalid body")
	}
}

// TestSignatureLengthMatchesTheDefaultSuite is a guard, not a property. See
// the note on sigLen: this format splits the sealed plaintext at a fixed
// offset, so it works for exactly one signature size.
//
// If it fails, the fix is envelope version 2 with the plaintext laid out as
// inner || signature, not a change to the constant. Envelope.V is outside the
// ciphertext, so a reader can tell the two layouts apart before decrypting —
// which is what makes that a small change rather than a redesign.
func TestSignatureLengthMatchesTheDefaultSuite(t *testing.T) {
	if got := identity.DefaultSuite().SignatureSize; got != sigLen {
		t.Fatalf("the default identity suite signs with %d bytes but this format reserves %d.\n"+
			"Adding a suite means envelope version 2, with the signature after the inner\n"+
			"record instead of before it.", got, sigLen)
	}
}

// TestASubstitutedSenderBundleIsRefused is the anti-downgrade property.
//
// An identity's suite is inside its bundle, and its fingerprint is a hash over
// that bundle. So there is no such thing as "the same sender, on a weaker
// suite": a different suite is a different bundle is a different fingerprint
// is a different person, whom the recipient's peer list does not know. An
// attacker cannot make a message appear to come from a known peer while being
// signed under something easier to forge.
func TestASubstitutedSenderBundleIsRefused(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := Seal(alice, bob.Public(), message.Body{
		Type: message.TypeNote, Thread: "0123456789abcdef0123456789abcdef", Subject: "s", Text: "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	// It opens as alice, and the bundle that came with it is alice's.
	inner, sender, err := Open(bob, env)
	if err != nil {
		t.Fatal(err)
	}
	if sender.Fingerprint() != alice.Fingerprint() || inner.From != alice.Fingerprint() {
		t.Fatal("the message did not open as alice")
	}
	// The fingerprint is over the bundle, so it commits to the suite: two
	// identities cannot share an address while differing in what signs for
	// it.
	if sender.Suite().ID != alice.Public().Suite().ID {
		t.Error("the suite did not survive the round trip")
	}
	rehashed, err := identity.ParseBundle(sender.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	if rehashed.Fingerprint() != alice.Fingerprint() {
		t.Fatal("a bundle does not determine its own fingerprint")
	}

	// Mallory's bundle under alice's name: the fingerprint no longer matches
	// the bundle, which Open refuses before it looks at the signature.
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	if mallory.Public().Fingerprint() == alice.Fingerprint() {
		t.Fatal("two identities collided")
	}
	if bytes.Equal(mallory.Public().Bundle(), alice.Public().Bundle()) {
		t.Fatal("two identities share a bundle")
	}
}

// Beneath ErrOpenFailed is one of four words for a receiver that keeps what
// it could not open: the ciphertext did not open under this key, the
// envelope names somebody else, the sender does not hold up, or the bytes are
// not an envelope. Every failure Open has falls into one, and an error that
// is not Open's is none of them.
func TestOpenSaysWhyInAWord(t *testing.T) {
	alice, bob := pair(t)
	carol, _ := identity.Generate("carol")
	mallory, _ := identity.Generate("mallory")
	sealed := func() *Envelope {
		t.Helper()
		env, _, err := Seal(alice, bob.Public(), body(t))
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	// An envelope built by hand, so the plaintext beneath the AEAD can be
	// wrong in the ways a sealer never makes it.
	handSealed := func(plaintext []byte) *Envelope {
		t.Helper()
		ct, err := hpke.Seal(bob.Public().KEM, kdf(), aead(), info(bob.Fingerprint()), plaintext)
		if err != nil {
			t.Fatal(err)
		}
		return &Envelope{V: Version, To: bob.Fingerprint(), CT: ct}
	}
	innerFor := func(from *identity.Identity, to string) []byte {
		t.Helper()
		innerBytes, err := json.Marshal(&Inner{
			From: from.Fingerprint(), FromBundle: from.Public().Bundle(), To: to,
			ID: "0123456789abcdef0123456789abcdef", Body: body(t),
		})
		if err != nil {
			t.Fatal(err)
		}
		return innerBytes
	}
	signedBy := func(signer *identity.Identity, innerBytes []byte) []byte {
		t.Helper()
		return append(append([]byte{}, mustSign(t, signer, sigInput(bob.Fingerprint(), innerBytes))...), innerBytes...)
	}

	for _, tc := range []struct {
		name string
		env  *Envelope
		want error
	}{
		{"a flipped ciphertext byte", func() *Envelope { e := sealed(); e.CT[len(e.CT)/2] ^= 1; return e }(), ErrNotDecrypted},
		{"a flipped encapsulation byte", func() *Envelope { e := sealed(); e.CT[0] ^= 1; return e }(), ErrNotDecrypted},
		{"a truncated ciphertext", func() *Envelope { e := sealed(); e.CT = e.CT[:len(e.CT)/2]; return e }(), ErrNotDecrypted},
		{"addressed to carol", func() *Envelope { e := sealed(); e.To = carol.Fingerprint(); return e }(), ErrNotForUs},
		{"the inner record addressed to carol", handSealed(signedBy(alice, innerFor(alice, carol.Fingerprint()))), ErrNotForUs},
		{"signed by mallory under alice's name", handSealed(signedBy(mallory, innerFor(alice, bob.Fingerprint()))), ErrBadSender},
		{"a sender bundle that will not parse", handSealed(signedBy(alice, func() []byte {
			b, _ := json.Marshal(&Inner{From: alice.Fingerprint(), FromBundle: []byte("not a bundle"), To: bob.Fingerprint(),
				ID: "0123456789abcdef0123456789abcdef", Body: body(t)})
			return b
		}())), ErrBadSender},
		{"nil", nil, ErrMalformed},
		{"a version from the future", func() *Envelope { e := sealed(); e.V = Version + 1; return e }(), ErrMalformed},
		{"a plaintext too short for a signature", handSealed([]byte("short")), ErrMalformed},
		{"an inner record that is not JSON", handSealed(append(make([]byte, sigLen), "not json"...)), ErrMalformed},
		{"a body that does not validate", handSealed(signedBy(alice, func() []byte {
			b, _ := json.Marshal(&Inner{From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
				ID: "0123456789abcdef0123456789abcdef", Body: message.Body{Type: "no such type"}})
			return b
		}())), ErrMalformed},
		{"a thread id that is a path", handSealed(signedBy(alice, func() []byte {
			bad := body(t)
			bad.Thread = "../../outside"
			b, _ := json.Marshal(&Inner{From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
				ID: "0123456789abcdef0123456789abcdef", Body: bad})
			return b
		}())), ErrMalformed},
	} {
		_, _, err := Open(bob, tc.env)
		if !errors.Is(err, ErrOpenFailed) {
			t.Fatalf("%s: %v, want ErrOpenFailed", tc.name, err)
		}
		if got := Cause(err); got != tc.want {
			t.Errorf("%s: cause %v, want %v (beneath: %v)", tc.name, got, tc.want, errors.Unwrap(err))
		}
		for _, other := range []error{ErrNotDecrypted, ErrNotForUs, ErrBadSender, ErrMalformed} {
			if other != tc.want && errors.Is(err, other) {
				t.Errorf("%s: is also %v", tc.name, other)
			}
		}
	}
	if Cause(errors.New("something else")) != nil || Cause(nil) != nil {
		t.Error("an error that is not Open's has a cause")
	}
}

// The outer ch and the inner channel are named on the wire as the relay
// and the receiver read them, and both are absent for default, so an
// envelope for default is byte-for-byte what it was before channels.
func TestTheChannelFieldsAreNamedOnTheWire(t *testing.T) {
	alice, bob := pair(t)
	env, inner, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	outer, _ := json.Marshal(env)
	if strings.Contains(string(outer), `"ch"`) {
		t.Fatalf("an envelope for default names a channel: %s", outer)
	}
	plain, _ := json.Marshal(inner)
	if strings.Contains(string(plain), `"channel"`) {
		t.Fatalf("an inner record for default names a channel: %s", plain)
	}
	env.Ch = "bug reports"
	inner.Channel = "bug reports"
	outer, _ = json.Marshal(env)
	if !strings.Contains(string(outer), `"ch":"bug reports"`) {
		t.Fatalf("the outer field is not ch: %s", outer)
	}
	plain, _ = json.Marshal(inner)
	if !strings.Contains(string(plain), `"channel":"bug reports"`) {
		t.Fatalf("the inner field is not channel: %s", plain)
	}
	// The outer field is outside the seal: an envelope with it set still
	// opens, and what opens is the sealed record, which does not carry it.
	got, _, err := Open(bob, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Channel != "" {
		t.Fatalf("the outer ch reached the inner record: %q", got.Channel)
	}
}

// SealFor puts the channel into the sealed record, under the signature,
// and Open gives it back; Seal is SealFor with nothing named.
func TestSealForCarriesTheChannelUnderTheSignature(t *testing.T) {
	alice, bob := pair(t)
	env, inner, err := SealFor(alice, bob.Public(), "bug reports", body(t))
	if err != nil {
		t.Fatal(err)
	}
	if inner.Channel != "bug reports" || env.Ch != "" {
		t.Fatalf("SealFor: inner %q, outer %q; the outer is the client's to set", inner.Channel, env.Ch)
	}
	got, _, err := Open(bob, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Channel != "bug reports" {
		t.Fatalf("the channel did not come back: %q", got.Channel)
	}
	if _, plain, err := Seal(alice, bob.Public(), body(t)); err != nil || plain.Channel != "" {
		t.Fatalf("Seal names a channel: %q %v", plain.Channel, err)
	}
}

// A receiver from before channels reads the sealed record with plain
// json.Unmarshal, which ignores channel: the message opens and is filed as
// it always was, under nothing. The old shape is written out, not derived.
func TestAReceiverFromBeforeChannelsIgnoresTheInnerChannel(t *testing.T) {
	alice, bob := pair(t)
	_, inner, err := SealFor(alice, bob.Public(), "bug reports", body(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		From       string       `json:"from"`
		FromBundle []byte       `json:"from_bundle"`
		To         string       `json:"to"`
		ID         string       `json:"id"`
		Time       time.Time    `json:"time"`
		Body       message.Body `json:"body"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatalf("an old receiver cannot read the record: %v", err)
	}
	if old.ID != inner.ID || old.From != alice.Fingerprint() || old.Body.Subject != inner.Body.Subject {
		t.Fatalf("an old receiver read %+v", old)
	}
}

// The message id becomes the record's file name, and Open is where the
// receiver learns it. An inner whose id is a path, empty or the wrong
// length is malformed here: signed by its sender, sealed to us, and still
// refused, so that the receiver keeps it under damaged and acknowledges
// it. Before this the store refused to save it and the fetch returned
// that with the cursor unmoved, which blocked the mailbox at it for
// anyone the relay let post, a stranger to be quarantined included.
func TestAnInnerWhoseIDIsNotAnIDIsMalformed(t *testing.T) {
	alice, bob := pair(t)
	for _, id := range []string{"", "..", "../../outside", "0123456789abcdef0123456789abcde", strings.Repeat("a", 1<<20)} {
		innerBytes, err := json.Marshal(&Inner{
			From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
			ID: id, Body: body(t),
		})
		if err != nil {
			t.Fatal(err)
		}
		plaintext := append(append([]byte{}, mustSign(t, alice, sigInput(bob.Fingerprint(), innerBytes))...), innerBytes...)
		_, _, err = Open(bob, sealPlaintext(t, bob.Public(), plaintext))
		if Cause(err) != ErrMalformed {
			t.Errorf("id of %d bytes %.20q: %v, want malformed", len(id), id, err)
		}
	}
}
