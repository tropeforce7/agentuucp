package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// aeadTagSize is the AES-256-GCM tag appended by the AEAD.
const aeadTagSize = 16

// encapSize derives the length of the KEM encapsulation at the front of a
// sealed ciphertext from a real seal, so the offsets below stay correct if the
// suite ever changes. Never write it as a literal.
func encapSize(t *testing.T, to *identity.Public) int {
	t.Helper()
	plaintext := []byte("x")
	ct, err := hpke.Seal(to.KEM, kdf(), aead(), info(to.Fingerprint()), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return len(ct) - len(plaintext) - aeadTagSize
}

// mustSeal is Seal without the error handling, for tests that go on to damage
// what it produced.
func mustSeal(t *testing.T, from *identity.Identity, to *identity.Identity, b message.Body) *Envelope {
	t.Helper()
	env, _, err := Seal(from, to.Public(), b)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// sealPlaintext wraps arbitrary plaintext the way Seal does, so a test can
// build an envelope whose inner bytes Seal would never produce.
func sealPlaintext(t *testing.T, to *identity.Public, plaintext []byte) *Envelope {
	t.Helper()
	ct, err := hpke.Seal(to.KEM, kdf(), aead(), info(to.Fingerprint()), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return &Envelope{V: Version, To: to.Fingerprint(), CT: ct}
}

// A fixed message takes one path through the padding, the block boundaries and
// the encoding. Random content and random length take the others, which is
// where a bug that survives every fixed test lives.
func TestRoundTripRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	alice, bob := pair(t)

	// Lengths that must appear whatever the seed, plus random ones.
	lengths := testutil.Lengths(64<<10, 16)
	for range 60 {
		lengths = append(lengths, r.IntN(64<<10))
	}

	for _, n := range lengths {
		text := testutil.Text(r, n)
		var attachments []message.Attachment
		// Names are unique by construction: a message with two attachments of
		// the same name is invalid, and this test is about the envelope
		// rather than about that rule, which message_test.go covers.
		for i := range r.IntN(4) {
			size := r.IntN(4 << 10)
			a, err := message.NewAttachment(
				fmt.Sprintf("f%d.bin", i), testutil.Bytes(r, size))
			if err != nil {
				t.Fatalf("seed %d: attachment of %d bytes: %v", seed, size, err)
			}
			attachments = append(attachments, a)
		}
		in := message.Body{
			Type:        message.TypeAsk,
			Subject:     testutil.Text(r, r.IntN(200)),
			Thread:      "0123456789abcdef0123456789abcdef",
			Text:        text,
			Attachments: attachments,
		}

		env, _, err := Seal(alice, bob.Public(), in)
		if err != nil {
			t.Fatalf("seed %d: sealing %d bytes of text: %v", seed, n, err)
		}
		out, sender, err := Open(bob, env)
		if err != nil {
			t.Fatalf("seed %d: opening %d bytes of text: %v", seed, n, err)
		}
		if out.Body.Text != in.Text || out.Body.Subject != in.Subject {
			t.Fatalf("seed %d: body did not survive at length %d", seed, n)
		}
		if len(out.Body.Attachments) != len(in.Attachments) {
			t.Fatalf("seed %d: %d attachments became %d", seed, len(in.Attachments), len(out.Body.Attachments))
		}
		for i, a := range out.Body.Attachments {
			if !bytes.Equal(a.Data, in.Attachments[i].Data) {
				t.Fatalf("seed %d: attachment %d did not survive", seed, i)
			}
		}
		if sender.Fingerprint() != alice.Fingerprint() {
			t.Fatalf("seed %d: wrong sender", seed)
		}
	}
}

// Each message carries a fresh encapsulation, so sealing the same body twice
// must never produce the same ciphertext.
func TestEveryEnvelopeIsUnique(t *testing.T) {
	r, seed := testutil.Seed(t)
	alice, bob := pair(t)
	b := body(t)
	b.Text = testutil.Text(r, 64)

	seen := map[string]bool{}
	for i := range 50 {
		env, _, err := Seal(alice, bob.Public(), b)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		key := hex.EncodeToString(env.CT)
		if seen[key] {
			t.Fatalf("seed %d: envelope %d repeated a ciphertext", seed, i)
		}
		seen[key] = true
	}
}

// One flipped bit in each structurally distinct region. Each region is
// guarded by a different check, so a flip in only the last byte tests only the
// last check. Offsets come from the format's constants.
func TestBitFlipInEveryRegion(t *testing.T) {
	r, seed := testutil.Seed(t)
	alice, bob := pair(t)
	encap := encapSize(t, bob.Public())

	regions := func(ct []byte) map[string]int {
		return map[string]int{
			"first byte of the encapsulation": 0,
			"middle of the encapsulation":     encap / 2,
			"last byte of the encapsulation":  encap - 1,
			"first byte of the ciphertext":    encap,
			"middle of the ciphertext":        encap + (len(ct)-encap)/2,
			"last byte, inside the AEAD tag":  len(ct) - 1,
			"start of the AEAD tag":           len(ct) - aeadTagSize,
		}
	}

	for name, offset := range regions(mustSeal(t, alice, bob, body(t)).CT) {
		t.Run(name, func(t *testing.T) {
			env := mustSeal(t, alice, bob, body(t))
			if offset < 0 || offset >= len(env.CT) {
				t.Skipf("offset %d is outside a %d byte ciphertext", offset, len(env.CT))
			}
			env.CT = testutil.FlipByteBit(env.CT, offset, r.IntN(8))
			if _, _, err := Open(bob, env); err == nil {
				t.Fatalf("seed %d: a flipped bit at offset %d opened cleanly", seed, offset)
			}
		})
	}
}

// Truncate by one, extend by one. Both keep the ciphertext plausible.
func TestLengthVandalism(t *testing.T) {
	alice, bob := pair(t)

	short := mustSeal(t, alice, bob, body(t))
	short.CT = short.CT[:len(short.CT)-1]
	if _, _, err := Open(bob, short); err == nil {
		t.Fatal("a ciphertext one byte short opened")
	}

	long := mustSeal(t, alice, bob, body(t))
	long.CT = append(long.CT, 0x00)
	if _, _, err := Open(bob, long); err == nil {
		t.Fatal("a ciphertext one byte long opened")
	}

	empty := mustSeal(t, alice, bob, body(t))
	empty.CT = nil
	if _, _, err := Open(bob, empty); err == nil {
		t.Fatal("an empty ciphertext opened")
	}
}

// The inner signature cannot be reached by flipping ciphertext bits, so the
// envelope is built by hand with the right bundle and a vandalised signature.
// This is distinct from the bundle-mismatch case: there the key is wrong, here
// the key is right and the signature is damaged.
func TestVandalisedInnerSignature(t *testing.T) {
	r, seed := testutil.Seed(t)
	alice, bob := pair(t)

	inner := &Inner{V: Version,
		From:       alice.Fingerprint(),
		FromBundle: alice.Public().Bundle(),
		To:         bob.Fingerprint(),
		ID:         "00000000000000000000000000000001",
		Body:       body(t),
	}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	sig := mustSign(t, alice, sigInput(bob.Fingerprint(), innerBytes))
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes", len(sig))
	}
	bad := testutil.FlipBit(sig, r.IntN(ed25519.SignatureSize*8))

	env := sealPlaintext(t, bob.Public(), append(append([]byte{}, bad...), innerBytes...))
	if _, _, err := Open(bob, env); err == nil {
		t.Fatalf("seed %d: an envelope with a vandalised inner signature opened", seed)
	}

	// The same envelope with the untouched signature must open, or the test
	// proves nothing about the signature in particular.
	good := sealPlaintext(t, bob.Public(), append(append([]byte{}, sig...), innerBytes...))
	if _, _, err := Open(bob, good); err != nil {
		t.Fatalf("seed %d: the control envelope did not open: %v", seed, err)
	}
}

// A hex digit changed in the recipient field keeps it a valid fingerprint and
// must still fail: the field is bound into the HPKE info string.
func TestVandalisedRecipientField(t *testing.T) {
	alice, bob := pair(t)
	env := mustSeal(t, alice, bob, body(t))

	to := []byte(env.To)
	if to[0] == 'a' {
		to[0] = 'b'
	} else {
		to[0] = 'a'
	}
	env.To = string(to)
	if _, _, err := Open(bob, env); err == nil {
		t.Fatal("an envelope with one changed hex digit in its recipient opened")
	}
}

// The same identity key signs envelopes, requests and tokens. A signature made
// for one purpose must not verify for another; the token and request pair is
// tested in internal/token, and this completes the triangle.
func TestEnvelopeSignatureDomainIsSeparate(t *testing.T) {
	alice, bob := pair(t)

	inner := &Inner{V: Version,
		From:       alice.Fingerprint(),
		FromBundle: alice.Public().Bundle(),
		To:         bob.Fingerprint(),
		ID:         "00000000000000000000000000000002",
		Body:       body(t),
	}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}

	// Signed with the request domain instead of the envelope's.
	wrongDomain := mustSign(t, alice, relayapi.SigningString("POST", "/v1/mailbox/x", 0, "n", innerBytes))
	env := sealPlaintext(t, bob.Public(), append(append([]byte{}, wrongDomain...), innerBytes...))
	if _, _, err := Open(bob, env); err == nil {
		t.Fatal("a request signature verified as an envelope signature")
	}

	// And the reverse: an envelope signature must not verify as a request.
	envSig := mustSign(t, alice, sigInput(bob.Fingerprint(), innerBytes))
	auth := &relayapi.Auth{TS: 0, Nonce: "n", Sig: envSig}
	if auth.Verify(alice.Public(), "POST", "/v1/mailbox/x", innerBytes) {
		t.Fatal("an envelope signature verified as a request signature")
	}
}
