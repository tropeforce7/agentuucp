package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// Parse used to decode the payload and then check its length, which allocates
// the whole output from a number the peer chose before refusing it.
//
// The order is proven by which error comes back: the input below is over the
// cap and its last character is not valid base64. If the decode ran first, the
// base64 message is returned; the length message means the length was checked
// first.
func TestPayloadLengthIsCheckedBeforeDecoding(t *testing.T) {
	maxEncoded := base64.RawURLEncoding.EncodedLen(MaxPayloadBytes)
	oversize := Prefix + "." + strings.Repeat("A", maxEncoded) + "!" + "." +
		strings.Repeat("A", base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize))

	_, err := Parse(oversize)
	if !errors.Is(err, ErrForm) {
		t.Fatalf("Parse gave %v, want ErrForm", err)
	}
	if strings.Contains(err.Error(), "bad base64") {
		t.Fatalf("the decode ran before the length check: %v", err)
	}
	if !strings.Contains(err.Error(), "encoded bytes") {
		t.Fatalf("error %q does not name the encoded length", err)
	}
}

// The same for the signature, whose encoded length is a single valid value.
func TestSignatureLengthIsCheckedBeforeDecoding(t *testing.T) {
	id := admin(t)
	good, err := Issue(id, base(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")

	for _, name := range []string{"one short", "one long"} {
		sig := parts[2][:len(parts[2])-1]
		if name == "one long" {
			sig = parts[2] + "A"
		}
		_, err := Parse(parts[0] + "." + parts[1] + "." + sig)
		if !errors.Is(err, ErrForm) {
			t.Fatalf("%s: %v, want ErrForm", name, err)
		}
		if !strings.Contains(err.Error(), "signature is") {
			t.Fatalf("%s: error %q does not name the signature length", name, err)
		}
	}

	// A signature of the right encoded length but invalid base64 gets past
	// the length check and is refused by the decoder, which is the right order.
	bad := strings.Repeat("A", len(parts[2])-1) + "!"
	if _, err := Parse(parts[0] + "." + parts[1] + "." + bad); !strings.Contains(err.Error(), "bad base64") {
		t.Fatalf("a correctly sized but undecodable signature gave %v", err)
	}
}

// The cap itself is a boundary, so both sides of it are tested.
func TestPayloadAtTheCap(t *testing.T) {
	id := admin(t)
	c := base(time.Now())
	// Grow the note until the payload is as close to the cap as it can be.
	for n := 1; n <= MaxNoteBytes; n++ {
		c.Note = strings.Repeat("n", n)
		if _, err := Issue(id, c); err != nil {
			t.Fatalf("a note of %d bytes was refused: %v", n, err)
		}
	}
	// And a payload one byte over the cap cannot be parsed, however it was
	// produced.
	payload := strings.Repeat("x", MaxPayloadBytes+1)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := strings.Repeat("A", base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize))
	if _, err := Parse(Prefix + "." + encoded + "." + sig); !errors.Is(err, ErrForm) {
		t.Fatalf("a payload of %d bytes parsed", len(payload))
	}
}
