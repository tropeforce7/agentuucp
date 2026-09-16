package keyfile

import (
	"bytes"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// homeKey is a fixed home key for the tests that pin the format. A real one
// is random; nothing here depends on the value.
func homeKey() []byte { return bytes.Repeat([]byte{0x42}, HomeKeySize) }

// TestWrapKnownAnswer pins the wrapped format's shape: the block type, the
// one header, and the body being the plaintext plus a nonce and a tag. The
// ciphertext itself cannot be pinned, because the nonce is random.
func TestWrapKnownAnswer(t *testing.T) {
	plaintext := []byte("a key worth wrapping")
	out, err := Wrap(plaintext, homeKey())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "-----BEGIN "+WrappedBlockType+"-----\n") {
		t.Errorf("wrong block type:\n%s", out)
	}
	block, rest := pem.Decode(out)
	if block == nil || len(rest) != 0 {
		t.Fatal("Wrap did not write exactly one PEM block")
	}
	if len(block.Headers) != 1 || block.Headers[hdrCipher] != cipherGCM {
		t.Errorf("headers are %v, want only %s: %s", block.Headers, hdrCipher, cipherGCM)
	}
	if want := len(plaintext) + nonceSize + tagSize; len(block.Bytes) != want {
		t.Errorf("body is %d bytes, want %d: plaintext plus nonce plus tag", len(block.Bytes), want)
	}
	back, err := Unwrap(out, homeKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Error("the plaintext came back changed")
	}
	// And it is not a passphrase file, so the other reader refuses it by
	// type rather than trying a derivation on it.
	if _, err := Decrypt(out, []byte(secret)); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("Decrypt on a wrapped block gave %v, want ErrNotEncrypted", err)
	}
	if !IsWrapped(out) || IsEncrypted(out) {
		t.Error("IsWrapped and IsEncrypted disagree about a wrapped block")
	}
}

// TestWrapRoundTripRandom seals and opens random content at random lengths
// and at the lengths a block cipher and an empty input make interesting.
func TestWrapRoundTripRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	lengths := testutil.Lengths(1<<20, 16)
	for i := 0; i < 24; i++ {
		lengths = append(lengths, r.IntN(4096))
	}
	for _, n := range lengths {
		key := testutil.Bytes(r, HomeKeySize)
		plaintext := testutil.Bytes(r, n)
		out, err := Wrap(plaintext, key)
		if err != nil {
			t.Fatalf("length %d: Wrap: %v (seed %d)", n, err, seed)
		}
		back, err := Unwrap(out, key)
		if err != nil {
			t.Fatalf("length %d did not open: %v (seed %d)", n, err, seed)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("length %d came back changed (seed %d)", n, seed)
		}
	}
}

// TestUnwrapRefusesEveryAlteration vandalises each structurally distinct
// region one bit at a time, tries the wrong key, the wrong block type, and
// a changed header — and, since a changed header is refused by the cipher
// name check before the AEAD ever sees it, asserts separately that the
// header is in the additional data, which is what would refuse a header
// somebody adds later.
func TestUnwrapRefusesEveryAlteration(t *testing.T) {
	out, err := Wrap([]byte("a key worth stealing"), homeKey())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(out)
	body := block.Bytes
	for _, region := range []struct {
		name string
		bit  int
	}{
		{"nonce", 0},
		{"nonce, last byte", (nonceSize - 1) * 8},
		{"ciphertext, first byte", nonceSize * 8},
		{"ciphertext, last byte", (len(body) - tagSize - 1) * 8},
		{"tag, first byte", (len(body) - tagSize) * 8},
		{"tag, last byte", (len(body) - 1) * 8},
	} {
		t.Run(region.name, func(t *testing.T) {
			bad := *block
			bad.Bytes = testutil.FlipBit(body, region.bit)
			if _, err := UnwrapBlock(&bad, homeKey()); !errors.Is(err, ErrHomeKey) {
				t.Errorf("a flipped bit in the %s gave %v, want ErrHomeKey", region.name, err)
			}
		})
	}
	t.Run("truncated and extended", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body []byte
		}{
			{"a byte off the front", body[1:]},
			{"a byte off the back", body[:len(body)-1]},
			{"a byte added", append(append([]byte{}, body...), 0)},
		} {
			bad := *block
			bad.Bytes = tc.body
			if _, err := UnwrapBlock(&bad, homeKey()); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		}
	})
	t.Run("the wrong key", func(t *testing.T) {
		wrong := homeKey()
		wrong[0] ^= 1
		if _, err := Unwrap(out, wrong); !errors.Is(err, ErrHomeKey) {
			t.Errorf("the wrong key gave %v, want ErrHomeKey", err)
		}
		if _, err := Unwrap(out, wrong[:HomeKeySize-1]); !errors.Is(err, ErrHomeKeySize) {
			t.Errorf("a short key gave %v, want ErrHomeKeySize", err)
		}
		if _, err := Wrap([]byte("x"), append(homeKey(), 0)); !errors.Is(err, ErrHomeKeySize) {
			t.Errorf("Wrap under a long key gave %v, want ErrHomeKeySize", err)
		}
	})
	t.Run("a plain key block", func(t *testing.T) {
		plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("der")})
		if _, err := Unwrap(plain, homeKey()); !errors.Is(err, ErrWrapped) {
			t.Errorf("a PRIVATE KEY block gave %v, want ErrWrapped", err)
		}
		if _, err := Unwrap(sealed(t, []byte("x")), homeKey()); !errors.Is(err, ErrWrapped) {
			t.Errorf("a passphrase block gave %v, want ErrWrapped", err)
		}
		if _, err := Unwrap([]byte("not pem"), homeKey()); !errors.Is(err, ErrWrapped) {
			t.Errorf("no PEM gave %v, want ErrWrapped", err)
		}
	})
	t.Run("a changed cipher header", func(t *testing.T) {
		bad := *block
		bad.Headers = map[string]string{hdrCipher: "AES-128-GCM"}
		_, err := UnwrapBlock(&bad, homeKey())
		if err == nil {
			t.Fatal("a changed Cipher header was accepted")
		}
		// It is the name check that fires, not the AEAD: say so, so that
		// nobody reads this as proof of the additional data.
		if !strings.Contains(err.Error(), "unknown cipher") {
			t.Errorf("the refusal is %q, which is not the cipher name check", err)
		}
		bad.Headers = map[string]string{hdrCipher: cipherGCM, "Extra": "x"}
		if _, err := UnwrapBlock(&bad, homeKey()); err == nil || !strings.Contains(err.Error(), "unknown header") {
			t.Errorf("an extra header gave %v, want the unknown header refusal", err)
		}
		bad.Headers = map[string]string{}
		if _, err := UnwrapBlock(&bad, homeKey()); err == nil || !strings.Contains(err.Error(), "no Cipher header") {
			t.Errorf("no header gave %v, want the missing header refusal", err)
		}
	})
	t.Run("the header is in the additional data", func(t *testing.T) {
		covered := string(aad(WrappedBlockType, block.Headers))
		if !strings.HasPrefix(covered, WrappedBlockType+"\n") {
			t.Errorf("the additional data does not start with the block type: %q", covered)
		}
		for k, v := range block.Headers {
			if !strings.Contains(covered, k+": "+v+"\n") {
				t.Errorf("header %q is not in the additional data:\n%s", k, covered)
			}
		}
		// And the two formats' additional data differ in the type, so a
		// body cannot be carried from one block type to the other.
		if string(aad(BlockType, block.Headers)) == covered {
			t.Error("the two block types produce the same additional data")
		}
		// That aad covers the headers proves nothing about Wrap unless Wrap
		// uses it: the body must refuse to open without the additional
		// data, and open with it. This is the check that fails if the
		// binding is dropped, which no other test in this file would notice.
		aead, err := homeAEAD(homeKey())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aead.Open(nil, nil, body, nil); err == nil {
			t.Error("the body opens with no additional data: Wrap is not binding the headers")
		}
		if _, err := aead.Open(nil, nil, body, []byte(covered)); err != nil {
			t.Errorf("the body does not open under the additional data aad computes: %v", err)
		}
	})
	t.Run("a body too short for a nonce and a tag", func(t *testing.T) {
		for _, n := range []int{0, 1, nonceSize + tagSize - 1} {
			bad := *block
			bad.Bytes = bytes.Repeat([]byte{0}, n)
			if _, err := UnwrapBlock(&bad, homeKey()); err == nil || !strings.Contains(err.Error(), "shorter than a nonce and a tag") {
				t.Errorf("a %d-byte body gave %v, want the length refusal", n, err)
			}
		}
		bad := *block
		bad.Bytes = bytes.Repeat([]byte{0}, nonceSize+tagSize)
		if _, err := UnwrapBlock(&bad, homeKey()); !errors.Is(err, ErrHomeKey) {
			t.Errorf("a body of exactly a nonce and a tag gave %v, want ErrHomeKey", err)
		}
	})
}
