package withdraw_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// The known answer, from outside the package: the domain, the framing and
// the stored form are pinned by a value computed apart from this code (by
// Python's hashlib over the same three length-prefixed parts), so a change
// to any of them, which would leave every key a sender holds unable to
// withdraw what it was made for, fails here by name.
func TestTheWithdrawalKeyIsTheKnownAnswer(t *testing.T) {
	to := strings.Repeat("ab", 32)
	const (
		wantKey    = "e9b3ddd91286eb3a97ebffe1a7c93e53feb5b95841a7b77663cdeb38588c033a"
		wantStored = "cff093e16af953185ef331199ec7790687ba8b7bb42c956f0d13f807af8128ea"
	)
	if withdraw.Domain != "ccx-withdraw-v1" {
		t.Fatalf("the domain is %q", withdraw.Domain)
	}
	k := withdraw.EnvelopeKey(to, []byte("sealed bytes"))
	if k != wantKey {
		t.Fatalf("EnvelopeKey is %s, want %s", k, wantKey)
	}
	if got := withdraw.Stored(k); got != wantStored {
		t.Fatalf("Stored is %s, want %s", got, wantStored)
	}
	if !withdraw.Valid(k) || !withdraw.Valid(withdraw.Stored(k)) {
		t.Fatal("a key or its stored form is not Valid")
	}
}

// framed is the framing written out again here, under any domain: the
// carried hash's own is the same framing under ccx-carried-v1.
func framed(domain, to string, ct []byte) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(domain), []byte(to), ct} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The same recipient and ciphertext under the carried hash's domain give
// another value, so a carried hash a relay has seen is never a key, and
// the domain is what the framing is under.
func TestTheWithdrawalKeyIsNotTheCarriedHash(t *testing.T) {
	to := strings.Repeat("cd", 32)
	ct := []byte("the same sealed bytes")
	k := withdraw.EnvelopeKey(to, ct)
	if k != framed(withdraw.Domain, to, ct) {
		t.Fatal("EnvelopeKey is not the framing under its own domain")
	}
	if k == framed("ccx-carried-v1", to, ct) {
		t.Fatal("the key under ccx-withdraw-v1 equals the carried hash over the same bytes")
	}
	// The length prefixes keep a byte moved from the recipient to the
	// ciphertext from giving the same key.
	if withdraw.EnvelopeKey(to[:63], append([]byte(to[63:]), ct...)) == k {
		t.Fatal("moving a byte across the parts gave the same key")
	}
}

// A stream's key is EnvelopeKey's over its first min(size, StreamPrefix)
// bytes, at 0, 1, the prefix and one past it; the bytes past the prefix
// are not read and change nothing; a reader that ends before the count
// is an error, and so is a negative size.
func TestAStreamsKeyIsOverItsPrefix(t *testing.T) {
	to := strings.Repeat("ef", 32)
	long := bytes.Repeat([]byte{0x5a}, withdraw.StreamPrefix+1)
	for _, size := range []int{0, 1, withdraw.StreamPrefix, withdraw.StreamPrefix + 1} {
		k, err := withdraw.StreamKey(to, bytes.NewReader(long[:size]), int64(size))
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		n := min(size, withdraw.StreamPrefix)
		if want := withdraw.EnvelopeKey(to, long[:n]); k != want {
			t.Errorf("size %d: the key is not EnvelopeKey over the first %d bytes", size, n)
		}
	}
	// One byte past the prefix changed: the same key.
	other := bytes.Clone(long)
	other[withdraw.StreamPrefix] ^= 1
	a, _ := withdraw.StreamKey(to, bytes.NewReader(long), int64(len(long)))
	b, _ := withdraw.StreamKey(to, bytes.NewReader(other), int64(len(other)))
	if a != b {
		t.Error("a byte past the prefix changed the key")
	}
	// The last byte of the prefix changed: another key.
	other[withdraw.StreamPrefix-1] ^= 1
	if c, _ := withdraw.StreamKey(to, bytes.NewReader(other), int64(len(other))); c == a {
		t.Error("a byte inside the prefix did not change the key")
	}
	// Short by one, at the prefix and below it.
	for _, size := range []int{1, withdraw.StreamPrefix} {
		_, err := withdraw.StreamKey(to, bytes.NewReader(long[:size-1]), int64(size))
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Errorf("a reader one byte short of %d: %v", size, err)
		}
	}
	if _, err := withdraw.StreamKey(to, bytes.NewReader(nil), -1); err == nil {
		t.Error("a negative size gave a key")
	}
}

// Valid takes exactly 64 lowercase hex characters, and Stored gives
// nothing for anything else, so no malformed key has a stored form a
// column could hold.
func TestAKeyHasOneShape(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if !withdraw.Valid(good) {
		t.Fatal("64 lowercase hex characters are not a key")
	}
	for name, k := range map[string]string{
		"empty":      "",
		"63":         good[:63],
		"65":         good + "0",
		"uppercase":  strings.ToUpper(good),
		"one upper":  "A" + good[1:],
		"not hex":    "g" + good[1:],
		"a space":    " " + good[1:],
		"a NUL":      "\x00" + good[1:],
		"multi-byte": "é" + good[2:],
	} {
		if withdraw.Valid(k) {
			t.Errorf("%s: %q is Valid", name, k)
		}
		if withdraw.Stored(k) != "" {
			t.Errorf("%s: %q has a stored form", name, k)
		}
	}
}
