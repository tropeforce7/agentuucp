// Package withdraw is the key a sender withdraws a posted message by, and
// the form the relay keeps of it.
//
// The key is derived, never minted: both ends compute it from the sealed
// bytes the relay stores. The sender computes it from the copy it sealed
// and keeps it in its sent record; the relay computes it from the copy it
// is storing and keeps only Stored of it, a hash of the key, beside the
// row. Nothing new travels in any answer, and a post whose answer was lost
// and was sent again is as withdrawable as any other, since the same bytes
// give the same key.
//
// Who can make the key is whoever holds the sealed bytes: the sender; the
// recipient once they have fetched them, who can remove their own mail
// anyway; and whoever holds the relay's message files, who can delete them
// anyway. The relay's database alone does not give it: the column holds a
// hash of the key, which names nobody and cannot be tested against a
// candidate sender.
//
// The package imports nothing of the relay's or the client's, so that the
// one arithmetic is the same at both ends by construction.
package withdraw

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// Domain separates the key from every other hash over the same bytes, the
// carried hash over the same recipient and ciphertext among them. It is
// one of the ccx constants the development guide counts, and like
// ccx-carried-v1 it is on no wire: the key is, and the domain is inside it.
const Domain = "ccx-withdraw-v1"

// StreamPrefix is how much of a sealed stream the key is over: its first
// bytes, which begin with the seal's own encapsulated key and so are
// another message's for every seal, whoever it is to. A stream is up to
// gigabytes and the relay computes the key as it places one, so the key
// is over a prefix rather than the whole. It is this package's constant
// and no setting: both ends must read the same number.
const StreamPrefix = 4096

// keyLen is the bytes of a key, and of what Stored keeps of one: a SHA-256
// sum each.
const keyLen = sha256.Size

// EnvelopeKey is the key of a sealed envelope: SHA-256 over the domain,
// the recipient's fingerprint and the ciphertext, each preceded by its
// length as eight bytes big-endian, as the carried hash frames its parts.
// The channel is left out, as the carried hash leaves it out: it is
// outside the seal, and the same ciphertext is the same message however it
// is filed. It is lowercase hex, which is what Valid holds a key to.
func EnvelopeKey(to string, ct []byte) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(Domain), []byte(to), ct} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// StreamKey is the key of a sealed stream of size bytes read from r:
// EnvelopeKey's framing over the first min(size, StreamPrefix) of them.
// Exactly that many are read, and a reader that ends sooner is an error,
// since a key over fewer bytes than the stream holds would be another
// stream's. A negative size is the caller's fault and is refused.
func StreamKey(to string, r io.Reader, size int64) (string, error) {
	if size < 0 {
		return "", fmt.Errorf("withdraw: a stream of %d bytes", size)
	}
	buf := make([]byte, min(size, StreamPrefix))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("withdraw: reading the first %d bytes of the stream: %w", len(buf), err)
	}
	return EnvelopeKey(to, buf), nil
}

// Stored is what the relay keeps of a key: the lowercase hex of SHA-256
// over the key's own bytes, decoded from its hex. A key that is not Valid
// has no stored form and gives the empty string, which no row's column
// is compared with: a row with an empty column is not withdrawable.
func Stored(k string) string {
	if !Valid(k) {
		return ""
	}
	raw, _ := hex.DecodeString(k)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Valid says whether k has a key's shape: 64 lowercase hex characters, the
// form EnvelopeKey writes. Uppercase is refused rather than folded, so one
// key has one spelling.
func Valid(k string) bool {
	if len(k) != 2*keyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
