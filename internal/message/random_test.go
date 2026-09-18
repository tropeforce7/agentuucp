package message

import (
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

func TestAttachmentRandom(t *testing.T) {
	r, seed := testutil.Seed(t)

	for _, n := range append(testutil.Lengths(1<<16, 32), 0, 1, 65) {
		data := testutil.Bytes(r, n)
		a, err := NewAttachment("f.bin", data)
		if err != nil {
			t.Fatalf("seed %d: %d bytes: %v", seed, n, err)
		}
		b := Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Text: "x", Attachments: []Attachment{a}}
		if err := b.Validate(); err != nil {
			t.Fatalf("seed %d: %d bytes did not validate: %v", seed, n, err)
		}
		if a.Size != int64(n) {
			t.Fatalf("seed %d: size %d for %d bytes", seed, a.Size, n)
		}

		// One flipped bit of the data must break the digest.
		if n > 0 {
			bad := b
			vandalised := a
			vandalised.Data = testutil.FlipBit(a.Data, r.IntN(n*8))
			bad.Attachments = []Attachment{vandalised}
			if err := bad.Validate(); err == nil {
				t.Fatalf("seed %d: a flipped data bit passed the digest check at %d bytes", seed, n)
			}
		}
		// And one flipped bit of the digest, likewise.
		bad := b
		vandalised := a
		digest := []byte(a.SHA256)
		i := r.IntN(len(digest))
		if digest[i] == '0' {
			digest[i] = '1'
		} else {
			digest[i] = '0'
		}
		vandalised.SHA256 = string(digest)
		bad.Attachments = []Attachment{vandalised}
		if err := bad.Validate(); err == nil {
			t.Fatalf("seed %d: a changed digest passed at %d bytes", seed, n)
		}
	}
}

// Both sides of both size limits.
func TestBodyLimitBoundaries(t *testing.T) {
	ok := func(b Body) error { return b.Validate() }

	atCap := Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Subject: strings.Repeat("s", maxSubjectBytes), Text: "x"}
	if err := ok(atCap); err != nil {
		t.Fatalf("a subject of exactly %d bytes was refused: %v", maxSubjectBytes, err)
	}
	overCap := atCap
	overCap.Subject = strings.Repeat("s", maxSubjectBytes+1)
	if err := ok(overCap); err == nil {
		t.Fatalf("a subject of %d bytes was accepted", maxSubjectBytes+1)
	}

	// Attachment names: 255 accepted, 256 refused. The name must survive
	// NewAttachment's own checks, so it carries an extension.
	name := strings.Repeat("n", maxNameBytes-4) + ".bin"
	a, err := NewAttachment(name, []byte("x"))
	if err != nil {
		t.Fatalf("a name of %d bytes was refused: %v", len(name), err)
	}
	b := Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Text: "x", Attachments: []Attachment{a}}
	if err := ok(b); err != nil {
		t.Fatalf("a name of exactly %d bytes was refused: %v", maxNameBytes, err)
	}
	a.Name = strings.Repeat("n", maxNameBytes+1)
	b.Attachments = []Attachment{a}
	if err := ok(b); err == nil {
		t.Fatalf("a name of %d bytes was accepted", maxNameBytes+1)
	}
}
