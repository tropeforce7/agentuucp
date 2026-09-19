package message

import (
	"math"
	"strings"
	"testing"
)

// TestLimitAttachmentSize: an attachment's size must be the length of its
// data, so every other value is refused, the negative ones and the type's
// extremes among them, and the length itself, zero included, is accepted.
func TestLimitAttachmentSize(t *testing.T) {
	a, err := NewAttachment("notes.txt", []byte("four"))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{-1, math.MinInt64, 3, 5, math.MaxInt64} {
		a.Size = size
		err := a.Validate()
		if err == nil || !strings.Contains(err.Error(), "size ") || !strings.Contains(err.Error(), "does not match 4 bytes of data") {
			t.Errorf("size %d: %v; want the refusal naming the size and the data's length", size, err)
		}
	}
	a.Size = 4
	if err := a.Validate(); err != nil {
		t.Errorf("size 4 for four bytes: %v", err)
	}
	empty, err := NewAttachment("empty.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Size != 0 {
		t.Fatalf("an empty attachment has size %d", empty.Size)
	}
	if err := empty.Validate(); err != nil {
		t.Errorf("size 0 for no bytes: %v", err)
	}
	empty.Size = -1
	if err := empty.Validate(); err == nil {
		t.Error("size -1 for no bytes was accepted")
	}
}

// TestLimitAttachmentDigest: an attachment's digest is 64 lowercase hex
// characters and the digest of its data, one predicate at Validate and at
// the store's Load, so that what Open accepts is what the home reads
// back. One character short, one long, uppercase (the right digest in the
// wrong case, which Open once took and Load then refused) and a wrong
// digest are each refused naming the attachment; the digest as
// NewAttachment writes it is accepted.
func TestLimitAttachmentDigest(t *testing.T) {
	a, err := NewAttachment("notes.txt", []byte("four"))
	if err != nil {
		t.Fatal(err)
	}
	right := a.SHA256
	for _, tc := range []struct{ name, digest, says string }{
		{"one short", right[:63], "digest is 63 characters, not 64"},
		{"one long", right + "0", "digest is 65 characters, not 64"},
		{"uppercase", strings.ToUpper(right), "digest is not lowercase hex"},
		{"wrong", strings.Repeat("0", 64), "sha256 does not match data"},
		{"empty", "", "digest is 0 characters, not 64"},
	} {
		a.SHA256 = tc.digest
		err := a.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.says)
		}
	}
	a.SHA256 = right
	if err := a.Validate(); err != nil {
		t.Errorf("the digest as written: %v", err)
	}
}

// TestLimitNamesAreNotPathsAtValidate: a thread id and a reply id name a
// directory under an expert host's serve directory, and Body.Validate
// runs message.ValidID on each, so a value from the limit guide's
// traversal set — `..`, `../x`, `x/../../y`, `a/b`, an absolute path, a
// backslash form, a drive letter, a Windows device name, a NUL, the empty
// string, `.`, and a 300-byte name — is refused at the door. An
// attachment name is a file on the receiver, and the same values are
// not refused there but made safe: Validate takes each (but a NUL and
// the 300 bytes, which the text rule refuses), SafeName of it is a base
// name the sender's rule takes, and the sender's rule refuses the value
// itself.
func TestLimitNamesAreNotPathsAtValidate(t *testing.T) {
	set := []string{"..", "../x", "x/../../y", "a/b", "/etc/passwd", `..\x`, `C:\x`, "C:x", "CON", "com1.txt", "\x00", "", ".", strings.Repeat("a", 300)}
	for _, v := range set {
		b := goodBody(t)
		b.Thread = v
		if err := b.Validate(); err == nil {
			t.Errorf("thread %q was accepted", v)
		}
		if v != "" {
			b = goodBody(t)
			b.InReplyTo = v
			if err := b.Validate(); err == nil {
				t.Errorf("in_reply_to %q was accepted", v)
			}
		}
		b = goodBody(t)
		b.Attachments[0].Name = v
		text := v != "\x00" && len(v) <= 255
		if err := b.Validate(); (err == nil) != text {
			t.Errorf("attachment name %q at Validate: %v; want taken=%v", v, err, text)
		}
		safe := SafeName(v)
		if strings.ContainsAny(safe, `/\`) || safe == "" || safe == "." || safe == ".." || len(safe) > SafeNameMaxBytes {
			t.Errorf("SafeName(%q) = %q is not a base name", v, safe)
		}
		if err := ValidAttachmentName(safe); err != nil {
			t.Errorf("the sender's rule refuses SafeName(%q) = %q: %v", v, safe, err)
		}
		if err := ValidAttachmentName(v); err == nil {
			t.Errorf("ValidAttachmentName took %q", v)
		}
	}
}
