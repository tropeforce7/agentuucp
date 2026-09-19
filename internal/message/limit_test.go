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
