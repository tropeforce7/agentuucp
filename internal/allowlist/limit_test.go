package allowlist

import (
	"math"
	"strings"
	"testing"
)

// TestLimitDocumentV: a list's v is 1, and Validate refuses every other
// value with the version this build reads, the type's extremes among them.
func TestLimitDocumentV(t *testing.T) {
	id := owner(t)
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		d := base(id)
		d.V = v
		err := d.Validate()
		if err == nil || !strings.Contains(err.Error(), "this build reads 1") {
			t.Errorf("v %d: %v; want the refusal naming the version this build reads", v, err)
		}
	}
	if err := base(id).Validate(); err != nil {
		t.Errorf("v 1: %v", err)
	}
}

// TestLimitSenderOneShort: every sender on a list is a fingerprint, held
// at Validate before a print slices its first characters; one character
// short is refused naming the sender.
func TestLimitSenderOneShort(t *testing.T) {
	id := owner(t)
	for _, bad := range []string{strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), ""} {
		d := base(id)
		d.Senders = []string{bad}
		if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "is not a fingerprint") {
			t.Errorf("sender %q: %v; want the refusal", bad, err)
		}
	}
	d := base(id)
	d.Owner = strings.Repeat("a", 63)
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "owner is not a fingerprint") {
		t.Errorf("owner one short: %v; want the refusal", err)
	}
}
