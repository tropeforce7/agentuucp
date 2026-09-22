package card

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitCardV: the one integer a card carries is its version, held to
// exactly 1; every other value, the type's extremes included, is refused
// naming the version this build reads.
func TestLimitCardV(t *testing.T) {
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

// TestLimitACardDocumentIsCapped: the document's bytes at the cap taken,
// one over refused by name, at every edge the reader meets — the empty
// document, which the signature refuses, and the cap, cap+1 and far past
// it, which the length refuses first.
func TestLimitACardDocumentIsCapped(t *testing.T) {
	id := owner(t)
	for _, n := range []int{relayapi.MaxCardBytes + 1, relayapi.MaxCardBytes * 2, 1 << 16} {
		doc := []byte("{" + strings.Repeat(" ", n-2) + "}")
		_, err := Verify(id.Public(), doc, mustSign(t, id, signingBytes(doc)))
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), fmt.Sprintf("the card is %d bytes; at most %d", n, relayapi.MaxCardBytes)) {
			t.Errorf("%d bytes: %v; want the length's refusal", n, err)
		}
	}
	if _, err := Verify(id.Public(), nil, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("an empty document: %v; want the signature's refusal", err)
	}
}
