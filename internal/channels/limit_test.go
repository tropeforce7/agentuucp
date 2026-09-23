package channels

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitDirectoryV: a directory's v is 1, and Validate refuses every
// other value with the version this build reads, the type's extremes
// among them.
func TestLimitDirectoryV(t *testing.T) {
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

// TestLimitADirectoryDocumentIsCapped: the document's bytes at every edge
// a reader meets — the empty document, which the signature refuses since
// there is nothing for the length to refuse, and the cap, one over it and
// far past it, which the length refuses first and by name.
func TestLimitADirectoryDocumentIsCapped(t *testing.T) {
	id := owner(t)
	for _, n := range []int{relayapi.MaxDirectoryBytes + 1, relayapi.MaxDirectoryBytes * 2, relayapi.MaxDocumentBytes} {
		doc := []byte("{" + strings.Repeat(" ", n-2) + "}")
		_, err := Verify(id.Public(), doc, mustSign(t, id, signingBytes(doc)))
		if !errors.Is(err, ErrForm) ||
			!strings.Contains(err.Error(), fmt.Sprintf("the directory is %d bytes; at most %d", n, relayapi.MaxDirectoryBytes)) {
			t.Errorf("%d bytes: %v; want the length's refusal", n, err)
		}
	}
	if _, err := Verify(id.Public(), nil, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("an empty document: %v; want the signature's refusal", err)
	}
}
