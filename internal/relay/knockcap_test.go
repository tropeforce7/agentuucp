package relay

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// The default knock cap is a relationship and not a figure (D27): a knock
// at its longest text and name, carrying message.MaxKnockVouches vouches
// each at its longest name, fits under it as sealed and posted, and one
// more vouch would not. Five cannot be sealed, since Validate refuses them,
// so the fifth is the measured cost of the fourth added to the four.
// Changing the cap, the vouch's shape, the knock's limits or the count
// fails this and asks whether the others were meant to move with it.
func TestTheDefaultKnockCapTakesFourVouchesAndNotFive(t *testing.T) {
	gen := func(name string) *identity.Identity {
		t.Helper()
		id, err := identity.Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	longest := strings.Repeat("n", identity.MaxNameBytes)
	knocker, recipient := gen(longest), gen("r")
	now := time.Now()
	vouches := make([]message.Carried, 0, message.MaxKnockVouches)
	for i := 0; i < message.MaxKnockVouches; i++ {
		doc, sig, err := vouch.Sign(gen("v"), &vouch.Document{Subject: knocker.Fingerprint(),
			Bundle: knocker.Public().Bundle(), Name: longest, Issued: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		vouches = append(vouches, message.Carried{Document: doc, Signature: sig})
	}
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	sealed := func(n int) int64 {
		t.Helper()
		body := message.Body{Type: message.TypeKnock, Thread: thread, Name: longest,
			Text: strings.Repeat("t", message.MaxKnockText), Vouches: vouches[:n]}
		env, _, err := envelope.SealFor(knocker, recipient.Public(), "", body)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return int64(len(raw))
	}
	cap := DefaultLimits().KnockMaxBytes
	four, three := sealed(message.MaxKnockVouches), sealed(message.MaxKnockVouches-1)
	t.Logf("sealed at the longest: %d bytes with none, %d with three, %d with four; the default cap is %d",
		sealed(0), three, four, cap)
	if four > cap {
		t.Errorf("a knock with %d vouches is %d bytes, over the default cap of %d", message.MaxKnockVouches, four, cap)
	}
	if five := four + (four - three); five <= cap {
		t.Errorf("a knock with one vouch more would be %d bytes, under the default cap of %d: the cap admits more than the count", five, cap)
	}
}
