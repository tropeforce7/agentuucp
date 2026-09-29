package relay

import (
	"path/filepath"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// Two relays peered, for the tests that need an envelope to actually cross
// one: the worker dialling a neighbour, the neighbour taking it, and the row
// here becoming handed.
//
// Everything about the peering is the real thing — a courier identity with a
// mailbox at the neighbour, that neighbour's couriers file naming it, and the
// client package doing the dialling and the signing — because what these
// tests are for is the part that only exists when two relays are in the same
// room. What they do not do
// is register over HTTP: h.enroll writes the mailbox row, since registering
// spends the budgets some of these tests are measuring.

// peerage is one relay's side of a peering under test.
type peerage struct {
	h       *harness
	courier *identity.Identity
	home    string
}

// peer builds a relay that dials `to` under the given name, and makes `to`
// accept from it. It answers the dialling side's harness.
//
// The order matters and is the operator's order: the neighbour exists first,
// the courier enrols there, and only then is the relay that dials it built,
// since its courier home has to name a URL that is already listening.
// theirName is the name the dialling relay gives its neighbour, and ourName
// the name that neighbour gives back. They are deliberately different in
// every test that uses this: a name is relative to the relay reading it,
// there is no global namespace, and a test where both sides said "bar" would
// pass whichever name the code happened to use.
func peer(t *testing.T, to *harness, theirName, ourName string, limits CourierLimits) *peerage {
	t.Helper()
	// The courier identity, with a mailbox at the neighbour: that is what
	// "enrolled there" means, and it is why the neighbour can verify what
	// it signs. Its name in the export line is the name the neighbour will
	// know it by, since that line is what the neighbour's file holds.
	courier, err := identity.Generate(ourName)
	if err != nil {
		t.Fatal(err)
	}
	to.enroll(courier)

	// The neighbour admits it, under its own name for it. The file is the
	// one that neighbour's courier set is already watching, so this is the
	// edit an operator makes and not a restart.
	if to.server.courier == nil {
		t.Fatal("the neighbour has no courier configuration to add a line to")
	}
	writeCouriers(t, to.server.courier.couriers.path, courier)

	// The dialling side's home: the courier's identity and one relay entry
	// for the neighbour, at the URL it is actually listening on.
	root := filepath.Join(t.TempDir(), "courier")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(courier); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay(theirName, to.srv.URL); err != nil {
		t.Fatal(err)
	}
	// Nothing is pinned, because the harness serves plain HTTP: what these
	// tests are for is an envelope crossing between two relays, and the
	// transport it crosses over is the client package's own business, with
	// its own tests for the pin, the ratchet and the refusals, and the
	// container suite for the whole of it under TLS.

	c, err := NewCourier(CourierConfig{Home: root, PublicURL: "https://mine.example"}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, Config{Courier: c, CourierLimits: limits, Limits: DefaultLimits()})
	quiet(t, h)
	return &peerage{h: h, courier: courier, home: root}
}
