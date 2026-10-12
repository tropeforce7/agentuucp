package envelope

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// A section this build knows only on another path is one it does not know
// on a message (G23, R27): the recipient count, known on requests alone,
// and the maximum, known on answers alone, are read on a message as a name
// nobody registered is, a critical one needing a newer auu and an optional
// one opening.
func TestASectionKnownOnlyOnAnotherPathIsUnknownOnAMessage(t *testing.T) {
	alice, bob := pair(t)
	for _, name := range []string{recipients.CountName, recipients.MaxName, "review-unknown"} {
		for _, critical := range []bool{false, true} {
			label := name + "/optional"
			if critical {
				label = name + "/critical"
			}
			t.Run(label, func(t *testing.T) {
				if wire.Known(name, wire.OnMessage) {
					t.Fatalf("precondition: %s is known on messages", name)
				}
				env, _, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{{Name: name, Critical: critical, Data: json.RawMessage(`{"uninterpreted":true}`)}})
				if err != nil {
					t.Fatal(err)
				}
				_, _, err = Open(bob, env)
				if critical && !errors.Is(err, wire.ErrNeedsNewer) {
					t.Errorf("critical %s: err=%v; want needs-newer", name, err)
				}
				if !critical && err != nil {
					t.Errorf("optional %s: %v", name, err)
				}
			})
		}
	}
}

// A message is read on its own path and not on a manifest's: with today's
// registry the two paths know the same names, so the test registers one
// name on each alone. Critical, the message's own opens and the manifest's
// needs a newer auu by its name.
func TestAMessageIsSortedOnTheMessagePathNotTheManifestPath(t *testing.T) {
	t.Cleanup(wire.Register("scope-message-only", wire.OnMessage))
	t.Cleanup(wire.Register("scope-manifest-only", wire.OnManifest))
	alice, bob := pair(t)
	seal := func(name string) *Envelope {
		env, _, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{{Name: name, Critical: true, Data: json.RawMessage(`{"n":1}`)}})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	if _, _, err := Open(bob, seal("scope-message-only")); err != nil {
		t.Fatalf("a critical section known on a message: %v; want it opened", err)
	}
	_, _, err := Open(bob, seal("scope-manifest-only"))
	var nn *wire.NeedsNewerError
	if !errors.As(err, &nn) || nn.Name != "scope-manifest-only" {
		t.Fatalf("a critical section known only in a manifest: %v; want it named as needing a newer auu", err)
	}
}
