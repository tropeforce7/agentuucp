package stream

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// A section this build knows only on another path is one it does not know
// in a manifest (G23, R27): the recipient count, known on requests alone,
// and the maximum, known on answers alone, are read in a manifest as a name
// nobody registered is, a critical one needing a newer auu by its name,
// with the verified manifest handed back, and an optional one opening.
func TestASectionKnownOnlyOnAnotherPathIsUnknownInAManifest(t *testing.T) {
	from, to := pair(t)
	for _, name := range []string{recipients.CountName, recipients.MaxName, "review-unknown"} {
		for _, critical := range []bool{false, true} {
			label := name + "/optional"
			if critical {
				label = name + "/critical"
			}
			t.Run(label, func(t *testing.T) {
				if wire.Known(name, wire.OnManifest) {
					t.Fatalf("precondition: %s is known in a manifest", name)
				}
				m, header, chunk0 := sealedWith(t, from, to, []wire.Section{{Name: name, Critical: critical, Data: json.RawMessage(`{"uninterpreted":true}`)}})
				opened, err := OpenManifest(to, header, chunk0)
				var nn *wire.NeedsNewerError
				if critical {
					if !errors.Is(err, wire.ErrNeedsNewer) || !errors.As(err, &nn) || nn.Name != name {
						t.Fatalf("critical %s: err=%v; want needs-newer naming it", name, err)
					}
					if errors.Is(err, ErrForm) || errors.Is(err, ErrSignature) {
						t.Errorf("critical %s was called malformed or unsigned: %v", name, err)
					}
				} else if err != nil {
					t.Fatalf("optional %s: %v", name, err)
				}
				if opened == nil || opened.Manifest.ID != m.ID || opened.Sender.Fingerprint() != from.Fingerprint() {
					t.Fatalf("the verified manifest and its sender were not handed back: %+v", opened)
				}
			})
		}
	}
}

// The manifest is read on its own path and not on a message's: with today's
// registry the two paths know the same names, so the test registers one name
// on each alone. Critical, the manifest's own opens and the message's needs
// a newer auu by its name.
func TestAManifestIsSortedOnTheManifestPathNotTheMessagePath(t *testing.T) {
	t.Cleanup(wire.Register("scope-manifest-only", wire.OnManifest))
	t.Cleanup(wire.Register("scope-message-only", wire.OnMessage))
	from, to := pair(t)
	critical := func(name string) []wire.Section {
		return []wire.Section{{Name: name, Critical: true, Data: json.RawMessage(`{"n":1}`)}}
	}
	_, header, chunk0 := sealedWith(t, from, to, critical("scope-manifest-only"))
	if _, err := OpenManifest(to, header, chunk0); err != nil {
		t.Fatalf("a critical section known in a manifest: %v; want it opened", err)
	}
	_, header, chunk0 = sealedWith(t, from, to, critical("scope-message-only"))
	_, err := OpenManifest(to, header, chunk0)
	var nn *wire.NeedsNewerError
	if !errors.As(err, &nn) || nn.Name != "scope-message-only" {
		t.Fatalf("a critical section known only on a message: %v; want it named as needing a newer auu", err)
	}
}
