package auu

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The second review's F13, kept: every name known only off the message path
// is held to the kept cap by keptSections, which both the message path and
// a received stream's manifest go through, at one byte over and kept at the
// cap, critical or not; and recipients, known on both, keeps its own rule.
func TestSectionsKnownOnlyOffTheMessagePathAreHeldToTheKeptCap(t *testing.T) {
	sec := func(name string, n int, critical bool) wire.Section {
		return wire.Section{Name: name, Critical: critical,
			Data: json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), n-2)) + `"`)}
	}
	for _, name := range []string{recipients.CountName, recipients.MaxName} {
		for _, critical := range []bool{false, true} {
			kept, dropped := keptSections([]wire.Section{sec(name, wire.MaxKeptBytes+1, critical)})
			if dropped != 1 || len(kept) != 0 {
				t.Errorf("%s critical=%v one over the cap: kept %d dropped %d", name, critical, len(kept), dropped)
			}
			kept, dropped = keptSections([]wire.Section{sec(name, wire.MaxKeptBytes, critical)})
			if dropped != 0 || len(kept) != 1 {
				t.Errorf("%s critical=%v at the cap: kept %d dropped %d", name, critical, len(kept), dropped)
			}
		}
	}
	if wire.Known(recipients.CountName, wire.OnMessage|wire.OnManifest) || wire.Known(recipients.MaxName, wire.OnMessage|wire.OnManifest) {
		t.Errorf("a request or answer section is known on a message or manifest")
	}
	if !wire.Known(recipients.Name, wire.OnMessage) || !wire.Known(recipients.Name, wire.OnManifest) || wire.Known(recipients.Name, wire.OnRequest|wire.OnAnswer) {
		t.Errorf("recipients is not known exactly on a message and a manifest")
	}
	if _, err := recipients.Check(bytes.Repeat([]byte(" "), recipients.MaxBytes+1), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err == nil {
		t.Errorf("an oversized recipients list passed its own rule")
	}
}
