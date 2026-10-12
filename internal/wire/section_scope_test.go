package wire

import (
	"encoding/json"
	"errors"
	"testing"
)

// theRegistry is every name this build registers and the paths it
// registers each on, as internal/recipients' init calls Register. This
// package's tests link no feature, so the table fills the registry from it;
// TestTheSectionsAreKnownOnTheirPathsAlone in internal/recipients holds the
// real registry to the same sort.
var theRegistry = []struct {
	name string
	on   Path
}{
	{"recipients", OnMessage | OnManifest},
	{"recipient-count", OnRequest},
	{"max-recipients", OnAnswer},
}

// A section is known on its own path alone (G23, R27). For every
// registered name and every one of the four paths, critical and not, Sort's
// outcome is asserted: on a path the name is registered on it is handed on;
// on any other a critical one needs a newer auu by its name and an optional
// one is ignored. CheckBody, on the two body paths, says the same.
func TestASectionIsKnownOnItsOwnPathAlone(t *testing.T) {
	if len(known) != 0 {
		t.Fatalf("the registry holds %d names before the table fills it", len(known))
	}
	for _, r := range theRegistry {
		t.Cleanup(Register(r.name, r.on))
	}
	for _, r := range theRegistry {
		for _, p := range fourPaths {
			for _, critical := range []bool{false, true} {
				label := r.name + " on " + p.label
				if critical {
					label += ", critical"
				}
				own := r.on&p.on != 0
				s := Section{Name: r.name, Critical: critical, Data: json.RawMessage(`{"n":1}`)}

				k, ign, err := Sort([]Section{s}, p.on)
				var nn *NeedsNewerError
				switch {
				case own:
					if err != nil || len(k) != 1 || k[0].Name != r.name || len(ign) != 0 {
						t.Errorf("%s: known %v, ignored %v, %v; want it handed on", label, k, ign, err)
					}
				case critical:
					if !errors.As(err, &nn) || nn.Name != r.name || k != nil || ign != nil {
						t.Errorf("%s: known %v, ignored %v, %v; want it named as needing a newer auu", label, k, ign, err)
					}
				default:
					if err != nil || len(k) != 0 || len(ign) != 1 || ign[0].Name != r.name {
						t.Errorf("%s: known %v, ignored %v, %v; want it ignored", label, k, ign, err)
					}
				}

				if p.on != OnRequest && p.on != OnAnswer {
					continue
				}
				err = CheckBody([]Section{s}, p.on)
				if !own && critical {
					if !errors.As(err, &nn) || nn.Name != r.name {
						t.Errorf("CheckBody, %s: %v; want it named as needing a newer auu", label, err)
					}
				} else if err != nil {
					t.Errorf("CheckBody, %s: %v; want the body taken", label, err)
				}
			}
		}
	}
}
