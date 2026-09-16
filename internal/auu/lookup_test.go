package auu

import (
	"encoding/json"
	"strings"
	"testing"
)

// The relay knows three things about an identity a person can ask for
// before deciding to add it: the name it registered under, when, and its
// keys. Any of the forms a person has to hand finds it, a flag goes after
// the argument, and the answer says whether the peer list already knows it.
func TestLookupAsksTheRelayAboutAnID(t *testing.T) {
	url := startRelay(t)
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	fp := alice.exportFingerprint()

	var out lookupJSON
	if err := json.Unmarshal([]byte(bob.run("lookup", fp, "--json")), &out); err != nil {
		t.Fatal(err)
	}
	if out.Fingerprint != fp || out.Name != "alice" || out.Short != fp[:16] {
		t.Fatalf("lookup by fingerprint: %+v", out)
	}
	if out.Registered == nil {
		t.Fatal("lookup does not say when alice registered")
	}
	if out.KnownAs != "" {
		t.Fatalf("alice is not on bob's list yet, but known_as is %q", out.KnownAs)
	}
	if out.Suite == "" || out.ExportLine == "" {
		t.Fatalf("lookup is missing the keys or the export line: %+v", out)
	}

	// The short id listings print.
	var byShort lookupJSON
	if err := json.Unmarshal([]byte(bob.run("lookup", fp[:16], "--json")), &byShort); err != nil {
		t.Fatal(err)
	}
	if byShort.Fingerprint != fp {
		t.Fatalf("lookup by short id found %s", byShort.Fingerprint)
	}

	text := bob.run("lookup", fp)
	for _, want := range []string{"name on relay: alice", "registered:", "peer list:     not on yours", "Confirm that fingerprint"} {
		if !strings.Contains(text, want) {
			t.Errorf("lookup text lacks %q:\n%s", want, text)
		}
	}

	// By name, once alice is a peer, and then the answer says so and stops
	// telling bob to confirm what he has already confirmed.
	bob.run("peers", "add", strings.TrimSpace(alice.run("id", "export")))
	var byName lookupJSON
	if err := json.Unmarshal([]byte(bob.run("lookup", "alice", "--json")), &byName); err != nil {
		t.Fatal(err)
	}
	if byName.Fingerprint != fp || byName.KnownAs != "alice" {
		t.Fatalf("lookup by peer name: %+v", byName)
	}
	if text := bob.run("lookup", "alice"); !strings.Contains(text, `on yours, as "alice"`) || strings.Contains(text, "Confirm that") {
		t.Errorf("lookup of a known peer:\n%s", text)
	}

	// Yourself.
	if text := bob.run("lookup", bob.exportFingerprint()); !strings.Contains(text, "this is you") {
		t.Errorf("lookup of oneself:\n%s", text)
	}

	// Nobody by that fingerprint, and nobody by that name.
	if _, err := bob.tryRun("lookup", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "not registered on") {
		t.Fatalf("an unknown fingerprint: %v", err)
	}
	if _, err := bob.tryRun("lookup", "nobody-i-know"); err == nil || !strings.Contains(err.Error(), "not a fingerprint") {
		t.Fatalf("an unknown name: %v", err)
	}

	// The older spelling is the same command.
	if text := bob.run("peers", "fetch", fp); !strings.Contains(text, "name on relay: alice") {
		t.Errorf("peers fetch:\n%s", text)
	}
}
