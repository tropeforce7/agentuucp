package auu

import (
	"encoding/json"
	"strings"
	"testing"
)

// auu version says what this binary was built from, in one line or as one
// field. What it says depends on the tree it was built from — a tag, a
// pseudo-version, or the word for nothing — so the assertion is that it is
// carried, not what it is.
func TestVersionSaysWhatThisBinaryIs(t *testing.T) {
	alice := newUser(t, "alice", startRelay(t))
	out := alice.run("version")
	if !strings.HasPrefix(out, "auu ") || strings.TrimSpace(strings.TrimPrefix(out, "auu ")) == "" {
		t.Fatalf("auu version said %q", out)
	}
	var got versionJSON
	if err := json.Unmarshal([]byte(alice.run("version", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version == "" {
		t.Fatal("auu version --json carries no version")
	}
	if got.Version != strings.TrimSpace(strings.TrimPrefix(out, "auu ")) {
		t.Fatalf("the two forms disagree: %q and %q", out, got.Version)
	}
	// One field, and no relay was asked anything: a version is a fact
	// about the binary in the user's hand.
	raw := alice.run("version", "--json")
	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 {
		t.Fatalf("auu version --json is %s, want the one field", raw)
	}
	usageError(t, alice, `unexpected argument "extra"`, "version", "extra")
}
