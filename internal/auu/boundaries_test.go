package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// parseArgs exists because Go's flag package stops at the first positional, so
// "auu read ID --json" silently ignored the flag. Every command that takes a
// positional needs a test that a flag after it is seen.
func TestFlagsAfterPositionalArguments(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// With an attachment, so extract has something to do.
	attachment := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(attachment, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	sent := alice.run("send", "--to", "bob", "--subject", "s", "--attach", attachment, "text")
	if !strings.Contains(sent, "sent to bob") {
		t.Fatalf("send failed:\n%s", sent)
	}
	bob.run("inbox", "--no-fetch")
	out := bob.run("inbox", "--json")
	var inbox inboxJSON
	if err := jsonUnmarshal(out, &inbox); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	if len(inbox.Messages) == 0 {
		t.Fatal("nothing arrived")
	}
	id := inbox.Messages[0].ID

	// Each of these puts the flag after the positional. A command that ignored
	// it would print the human form, which is not JSON.
	for _, args := range [][]string{
		{"read", id, "--json"},
		{"quarantine", "ls", "--json"},
	} {
		got := bob.run(args...)
		if !strings.HasPrefix(strings.TrimSpace(got), "{") && !strings.HasPrefix(strings.TrimSpace(got), "[") {
			t.Fatalf("%v ignored --json:\n%s", args, got)
		}
	}

	// extract takes a positional and a flag that changes where files land, so
	// the flag being seen is observable in the filesystem.
	dir := t.TempDir()
	bob.run("extract", id, "--out", dir)
	if _, err := os.Stat(filepath.Join(dir, "note.txt")); err != nil {
		t.Fatalf("extract ignored --out after the positional: %v", err)
	}

	// reply takes a positional and a flag.
	replied := bob.run("reply", id, "--subject", "changed", "thanks")
	if !strings.Contains(replied, "sent to") {
		t.Fatalf("reply with a flag after the positional failed:\n%s", replied)
	}
}

// wait refuses an interval that would hammer the relay, and the boundary is
// exactly five seconds.
func TestWaitIntervalBoundary(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)

	if _, err := alice.tryRun("wait", "--thread", "t", "--timeout", "1s", "--interval", "4s"); err == nil {
		t.Fatal("an interval of 4s was accepted")
	} else if !strings.Contains(err.Error(), "at least 5s") {
		t.Fatalf("error %q does not name the limit", err)
	}

	// Exactly five seconds is allowed; it times out rather than being refused.
	_, err := alice.tryRun("wait", "--thread", "t", "--timeout", "1s", "--interval", "5s")
	if err == nil {
		t.Fatal("wait returned success with nothing to find")
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("an interval of exactly 5s was refused as usage: %v", err)
	}
}
