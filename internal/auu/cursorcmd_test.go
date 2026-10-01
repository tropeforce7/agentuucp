package auu

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// 'auu cursor show': each relay the home is on, its cursor beside what the
// relay holds, and a dash for one that cannot be asked; --relay narrows it
// and --json is the same as data.
func TestCursorShowsEachRelay(t *testing.T) {
	work, workSt := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	personal, _ := startRelayServer(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work, personal.URL)
	bob := onBothRelays(t, "bob", work, personal.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("send", "--to", "bob", "--subject", "one", "x", "--relay", "work")
	alice.run("send", "--to", "bob", "--subject", "two", "y", "--relay", "work")
	bob.run("inbox", "--relay", "work")
	ids := queuedOn(t, workSt, bob.exportFingerprint())
	personal.Close()

	var got []cursorJSON
	if err := json.Unmarshal([]byte(bob.run("cursor", "show", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("cursor show --json: %+v", got)
	}
	byName := map[string]cursorJSON{}
	for _, l := range got {
		byName[l.Relay] = l
	}
	w, p := byName["work"], byName["personal"]
	if w.Cursor == nil || *w.Cursor != ids[1] || w.First == nil || *w.First != ids[0] || *w.Last != ids[1] || *w.Queued != 2 || w.Error != "" {
		t.Fatalf("work: %+v", w)
	}
	if p.Cursor == nil || *p.Cursor != 0 || p.First != nil || p.Queued != nil || p.Error == "" {
		t.Fatalf("personal, which cannot be asked: %+v", p)
	}
	plain := bob.run("cursor", "show")
	if !strings.Contains(plain, "work  cursor "+itoa(ids[1])+"  relay holds 2, numbered "+itoa(ids[0])+" to "+itoa(ids[1])) ||
		!strings.Contains(plain, "personal  cursor 0  relay -  (") {
		t.Fatalf("cursor show:\n%s", plain)
	}
	// Narrowed, with the flag before and after the subcommand's others.
	if out := bob.run("cursor", "show", "--relay", "work", "--json"); strings.Contains(out, "personal") || !strings.Contains(out, `"relay": "work"`) {
		t.Fatalf("cursor show --relay work --json:\n%s", out)
	}
	if out := bob.run("cursor", "show", "--json", "--relay", "work"); strings.Contains(out, "personal") {
		t.Fatalf("cursor show --json --relay work:\n%s", out)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// 'auu cursor reset': says what the next fetch will fetch, asks, and
// writes; no leaves the file as it was, yes writes zero, --to writes its
// number, and --yes needs no terminal. Without --yes and without a
// terminal it is refused, as adding a peer is; a relay that is not named is
// a usage error. It never fetches.
func TestCursorResetAsksAndWrites(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "one", "x")
	bob.run("inbox")
	alice.run("send", "--to", "bob", "--subject", "two", "y")
	ids := queuedOn(t, st, bob.exportFingerprint())
	before := cursorIs(t, bob)

	atTerminal(t)
	out, err := bob.answer("n", "cursor", "reset", "--relay", name)
	if err != nil || !strings.Contains(out, "the next fetch from "+name+" will fetch everything the relay holds, 2 messages") ||
		!strings.Contains(out, "nothing changed") {
		t.Fatalf("reset, answered no: %v\n%s", err, out)
	}
	if got := cursorIs(t, bob); got != before {
		t.Fatalf("the cursor after no is %d, want %d", got, before)
	}
	out, err = bob.answer("y", "cursor", "reset", "--relay", name)
	if err != nil || !strings.Contains(out, name+"'s cursor is 0; run 'auu inbox --relay "+name+"' to fetch") {
		t.Fatalf("reset, answered yes: %v\n%s", err, out)
	}
	if got := cursorIs(t, bob); got != 0 {
		t.Fatalf("the cursor after yes is %d, want 0", got)
	}
	// It did not fetch: the second message is still only on the relay.
	if spoolHas(t, bob, store.Inbox, "two") {
		t.Fatal("reset fetched")
	}
	out, err = bob.answer("y", "cursor", "reset", "--to", itoa(ids[0]), "--relay", name)
	if err != nil || !strings.Contains(out, "will fetch what it holds after message "+itoa(ids[0])) {
		t.Fatalf("reset --to the first: %v\n%s", err, out)
	}
	if got := cursorIs(t, bob); got != ids[0] {
		t.Fatalf("the cursor after --to is %d, want %d", got, ids[0])
	}
	// At the last id: the next fetch fetches what is after it, which is
	// nothing yet, and the cursor is not past anything.
	out, err = bob.answer("n", "cursor", "reset", "--relay", name, "--to", itoa(ids[1]))
	if err != nil || !strings.Contains(out, "will fetch what it holds after message "+itoa(ids[1])) {
		t.Fatalf("reset --to the last: %v\n%s", err, out)
	}
	out, err = bob.answer("y", "cursor", "reset", "--relay", name, "--to", "9223372036854775807")
	if err != nil || !strings.Contains(out, "so the next fetch will find the cursor past everything and set it right itself") {
		t.Fatalf("reset --to the maximum: %v\n%s", err, out)
	}
	if got := cursorIs(t, bob); got != 9223372036854775807 {
		t.Fatalf("the cursor after --to the maximum is %d", got)
	}
	// And the fetch then sets it right: the second message arrives once.
	if in := bob.inboxJSON(); in.Fetch.Delivered != 1 {
		t.Fatalf("the fetch after: %+v", in.Fetch)
	}

	_, err = bob.tryRun("cursor", "reset")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "cursor reset --relay NAME") {
		t.Fatalf("reset without --relay: %v", err)
	}
	if _, err := bob.tryRun("cursor", "frob"); !errors.As(err, &e) || e.code != exitUsage {
		t.Fatalf("an unknown subcommand: %v", err)
	}
}

// Without a terminal: --yes writes, and without it the reset is refused in
// the words every person's decision is, leaving the cursor as it was.
func TestCursorResetWithoutATerminal(t *testing.T) {
	relayURL := startRelay(t)
	_, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	bob.setCursor(name, "5\n")
	_, err := bob.tryRun("cursor", "reset", "--relay", name)
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage ||
		err.Error() != "setting a cursor is a person's decision: run this at a terminal, or pass --yes from your own script" {
		t.Fatalf("reset without a terminal: %v", err)
	}
	if data, _ := os.ReadFile(bob.cursorPath(name)); string(data) != "5\n" {
		t.Fatalf("the cursor after the refusal: %q", data)
	}
	bob.run("cursor", "reset", "--relay", name, "--yes", "--to", "2")
	if got := cursorIs(t, bob); got != 2 {
		t.Fatalf("the cursor after --yes is %d, want 2", got)
	}
}

// TestLimitCursorResetTo: --to is a relay message id, zero or more, in
// decimal: a negative, the type's minimum, the text one past its maximum,
// a word, a space either side, hex, binary, an underscore, an exponent
// and nothing are usage errors that write nothing; zero, one, the type's
// maximum, a leading plus and a leading zero are read in decimal, so 010
// is ten and not eight.
func TestLimitCursorResetTo(t *testing.T) {
	relayURL := startRelay(t)
	_, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	bob.setCursor(name, "5\n")
	for _, to := range []string{"-1", "-9223372036854775808", "9223372036854775808", "seven",
		" 1", "1 ", "0x10", "0b11", "1_000", "1e3", ""} {
		_, err := bob.tryRun("cursor", "reset", "--relay", name, "--to", to, "--yes")
		var e *exitError
		if !errors.As(err, &e) || e.code != exitUsage {
			t.Errorf("--to %s: %v, want a usage error", to, err)
		}
		if data, _ := os.ReadFile(bob.cursorPath(name)); string(data) != "5\n" {
			t.Fatalf("--to %s wrote %q", to, data)
		}
	}
	for _, tc := range []struct {
		text string
		want int64
	}{{"0", 0}, {"1", 1}, {"+1", 1}, {"010", 10}, {"9223372036854775807", 9223372036854775807}} {
		bob.run("cursor", "reset", "--relay", name, "--to", tc.text, "--yes")
		if got := cursorIs(t, bob); got != tc.want {
			t.Errorf("--to %s wrote %d, want %d", tc.text, got, tc.want)
		}
	}
}

// A relay this home has added but never joined has no cursor, and reset
// does not make one: the file is also the record of having joined, and a
// plain fetch would try that relay from then on.
func TestCursorResetRefusesARelayNotJoined(t *testing.T) {
	work := startRelay(t)
	other := startRelay(t)
	bob := newUser(t, "bob", work)
	bob.run("relay", "add", other, "--name", "other")
	_, err := bob.tryRun("cursor", "reset", "--relay", "other", "--yes")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage ||
		err.Error() != "this home has not joined other, so it has no cursor there; join it with 'auu register --relay other'" {
		t.Fatalf("reset on a relay not joined: %v", err)
	}
	if _, err := os.Stat(bob.cursorPath("other")); !os.IsNotExist(err) {
		t.Fatalf("a cursor was written for a relay not joined: %v", err)
	}
}
