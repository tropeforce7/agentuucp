package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cursorPath is where this user's cursor for a relay lives, and setCursor
// writes it the way a person with an editor, or a copied home, would.
func (u *user) cursorPath(relayName string) string {
	u.t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		u.t.Fatal(err)
	}
	r, err := s.Relay(relayName)
	if err != nil {
		u.t.Fatal(err)
	}
	return filepath.Join(s.RelayDir(r), "cursor")
}

// leftOn is what this user's store counts as left on a relay on purpose.
func leftOn(u *user, relayName string) (int64, error) {
	s, err := store.Open(u.home)
	if err != nil {
		return 0, err
	}
	return s.LeftOn(relayName)
}

// relayLast is the relay's highest id for a mailbox, as a cursor file holds it.
func relayLast(t *testing.T, st *relay.Store, fp string) string {
	t.Helper()
	l, err := st.Listing(fp, 0, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(l.Last, 10) + "\n"
}

func (u *user) setCursor(relayName, text string) {
	u.t.Helper()
	if err := os.WriteFile(u.cursorPath(relayName), []byte(text), 0o600); err != nil {
		u.t.Fatal(err)
	}
}

// A cursor past mail the relay still holds is said to be, with the relay's
// count, the file and the command that starts again; nothing is acknowledged
// and the cursor is not written, since only a person can decide the cursor
// is wrong. The cursor here is at the relay's last id, inside its span, so
// the mail it skipped is in the middle and no reset from the front could
// fetch it without delivering again what was fetched; a cursor above the
// span is reset.go's, and TestACursorPastEverythingTheRelayHolds's. A listing whose count is absent decodes as zero, an empty
// mailbox, and is silence: absent and zero are one number. The container
// suite's K17 found the mail sitting on the relay with nothing to say so.
func TestASkippedMailboxIsSaidToBe(t *testing.T) {
	relayURL, gate, st := startGatedRelayStore(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	name := bob.defaultRelayName()
	bobFP := bob.exportFingerprint()
	cursor := bob.cursorPath(name)
	// This test is about the cursor, and every count below is of what the
	// relay holds, so bob's mail is acknowledged away as it was before
	// channels could be set to keep. What a cursor makes of kept mail is
	// TestAFetchLeavesKeptMailWhereTheCursorIsPastIt's.
	bob.run("channel", "keep", "default", "off")

	alice.run("send", "--to", "bob", "--subject", "first", "one")
	alice.run("send", "--to", "bob", "--subject", "second", "two")
	queued, err := st.List(bobFP, 0, 10)
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued %d (%v), want 2", len(queued), err)
	}

	// Refused, by the count and the file, at exit 5.
	written := strconv.FormatInt(queued[1].ID, 10) + "\n"
	bob.setCursor(name, written)
	spool := func() map[string]int {
		t.Helper()
		out := map[string]int{}
		for _, box := range []string{"inbox", "quarantine"} {
			entries, _ := os.ReadDir(filepath.Join(bob.home, box))
			out[box] = len(entries)
		}
		return out
	}
	refused := func(want string) {
		t.Helper()
		before := spool()
		var stderr string
		var err error
		stderr = captureStderr(t, func() { _, err = bob.tryRun("inbox") })
		var e *exitError
		if !errors.As(err, &e) || e.code != exitDamaged {
			t.Fatalf("inbox with the cursor ahead: %v, want exit %d", err, exitDamaged)
		}
		if err.Error() != want {
			t.Fatalf("inbox with the cursor ahead said\n%q\nwant\n%q", err.Error(), want)
		}
		if stderr != "" {
			t.Fatalf("inbox with the cursor ahead wrote to stderr before failing:\n%s", stderr)
		}
		// Nothing touched: the relay holds what it held, the cursor is the
		// bytes that were written, and the spool is as it was.
		if data, err := os.ReadFile(cursor); err != nil || string(data) != written {
			t.Fatalf("the cursor is %q (%v) after the refusal, want the %q that was written", data, err, written)
		}
		if after := spool(); after["inbox"] != before["inbox"] || after["quarantine"] != before["quarantine"] {
			t.Fatalf("the spool went from %v to %v across the refusal", before, after)
		}
	}
	refused("2 messages are waiting on " + name + " before this machine's cursor; run 'auu cursor reset --relay " + name +
		"' to fetch from the beginning")
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 2 {
		t.Fatalf("the relay holds %d (%v) after the refusal, want 2 untouched", len(left), err)
	}

	// One fewer, and the sentence counts one.
	if gone, err := st.Delete(bobFP, queued[0].ID); err != nil || !gone {
		t.Fatalf("delete on the relay: %v %v", gone, err)
	}
	refused("1 message is waiting on " + name + " before this machine's cursor; run 'auu cursor reset --relay " + name +
		"' to fetch from the beginning")

	// The advice, followed: the remaining message arrives, the cursor is
	// written again, and the relay is empty.
	bob.run("cursor", "reset", "--relay", name, "--yes")
	if in := bob.inboxJSON("--relay", name); in.Fetch.Delivered != 1 || len(in.Messages) != 1 {
		t.Fatalf("after following the advice: %+v", in.Fetch)
	}
	if _, err := os.Stat(cursor); err != nil {
		t.Fatalf("the cursor was not written by the fetch: %v", err)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 0 {
		t.Fatalf("the relay holds %d (%v) after the fetch, want 0", len(left), err)
	}

	// A stranger's stream is quarantined from its manifest and its payload
	// left on the relay on purpose, behind the cursor: the relay counts
	// it, this machine knows it did that, and a fetch is silence. Mail
	// skipped beyond it counts one, not two.
	bob.run("allow", "clear")
	stranger := newUser(t, "stranger", relayURL)
	stranger.run("peers", "add", bob.exportLine())
	payload := make([]byte, 300<<10)
	file := filepath.Join(t.TempDir(), "unasked.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	stranger.run("send", "--to", bobFP, "--subject", "unasked", "--attach", file, "hello")
	if in := bob.inboxJSON(); in.Fetch.Quarantined != 1 {
		t.Fatalf("the stranger's stream: %+v", in.Fetch)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 1 {
		t.Fatalf("the relay holds %d (%v) after the quarantine, want the stream left there", len(left), err)
	}
	if in := bob.inboxJSON(); in.Fetch.Delivered != 0 || in.Fetch.Quarantined != 0 {
		t.Fatalf("a fetch with the stream left on the relay: %+v", in.Fetch)
	}
	// A stranger's envelope is quarantined whole and acknowledged: it is
	// in the quarantine and not on the relay, and must not be subtracted.
	stranger.run("send", "--to", bobFP, "--subject", "small", "and unasked")
	if in := bob.inboxJSON(); in.Fetch.Quarantined != 1 {
		t.Fatalf("the stranger's envelope: %+v", in.Fetch)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 1 {
		t.Fatalf("the relay holds %d (%v) after the envelope, want the stream alone", len(left), err)
	}
	alice.run("send", "--to", "bob", "--subject", "skipped", "past")
	written = relayLast(t, st, bobFP)
	bob.setCursor(name, written)
	refused("1 message is waiting on " + name + " before this machine's cursor; run 'auu cursor reset --relay " + name +
		"' to fetch from the beginning")
	bob.run("cursor", "reset", "--relay", name, "--yes")
	// Fetched from the beginning: the skipped message arrives, and the
	// stream is listed again and met at its manifest under the one record
	// it has, not quarantined again or counted (ruling 53, a behaviour
	// changed on purpose: a message the relay serves again is met). The
	// relay is back to holding the stream alone.
	if in := bob.inboxJSON("--relay", name); in.Fetch.Delivered != 1 || in.Fetch.Quarantined != 0 {
		t.Fatalf("after following the advice with a stream left on the relay: %+v", in.Fetch)
	}
	var q []messageJSON
	if err := json.Unmarshal([]byte(bob.run("quarantine", "ls", "--json")), &q); err != nil {
		t.Fatal(err)
	}
	if len(q) != 2 {
		t.Fatalf("quarantine holds %d, want the stream and the envelope", len(q))
	}
	// Trusting the stranger fetches and acknowledges the stream, and the
	// subtraction follows the quarantine's state: the next fetch, with the
	// relay empty and nothing left there on purpose, is silence.
	var streamID string
	for _, m := range q {
		if m.Subject == "unasked" {
			streamID = m.ID
		}
	}
	if _, err := bob.answer("stranger", "quarantine", "trust", streamID); err != nil {
		t.Fatalf("trust: %v", err)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 0 {
		t.Fatalf("the relay holds %d (%v) after the trust, want 0", len(left), err)
	}
	if in := bob.inboxJSON(); in.Fetch.Delivered != 0 || in.Fetch.Quarantined != 0 {
		t.Fatalf("a fetch after the trust: %+v", in.Fetch)
	}
	if n, err := leftOn(bob, name); err != nil || n != 0 {
		t.Fatalf("payloads left on %s after the trust: %d (%v), want 0", name, n, err)
	}

	// The count left out of the listing: the same mail behind the same
	// cursor, and nothing to say, since an absent count decodes as zero,
	// which is an empty mailbox; a count is the one required field whose
	// absence is not refused, being one number with a value the relay
	// sends.
	alice.run("send", "--to", "bob", "--subject", "third", "three")
	bob.setCursor(name, relayLast(t, st, bobFP))
	gate.set("old", -1)
	var stderr string
	var out string
	stderr = captureStderr(t, func() { out, err = bob.tryRun("inbox", "--json") })
	if err != nil {
		t.Fatalf("inbox against a listing without the count: %v", err)
	}
	var in inboxJSON
	if err := json.Unmarshal([]byte(out), &in); err != nil {
		t.Fatal(err)
	}
	if in.Fetch.Delivered != 0 || in.Fetch.Quarantined != 0 || stderr != "" {
		t.Fatalf("inbox against a listing without the count: fetched %+v, stderr %q", in.Fetch, stderr)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 1 {
		t.Fatalf("the relay holds %d (%v) after the silent fetch, want 1", len(left), err)
	}
	// And that the gate did take the field out, so the silence was the
	// old shape's and not a count of zero.
	if gate.lists.Load() == 0 {
		t.Fatal("the gate saw no list")
	}
}

// The advice is 'auu cursor reset', which writes the cursor rather than
// removing it: the cursor is also the record of a mailbox there, and in a
// home on two relays a plain 'auu inbox' would pass a relay whose cursor is
// gone by as one nobody has joined. With it written, the plain command
// drains it, in a home on two relays and in one on a single relay.
func TestTheCursorAdviceWorksInBothShapesOfHome(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)
	bob := onBothRelays(t, "bob", work, personalURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push", "--relay", "work")
	bob.run("allow", "push", "--relay", "work")
	alice.run("send", "--to", "bob", "--subject", "on work", "hello", "--relay", "work")

	// A stranger's stream left on personal, on purpose, is personal's and
	// is not subtracted from what work counts.
	stranger := onBothRelays(t, "stranger", work, personalURL)
	stranger.run("peers", "add", bob.exportLine())
	payload := make([]byte, 300<<10)
	file := filepath.Join(t.TempDir(), "unasked.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	stranger.run("send", "--to", bob.exportFingerprint(), "--subject", "unasked", "--attach", file, "hello", "--relay", "personal")
	if in := bob.inboxJSON("--relay", "personal"); in.Fetch.Quarantined != 1 {
		t.Fatalf("the stranger's stream on personal: %+v", in.Fetch)
	}
	if n, err := leftOn(bob, "personal"); err != nil || n != 1 {
		t.Fatalf("payloads left on personal: %d (%v), want 1", n, err)
	}

	// The cursor at work's one message, which bob never fetched, refused
	// by name at exit 5 — the command's failure, not one relay's trouble
	// among two — and then put right as advised. Work is a relay of its
	// own and alice's is the only message on it, so it is numbered 1.
	bob.setCursor("work", "1\n")
	var err error
	stderr := captureStderr(t, func() { _, err = bob.tryRun("inbox") })
	var e *exitError
	if !errors.As(err, &e) || e.code != exitDamaged || err.Error() !=
		"1 message is waiting on work before this machine's cursor; run 'auu cursor reset --relay work' to fetch from the beginning" {
		t.Fatalf("inbox with work's cursor ahead: %v, want exit %d and the sentence", err, exitDamaged)
	}
	if stderr != "" {
		t.Fatalf("inbox with work's cursor ahead reported it as a relay that could not be reached:\n%s", stderr)
	}
	// The advice writes the cursor, so the relay is still one this home
	// has joined, and the plain command drains it with the other.
	bob.run("cursor", "reset", "--relay", "work", "--yes")
	in := bob.inboxJSON()
	if in.Fetch.Delivered != 1 || len(in.Relays) != 2 {
		t.Fatalf("plain inbox after the advice drained %+v, %+v", in.Fetch, in.Relays)
	}

	// One relay: the same.
	relayURL := startRelay(t)
	carol := newUser(t, "carol", relayURL)
	dave := newUser(t, "dave", relayURL)
	carol.run("peers", "add", dave.exportLine())
	dave.run("peers", "add", carol.exportLine())
	carol.run("allow", "push")
	dave.run("allow", "push")
	carol.run("send", "--to", "dave", "--subject", "alone", "hello")
	name := dave.defaultRelayName()
	dave.setCursor(name, "1\n")
	if _, err := dave.tryRun("inbox"); err == nil {
		t.Fatal("inbox with the cursor ahead succeeded")
	}
	dave.run("cursor", "reset", "--relay", name, "--yes")
	if in := dave.inboxJSON(); in.Fetch.Delivered != 1 {
		t.Fatalf("plain inbox in a one-relay home after the advice: %+v", in.Fetch)
	}
}

// The fetch lock is a file in this home, and one that cannot be made is
// this home's trouble, said with the path at the plain exit code, not the
// relay's at the transport's; nothing has been fetched, so nothing is
// lost. The container suite's K29 found a read-only home reported as
// "permission denied" at exit 2.
func TestAFetchLockThatCannotBeMadeIsThisHomesTrouble(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere")
	}
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	alice.run("send", "--to", "bob", "--subject", "read-only", "can you store this")
	name := bob.defaultRelayName()
	dir := filepath.Dir(bob.cursorPath(name))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err := bob.tryRun("inbox")
	var e *exitError
	if errors.As(err, &e) {
		t.Fatalf("inbox with the relay directory read-only: exit %d, want the plain code", e.code)
	}
	want := "taking the fetch lock for " + name + ": open " + filepath.Join(dir, "fetch.lock") + ": permission denied"
	if err == nil || err.Error() != want {
		t.Fatalf("inbox with the relay directory read-only: %v, want %q", err, want)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if in := bob.inboxJSON(); in.Fetch.Delivered != 1 {
		t.Fatalf("after the directory was writable again: %+v", in.Fetch)
	}
}
