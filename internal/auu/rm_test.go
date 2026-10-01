package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// auu rm: a message removed from the relay and from here, or from either.

// rmJSON runs rm --json and returns what it said.
func rmJSON(t *testing.T, u *user, args ...string) []rmResult {
	t.Helper()
	var out []rmResult
	if err := json.Unmarshal([]byte(u.run(append([]string{"rm", "--json"}, args...)...)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// spoolHas reports whether a user's inbox holds a message with the subject.
func spoolHas(t *testing.T, u *user, box store.Box, subject string) bool {
	t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(box)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Inner.Body.Subject == subject {
			return true
		}
	}
	return false
}

// Both: the relay's copy and this machine's, in that order, with the line
// naming the relay.
func TestRmRemovesFromTheRelayAndHere(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "first", "one")
	alice.run("send", "--to", "bob", "--subject", "second", "two")
	bob.run("inbox")
	first := recordOf(t, bob, store.Inbox, "first")

	out := bob.run("rm", first.Inner.ID[:12])
	if want := first.Inner.ID[:12] + ": removed from " + name + " and here\n"; out != want {
		t.Fatalf("rm said:\n%s\nwant\n%s", out, want)
	}
	if spoolHas(t, bob, store.Inbox, "first") {
		t.Fatal("the local copy is still there")
	}
	left := queuedOn(t, st, bob.exportFingerprint())
	if len(left) != 1 || left[0] == first.RelayID {
		t.Fatalf("the relay holds %v, want the other message alone", left)
	}
	// The one left is still marked, and the count line counts it alone.
	if listing := bob.run("inbox", "--no-fetch"); strings.Count(listing, "  on relay") != 1 {
		t.Fatalf("the listing after the removal:\n%s", listing)
	}
	// The JSON shape.
	second := recordOf(t, bob, store.Inbox, "second")
	got := rmJSON(t, bob, second.Inner.ID[:12])
	if len(got) != 1 || got[0].ID != second.Inner.ID || got[0].Relay != name ||
		!got[0].RemovedRelay || !got[0].RemovedLocal {
		t.Fatalf("rm --json: %+v", got)
	}
	if len(queuedOn(t, st, bob.exportFingerprint())) != 0 {
		t.Fatal("the relay still holds something")
	}
	// Nothing but JSON on standard output, even for an id that has
	// nothing on the relay to remove: a third message, kept here with
	// --remote-only run twice.
	alice.run("send", "--to", "bob", "--subject", "third", "three")
	bob.run("inbox")
	third := recordOf(t, bob, store.Inbox, "third")
	bob.run("rm", "--remote-only", third.Inner.ID[:12])
	if got := rmJSON(t, bob, "--remote-only", third.Inner.ID[:12]); len(got) != 1 ||
		got[0].RemovedRelay || got[0].RemovedLocal {
		t.Fatalf("rm --json --remote-only on a record not on the relay: %+v", got)
	}
	if len(queuedOn(t, st, bob.exportFingerprint())) != 0 {
		t.Fatal("the relay still holds something")
	}
}

// --remote-only keeps the record and unmarks it; a record that is not on
// the relay says so and is left alone.
func TestRmRemoteOnlyKeepsTheRecord(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "kept")

	out := bob.run("rm", "--remote-only", m.Inner.ID[:12])
	if want := m.Inner.ID[:12] + ": removed from " + name + "\n"; out != want {
		t.Fatalf("rm --remote-only said:\n%s\nwant\n%s", out, want)
	}
	if !spoolHas(t, bob, store.Inbox, "kept") {
		t.Fatal("--remote-only removed the local copy")
	}
	if again := recordOf(t, bob, store.Inbox, "kept"); again.OnRelay || again.PayloadOnRelay {
		t.Fatalf("the record still claims to be on the relay: %+v", again)
	}
	if len(queuedOn(t, st, bob.exportFingerprint())) != 0 {
		t.Fatal("the relay still holds it")
	}
	if listing := bob.run("inbox", "--no-fetch"); strings.Contains(listing, "on relay") {
		t.Fatalf("the listing still marks it:\n%s", listing)
	}
	// Again, with nothing on the relay to remove: said, and exit 0.
	out = bob.run("rm", "--remote-only", m.Inner.ID[:12])
	if want := m.Inner.ID[:12] + ": not on the relay\n"; out != want {
		t.Fatalf("a second --remote-only said:\n%s\nwant\n%s", out, want)
	}
	if !spoolHas(t, bob, store.Inbox, "kept") {
		t.Fatal("the record went on the second run")
	}
}

// --local-only removes the record and leaves the relay's copy, and the
// machine does not fetch it again — nor does it call this home damaged for
// mail it left there on purpose.
func TestRmLocalOnlyLeavesTheRelaysCopy(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "kept")

	out := bob.run("rm", "--local-only", m.Inner.ID[:12])
	want := m.Inner.ID[:12] + ": removed here; still on " + name + ", and this machine will not fetch it again\n"
	if out != want {
		t.Fatalf("rm --local-only said:\n%s\nwant\n%s", out, want)
	}
	if spoolHas(t, bob, store.Inbox, "kept") {
		t.Fatal("the local copy is still there")
	}
	if len(queuedOn(t, st, bob.exportFingerprint())) != 1 {
		t.Fatal("the relay's copy went too")
	}
	// The left-behind file remembers it, so the next fetch is quiet and
	// fetches nothing.
	s, _, _ := bob.opened()
	// By the relay's id, and by the message's own with the relay's time
	// and size, which name it whatever the relay calls it later.
	if ids, err := s.LeftBehind(name); err != nil || len(ids) != 1 ||
		ids[0] != (store.LeftEntry{RelayID: m.RelayID, ID: m.Inner.ID, Received: m.Received, Size: m.RelaySize, From: m.Inner.From}) || m.RelaySize <= 0 {
		t.Fatalf("left behind: %v (%v), want %d %s %s %d", ids, err, m.RelayID, m.Inner.ID, m.Received, m.RelaySize)
	}
	in := bob.inboxJSON()
	if in.Fetch.Delivered != 0 || len(in.Messages) != 0 {
		t.Fatalf("the fetch after --local-only: %+v", in)
	}
	if out := bob.run("inbox"); strings.Contains(out, "before this machine's cursor") {
		t.Fatalf("the fetch called the home damaged:\n%s", out)
	}
	// The order: the id is remembered before the record goes, so a write
	// that fails leaves the record rather than a message nothing knows
	// about. With the relay's directory unwritable, --local-only fails
	// and the second message is still here.
	alice.run("send", "--to", "bob", "--subject", "second", "two")
	bob.run("inbox")
	second := recordOf(t, bob, store.Inbox, "second")
	relayDir := filepath.Dir(bob.cursorPath(name))
	if err := os.Chmod(relayDir, 0o500); err != nil {
		t.Fatal(err)
	}
	_, err := bob.tryRun("rm", "--local-only", second.Inner.ID[:12])
	if err := os.Chmod(relayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err == nil {
		t.Fatal("a --local-only that could not remember the relay's copy said nothing")
	}
	if !spoolHas(t, bob, store.Inbox, "second") {
		t.Fatal("the record went though the id could not be remembered")
	}
	bob.run("rm", "--remote-only", second.Inner.ID[:12])

	// And when it does go from the relay, the file is pruned.
	if gone, err := st.Delete(bob.exportFingerprint(), m.RelayID); err != nil || !gone {
		t.Fatalf("delete on the relay: %v %v", gone, err)
	}
	bob.run("inbox")
	if ids, err := s.LeftBehind(name); err != nil || len(ids) != 0 {
		t.Fatalf("left behind after the message went: %v (%v)", ids, err)
	}
}

// A sent message was never in this identity's mailbox: rm removes it here,
// and --remote-only on one is a usage error that says why.
func TestRmOfASentMessage(t *testing.T) {
	relayURL := startRelay(t)
	alice, _ := watchers(t, relayURL)
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "mine", "--json", "hello")), &sent); err != nil {
		t.Fatal(err)
	}
	usageError(t, alice, sent.ID[:12]+": a sent message is not in your mailbox on any relay",
		"rm", "--remote-only", sent.ID[:12])
	if !spoolHas(t, alice, store.Sent, "mine") {
		t.Fatal("the refused --remote-only removed it")
	}
	out := alice.run("rm", sent.ID[:12])
	if want := sent.ID[:12] + ": removed here\n"; out != want {
		t.Fatalf("rm of a sent message said:\n%s\nwant\n%s", out, want)
	}
	if spoolHas(t, alice, store.Sent, "mine") {
		t.Fatal("the sent copy is still there")
	}
}

// A message the relay no longer has is the state that was asked for: rm
// says it removed it, from both, and does not fail.
func TestRmOfAMessageAlreadyGoneFromTheRelay(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "kept")
	if gone, err := st.Delete(bob.exportFingerprint(), m.RelayID); err != nil || !gone {
		t.Fatalf("delete on the relay: %v %v", gone, err)
	}
	got := rmJSON(t, bob, m.Inner.ID[:12])
	if len(got) != 1 || !got[0].RemovedRelay || !got[0].RemovedLocal {
		t.Fatalf("rm of a message already gone: %+v", got)
	}
	if spoolHas(t, bob, store.Inbox, "kept") {
		t.Fatal("the local copy is still there")
	}
}

// A relay that cannot be reached ends the run at exit 2, naming it: the
// ids before it are done, and this one's local copy is untouched, so the
// command can be run again.
func TestRmStopsAtAnUnreachableRelay(t *testing.T) {
	workURL := startRelay(t)
	personal, _ := startRelayServer(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", workURL, personal.URL)
	bob := onBothRelays(t, "bob", workURL, personal.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("send", "--to", "bob", "--relay", "work", "--subject", "first", "one")
	alice.run("send", "--to", "bob", "--relay", "personal", "--subject", "second", "two")
	bob.run("inbox")
	first := recordOf(t, bob, store.Inbox, "first")
	second := recordOf(t, bob, store.Inbox, "second")

	// The first removal goes to work, which is up; the second is on
	// personal, which has gone.
	personal.Close()
	out, err := bob.tryRun("rm", first.Inner.ID[:12], second.Inner.ID[:12])
	var exit *exitError
	if !asExit(err, &exit) || exit.code != exitTransport || !strings.Contains(err.Error(), "personal: ") {
		t.Fatalf("rm against a relay that has gone: %v", err)
	}
	if !strings.Contains(out, first.Inner.ID[:12]+": removed from work and here\n") {
		t.Fatalf("what was done before the failure was not said:\n%s", out)
	}
	if spoolHas(t, bob, store.Inbox, "first") {
		t.Fatal("the first message's local copy survived")
	}
	if !spoolHas(t, bob, store.Inbox, "second") {
		t.Fatal("the second message's local copy went, though the relay refused")
	}
	if m := recordOf(t, bob, store.Inbox, "second"); !m.OnRelay {
		t.Fatalf("the second record was unmarked by a removal that did not happen: %+v", m)
	}
}

// The arguments: no id, both flags, an id nobody has, and a prefix that
// matches two.
func TestRmChecksItsArguments(t *testing.T) {
	relayURL := startRelay(t)
	alice, bob := watchers(t, relayURL)
	usageError(t, bob, "usage: auu rm MESSAGE-ID... [--local-only | --remote-only]", "rm")
	usageError(t, bob, "--local-only and --remote-only ask for opposite things; give one or neither",
		"rm", "--local-only", "--remote-only", "abcdef")
	usageError(t, bob, `no message matches "deadbeef"`, "rm", "deadbeef")
	usageError(t, bob, "message id prefix must be at least 4 characters", "rm", "ab")
	_ = alice
}

// A locked home: removing the local copy alone needs no key, and anything
// that would speak to a relay stops at exit 4 before any request.
func TestRmWithALockedAgent(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := encryptedUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("send", "--to", bob.exportFingerprint(), "--subject", "kept", "one")
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "kept")
	bob.run("lock")
	gate.requests.Store(0)

	_, err := bob.tryRun("rm", m.Inner.ID[:12])
	var exit *exitError
	if !asExit(err, &exit) || exit.code != exitLocked {
		t.Fatalf("rm with a locked agent: %v, want exit %d", err, exitLocked)
	}
	if gate.requests.Load() != 0 {
		t.Fatalf("%d requests were made by a locked rm", gate.requests.Load())
	}
	if !spoolHas(t, bob, store.Inbox, "kept") {
		t.Fatal("the refused rm removed the local copy")
	}
	// --local-only needs no key.
	out := bob.run("rm", "--local-only", m.Inner.ID[:12])
	if !strings.Contains(out, "removed here; still on ") {
		t.Fatalf("rm --local-only with a locked agent:\n%s", out)
	}
	if spoolHas(t, bob, store.Inbox, "kept") {
		t.Fatal("the local copy is still there")
	}
	if gate.requests.Load() != 0 {
		t.Fatalf("%d requests were made by a locked rm --local-only", gate.requests.Load())
	}
}

// A quarantined stream: its body was never fetched, and rm takes the whole
// thing off the relay, the manifest record and the empty attachment
// directory with it.
func TestRmOfAQuarantinedStream(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	_, bob := watchers(t, relayURL)
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	bob.run("allow", "clear")
	stranger := newUser(t, "stranger", relayURL)
	stranger.run("peers", "add", bob.exportLine())
	stranger.run("send", "--to", bob.exportFingerprint(), "--subject", "unasked", "--attach", big, "hello")
	bob.run("inbox")
	q := recordOf(t, bob, store.Quarantine, "unasked")

	out := bob.run("rm", q.Inner.ID[:12])
	if !strings.Contains(out, ": removed from "+bob.defaultRelayName()+" and here") {
		t.Fatalf("rm of a quarantined stream:\n%s", out)
	}
	if spoolHas(t, bob, store.Quarantine, "unasked") {
		t.Fatal("the quarantined record is still there")
	}
	if len(queuedOn(t, st, bob.exportFingerprint())) != 0 {
		t.Fatal("the relay still holds the stream")
	}
	s, _, _ := bob.opened()
	if _, err := os.Stat(s.AttachmentDir(store.Quarantine, q.Inner.ID)); !os.IsNotExist(err) {
		t.Fatalf("the attachment directory is still there: %v", err)
	}
}

// TestRmRemovesARecordLoadRefusesByItsID: a record Load refuses — here one
// kept on the relay whose digest was changed on disk — is not listed and
// not found by a prefix, but its whole id removes it without the record
// being read: the file and its attachment directory go, the relay's copy
// is remembered as left behind from the relay name and number the raw
// record carried, the next fetch is quiet, and the sentence says the
// record could not be read. A prefix is not enough, --remote-only is
// refused, and a record with no relay fields says the relay was not
// told. The edge is older than the safe-name commit that closed it: rm
// loaded first, so a record this program could not read was one it could
// not let go of either.
func TestRmRemovesARecordLoadRefusesByItsID(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "kept")
	s, _, _ := bob.opened()
	path := filepath.Join(bob.home, "inbox", m.Inner.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A thread that is not a message id: what Load refuses, written by
	// hand into the indented record.
	broken := strings.Replace(string(data), `"thread": "`, `"thread": "zz`, 1)
	if broken == string(data) {
		t.Fatalf("the record has no thread to break:\n%s", data)
	}
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.AttachmentDir(store.Inbox, m.Inner.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(store.Inbox, m.Inner.ID); err == nil {
		t.Fatal("the broken record still loads")
	}
	// A prefix cannot name it, and --remote-only has nothing to do.
	if _, err := bob.tryRun("rm", m.Inner.ID[:12]); err == nil || !strings.Contains(err.Error(), "no message matches") {
		t.Errorf("rm by prefix: %v; want no match", err)
	}
	if _, err := bob.tryRun("rm", "--remote-only", m.Inner.ID); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("rm --remote-only: %v; want the refusal", err)
	}
	out := bob.run("rm", m.Inner.ID)
	want := m.Inner.ID[:12] + ": removed here (the record could not be read); its copy on " + name + ", if there is one, is left there\n"
	if out != want {
		t.Fatalf("rm said:\n%s\nwant\n%s", out, want)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the record is still there: %v", err)
	}
	if _, err := os.Stat(s.AttachmentDir(store.Inbox, m.Inner.ID)); !os.IsNotExist(err) {
		t.Errorf("the attachment directory is still there: %v", err)
	}
	// The record could not be read, so the entry has the relay's id and
	// the message's own, and zero for what only the record knew.
	if ids, err := s.LeftBehind(name); err != nil || len(ids) != 1 ||
		ids[0].RelayID != m.RelayID || ids[0].ID != m.Inner.ID || !ids[0].Received.IsZero() || ids[0].Size != 0 || ids[0].From != m.Inner.From {
		t.Fatalf("left behind: %v (%v), want %d %s", ids, err, m.RelayID, m.Inner.ID)
	}
	if len(queuedOn(t, st, bob.exportFingerprint())) != 1 {
		t.Fatal("the relay's copy went")
	}
	if out := bob.run("inbox"); strings.Contains(out, "before this machine's cursor") {
		t.Fatalf("the fetch called the home damaged:\n%s", out)
	}
	// A record with no relay fields that pass: the local copy goes and
	// the sentence says the relay was not told.
	other := strings.Repeat("c", 32)
	if err := os.WriteFile(filepath.Join(bob.home, "inbox", other+".json"), []byte(`{"relay":"","relay_id":-1,"inner":{"id":"`+other+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out = bob.run("rm", other)
	want = other[:12] + ": removed here (the record could not be read); the relay's copy, if there is one, was not told\n"
	if out != want {
		t.Fatalf("rm of a record with no relay fields said:\n%s\nwant\n%s", out, want)
	}
	// And an id no box holds is the ordinary refusal.
	if _, err := bob.tryRun("rm", strings.Repeat("d", 32)); err == nil || !strings.Contains(err.Error(), "no message matches") {
		t.Errorf("rm of an unknown id: %v", err)
	}
}
