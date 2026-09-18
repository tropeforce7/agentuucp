package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The second adversarial trace, at v0.9.0: what a received message
// controls on an expert host.

// sealByHand is an envelope from one user to another with the inner record
// exactly as given, signed with the sender's real key and sealed to the
// recipient: what a client that is not auu's would send, since auu's own
// refuses a body that fails Validate before it seals. The wire constants
// are written here as literals, from outside the package that defines
// them, as damaged_test does.
func sealByHand(t *testing.T, from, to *user, inner *envelope.Inner) *envelope.Envelope {
	t.Helper()
	s, err := store.Open(from.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return sealInnerByHand(t, id, mustParseBundle(t, mustBundle(t, to)), inner)
}

// A thread id is a message id, and serve builds the thread's directory and
// the worktree's path from it. The trace sent `--thread "../../outside"`
// from an admitted peer: serve joined it onto its directory, wrote the
// message's text there, asked git for a worktree there, and when that
// failed ended the round with an error and nothing in the ledger, so the
// same message ended every later round the same way. Now the shape is a
// rule of the format: the message is refused as malformed when it is
// opened, kept under damaged and acknowledged, and serve never sees it.
func TestAThreadIDThatIsAPathNeverReachesServe(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	root := filepath.Join(bob.home, "serve")
	outside := filepath.Join(bob.home, "outside")

	env := sealByHand(t, alice, bob.user, &envelope.Inner{
		ID: "0123456789abcdef0123456789abcdef", Time: time.Now().UTC(),
		Body:    message.Body{Type: message.TypeAsk, Thread: "../../outside", Subject: "hello", Text: "please look"},
		Channel: "jostle",
	})
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(s, id, r)
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := c.Post(t.Context(), env, "jostle")
	if err != nil {
		t.Fatalf("post: %v", err)
	}

	var out string
	stderr := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once", "--json") })
	if err != nil {
		t.Fatalf("serve --once ended with an error on a message whose thread id is \"../../outside\": %v\n%s\n%s", err, out, stderr)
	}
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Fatalf("serve saw the message: %+v", report)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("a peer's thread id \"../../outside\" made serve write %s, outside %s", outside, root)
	}
	// Refused as malformed when it was opened: kept under damaged, with
	// the word for it, and acknowledged.
	bobStore, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if rec := damagedRecord(t, bobStore, bob.defaultRelayName(), relayID); rec.Cause != "malformed" {
		t.Errorf("kept as %q, want malformed", rec.Cause)
	}
	if msgs, err := bobStore.List(store.Inbox); err != nil {
		t.Fatal(err)
	} else if len(msgs) != 0 {
		t.Errorf("the message reached the inbox: %+v", msgs[0].Inner.Body)
	}
	// The next round is clean: the message is not met again, and the
	// expert answers what comes after it.
	if report := bob.round(t); len(report.Failed) != 0 || len(report.Answered) != 0 {
		t.Fatalf("the second round was not clean: %+v", report)
	}
	sent := alice.ask(t, "jostle", "after it", "still there?")
	if report := bob.round(t); len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the ask behind it was not answered: %+v", report)
	}
}

// auu's own send refuses a thread id of the wrong shape before anything is
// read or sealed, with a usage error naming the shape; so does --reply-to.
func TestSendRefusesAThreadIDThatIsNotAMessageID(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	for _, tc := range []struct{ flag, value string }{
		{"--thread", "../x"},
		{"--thread", "t1"},
		{"--thread", "0123456789ABCDEF0123456789abcdef"},
		{"--reply-to", "../x"},
	} {
		_, err := alice.tryRun("send", "--to", "bob", tc.flag, tc.value, "hello")
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage {
			t.Fatalf("%s %s: %v, want a usage error", tc.flag, tc.value, err)
		}
		if !strings.Contains(err.Error(), tc.flag+" "+`"`+tc.value+`"`) ||
			!strings.Contains(err.Error(), "not a message id (32 lowercase hex characters)") {
			t.Fatalf("%s %s: %q does not name the flag and the shape", tc.flag, tc.value, err)
		}
	}
	// And the shape is the whole rule: an id that is not a thread this
	// home knows is still a thread id.
	alice.run("send", "--to", "bob", "--thread", "fedcba9876543210fedcba9876543210", "hello")
}

// A record in the spool with a thread id of the wrong shape can only have
// been written by hand, since every message that arrives has been through
// Validate; serve still checks before the id is joined onto anything, and
// it is that message's failure, written in the ledger and stepped over,
// never the run's: the message behind it is answered in the same round.
func TestServeRecordsABadThreadIDAgainstTheMessageAndGoesOn(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	outside := filepath.Join(bob.home, "outside")
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	crafted := &store.Stored{
		Relay:    bob.defaultRelayName(),
		Received: time.Now().UTC().Add(-time.Minute),
		Inner: &envelope.Inner{
			From: alice.exportFingerprint(), To: bob.exportFingerprint(),
			ID: "0123456789abcdef0123456789abcdef", Time: time.Now().UTC().Add(-time.Minute),
			Body: message.Body{Type: message.TypeAsk, Thread: "../../outside", Subject: "by hand", Text: "written into the spool"},
		},
		SenderName: "alice",
		Channel:    "jostle",
	}
	if err := s.Save(store.Inbox, crafted); err != nil {
		t.Fatal(err)
	}
	sent := alice.ask(t, "jostle", "after it", "please look")

	out, err := bob.tryRun("serve", "--once", "--json")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage {
		t.Fatalf("a round with one failure ended %v, want the usage exit that says so\n%s", err, out)
	}
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 1 || report.Failed[0].ID != crafted.Inner.ID {
		t.Fatalf("failed: %+v, want the crafted message", report.Failed)
	}
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("answered: %+v, want the ask behind it", report.Answered)
	}
	if entry := bob.ledgerOf(t).Messages[crafted.Inner.ID]; entry == nil || entry.Failures != 1 {
		t.Fatalf("the ledger has %+v for the crafted message, want one failure", entry)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("the thread id was joined onto a path: %s exists", outside)
	}
	// serve ls neither joins the name onto a path nor prints it raw.
	ls := bob.run("serve", "ls")
	if strings.Contains(ls, "../../outside") || !strings.Contains(ls, `"../../outsid"  0 turns`) {
		t.Errorf("serve ls printed the thread id raw or not at all:\n%s", ls)
	}
	// And worktreeFor refuses it on its own, though handle never lets it
	// this far.
	if _, _, err := worktreeFor(filepath.Join(bob.home, "serve"), bob.row, "../../outside",
		t.TempDir(), true); err == nil || !strings.Contains(err.Error(), "not a message id") {
		t.Errorf("worktreeFor took a thread id that is a path: %v", err)
	}
}
