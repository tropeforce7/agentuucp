package relay

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// stubs=1 answers the rows without their envelopes, for a client checking
// which of the messages it kept are still queued: a mailbox of kept mail
// would otherwise be downloaded again on every check.

// The two listings agree about everything but the envelopes, on a mailbox
// whose files are all there: the same ids, kinds, sizes, channels and
// queued, and not one envelope in the stubs answer.
func TestAStubsListingIsThePlainOneWithoutTheEnvelopes(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	h.postTo(bob, alice, "")
	h.postTo(bob, alice, "")

	_, plain, _ := h.list(alice, "").answer(t)
	status, stubs, _ := h.list(alice, "stubs=1").answer(t)
	if status != http.StatusOK {
		t.Fatalf("a stubs listing: %d", status)
	}
	if stubs.Queued != plain.Queued || len(stubs.Messages) != len(plain.Messages) || len(stubs.Messages) != 2 {
		t.Fatalf("stubs %+v, plain %+v", stubs, plain)
	}
	for i, got := range stubs.Messages {
		want := plain.Messages[i]
		if got.ID != want.ID || got.Kind != want.Kind || got.Size != want.Size ||
			got.Channel != want.Channel || !got.Received.Equal(want.Received) {
			t.Fatalf("row %d: stubs %+v, plain %+v", i, got, want)
		}
		if len(got.Envelope) != 0 {
			t.Fatalf("row %d carries an envelope in a stubs listing: %s", i, got.Envelope)
		}
		if len(want.Envelope) == 0 {
			t.Fatalf("row %d carries no envelope in the plain listing, so this test proves nothing", i)
		}
	}
	// true is accepted as 1 is, and 0 and false are the plain listing.
	_, alsoStubs, _ := h.list(alice, "stubs=true").answer(t)
	if len(alsoStubs.Messages) != 2 || len(alsoStubs.Messages[0].Envelope) != 0 {
		t.Fatalf("stubs=true: %+v", alsoStubs)
	}
	for _, off := range []string{"stubs=0", "stubs=false", "stubs="} {
		_, resp, _ := h.list(alice, off).answer(t)
		if len(resp.Messages) != 2 || len(resp.Messages[0].Envelope) == 0 {
			t.Fatalf("%s answered without envelopes: %+v", off, resp)
		}
	}
	// Anything else is the caller's mistake, said rather than taken for
	// either.
	for _, bad := range []string{"stubs=yes", "stubs=2", "stubs=1,1"} {
		status, _, body := h.list(alice, bad).answer(t)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "bad stubs parameter") {
			t.Fatalf("%s: %d %s", bad, status, body)
		}
	}
}

// A stubs listing holds and wakes as the plain one does: the parameter is
// about what is answered, not about whether the answer waits.
func TestAStubsListingHoldsAndWakes(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	l := h.list(alice, longHold+"&stubs=1")
	h.holding(1)
	h.subscribed(mailKey(alice.Fingerprint()), 1)
	if l.answered() {
		t.Fatal("an empty mailbox was answered without the hold")
	}
	posted := time.Now()
	if status, body := h.postTo(bob, alice, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	status, resp, _ := l.answer(t)
	if status != http.StatusOK || len(resp.Messages) != 1 || resp.Messages[0].ID != 1 || resp.Queued != 1 {
		t.Fatalf("the answer to a woken stubs hold: %d %+v", status, resp)
	}
	if len(resp.Messages[0].Envelope) != 0 {
		t.Fatalf("the woken stubs listing carries an envelope: %s", resp.Messages[0].Envelope)
	}
	if since := time.Since(posted); since > patience {
		t.Fatalf("the hold answered %s after the post", since)
	}
	h.holding(0)
}

// A stubs listing opens no message file. With the mailbox's directory
// unreadable, the plain listing fails at 500 and the stubs listing answers
// from the database alone.
func TestAStubsListingOpensNoMessageFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable directory is readable")
	}
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	h.postTo(bob, alice, "")

	dir := h.store.mailboxDir(alice.Fingerprint())
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	status, _, body := h.list(alice, "").answer(t)
	if status != http.StatusInternalServerError {
		t.Fatalf("the plain listing with the directory unreadable: %d %s", status, body)
	}
	status, resp, body := h.list(alice, "stubs=1").answer(t)
	if status != http.StatusOK || len(resp.Messages) != 1 || resp.Messages[0].ID != 1 || resp.Queued != 1 {
		t.Fatalf("the stubs listing with the directory unreadable: %d %s", status, body)
	}
	if len(resp.Messages[0].Envelope) != 0 {
		t.Fatalf("it read the file after all: %s", resp.Messages[0].Envelope)
	}
}

// A row whose file has gone is listed by stubs and hidden by the plain
// listing, which also takes it out of queued. The database's answer is the
// right one for a client checking what it kept: the row is still queued,
// and the relay will say so until its next start reconciles the two.
func TestAStubsListingReportsARowWhoseFileHasGone(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	h.postTo(bob, alice, "")
	h.postTo(bob, alice, "")
	if err := os.Remove(h.store.messagePath(alice.Fingerprint(), 1)); err != nil {
		t.Fatal(err)
	}

	_, plain, _ := h.list(alice, "").answer(t)
	if len(plain.Messages) != 1 || plain.Messages[0].ID != 2 || plain.Queued != 1 {
		t.Fatalf("the plain listing hides the row and its count: %+v", plain)
	}
	_, stubs, _ := h.list(alice, "stubs=1").answer(t)
	if len(stubs.Messages) != 2 || stubs.Messages[0].ID != 1 || stubs.Messages[1].ID != 2 || stubs.Queued != 2 {
		t.Fatalf("the stubs listing answers what the database holds: %+v", stubs)
	}
}
