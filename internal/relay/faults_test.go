package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A storage fault is answered as a 500 that says nothing, so the relay says
// why in its log: one WARN line with the path and the error, once a minute
// per path. The container suite's R17 and R24 found nineteen storage faults
// answered with no line at all.
func TestStorageFaultsAreLoggedOnce(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	tmp := filepath.Join(h.messagesDir(), "tmp")
	if err := os.RemoveAll(tmp); err != nil {
		t.Fatal(err)
	}

	post := func() {
		t.Helper()
		status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "nowhere to write"), nil)
		if status != http.StatusInternalServerError {
			t.Fatalf("post with no tmp directory: %d %s", status, body)
		}
		if got := errorText(t, body); got != "storage error" {
			t.Fatalf("500 body %q, want the storage sentence the client keys on", got)
		}
	}
	lines := func() int {
		return strings.Count(h.logs.String(), `msg="storage fault"`)
	}

	post()
	post()
	if n := lines(); n != 1 {
		t.Fatalf("two faults on one path inside a minute logged %d lines, want 1:\n%s", n, h.logs.String())
	}
	want := fmt.Sprintf(`level=WARN msg="storage fault" path=%s err="open %s/`, tmp, tmp)
	if !strings.Contains(h.logs.String(), want) {
		t.Fatalf("the fault line does not carry the path and the error as %q:\n%s", want, h.logs.String())
	}

	// One step short of a minute is still the same minute; the minute is a
	// new line.
	h.clock.advance(time.Minute - time.Nanosecond)
	post()
	if n := lines(); n != 1 {
		t.Fatalf("a fault a nanosecond short of a minute later logged again (%d lines)", n)
	}
	h.clock.advance(time.Nanosecond)
	post()
	if n := lines(); n != 2 {
		t.Fatalf("a fault a minute later logged %d lines, want 2", n)
	}

	// Another path is another line at once: a read of a message whose file
	// has gone, which is what a deleted message directory looks like. The
	// list skips the row, as it always has, and the sweep at the next start
	// drops it; the line is what tells the operator the mail was lost.
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "stored, then lost"), nil)
	if status != http.StatusOK {
		t.Fatalf("post with the directory back: %d %s", status, body)
	}
	if err := os.RemoveAll(filepath.Join(h.messagesDir(), bob.Fingerprint()[:2])); err != nil {
		t.Fatal(err)
	}
	status, body, _ = h.send(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"messages":[]`) {
		t.Fatalf("list with the message file gone: %d %s", status, body)
	}
	if n := lines(); n != 3 {
		t.Fatalf("a fault on a second path logged %d lines in all, want 3", n)
	}
	if !strings.Contains(h.logs.String(), "path="+filepath.Join(h.messagesDir(), bob.Fingerprint()[:2], bob.Fingerprint())) {
		t.Fatalf("the read fault does not name the message's path:\n%s", h.logs.String())
	}
}

// The map of recently logged paths is bounded twice over: entries older than
// a minute go on every line written, and past 1,024 the oldest goes.
func TestFaultLogIsBounded(t *testing.T) {
	clock := newTestClock()
	logs := &syncBuffer{}
	f := newFaultLog(slog.New(slog.NewTextHandler(logs, nil)), clock.Now)

	// A nanosecond apart, so that "oldest" is a fact and not a tie.
	for i := 0; i < faultEntries+100; i++ {
		f.note(fmt.Sprintf("/var/lib/auu/messages/%04d", i), errors.New("no"))
		clock.advance(time.Nanosecond)
	}
	if got := f.size(); got != faultEntries {
		t.Fatalf("%d paths remembered after %d distinct faults, want the cap %d", got, faultEntries+100, faultEntries)
	}
	// The oldest went, so its next fault is logged again; the newest did
	// not, so its next fault is not.
	before := strings.Count(logs.String(), `msg="storage fault"`)
	f.note("/var/lib/auu/messages/0000", errors.New("no"))
	f.note(fmt.Sprintf("/var/lib/auu/messages/%04d", faultEntries+99), errors.New("no"))
	if got := strings.Count(logs.String(), `msg="storage fault"`) - before; got != 1 {
		t.Fatalf("after the cap, the evicted path and the kept path together logged %d lines, want 1", got)
	}

	// A minute on, everything is stale, and one fault empties the map to
	// itself.
	clock.advance(time.Minute)
	f.note("/var/lib/auu/messages/fresh", errors.New("no"))
	if got := f.size(); got != 1 {
		t.Fatalf("%d paths remembered a minute later, want the one just logged", got)
	}
}
