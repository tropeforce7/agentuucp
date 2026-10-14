package auu

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// An interrupted upload is finished on the relay it was opened on (G30,
// R45). A --relay naming another is refused before anything is opened
// there, with the sentence, and the record is left as it was, so the plain
// resume after it finishes on the relay the record names. Only when this
// home no longer has that relay may --relay move it, and the move writes
// the record's relay and an emptied upload together before the open: a
// move cut short leaves a record naming the new relay and the upload
// opened there.
func TestAResumeOnAnotherRelayIsRefusedBeforeAnyUpload(t *testing.T) {
	work, workGate := startInterruptibleRelay(t, 2, 64<<10)
	_, personalGate := startInterruptibleRelay(t, 2, 64<<10)
	var opensOnPersonal atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/streams") {
			opensOnPersonal.Add(1)
		}
		personalGate.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	alice := onBothRelays(t, "alice", work, front.URL)
	bob := onBothRelays(t, "bob", work, front.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	file := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(file, bytes.Repeat([]byte("outbox recovery"), 40000), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.tryRun("send", "--to", "bob", "--relay", "work", "--attach", file, "payload"); err == nil {
		t.Fatal("the first upload should have been cut off")
	}
	first := onlyPending(t, alice)
	if first.Relay != "work" || first.Upload == "" {
		t.Fatalf("the record after the cut: %+v", first)
	}

	// --relay personal: refused before any open there.
	var err error
	said := captureStderr(t, func() { _, err = alice.tryRun("send", "--resume", "--relay", "personal") })
	want := "it was opened on work; finish it there with --relay work, or abandon it and send the message afresh"
	if err == nil || !strings.Contains(said, first.MessageID[:12]+": "+want) {
		t.Fatalf("a resume on another relay: %v\n%s; want %q", err, said, want)
	}
	if n := opensOnPersonal.Load(); n != 0 {
		t.Fatalf("%d uploads were opened on personal", n)
	}
	if after := onlyPending(t, alice); after.Relay != first.Relay || after.Upload != first.Upload {
		t.Fatalf("the record changed: %+v, was %+v", after, first)
	}
	// --relay work, the one it was opened on, is the plain resume.
	workGate.open()
	alice.run("send", "--resume", "--relay", "work")
	if workGot, personalGot := bob.inboxJSON("--relay", "work").Fetch.Delivered, bob.inboxJSON("--relay", "personal").Fetch.Delivered; workGot != 1 || personalGot != 0 {
		t.Fatalf("delivered on work %d and personal %d; want it on work", workGot, personalGot)
	}

	// The relay it was opened on gone from this home: --relay moves it,
	// and a move cut short leaves the record naming personal and the
	// upload opened there, together.
	// The gate cuts again, as it first did.
	workGate.mu.Lock()
	workGate.allow = 2 * 64 << 10
	workGate.mu.Unlock()
	if _, err := alice.tryRun("send", "--to", "bob", "--relay", "work", "--attach", file, "again"); err == nil {
		t.Fatal("the second upload should have been cut off")
	}
	second := onlyPending(t, alice)
	alice.run("relay", "rm", "work", "--yes")
	if _, err := alice.tryRun("send", "--resume"); err == nil {
		t.Fatal("a resume on a relay this home no longer has was taken")
	}
	if _, err := alice.tryRun("send", "--resume", "--relay", "personal"); err == nil {
		t.Fatal("the move should have been cut off on personal")
	}
	moved := onlyPending(t, alice)
	if moved.Relay != "personal" || moved.Upload == "" || moved.Upload == second.Upload {
		t.Fatalf("the moved record: %+v; want personal with the upload opened there", moved)
	}
	if opensOnPersonal.Load() == 0 {
		t.Fatal("nothing was opened on personal")
	}
	personalGate.open()
	alice.run("send", "--resume")
	if got := bob.inboxJSON("--relay", "personal").Fetch.Delivered; got != 1 {
		t.Fatalf("the moved message delivered %d times on personal; want once", got)
	}
}
