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

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
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

// A copy posted whole, and a stream copy whose upload was never opened,
// were never opened on a relay: a resume says them as what was to be
// posted to the relay they name, not as an upload opened there (57c). The
// move is held to the same rule, since a post whose answer was lost may be
// on that relay: --relay naming another is refused while this home has it,
// with the drop that gives the copy up, and once the relay is gone --relay
// moves every copy and each is delivered once.
func TestAnUnopenedCopyIsSaidAsWhatWasToBePosted(t *testing.T) {
	for _, kind := range []string{"envelope", "stream"} {
		t.Run(kind, func(t *testing.T) {
			work, personal := startRelay(t), startRelay(t)
			alice := onBothRelays(t, "alice", work, personal)
			bob := onBothRelays(t, "bob", work, personal)
			carol := onBothRelays(t, "carol", work, personal)
			for _, u := range []*user{bob, carol} {
				alice.run("peers", "add", u.exportLine())
				u.run("peers", "add", alice.exportLine())
			}
			var id string
			if kind == "envelope" {
				id, _ = sealCopies(t, alice, "bob", "carol")
			} else {
				id = sealUnopenedStreams(t, alice, "bob", "carol")
			}
			for _, p := range pendingOf(t, alice) {
				if p.Relay != "work" || p.Upload != "" {
					t.Fatalf("a copy before the resume: %+v", p)
				}
			}

			var err error
			said := captureStderr(t, func() { _, err = alice.tryRun("send", "--resume", "--relay", "personal") })
			want := id[:12] + ": it was to be posted to work; post it there with --relay work, or give it up with 'auu outbox drop " + id[:12] + " "
			if err == nil || strings.Count(said, want) != 2 || strings.Contains(said, "opened on") {
				t.Fatalf("a resume on another relay: %v\n%s\nwant %q for each copy", err, said, want)
			}

			alice.run("relay", "rm", "work", "--yes")
			said = captureStderr(t, func() { _, err = alice.tryRun("send", "--resume") })
			want = id[:12] + ": it was to be posted to work, which this home no longer has; add it again, post it to another with --relay, or send the message afresh"
			if err == nil || strings.Count(said, want) != 2 {
				t.Fatalf("a resume after the relay went: %v\n%s\nwant %q for each copy", err, said, want)
			}

			alice.run("send", "--resume", "--relay", "personal")
			for _, u := range []*user{bob, carol} {
				if got := u.inboxJSON("--relay", "personal").Fetch.Delivered; got != 1 {
					t.Errorf("a moved copy delivered %d times on personal; want once", got)
				}
			}
		})
	}
}

// sealUnopenedStreams writes a stream to several to u's outbox on its
// default relay, sealed and recorded and never opened as an upload, as a
// send stopped before its first open leaves it, and answers its id.
func sealUnopenedStreams(t *testing.T, u *user, peers ...string) string {
	t.Helper()
	t.Setenv("AUU_HOME", u.home)
	s, me, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	var to []addressed
	for _, name := range peers {
		pub, err := s.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		to = append(to, addressed{pub: pub})
	}
	file, _ := attachment(t, "x.bin", 10<<10)
	body := message.Body{Type: message.TypeAsk, Thread: strings.Repeat("a", 32), Text: "x"}
	written, _, err := sealStreams(s, me, r, to, body, []string{file}, streamSettings{threshold: stream.DefaultThreshold, chunkSize: stream.MinChunkSize}, "")
	if err != nil {
		t.Fatal(err)
	}
	return written[0].MessageID
}

// pendingOf is what waits in u's outbox.
func pendingOf(t *testing.T, u *user) []*pending {
	t.Helper()
	pending, broken := outboxOf(t, u)
	if len(broken) != 0 {
		t.Fatalf("the outbox holds broken records: %v", broken)
	}
	return pending
}

// dropCommand names the copy for a message to several, whose id several
// records share, and the id alone for a message to one.
func TestTheDropCommandNamesTheCopyOnlyForSeveral(t *testing.T) {
	id := strings.Repeat("ab", 16)
	one := &pending{MessageID: id, To: strings.Repeat("c", 64)}
	if got, want := dropCommand(one), "auu outbox drop "+id[:12]; got != want {
		t.Errorf("a message to one: %q, want %q", got, want)
	}
	several := &pending{MessageID: id, To: strings.Repeat("c", 64), ToName: "carol", RecipientCount: 2}
	if got, want := dropCommand(several), "auu outbox drop "+id[:12]+" carol"; got != want {
		t.Errorf("a copy of a message to several: %q, want %q", got, want)
	}
}

// A copy of a message to several moved to another relay has that relay in
// the message's sent record, beside the copies that stayed on the record's
// own relay, which name none (57c2, D140): the record names the relay the
// message went by, and the moved copy's id is the other relay's. The record
// reads back under the strict read, and the copy that stayed carries no
// relay, as every record from before the key does.
func TestAMovedCopyNamesItsRelayInTheSentRecord(t *testing.T) {
	work, personal := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personal)
	bob := onBothRelays(t, "bob", work, personal)
	// carol is on personal alone, so work refuses her copy and it waits.
	carol := newUser(t, "carol", personal)
	for _, u := range []*user{bob, carol} {
		alice.run("peers", "add", u.exportLine())
		u.run("peers", "add", alice.exportLine())
	}
	captureStderr(t, func() { alice.tryRun("send", "--to", "bob,carol", "--subject", "to both", "one message") })
	left := pendingOf(t, alice)
	if len(left) != 1 || left[0].To != carol.exportFingerprint() {
		t.Fatalf("waiting after the send: %+v; want carol's copy alone", left)
	}
	id := left[0].MessageID

	alice.run("relay", "rm", "work", "--yes")
	alice.run("send", "--resume", "--relay", "personal")
	if got := carol.inboxJSON().Fetch.Delivered; got != 1 {
		t.Fatalf("carol's moved copy delivered %d times; want once", got)
	}
	sent := alice.stored(store.Sent, id)
	if sent.Relay != "work" {
		t.Fatalf("the sent record names %q; want the relay the message went by, work", sent.Relay)
	}
	for _, c := range sent.Copies {
		switch c.Fingerprint {
		case bob.exportFingerprint():
			if c.Relay != "" || c.RelayID == 0 {
				t.Errorf("bob's copy, which stayed on work: %+v; want no relay and its id", c)
			}
		case carol.exportFingerprint():
			if c.Relay != "personal" || c.RelayID == 0 {
				t.Errorf("carol's moved copy: %+v; want personal and its id there", c)
			}
		default:
			t.Errorf("a copy for nobody sent to: %+v", c)
		}
	}
	// auu read says where the moved copy is, and --json carries it.
	if out := alice.run("read", id[:12]); !strings.Contains(out, "sent, on personal") {
		t.Errorf("auu read of the message says:\n%s", out)
	}
	if out := alice.run("read", id[:12], "--json"); !strings.Contains(out, `"relay": "personal"`) {
		t.Errorf("auu read --json of the message says:\n%s", out)
	}

	// A stop between the move and its write to the sent record leaves the
	// copy naming no relay; landing it says the relay all the same, from
	// the outbox record the move saved.
	t.Setenv("AUU_HOME", alice.home)
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSent(id, func(m *store.Stored) *store.Stored {
		for i := range m.Copies {
			m.Copies[i].Relay = ""
		}
		return m
	}); err != nil {
		t.Fatal(err)
	}
	landCopy(s, &pending{MessageID: id, To: carol.exportFingerprint(), Relay: "personal"}, 7)
	for _, c := range alice.stored(store.Sent, id).Copies {
		if c.Fingerprint == carol.exportFingerprint() && (c.Relay != "personal" || c.RelayID != 7) {
			t.Errorf("carol's copy landed after a stop: %+v; want personal and its id", c)
		}
	}
}
