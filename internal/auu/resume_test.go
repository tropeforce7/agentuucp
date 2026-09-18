package auu

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// interrupter sits in front of a relay and stops accepting upload pieces after
// a given number of them, by dropping the connection rather than answering.
// That is what a crashed relay, a closed laptop lid or a lost network looks
// like from the sending side: no status, no offset, nothing to go on but a
// HEAD.
type interrupter struct {
	inner  http.Handler
	mu     sync.Mutex
	allow  int // pieces still to let through; negative means all of them
	cut    int // pieces dropped
	passed int // pieces forwarded
}

func (f *interrupter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isPiece := r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/uploads/")
	if isPiece {
		f.mu.Lock()
		drop := f.allow == 0
		if drop {
			f.cut++
		} else {
			f.passed++
			if f.allow > 0 {
				f.allow--
			}
		}
		f.mu.Unlock()
		if drop {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "cannot hijack", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			conn.Close()
			return
		}
	}
	f.inner.ServeHTTP(w, r)
}

func (f *interrupter) open() {
	f.mu.Lock()
	f.allow = -1
	f.mu.Unlock()
}

func (f *interrupter) counts() (passed, cut int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passed, f.cut
}

// startInterruptibleRelay is startRelayConfig with a gate in front of the
// upload endpoint. piece is the relay's per-request cap, which is what the
// client sizes its pieces from, so a small one makes a small payload take
// several of them.
func startInterruptibleRelay(t *testing.T, allow int, piece int64) (string, *interrupter) {
	t.Helper()
	return startInterruptibleRelayWith(t, allow, piece, nil)
}

// startInterruptibleRelayWith is startInterruptibleRelay with a hand on the
// relay's settings before it starts.
func startInterruptibleRelayWith(t *testing.T, allow int, piece int64, mutate func(*relay.Config)) (string, *interrupter) {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := relay.Config{
		MaxBytes: piece,
		Streams:  true,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limits:   relay.DefaultLimits(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	gate := &interrupter{inner: relay.NewServer(st, cfg), allow: allow}
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)
	return srv.URL, gate
}

// An upload cut off part way is finished by --resume, and the message arrives
// once, byte for byte. Nothing is sealed twice: the HPKE context cannot be
// rewound, so the second attempt must be sending the same file.
func TestStreamResumesAfterAnInterruptedUpload(t *testing.T) {
	relayURL, gate := startInterruptibleRelay(t, 2, 64<<10)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// Several pieces long at a 64 KiB per-request cap.
	payload := make([]byte, 400<<10)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	file := filepath.Join(t.TempDir(), "interrupted.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := alice.tryRun("send", "--to", "bob", "--subject", "the long one",
		"--attach", file, "here it is"); err == nil {
		t.Fatalf("the send should have failed with the relay cut off after two pieces:\n%s", out)
	}
	passed, cut := gate.counts()
	if passed == 0 || cut == 0 {
		t.Fatalf("the gate let %d pieces through and cut %d; the test proves nothing", passed, cut)
	}

	// The sealed stream and its record are still there, and the record knows
	// which upload on the relay they belong to.
	p := onlyPending(t, alice)
	if p.Upload == "" {
		t.Fatal("the outbox record has no upload id, so a later process could not resume it")
	}
	if p.Bytes != int64(len(payload)) {
		t.Fatalf("outbox record says %d bytes, want %d", p.Bytes, len(payload))
	}
	sealed := filepath.Join(alice.home, "outbox", p.MessageID+".stream")
	info, err := os.Stat(sealed)
	if err != nil {
		t.Fatalf("the sealed stream did not survive the failure: %v", err)
	}
	const piece = 64 << 10
	whole := int((info.Size() + piece - 1) / piece)

	// A new message warns about it, without being blocked by it.
	small := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(small, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "meanwhile", "--attach", small, "hi")
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("sending something else disturbed the outbox: %v", err)
	}

	passedBefore, _ := gate.counts()
	gate.open()
	alice.run("send", "--resume")

	// It carried on from where the relay had got to rather than starting the
	// upload again, which is the whole point: the relay already holds a prefix
	// of these exact bytes.
	passedAfter, _ := gate.counts()
	resumed := passedAfter - passedBefore
	if resumed >= whole {
		t.Fatalf("--resume sent %d pieces of a %d-piece stream; it restarted rather than resumed",
			resumed, whole)
	}
	// Exactly one upload's worth of pieces went across the two attempts, at
	// the size the relay asked for. A resume that forgot what the relay said
	// it would take still finishes, but in the wrong number of requests, and
	// only counting them says so.
	if passedAfter != whole {
		t.Fatalf("%d pieces sent in total for a %d-piece stream (%d before the cut, %d after); "+
			"the resumed pieces are not the size the relay advertised",
			passedAfter, whole, passedBefore, resumed)
	}

	// Both halves of the outbox record are gone, and the bytes were never
	// re-sealed: what arrived is what was sealed before the interruption.
	if entries, err := os.ReadDir(filepath.Join(alice.home, "outbox")); err == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("outbox not cleared after --resume: %v", names)
	}
	if _, err := os.Stat(sealed); !os.IsNotExist(err) {
		t.Fatalf("the sealed stream was left behind: %v", err)
	}

	inbox := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(inbox), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, inbox)
	}
	var found int
	var id string
	for _, m := range got.Messages {
		if m.Subject == "the long one" {
			found++
			id = m.ID
		}
	}
	if found != 1 {
		t.Fatalf("the resumed message arrived %d times, want once: %+v", found, got.Messages)
	}

	dir := t.TempDir()
	bob.run("extract", id, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "interrupted.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("the resumed payload differs: %d bytes back, %d sent", len(back), len(payload))
	}

	// And a second --resume has nothing to do.
	if out := alice.run("send", "--resume"); !strings.Contains(out, "nothing to resume") {
		t.Fatalf("a second --resume said %q", strings.TrimSpace(out))
	}
}

// A record whose sealed stream has gone cannot be resumed, and says so rather
// than uploading something else. The bytes cannot be made again: the nonce
// counter that sealed them only goes forwards.
func TestResumeReportsASealedStreamThatHasGone(t *testing.T) {
	relayURL, gate := startInterruptibleRelay(t, 1, 64<<10)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("allow", "push")

	payload := make([]byte, 300<<10)
	file := filepath.Join(t.TempDir(), "gone.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.tryRun("send", "--to", "bob", "--attach", file, "x"); err == nil {
		t.Fatal("the send should have failed")
	}
	p := onlyPending(t, alice)
	if err := os.Remove(filepath.Join(alice.home, "outbox", p.MessageID+".stream")); err != nil {
		t.Fatal(err)
	}

	gate.open()
	out := alice.run("send", "--resume")
	if !strings.Contains(out, "nothing to resume") {
		t.Fatalf("resume with no sealed stream said %q", strings.TrimSpace(out))
	}
}

// --resume finishes what is sealed; it does not also take a new message.
func TestResumeRefusesOtherArguments(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	for _, args := range [][]string{
		{"send", "--resume", "--to", "bob"},
		{"send", "--resume", "hello"},
	} {
		if out, err := alice.tryRun(args...); err == nil {
			t.Fatalf("auu %s was accepted:\n%s", strings.Join(args, " "), out)
		}
	}
}

// onlyPending reads the single outbox record, failing if there is not exactly
// one.
func onlyPending(t *testing.T, u *user) *pending {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	waiting, broken, err := listPending(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting) != 1 {
		t.Fatalf("%d resumable streams and %d unusable records, want exactly one resumable",
			len(waiting), len(broken))
	}
	return waiting[0]
}

// A stream the relay refuses outright leaves nothing in the outbox: there is
// nothing on the relay to resume, and gigabytes of sealed copy would only be
// waiting for somebody to notice them. The refusal names the setting, because
// at the shipped defaults this is the first thing a large message meets.
func TestRefusedStreamLeavesNothingBehind(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 128 << 10 // smaller than the payload
	relayURL := startRelayWith(t, limits)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("allow", "push")

	file := filepath.Join(t.TempDir(), "toobig.bin")
	if err := os.WriteFile(file, make([]byte, 400<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := alice.tryRun("send", "--to", "bob", "--attach", file, "x")
	if err == nil {
		t.Fatalf("a stream over the byte budget was accepted:\n%s", out)
	}
	if !strings.Contains(err.Error(), "post_bytes_per_hour") {
		t.Fatalf("the refusal does not name the setting: %v", err)
	}
	if entries, e := os.ReadDir(filepath.Join(alice.home, "outbox")); e == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, x := range entries {
			names = append(names, x.Name())
		}
		t.Fatalf("a refused stream was left in the outbox: %v", names)
	}
	// And the warning on the next send has nothing to warn about.
	if out := alice.run("send", "--resume"); !strings.Contains(out, "nothing to resume") {
		t.Fatalf("--resume said %q", strings.TrimSpace(out))
	}
}

// fullDisk sits in front of a relay and answers a piece the way the relay
// does when its disk is full — 507 with relayapi.MsgRelayFull — after a
// given number of pieces have gone through. The relay behind it is real, so
// what the client resumes against is a real reservation.
type fullDisk struct {
	inner   http.Handler
	mu      sync.Mutex
	allow   int // pieces still to let through; negative means all of them
	refused int
	passed  int
}

func (f *fullDisk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/uploads/") {
		f.mu.Lock()
		refuse := f.allow == 0
		if refuse {
			f.refused++
		} else {
			f.passed++
			if f.allow > 0 {
				f.allow--
			}
		}
		f.mu.Unlock()
		if refuse {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInsufficientStorage)
			json.NewEncoder(w).Encode(relayapi.ErrorResponse{Error: relayapi.MsgRelayFull})
			return
		}
	}
	f.inner.ServeHTTP(w, r)
}

func (f *fullDisk) open() {
	f.mu.Lock()
	f.allow = -1
	f.mu.Unlock()
}

func (f *fullDisk) counts() (passed, refused int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passed, f.refused
}

// A relay that runs out of room part way through an upload says so with a
// 507, and the client keeps the sealed stream and the upload's record: the
// sentence names whose problem the room is and that --resume finishes it
// when there is some, and nothing is retried against a disk that has no
// room. The container suite's R18 found a 500 and a hint to resume an upload
// that could not finish.
func TestAFullRelayKeepsTheOutbox(t *testing.T) {
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	gate := &fullDisk{
		inner: relay.NewServer(st, relay.Config{
			MaxBytes: 64 << 10,
			Streams:  true,
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
			Limits:   relay.DefaultLimits(),
		}),
		allow: 2,
	}
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)

	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	payload := make([]byte, 400<<10)
	for i := range payload {
		payload[i] = byte(i*13 + 5)
	}
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var out string
	var runErr error
	warning := captureStderr(t, func() {
		out, runErr = alice.tryRun("send", "--to", "bob", "--subject", "the big one", "--attach", file, "here")
	})
	if runErr == nil {
		t.Fatalf("the send succeeded against a full relay:\n%s", out)
	}
	var e *exitError
	if !asExit(runErr, &e) || e.code != exitTransport {
		t.Fatalf("exit %v, want %d", runErr, exitTransport)
	}
	want := "the relay is out of storage; whoever runs it needs to make room. " +
		"The upload is kept; finish it with 'auu send --resume' when there is room"
	if runErr.Error() != want {
		t.Fatalf("error %q, want %q", runErr, want)
	}
	if warning != "" {
		t.Fatalf("stderr had more than the error: %q", warning)
	}
	if passed, refused := gate.counts(); passed != 2 || refused != 1 {
		t.Fatalf("%d pieces passed and %d were refused; a 507 is not to be retried", passed, refused)
	}

	// The outbox is untouched: the sealed stream and a record naming the
	// upload the relay still holds.
	p := onlyPending(t, alice)
	if p.Upload == "" {
		t.Fatal("the outbox record has no upload id")
	}
	sealed := filepath.Join(alice.home, "outbox", p.MessageID+".stream")
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("the sealed stream did not survive: %v", err)
	}
	if u, err := st.Upload(p.Upload); err != nil || u.Received == 0 {
		t.Fatalf("the relay's reservation: %+v, %v; want kept with the pieces it accepted", u, err)
	}

	// Room made: --resume finishes from where the relay got to.
	gate.open()
	alice.run("send", "--resume")
	if entries, err := os.ReadDir(filepath.Join(alice.home, "outbox")); err == nil && len(entries) != 0 {
		t.Fatalf("outbox not cleared after --resume: %d entries", len(entries))
	}
	inbox := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(inbox), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 || got.Messages[0].Subject != "the big one" {
		t.Fatalf("inbox: %+v", got.Messages)
	}
	extracted := t.TempDir()
	bob.run("extract", got.Messages[0].ID, "--out", extracted)
	back, err := os.ReadFile(filepath.Join(extracted, "big.bin"))
	if err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("the payload did not survive the full disk and the resume: %v", err)
	}
}
