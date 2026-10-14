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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// interrupter sits in front of a relay and cuts an upload attempt once a
// given number of its body's bytes have gone through, by closing the
// connection without an answer rather than answering; from then until it
// is opened it cuts every attempt the same way at its first byte. That is
// what a crashed relay, a closed laptop lid or a lost network looks like
// from the sending side: no status, no offset, nothing to go on but the
// next attempt. The relay behind it sees each cut attempt as one that
// stopped short, and applies its rule. Each attempt the relay answered
// through an open gate is recorded with the offset it declared and the
// status it got, which is how a test tells a resume from a restart.
type interrupter struct {
	inner    http.Handler
	mu       sync.Mutex
	allow    int64 // bytes of an attempt's body still let through; negative means all of them
	cut      int   // attempts dropped
	through  int64 // bytes of dropped attempts the relay was given
	answered []attemptSeen
}

// attemptSeen is one attempt the relay answered.
type attemptSeen struct {
	offset int64
	status int
}

func (f *interrupter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/v1/uploads/") {
		f.inner.ServeHTTP(w, r)
		return
	}
	offset, _ := strconv.ParseInt(r.Header.Get(relayapi.UploadOffsetHeader), 10, 64)
	f.mu.Lock()
	allow := f.allow
	f.mu.Unlock()
	if allow < 0 {
		rec := &statusSeen{ResponseWriter: w}
		f.inner.ServeHTTP(rec, r)
		f.mu.Lock()
		f.answered = append(f.answered, attemptSeen{offset, rec.status})
		f.mu.Unlock()
		return
	}
	// The body reaches the relay up to the allowance and then ends the way
	// a dropped connection's does; the relay's answer is swallowed and the
	// connection closed without it.
	body := &cutBody{r: r.Body, left: allow}
	r.Body = body
	f.inner.ServeHTTP(&swallowed{w: w}, r)
	f.mu.Lock()
	f.cut++
	f.through += body.given
	f.allow = 0
	f.mu.Unlock()
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
		}
	}
}

// open lets every attempt through from now on.
func (f *interrupter) open() {
	f.mu.Lock()
	f.allow = -1
	f.mu.Unlock()
}

// counts answers how many attempts the relay answered and how many the
// gate cut.
func (f *interrupter) counts() (passed, cut int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.answered), f.cut
}

// seen answers the attempts the relay answered, in order.
func (f *interrupter) seen() []attemptSeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]attemptSeen(nil), f.answered...)
}

// given answers how many bytes of cut attempts reached the relay.
func (f *interrupter) given() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.through
}

// cutBody delivers left bytes of a body and then fails the read, as a
// read from a connection that dropped does.
type cutBody struct {
	r     io.ReadCloser
	left  int64
	given int64
}

func (b *cutBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	b.given += int64(n)
	return n, err
}

func (b *cutBody) Close() error { return b.r.Close() }

// swallowed is a ResponseWriter that keeps the answer from the connection
// and hands the relay the real one underneath for its deadlines, so that
// the connection can be closed with nothing written on it.
type swallowed struct {
	w      http.ResponseWriter
	header http.Header
}

func (s *swallowed) Header() http.Header {
	if s.header == nil {
		s.header = make(http.Header)
	}
	return s.header
}
func (s *swallowed) WriteHeader(int)             {}
func (s *swallowed) Write(p []byte) (int, error) { return len(p), nil }
func (s *swallowed) Unwrap() http.ResponseWriter { return s.w }

// FlushError keeps a flush of the swallowed answer swallowed: without it a
// ResponseController reaches the connection through Unwrap, as it must for
// the relay's deadlines, and a flush there commits a header the gate means
// to write itself (the relay flushes a refusal before it drains, R42b).
func (s *swallowed) FlushError() error { return nil }

// statusSeen records the status an answer carried.
type statusSeen struct {
	http.ResponseWriter
	status int
}

func (s *statusSeen) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusSeen) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusSeen) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// startInterruptibleRelay is startRelayConfig with a gate in front of the
// upload route that lets pieces bytes of the first attempt through, in
// units of piece, before cutting it. piece is also the relay's max_bytes,
// which is the threshold under which a stopped attempt keeps nothing, so
// one piece or more through is a partial the relay keeps.
func startInterruptibleRelay(t *testing.T, pieces int, piece int64) (string, *interrupter) {
	t.Helper()
	return startInterruptibleRelayWith(t, pieces, piece, nil)
}

// startInterruptibleRelayWith is startInterruptibleRelay with a hand on the
// relay's settings before it starts.
func startInterruptibleRelayWith(t *testing.T, pieces int, piece int64, mutate func(*relay.Config)) (string, *interrupter) {
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
	gate := &interrupter{inner: relay.NewServer(st, cfg), allow: int64(pieces) * piece}
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)
	return srv.URL, gate
}

// An upload cut off part way is finished by --resume from where the relay
// says its copy ends, and the message arrives once, byte for byte. Nothing
// is sealed twice: the HPKE context cannot be rewound, so the second
// attempt must be sending the same file. Under the old wire this was
// proved by counting pieces; under the one-attempt wire the resumed
// attempt declares the offset the relay kept, and that is what is read.
func TestStreamResumesAfterAnInterruptedUpload(t *testing.T) {
	relayURL, gate := startInterruptibleRelay(t, 2, 64<<10)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// Several times the relay's threshold, so the cut leaves a partial
	// the relay keeps.
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
		t.Fatalf("the send should have failed with the relay cut off part way:\n%s", out)
	}
	passed, cut := gate.counts()
	if cut == 0 || passed != 0 {
		t.Fatalf("the gate answered %d attempts and cut %d; the test proves nothing", passed, cut)
	}
	const piece = 64 << 10
	if got := gate.given(); got != 2*piece {
		t.Fatalf("the relay was given %d bytes before the cut, want %d", got, 2*piece)
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

	// A new message warns about it, without being blocked by it.
	small := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(small, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "meanwhile", "--attach", small, "hi")
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("sending something else disturbed the outbox: %v", err)
	}

	gate.open()
	alice.run("send", "--resume")

	// It carried on from where the relay had got to rather than starting the
	// upload again, which is the whole point: the relay already holds a prefix
	// of these exact bytes. The first attempt from zero is how the sender
	// asks, and the relay's 409 says where; the second declares that offset
	// and places the stream. A resume that forgot what the relay said would
	// finish too, in an attempt from zero, and only the offsets say so.
	seen := gate.seen()
	if len(seen) != 2 {
		t.Fatalf("--resume made %d answered attempts, want 2 (the ask and the resume): %+v", len(seen), seen)
	}
	if seen[0].offset != 0 || seen[0].status != http.StatusConflict {
		t.Fatalf("the ask: %+v, want offset 0 answered 409", seen[0])
	}
	if seen[1].offset != 2*piece || seen[1].status != http.StatusCreated {
		t.Fatalf("the resume: %+v, want offset %d answered 201", seen[1], 2*piece)
	}
	if seen[1].offset >= info.Size() {
		t.Fatalf("the resume's offset %d is not inside the %d-byte stream", seen[1].offset, info.Size())
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

// fullDisk sits in front of a relay and answers an attempt the way the
// relay does when its disk fills part way through it — the bytes up to
// the full mark taken, then 507 with relayapi.MsgRelayFull — by letting a
// given number of bytes through to the relay, which sees an attempt that
// stopped short there and applies its rule to what it holds, and
// answering the 507 in the relay's place. The relay behind it is real, so
// what the client resumes against is a real partial, kept the way a full
// disk's is.
type fullDisk struct {
	inner   http.Handler
	mu      sync.Mutex
	allow   int64 // bytes of an attempt still let through; negative means all of them
	refused int
	passed  int
}

func (f *fullDisk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/v1/uploads/") {
		f.inner.ServeHTTP(w, r)
		return
	}
	f.mu.Lock()
	allow := f.allow
	if allow < 0 {
		f.passed++
	} else {
		f.refused++
		f.allow = 0
	}
	f.mu.Unlock()
	if allow < 0 {
		f.inner.ServeHTTP(w, r)
		return
	}
	r.Body = &cutBody{r: r.Body, left: allow}
	f.inner.ServeHTTP(&swallowed{w: w}, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInsufficientStorage)
	json.NewEncoder(w).Encode(relayapi.ErrorResponse{Error: relayapi.MsgRelayFull, Code: relayapi.CodeRelayFull})
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
// that could not finish. Under the one-attempt wire the relay keeps the
// partial by its rule, the attempt having got past the threshold, and
// --resume finds it by an attempt from zero and finishes from there.
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
		allow: 2 * (64 << 10),
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
		"The sealed copy is kept; finish it with 'auu send --resume' when there is room"
	if runErr.Error() != want {
		t.Fatalf("error %q, want %q", runErr, want)
	}
	if warning != "" {
		t.Fatalf("stderr had more than the error: %q", warning)
	}
	if passed, refused := gate.counts(); passed != 0 || refused != 1 {
		t.Fatalf("%d attempts passed and %d were refused; a 507 is not to be retried", passed, refused)
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
	if u, err := st.Upload(p.Upload); err != nil || u.Received != 2*(64<<10) {
		t.Fatalf("the relay's partial: %+v, %v; want kept at the bytes it accepted", u, err)
	}

	// Room made: --resume finishes from where the relay got to, in the
	// ask from zero and the attempt from there.
	gate.open()
	alice.run("send", "--resume")
	if passed, _ := gate.counts(); passed != 2 {
		t.Fatalf("--resume made %d attempts, want the ask and the resume", passed)
	}
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
