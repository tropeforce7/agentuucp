package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// The second adversarial trace, at v0.9.0 (reviews/trace/): the quota
// arithmetic, the upload lock and the purge. Its tests are here as the
// regression tests, each renamed for what it proves.

// TestAnEnvelopeIsChargedAgainstStreamReservations: OpenUpload counted what
// other open uploads had reserved as though it were already queued, and
// Put, the envelope path, read queued_bytes alone. An admitted sender who
// opened a stream for everything free and then posted envelopes filled the
// mailbox to its quota with the reservation uncounted, and when the stream
// completed the mailbox and the relay held more than their quotas by up to
// one stream. Now one helper answers both, so an envelope into the
// reservation is refused, and a stream after an envelope is refused the
// same way: the reservation counts in both directions.
func TestAnEnvelopeIsChargedAgainstStreamReservations(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	const quota = 8192 + 4096
	q := Quotas{MailboxMaxBytes: quota, RelayMaxBytes: quota}
	id, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const streamSize = 8192
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		streamSize, now, now.Add(time.Hour), q, 0); err != nil {
		t.Fatal(err)
	}
	// 8192 reserved of 12288, so at most 4096 is left for anything else.
	envelope := bytes.Repeat([]byte("e"), 4097)
	if _, err := h.store.Put(bob.Fingerprint(), "default", envelope, q); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("an envelope of %d bytes was queued for a mailbox with %d of its %d byte quota reserved by an open upload (err=%v); "+
			"expected ErrMailboxFull, since only %d bytes are unreserved", len(envelope), streamSize, quota, err, quota-streamSize)
	}
	// What is unreserved is taken.
	if _, err := h.store.Put(bob.Fingerprint(), "default", envelope[:4096], q); err != nil {
		t.Fatalf("an envelope that fits beside the reservation was refused: %v", err)
	}
	// And the stream, completed on top of it, leaves the mailbox and the
	// relay at their quotas, not past them.
	if received, err := h.store.ReceiveUpload(id, 0, relayapi.DefaultMaxBytes, time.Now, time.Minute, func(f *os.File, want int64) (int64, error) {
		return io.Copy(f, io.LimitReader(bytes.NewReader(bytes.Repeat([]byte("s"), streamSize)), want))
	}); err != nil || received.Placed == 0 {
		t.Fatalf("the stream: %+v %v; want it placed", received, err)
	}
	var queued, relayQueued int64
	if err := h.store.db.QueryRow(`SELECT queued_bytes FROM mailboxes WHERE fp = ?`, bob.Fingerprint()).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if err := h.store.db.QueryRow(`SELECT queued_bytes FROM relay_stats WHERE id = 1`).Scan(&relayQueued); err != nil {
		t.Fatal(err)
	}
	if queued > quota {
		t.Errorf("the mailbox holds %d bytes against a mailbox_max_bytes of %d; expected the quota to hold", queued, quota)
	}
	if relayQueued > quota {
		t.Errorf("the relay holds %d bytes against a relay_max_bytes of %d; expected the quota to hold", relayQueued, quota)
	}

	// The other direction, which held before and holds through the same
	// helper now: with the mailbox at its quota, a stream of one byte is
	// refused; and after an acknowledgement makes room for exactly one
	// more, a stream that would take two is refused while one is taken.
	other, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.OpenUpload(other, bob.Fingerprint(), alice.Fingerprint(), "default",
		1, now, now.Add(time.Hour), q, 0); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("a stream was opened for a mailbox at its quota: %v", err)
	}
	// The relay-wide quota by the same arithmetic: a second mailbox with
	// room of its own is still refused by the relay's total.
	if err := h.store.OpenUpload(other, alice.Fingerprint(), bob.Fingerprint(), "default",
		1, now, now.Add(time.Hour), q, 0); !errors.Is(err, ErrRelayFull) {
		t.Errorf("a stream was opened for another mailbox while the relay is at its quota: %v", err)
	}
	if _, err := h.store.Put(alice.Fingerprint(), "default", []byte("e"), q); !errors.Is(err, ErrRelayFull) {
		t.Errorf("an envelope was queued for another mailbox while the relay is at its quota: %v", err)
	}
}

// TestAnEnvelopeIsCountedBesideStreamReservations: the mirror for the
// message count. With mailbox_max_messages 2, one open upload and one
// envelope queued are the two, and a second envelope is refused, as a
// second stream would be.
func TestAnEnvelopeIsCountedBesideStreamReservations(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	q := Quotas{MailboxMaxMessages: 2}
	id, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		16, now, now.Add(time.Hour), q, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Put(bob.Fingerprint(), "default", []byte("first"), q); err != nil {
		t.Fatalf("the envelope beside one reservation was refused: %v", err)
	}
	if _, err := h.store.Put(bob.Fingerprint(), "default", []byte("second"), q); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("a second envelope was queued beside one reservation under mailbox_max_messages 2 (err=%v); expected ErrMailboxFull", err)
	}
	other, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.OpenUpload(other, bob.Fingerprint(), alice.Fingerprint(), "default",
		16, now, now.Add(time.Hour), q, 0); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("a second stream was opened beside one envelope and one reservation under mailbox_max_messages 2: %v", err)
	}
}

// TestAnExpiredUploadTakesNoBytes: an upload's expiry is the moment its
// reservation was promised to end, but the append and completion routes
// never read it; only the purge did, every hundredth request, so a sender
// could keep appending to an upload the relay had already declared
// abandoned, and its reservation with it. Now every route refuses an
// expired upload with 410, says when it expired and to open again, and
// aborts the row there and then, so the reservation goes with the answer.
// Under the one-attempt wire the expiry is the resume window, sixty
// seconds, from the open and again from a kept partial, and the edge is
// inclusive: at the window the upload is still here, a second past it is
// gone. The clock is the server's, moved by hand.
func TestAnExpiredUploadTakesNoBytes(t *testing.T) {
	// max_bytes 2048, so a partial of 3000 is past the threshold and kept.
	h := newHarness(t, Config{MaxBytes: 2048})
	clock := h.clock
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	blob := fakeStream(200, 4096)
	open := func() relayapi.OpenStreamResponse {
		t.Helper()
		status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
			relayapi.OpenStreamRequest{Size: int64(len(blob))}, nil)
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		var opened relayapi.OpenStreamResponse
		if err := json.Unmarshal(body, &opened); err != nil {
			t.Fatal(err)
		}
		return opened
	}
	rowsLeft := func(t *testing.T) int {
		t.Helper()
		var left int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&left); err != nil {
			t.Fatal(err)
		}
		return left
	}

	// An upload nobody puts a byte to within the window: the first attempt
	// a second past it is 410, the row and the file gone with the answer.
	first := open()
	if got, want := first.Expires, clock.Now().Add(relayapi.ResumeWindow).UTC().Truncate(time.Second); !got.Equal(want) {
		t.Fatalf("the open promises expiry at %s, want the window from now, %s", got, want)
	}
	clock.advance(relayapi.ResumeWindow + time.Second)
	status, body, _ := h.putStream(alice, first.Upload, blob, 0)
	if status != http.StatusGone {
		t.Fatalf("an attempt at an upload past its expiry (%s, clock now %s) was answered %d %s; "+
			"expected 410", first.Expires.Format(time.RFC3339), clock.Now().Format(time.RFC3339), status, body)
	}
	if !strings.Contains(string(body), "expired at "+first.Expires.UTC().Format(time.RFC3339)) ||
		!strings.Contains(string(body), "open a new stream") {
		t.Errorf("the refusal does not say when it expired and what to do: %s", body)
	}
	if left := rowsLeft(t); left != 0 {
		t.Errorf("%d upload rows remain after the refusal, want none", left)
	}
	if _, err := os.Stat(h.store.uploadPath(first.Upload)); !os.IsNotExist(err) {
		t.Errorf("the expired upload's file is still there: %v", err)
	}
	if status, body, _ := h.putStream(alice, first.Upload, blob, 0); status != http.StatusNotFound {
		t.Errorf("an attempt at the expired upload after the refusal: %d %s, want 404", status, body)
	}

	// A kept partial expires the same way: kept at 3000 with a new
	// expiry, the resume at the window's edge is taken, one a second past
	// it is 410 and the partial is gone.
	second := open()
	if status, body, _ := h.putPartial(alice, second.Upload, blob, 0, 3000); status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume") {
		t.Fatalf("a partial past the threshold: %d %s; want it kept", status, body)
	}
	u, err := h.store.Upload(second.Upload)
	if err != nil || u.Received != 3000 {
		t.Fatalf("the kept partial: %+v %v; want 3000", u, err)
	}
	if want := clock.Now().Add(relayapi.ResumeWindow); !u.Expires.Equal(want.Truncate(time.Second)) && !u.Expires.Equal(want) {
		t.Fatalf("the kept partial expires at %s, want the window from now, %s", u.Expires, want)
	}
	clock.advance(relayapi.ResumeWindow)
	if status, body, _ := h.putStream(alice, second.Upload, blob, 3000); status != http.StatusCreated {
		t.Fatalf("a resume at the window's edge: %d %s; want 201, the edge being inclusive", status, body)
	}
	third := open()
	if status, body, _ := h.putPartial(alice, third.Upload, blob, 0, 3000); status != http.StatusBadRequest {
		t.Fatalf("a partial past the threshold: %d %s", status, body)
	}
	clock.advance(relayapi.ResumeWindow + time.Second)
	if status, body, _ := h.putStream(alice, third.Upload, blob, 3000); status != http.StatusGone {
		t.Fatalf("a resume a second past the window: %d %s; want 410", status, body)
	}
	if left := rowsLeft(t); left != 0 {
		t.Errorf("%d upload rows remain after the refused resume, want none", left)
	}
	// An abort of an expired upload is the abort the sender wanted: the
	// route answers 410 with the row gone, and the client reads that as
	// gone.
	fourth := open()
	clock.advance(relayapi.ResumeWindow + time.Second)
	if status, body, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+fourth.Upload, nil, nil); status != http.StatusGone {
		t.Errorf("aborting an expired upload: %d %s, want 410", status, body)
	}
}

// TestThePurgeWaitsOnNoSender: PurgeUploads aborted every expired upload
// under that upload's lock, and ReceiveUpload holds the lock across the
// request body's copy. The purge runs inline at the end of every hundredth
// request, before that request's in-flight slot is released and its
// response flushed, so a sender still dribbling the body of an append to
// an expired upload parked an unrelated caller's request for as long as
// the read timeout let the dribble go on. Now the purge tries each lock,
// skips what is held, and returns; the skipped upload is met at the next
// purge, once the append has ended.
func TestThePurgeWaitsOnNoSender(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	const size = 8192
	id, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Expired an hour ago; the store's receive does not read the expiry,
	// the route does.
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		size, now.Add(-2*time.Hour), now.Add(-time.Hour), Quotas{}, 0); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	appended := make(chan error, 1)
	go func() {
		_, err := h.store.ReceiveUpload(id, 0, relayapi.DefaultMaxBytes, time.Now, time.Minute, func(f *os.File, want int64) (int64, error) {
			close(entered)
			<-release // the sender, dribbling
			return io.Copy(f, io.LimitReader(bytes.NewReader(bytes.Repeat([]byte("p"), size)), want))
		})
		appended <- err
	}()
	<-entered

	type result struct {
		purged, skipped int
		err             error
	}
	purged := make(chan result, 1)
	go func() {
		p, s, err := h.store.PurgeUploads(time.Now())
		purged <- result{len(p), s, err}
	}()
	select {
	case r := <-purged:
		if r.err != nil {
			t.Errorf("PurgeUploads: %v", r.err)
		}
		if r.purged != 0 || r.skipped != 1 {
			t.Errorf("the purge removed %d and skipped %d while the attempt held the lock; want 0 and 1", r.purged, r.skipped)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("PurgeUploads has waited 2s behind an attempt that is still reading its request body; " +
			"expected the purge, which runs inside an unrelated caller's request, not to wait on a sender")
	}
	// The upload is still there, untouched, for the attempt to finish on.
	if _, err := h.store.Upload(id); err != nil {
		t.Fatalf("the skipped upload is gone: %v", err)
	}
	close(release)
	if err := <-appended; err != nil {
		t.Fatalf("the attempt that held the lock: %v", err)
	}
	// The attempt ran to the end and placed the stream, so the next purge,
	// once the lock is free, finds nothing to take: the row went with the
	// placement and the entry with the row.
	p, s, err := h.store.PurgeUploads(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 0 || s != 0 {
		t.Errorf("the next purge removed %d and skipped %d; want nothing, the stream having been placed", len(p), s)
	}
	if _, err := h.store.Upload(id); !errors.Is(err, ErrNoUpload) {
		t.Errorf("the upload is still there after the attempt placed it: %v", err)
	}
	if h.store.uploadLocked(id) {
		t.Error("the placed upload's lock entry was kept")
	}
}

// TestAnAttemptThatMeetsAVanishedRowIs404: an upload aborted, placed or
// purged between the route's look at the row and the store's lock made
// the store answer ErrNoUpload, which the route turned into a 500 the
// sender retried; and the lock entry made for the gone id was never
// removed. Now it is the same 404 as for an id never seen, and the entry
// goes with it. (The finding was the append's; the attempt inherits it.)
func TestAnAttemptThatMeetsAVanishedRowIs404(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	// At the store: no row, no entry left behind.
	gone, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ReceiveUpload(gone, 0, 0, time.Now, 0, func(*os.File, int64) (int64, error) { return 0, nil }); !errors.Is(err, ErrNoUpload) {
		t.Fatalf("an attempt at no upload: %v, want ErrNoUpload", err)
	}
	if h.store.uploadLocked(gone) {
		t.Error("an attempt at no upload left a lock entry behind")
	}

	// At the route: the test holds the upload's lock while the append is
	// in flight, aborts the row under it, and lets the append go on to
	// find nothing; whichever side of the route's own look the abort
	// lands, the answer is the one 404.
	const size = 4096
	status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
		relayapi.OpenStreamRequest{Size: size}, nil)
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	var opened relayapi.OpenStreamResponse
	if err := json.Unmarshal(body, &opened); err != nil {
		t.Fatal(err)
	}
	unlock := h.store.uploadLock(opened.Upload)
	type answer struct {
		status int
		body   []byte
	}
	answered := make(chan answer, 1)
	go func() {
		status, body, _ := h.putStream(alice, opened.Upload, fakeStream(200, size-stream.HeaderSize-200), 0)
		answered <- answer{status, body}
	}()
	// Long enough for the route to have looked at the row and reached the
	// lock on a loaded machine; the answer is the same if it has not.
	time.Sleep(300 * time.Millisecond)
	if _, err := h.store.abortLocked(opened.Upload); err != nil {
		t.Fatal(err)
	}
	h.store.forgetUploadLock(opened.Upload, unlock)
	got := <-answered
	if got.status != http.StatusNotFound || !strings.Contains(string(got.body), msgNoUpload) {
		t.Fatalf("an attempt that met an aborted row was answered %d %s; want 404 %q", got.status, got.body, msgNoUpload)
	}
	if h.store.uploadLocked(opened.Upload) {
		t.Error("the aborted upload's lock entry was kept by the attempt that met it")
	}
}
