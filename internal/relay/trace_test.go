package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The adversarial trace of v0.8.1 (reviews/trace/) found six things on the
// far side of authentication, in what an admitted peer may claim a count
// or length for. Its tests are here as the regression tests, each renamed
// for what it proves and adjusted only as far as its fix needed; each
// failed on the code as shipped and passes on the fix.

// TestOneAppendAtATimePerUpload: AppendUpload read the row, copied onto the
// file, and only then added to the row, so two appends at one offset both
// passed the offset check, both landed on the file, and the upload held
// more than it declared and more than was reserved. Now the upload's lock
// is held from the offset check through the update: the first append
// lands, the second waits for it and meets ErrUploadOffset at the real
// offset, and the upload holds exactly what it declared. The trace's test
// called the second append while the first was parked, which under the
// lock would wait for ever; the second runs in a goroutine here and the
// first is released after it has been called.
func TestOneAppendAtATimePerUpload(t *testing.T) {
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
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		size, now, now.Add(time.Hour), Quotas{}, 0); err != nil {
		t.Fatal(err)
	}
	piece := bytes.Repeat([]byte("p"), size)

	entered := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := h.store.AppendUpload(id, 0, func(f *os.File, limit int64) (int64, error) {
			// Past the offset check, and about to copy.
			close(entered)
			<-release
			return io.Copy(f, io.LimitReader(bytes.NewReader(piece), limit))
		})
		first <- err
	}()
	<-entered
	// A second append at the same offset, while the first is still copying.
	// It waits on the upload's lock, so it is asked for in a goroutine and
	// the first is released once it has been.
	type outcome struct {
		received int64
		err      error
	}
	second := make(chan outcome, 1)
	go func() {
		received, err := h.store.AppendUpload(id, 0, func(f *os.File, limit int64) (int64, error) {
			return io.Copy(f, io.LimitReader(bytes.NewReader(piece), limit))
		})
		second <- outcome{received, err}
	}()
	// Nothing says when the second has reached the lock; a moment is
	// enough for it to have been called, and the outcome is the same either
	// way, since the lock decides the order and not the clock.
	time.Sleep(50 * time.Millisecond)
	close(release)
	firstErr := <-first
	secondOut := <-second

	u, err := h.store.Upload(id)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(h.store.uploadPath(id))
	if err != nil {
		t.Fatal(err)
	}
	if firstErr != nil {
		t.Fatalf("the first append: %v", firstErr)
	}
	if !errors.Is(secondOut.err, ErrUploadOffset) || secondOut.received != size {
		t.Fatalf("the second append at offset 0 gave received=%d err=%v, want ErrUploadOffset at %d",
			secondOut.received, secondOut.err, size)
	}
	if u.Received != size || info.Size() != size {
		t.Fatalf("an upload declared at %d bytes holds %d on disk and %d in its row after two appends at offset 0",
			size, info.Size(), u.Received)
	}
}

// TestTwoAppendsAtOneOffsetOnTheWireLandOnce is the same race over HTTP: two
// PATCH requests at Upload-Offset 0, the first still receiving its body
// while the second arrives whole. The first is answered 204 at the declared
// length, the second 409 naming the real offset, HEAD reports the declared
// length, and the disk holds exactly the reservation. The second PATCH is
// sent from a goroutine, since under the lock it is answered only after the
// first has finished.
func TestTwoAppendsAtOneOffsetOnTheWireLandOnce(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	const size = 64 << 10
	status, opened, body := h.openStream(alice, bob.Fingerprint(), size)
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}

	type answer struct {
		status int
		body   []byte
		offset string
	}
	pr, pw := io.Pipe()
	first := make(chan answer, 1)
	go func() {
		req, err := http.NewRequest("PATCH", h.srv.URL+"/v1/uploads/"+opened.Upload, pr)
		if err != nil {
			first <- answer{status: -1, body: []byte(err.Error())}
			return
		}
		req.ContentLength = size
		req.Header.Set(relayapi.UploadOffsetHeader, "0")
		if err := relayapi.SignRequest(alice, req, nil); err != nil {
			first <- answer{status: -1, body: []byte(err.Error())}
			return
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			first <- answer{status: -1, body: []byte(err.Error())}
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		first <- answer{resp.StatusCode, out, resp.Header.Get(relayapi.UploadOffsetHeader)}
	}()
	// Half the body goes through, and the relay is inside its copy once the
	// upload file has grown at all: the row was read before the copy began.
	if _, err := pw.Write(bytes.Repeat([]byte("a"), size/2)); err != nil {
		t.Fatal(err)
	}
	path := h.store.uploadPath(opened.Upload)
	for deadline := time.Now().Add(10 * time.Second); ; {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay never began writing the first piece")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The second PATCH, whole, at the same offset, from a goroutine: it is
	// answered once the first has finished.
	second := make(chan answer, 1)
	go func() {
		status, body, hdr := h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload,
			bytes.Repeat([]byte("b"), size), map[string]string{relayapi.UploadOffsetHeader: "0"})
		second <- answer{status, body, hdr.Get(relayapi.UploadOffsetHeader)}
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := pw.Write(bytes.Repeat([]byte("a"), size/2)); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	firstAnswer := <-first
	secondAnswer := <-second

	if firstAnswer.status != http.StatusNoContent || firstAnswer.offset != strconv.Itoa(size) {
		t.Fatalf("the first PATCH: %d %s offset=%s, want 204 at %d", firstAnswer.status, firstAnswer.body, firstAnswer.offset, size)
	}
	if secondAnswer.status != http.StatusConflict || secondAnswer.offset != strconv.Itoa(size) {
		t.Fatalf("the second PATCH at offset 0: %d %s offset=%s, want 409 naming %d", secondAnswer.status, secondAnswer.body, secondAnswer.offset, size)
	}
	status, _, hdr := h.sendRaw(alice, "HEAD", "/v1/uploads/"+opened.Upload, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("head: %d", status)
	}
	offset, _ := strconv.ParseInt(hdr.Get(relayapi.UploadOffsetHeader), 10, 64)
	length, _ := strconv.ParseInt(hdr.Get(relayapi.UploadLengthHeader), 10, 64)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset != length || info.Size() != size {
		t.Fatalf("after two PATCHes at offset 0 HEAD says %d of %d bytes and the file is %d bytes: the upload holds more than it declared",
			offset, length, info.Size())
	}
	// And the upload completes, as one that holds what it declared does —
	// once its shape is right: the bytes here are not a stream, so what is
	// asserted is that the relay got as far as looking, at the declared
	// length, rather than refusing at the offset.
	if status, body, _ := h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil); status == http.StatusConflict {
		t.Fatalf("complete after the race: %d %s; the upload's offset is not its length", status, body)
	}
}

// TestTheUploadLockIsHeldNoLongerThanTheAppend: a second append at the
// advanced offset, sent after the first has finished, goes through — the
// lock covers one append and is released with it — and a completion and an
// abort take the same lock and drop its entry, so the map holds an entry
// only for an upload in progress.
func TestTheUploadLockIsHeldNoLongerThanTheAppend(t *testing.T) {
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
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		size, now, now.Add(time.Hour), Quotas{}, 0); err != nil {
		t.Fatal(err)
	}
	half := bytes.Repeat([]byte("h"), size/2)
	append := func(offset int64) (int64, error) {
		return h.store.AppendUpload(id, offset, func(f *os.File, limit int64) (int64, error) {
			return io.Copy(f, io.LimitReader(bytes.NewReader(half), limit))
		})
	}
	done := make(chan error, 1)
	go func() {
		received, err := append(0)
		if err == nil && received != size/2 {
			err = errors.New("the first append did not land half")
		}
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The lock was released with the first append: the second, at the
	// advanced offset, is answered and not waited on.
	got := make(chan error, 1)
	go func() {
		received, err := append(size / 2)
		if err == nil && received != size {
			err = errors.New("the second append did not land the rest")
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second append at the advanced offset never returned: the lock outlived the first")
	}
	h.store.uploadsMu.Lock()
	_, held := h.store.uploads[id]
	h.store.uploadsMu.Unlock()
	if !held {
		t.Fatal("no lock entry for an upload in progress")
	}
	if _, err := h.store.CompleteUpload(id); err != nil {
		t.Fatal(err)
	}
	h.store.uploadsMu.Lock()
	_, held = h.store.uploads[id]
	h.store.uploadsMu.Unlock()
	if held {
		t.Fatal("the lock entry outlived the upload's completion")
	}
	// An abort of an upload that is gone takes and drops a fresh entry too.
	if aborted, err := h.store.AbortUpload(id); err != nil || aborted {
		t.Fatalf("abort of a completed upload: %v %v", aborted, err)
	}
	h.store.uploadsMu.Lock()
	n := len(h.store.uploads)
	h.store.uploadsMu.Unlock()
	if n != 0 {
		t.Fatalf("%d lock entries after complete and abort, want none", n)
	}
}

// TestRegisterHoldsTheNameToTheExportLinesRule: the relay stored and
// served a registration name with no rule at all, so a terminal escape
// reached every enrolled user's terminal through 'auu lookup' and the
// operator's through 'auu-admin mailboxes', and a megabyte was stored per
// mailbox. Now identity.ValidName, the export line's rule, is applied at
// registration and refused 400 with the rule's own sentence; a valid name
// is taken as before, and no name at all — nothing to print — is allowed.
func TestRegisterHoldsTheNameToTheExportLinesRule(t *testing.T) {
	h := newHarness(t, Config{})
	for _, tc := range []struct{ what, name string }{
		{"a terminal escape and a newline", "bob\x1b[2K\x1b[1;31mowned\nccx2.evil"},
		{"a megabyte", strings.Repeat("n", 1<<20)},
	} {
		id := ids(t, "x")[0]
		if identity.ValidName(tc.name) == nil {
			t.Fatalf("%s: the test's name is valid", tc.what)
		}
		status, body := h.do(id, "POST", "/v1/register", h.registerBody(id, tc.name, ""), nil)
		if status != http.StatusBadRequest {
			t.Errorf("%s: register answered %d, want 400: %.80s", tc.what, status, body)
		}
		if want := strings.TrimPrefix(identity.ValidName(tc.name).Error(), "identity: "); errorText(t, body) != want {
			t.Errorf("%s: the refusal says %q, want the rule's own %q", tc.what, errorText(t, body), want)
		}
		status, body = h.do(nil, "GET", "/v1/keys/"+id.Fingerprint(), nil, nil)
		if status != http.StatusOK {
			continue
		}
		var keys relayapi.KeysResponse
		if err := json.Unmarshal(body, &keys); err != nil {
			t.Fatal(err)
		}
		if keys.Name == tc.name {
			t.Errorf("%s: the relay serves the name back verbatim from /v1/keys (%d bytes)", tc.what, len(keys.Name))
		}
	}
	// A valid name, and none: taken.
	for _, name := range []string{"bob", "bob.laptop_2-x", ""} {
		id := ids(t, "y")[0]
		if status, body := h.do(id, "POST", "/v1/register", h.registerBody(id, name, ""), nil); status != http.StatusOK {
			t.Errorf("name %q: register answered %d, want 200: %s", name, status, body)
		}
	}
}

// TestAHugeDeclaredSizeIsRefusedNotWrapped: OpenUpload added the declared
// size to what was queued and reserved before comparing with the quota, so
// a size near MaxInt64 wrapped the sum negative — under any quota — and
// the reservation was taken; once on the row, SUM(size) over the uploads
// overflowed inside SQLite and every later open for the mailbox was a
// storage error. Now the size is compared with what is left, never added:
// the huge open is refused, and the one-byte open after it is taken.
func TestAHugeDeclaredSizeIsRefusedNotWrapped(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	q := Quotas{MailboxMaxBytes: 1 << 20, RelayMaxBytes: 1 << 20}
	now := time.Now()
	open := func(size int64) error {
		id, err := NewUploadID()
		if err != nil {
			t.Fatal(err)
		}
		return h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
			size, now, now.Add(time.Hour), q, 0)
	}
	if err := open(512 << 10); err != nil {
		t.Fatalf("a first, modest reservation: %v", err)
	}
	err := open(math.MaxInt64)
	if !errors.Is(err, ErrMailboxFull) && !errors.Is(err, ErrRelayFull) {
		t.Errorf("a stream of %d bytes was reserved against a %d-byte mailbox and relay quota: err=%v",
			int64(math.MaxInt64), q.MailboxMaxBytes, err)
	}
	// Nothing was reserved, so the next open is taken, and the sum SQLite
	// computes for it fits.
	if err := open(1); err != nil {
		t.Errorf("after the refused huge open, a one-byte open: %v, want it taken", err)
	}
	// With no quota at all the same bound holds against MaxInt64, so a size
	// that would wrap the sum on the next open is refused as too big, and
	// one that fits beside what is held is taken.
	q = Quotas{}
	if err := open(math.MaxInt64); !errors.Is(err, ErrStreamTooBig) {
		t.Errorf("with no quota, a stream of MaxInt64 bytes beside what is held: %v, want ErrStreamTooBig", err)
	}
	if err := open(1 << 40); err != nil {
		t.Errorf("with no quota, a terabyte: %v, want it taken", err)
	}
}

// TestNoRelayAcceptsAStreamPastTheCap: the handler refuses a declared size
// above MaxStreamSize whatever max_stream_bytes says, 0 for unlimited
// included, so unlimited is still a number the relay can add to what it
// holds.
func TestNoRelayAcceptsAStreamPastTheCap(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	for _, size := range []int64{MaxStreamSize + 1, math.MaxInt64} {
		status, _, body := h.openStream(alice, bob.Fingerprint(), size)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "no relay accepts more than") {
			t.Errorf("a stream of %d bytes: %d %s, want 400 naming the cap", size, status, body)
		}
	}
	if status, _, body := h.openStream(alice, bob.Fingerprint(), MaxStreamSize); status == http.StatusBadRequest && strings.Contains(string(body), "no relay accepts") {
		t.Errorf("a stream at the cap was refused for the cap: %s", body)
	}
}
