package auu

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// The adversarial trace of v0.8.1 (reviews/trace/): its client-side tests
// are here as the regression tests, renamed for what they prove and
// adjusted only as far as their fixes needed.

// TestAStreamWhoseManifestOverstatesItsPayloadIsKeptAndAcknowledged: the
// receiver never compared the size a signed manifest implies with the size
// the relay listed; it downloaded to the manifest's size, met the end of
// the blob early, reconnected from there, was told 416, and returned that
// as a transport failure, which is not permanent: nothing was kept, nothing
// acknowledged, the cursor stayed, and every fetch after it failed at the
// same message. Any sender the recipient has authorised could do it with
// one short upload, and the good message behind it was never delivered.
// Now the two sizes are compared before a byte of payload is asked for, a
// disagreement is kept under damaged/ naming both numbers and acknowledged,
// and the fetch goes on to the good message; the next fetch is clean.
func TestAStreamWhoseManifestOverstatesItsPayloadIsKeptAndAcknowledged(t *testing.T) {
	srv, st, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	bobFP := bob.exportFingerprint()

	// A stream sealed by alice for bob, honestly: 200 KiB in four chunks.
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
	to := mustParseBundle(t, mustBundle(t, bob))
	payload := make([]byte, 200<<10)
	for i := range payload {
		payload[i] = byte(i * 11)
	}
	sources := []stream.Source{{
		Name: "big.bin", Media: "application/octet-stream", Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
	}}
	messageID, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	m, err := stream.BuildManifest(id, to, messageID,
		stream.Body{Type: "ask", Thread: "t1", Subject: "the short one", Text: "streamed"},
		sources, stream.DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, id, to, m, sources); err != nil {
		t.Fatal(err)
	}
	full := blob.Bytes()
	n := int(binary.BigEndian.Uint32(full[stream.EncSize:stream.HeaderSize]))
	// Uploaded short: the header, the manifest and one body chunk of the
	// four. The relay checks the shape and takes it; only the manifest,
	// under the seal, says how much was meant to follow.
	short := full[:stream.HeaderSize+n+stream.DefaultChunkSize+stream.TagSize]

	ctx := context.Background()
	opened, err := c.OpenStream(ctx, bobFP, "", int64(len(short)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AppendStream(ctx, opened.Upload, 0, bytes.NewReader(short), int64(len(short))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CompleteStream(ctx, opened.Upload); err != nil {
		t.Fatal(err)
	}
	// And an ordinary message behind it.
	alice.run("send", "--to", "bob", "--subject", "the good one", "hello")
	queued, err := st.List(bobFP, 0, 10)
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued %d (%v), want 2", len(queued), err)
	}

	var out string
	var runErr error
	stderr := captureStderr(t, func() { out, runErr = bob.tryRun("inbox", "--json") })
	if runErr != nil {
		t.Fatalf("a stream whose manifest declares more than the relay holds made the fetch fail, "+
			"and the message behind it was not delivered: %v\nstdout: %s\nstderr: %s", runErr, out, stderr)
	}
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	if inbox.Fetch.Delivered != 1 || inbox.Fetch.Unreadable != 1 {
		t.Fatalf("fetch: %+v, want the good message delivered and the short stream unreadable", inbox.Fetch)
	}
	// The next fetch is clean: the short stream is not met again.
	firstStderr := stderr
	stderr = captureStderr(t, func() { out, runErr = bob.tryRun("inbox", "--json") })
	if runErr != nil {
		t.Fatalf("the second inbox failed too: %v\n%s", runErr, stderr)
	}
	stderr = firstStderr
	var again inboxJSON
	if err := json.Unmarshal([]byte(out), &again); err != nil {
		t.Fatal(err)
	}
	if !again.Fetch.empty() {
		t.Fatalf("the second fetch was not clean: %+v", again.Fetch)
	}
	// What was kept: the manifest chunk under damaged/, with a cause that
	// names both numbers, so a person can say which side lied; and the
	// good message is in the inbox.
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	rec := damagedRecord(t, bs, bob.defaultRelayName(), queued[0].ID)
	want := sizeCause(stream.Size(n, m.PayloadBytes, m.ChunkSize), int64(len(short)))
	if rec.Cause != want {
		t.Fatalf("the kept record's cause is %q, want %q", rec.Cause, want)
	}
	if !strings.Contains(stderr, "could not be opened (malformed: the manifest says the stream is") {
		t.Errorf("the warning does not name the disagreement:\n%s", stderr)
	}
	if !spoolHas(t, bob, store.Inbox, "the good one") {
		t.Error("the good message behind the bad stream is not in the inbox")
	}
}
