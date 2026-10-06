package auu

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
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
		stream.Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: "the short one", Text: "streamed"},
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
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(short), int64(len(short))); err != nil {
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

// TestLookupPrintsAHostileNameEscaped: a relay that is not ours can
// answer a name with a terminal escape in it. What 'auu
// lookup' prints — the name, and the export line built from it — carries
// no byte a terminal would obey, and the export line it prints is not one
// that parses, since that was never a name.
func TestLookupPrintsAHostileNameEscaped(t *testing.T) {
	url, _, db, _ := startEditableRelay(t)
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	fp := alice.exportFingerprint()
	// Planted in the row the way a relay from before the rule would hold it.
	hostile := "alice\x1b[2K\x1b[1;31mowned\nccx2.evil"
	if _, err := db.Exec(`UPDATE mailboxes SET name = ? WHERE fp = ?`, hostile, fp); err != nil {
		t.Fatal(err)
	}
	const escaped = `alice\x1b[2K\x1b[1;31mowned\nccx2.evil`
	for _, args := range [][]string{{"lookup", fp}, {"lookup", fp, "--json"}} {
		out := bob.run(args...)
		for i := 0; i < len(out); i++ {
			if c := out[i]; c == 0x1b || (c < 0x20 && c != '\n' && c != '\t') {
				t.Fatalf("%v printed byte %#x from the relay's name:\n%q", args, c, out)
			}
		}
	}
	if out := bob.run("lookup", fp); !strings.Contains(out, "name on relay: "+escaped+"\n") {
		t.Fatalf("lookup does not show the name escaped:\n%s", out)
	}
	var out lookupJSON
	if err := json.Unmarshal([]byte(bob.run("lookup", fp, "--json")), &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != escaped {
		t.Fatalf("lookup --json carries the name as %q, want %q", out.Name, escaped)
	}
	if _, err := identity.ParseExportLine(out.ExportLine); err == nil {
		t.Fatal("the export line built from a hostile name parses")
	}
}

// TestAnEmptyAttachmentIsDeliveredNotAckedAway: 'auu send --attach empty'
// as a stream used to succeed at the sender and arrive as a truncated
// stream at the receiver, who kept the manifest as damaged and
// acknowledged the message away: silent loss. The empty file arrives now,
// alone and beside a large one, as an empty file in the attachment
// directory.
func TestAnEmptyAttachmentIsDeliveredNotAckedAway(t *testing.T) {
	relayURL, _ := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "empty alone", "--stream", "--attach", empty, "nothing in it")
	alice.run("send", "--to", "bob", "--subject", "empty last", "--attach", big, "--attach", empty, "one of each")
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Delivered != 2 || inbox.Fetch.Unreadable != 0 {
		t.Fatalf("the fetch says %+v, want both delivered and nothing unreadable", inbox.Fetch)
	}
	for _, subject := range []string{"empty alone", "empty last"} {
		rec := recordOf(t, bob, store.Inbox, subject)
		if !rec.Streamed {
			t.Fatalf("%q did not arrive as a stream", subject)
		}
		bs, _, _ := bob.opened()
		// The spool keeps attachments by their position, not their name.
		at := -1
		for i, a := range rec.Inner.Body.Attachments {
			if a.Name == "empty.txt" {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("%q: the record has no attachment named empty.txt", subject)
		}
		path := filepath.Join(bs.AttachmentDir(store.Inbox, rec.Inner.ID), stream.SpoolName(at))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%q: the empty attachment is not there: %v", subject, err)
		}
		if info.Size() != 0 {
			t.Fatalf("%q: the empty attachment has %d bytes", subject, info.Size())
		}
	}
}

// TestAStreamThatNeedsANewerAuuDoesNotStopTheFetch: a stream whose signed
// manifest carries a critical section this build does not know is one it
// cannot open yet. The manifest reader says so after the signature, and a
// receiver that took that for a transport failure would leave it on the
// relay with the cursor unmoved, so that every fetch stopped at it and the
// message behind it never arrived: anyone the relay let post a stream could
// close a mailbox with one. It waits on the relay, recorded, with the
// cursor past it (D42), and the good message behind it is delivered.
func TestAStreamThatNeedsANewerAuuDoesNotStopTheFetch(t *testing.T) {
	srv, st, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	bobFP := bob.exportFingerprint()

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
	payload := []byte("the payload of a stream nobody here can read")
	sources := []stream.Source{{
		Name: "later.bin", Media: "application/octet-stream", Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
	}}
	messageID, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	m, err := stream.BuildManifestSections(id, to, messageID,
		stream.Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: "from a newer build", Text: "streamed"},
		sources, stream.DefaultChunkSize,
		[]wire.Section{{Name: "must-know", Critical: true, Data: json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, id, to, m, sources); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, bobFP, "", int64(blob.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(blob.Bytes()), int64(blob.Len())); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "the good one", "hello")
	if queued, err := st.List(bobFP, 0, 10); err != nil || len(queued) != 2 {
		t.Fatalf("queued %d (%v), want 2", len(queued), err)
	}

	var out string
	var runErr error
	stderr := captureStderr(t, func() { out, runErr = bob.tryRun("inbox", "--json") })
	if runErr != nil {
		t.Fatalf("a stream that needs a newer auu stopped the fetch: %v\nstdout: %s\nstderr: %s", runErr, out, stderr)
	}
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	if inbox.Fetch.Delivered != 1 || inbox.Fetch.Unreadable != 0 || len(inbox.Fetch.Newer) != 1 {
		t.Fatalf("fetch: %+v, want the good message delivered and the stream waiting on the relay", inbox.Fetch)
	}
	if !spoolHas(t, bob, store.Inbox, "the good one") {
		t.Error("the good message behind the stream is not in the inbox")
	}
	stderr = captureStderr(t, func() { out, runErr = bob.tryRun("inbox", "--json") })
	if runErr != nil {
		t.Fatalf("the second inbox failed: %v\n%s", runErr, stderr)
	}
	var again inboxJSON
	if err := json.Unmarshal([]byte(out), &again); err != nil {
		t.Fatal(err)
	}
	if !again.Fetch.empty() {
		t.Fatalf("the second fetch met the stream again: %+v", again.Fetch)
	}
}
