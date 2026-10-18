package auu

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// pendingBody is a body an outbox record may hold: the shape Load holds a
// sent record to, which listPending holds the record's to.
func pendingBody(thread string) message.Body {
	return message.Body{Type: message.TypeNote, Thread: thread, Text: "a pending message"}
}

// TestLimitAKeptUploadIDIsHeldToItsShape: an outbox record keeps the
// relay's upload id for a resume, which puts it in a request's path, and
// listPending held the record's id, recipient and relay to their rules but
// not the upload (F9, tracer B's CONCERN-5). A record whose upload is not
// 32 lowercase hex characters is now broken by name and not resumed; one
// with none yet, a stream not opened, and one with a good id are read.
func TestLimitAKeptUploadIDIsHeldToItsShape(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(streamPath(s, id), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(upload string) {
		t.Helper()
		p := pending{MessageID: id, To: strings.Repeat("c", 64), Relay: "relay", Started: time.Now(), Body: pendingBody(id),
			Upload: upload, Bytes: 5000, Chunks: 2, ChunkSize: stream.DefaultChunkSize}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pendingPath(s, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, upload := range []string{"../../v1/x", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("a", 30) + "/x"} {
		write(upload)
		waiting, broken, err := listPending(s)
		if err != nil || len(waiting) != 0 || len(broken) != 1 || broken[0] != id {
			t.Errorf("upload %q: waiting %d, broken %v, %v; want the record broken", upload, len(waiting), broken, err)
		}
	}
	for _, upload := range []string{"", strings.Repeat("a", 32)} {
		write(upload)
		waiting, broken, err := listPending(s)
		if err != nil || len(waiting) != 1 || len(broken) != 0 {
			t.Errorf("upload %q: waiting %d, broken %v, %v; want the record read", upload, len(waiting), broken, err)
		}
	}
}

// TestLimitAnOutboxRecordsBodyIsHeldAsLoadHoldsIt: the body an outbox
// record keeps becomes the sent record when the upload ends, and Load
// holds a sent record to Body.ValidShape, while listPending did not, so a
// record edited by hand was resumed and its sent copy found damaged later
// (the second trace's G). A record whose body would not read back is now
// broken where it is read; the body as written reads.
func TestLimitAnOutboxRecordsBodyIsHeldAsLoadHoldsIt(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(streamPath(s, id), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(body message.Body) {
		t.Helper()
		p := pending{MessageID: id, To: strings.Repeat("c", 64), Relay: "relay", Started: time.Now(), Body: body,
			Bytes: 5000, Chunks: 2, ChunkSize: stream.DefaultChunkSize}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pendingPath(s, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := pendingBody(id)
	for name, body := range map[string]message.Body{
		"no type":            {Thread: id, Text: "x"},
		"no thread":          {Type: message.TypeNote, Text: "x"},
		"a control in text":  {Type: message.TypeNote, Thread: id, Text: "x\x1b[2J"},
		"an attachment name": {Type: message.TypeNote, Thread: id, Attachments: []message.Attachment{{Name: "a\x00b", Media: "text/plain", SHA256: strings.Repeat("a", 64)}}},
	} {
		write(body)
		waiting, broken, err := listPending(s)
		if err != nil || len(waiting) != 0 || len(broken) != 1 {
			t.Errorf("%s: waiting %d, broken %v, %v; want the record broken", name, len(waiting), broken, err)
		}
	}
	write(good)
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 1 || len(broken) != 0 {
		t.Errorf("the body as written: waiting %d, broken %v, %v", len(waiting), broken, err)
	}
}
