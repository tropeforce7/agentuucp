package auu

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

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
		p := pending{MessageID: id, To: strings.Repeat("c", 64), Relay: "relay", Started: time.Now(),
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
