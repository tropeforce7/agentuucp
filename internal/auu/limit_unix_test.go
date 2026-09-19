//go:build unix

package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// TestLimitAStreamedAttachmentThatIsNotAFileIsRefused: a delivered
// stream's attachment sits in the spool under its name until extract
// copies it out; the spool is this home's own, but what stands under the
// name is not taken on trust. With the file replaced by a FIFO, and in a
// second row by a symbolic link to /dev/null, extract refuses with the
// handle's sentence, writes nothing under --out, and a witness file
// beside the target is untouched — the link is refused as a link and
// never followed to the device.
func TestLimitAStreamedAttachmentThatIsNotAFileIsRefused(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	payload := make([]byte, 100<<10)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	file := filepath.Join(t.TempDir(), "dump.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--attach", file, "--json", "look")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Kind != "stream" {
		t.Fatalf("sent as %q, want a stream", sent.Kind)
	}
	var got inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("inbox: %+v", got.Messages)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	spooled := filepath.Join(s.AttachmentDir(store.Inbox, got.Messages[0].ID), "dump.bin")
	if _, err := os.Stat(spooled); err != nil {
		t.Fatalf("the delivered attachment is not in the spool: %v", err)
	}
	for _, plant := range []struct {
		what  string
		plant func() error
	}{
		{"a named pipe", func() error { return syscall.Mkfifo(spooled, 0o600) }},
		{"a symbolic link", func() error { return os.Symlink(os.DevNull, spooled) }},
	} {
		if err := os.Remove(spooled); err != nil {
			t.Fatal(err)
		}
		if err := plant.plant(); err != nil {
			t.Fatal(err)
		}
		scratch := t.TempDir()
		out := filepath.Join(scratch, "out")
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		witness := filepath.Join(out, "witness")
		if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := bob.tryRun("extract", got.Messages[0].ID, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "is "+plant.what+", not a regular file") {
			t.Errorf("%s in the spool: extract said %v; want the handle's sentence", plant.what, err)
		}
		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != "witness" {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("%s in the spool: extract left %v under --out; want the witness alone", plant.what, names)
		}
		if data, _ := os.ReadFile(witness); string(data) != "keep me\n" {
			t.Errorf("%s in the spool: the witness reads %q", plant.what, data)
		}
		if beside, _ := os.ReadDir(scratch); len(beside) != 1 {
			t.Errorf("%s in the spool: something appeared beside --out: %d entries", plant.what, len(beside))
		}
	}
}
