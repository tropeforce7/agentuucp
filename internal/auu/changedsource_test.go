package auu

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// An attachment changed between its hashing and its sealing is refused
// before anything is uploaded (G34, R49): the send names the file and says
// to send it again, the relay holds nothing, and the sealed copy is not
// left in the outbox. It used to be sealed under the old digest and sent,
// and its recipient kept it as damaged after the sender was told it went.
func TestAStreamSendRefusesAnAttachmentChangedSinceItsHashing(t *testing.T) {
	before := bytes.Repeat([]byte("a"), 100<<10)
	for name, after := range map[string][]byte{
		"changed at its size": bytes.Repeat([]byte("b"), len(before)),
		// Grown, which used to reach the payload's end and be refused only
		// as more bytes than the manifest declares, with no name (57a).
		"grown": append(bytes.Clone(before), 'b'),
	} {
		t.Run(name, func(t *testing.T) { changedSinceHashing(t, before, after) })
	}
}

// changedSinceHashing sends an attachment written as before and rewritten
// as after once its hashing has finished, and holds the send to the
// refusal: the sentence alone at the terminal, without the stream
// package's "stream: malformed" (57a), nothing uploaded, nothing left in
// the outbox.
func changedSinceHashing(t *testing.T, before, after []byte) {
	alice, bob, st := peered(t)
	s, me, rs := alice.opened()
	recipient, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "changing.bin")
	if err := os.WriteFile(file, before, 0600); err != nil {
		t.Fatal(err)
	}
	// Manifest hashing has finished when its signature is requested. Model
	// another process rewriting the attachment before the sealing read.
	f := &failingSigner{inner: me, at: 1, fault: func() error { return os.WriteFile(file, after, 0600) }}
	wrapped, err := identity.FromRemote(me.Suite(), me.Name, me.Public().Bundle(), f, me.KEM())
	if err != nil {
		t.Fatal(err)
	}
	_, err = sendStream(s, wrapped, rs[0], recipient, message.Body{Type: message.TypeAsk, Thread: strings.Repeat("a", 32), Subject: "changed source", Text: "attachment"}, []string{file}, streamSettings{chunkSize: stream.MinChunkSize}, "", "")
	var e *exitError
	if want := "changing.bin changed while it was being sent; send it again"; !asExit(err, &e) || e.code != exitUsage || err.Error() != want {
		t.Fatalf("a source changed after hashing: %v; want exit %d and %q", err, exitUsage, want)
	}
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("the relay holds %v; want nothing uploaded", left)
	}
	if pending, broken := outboxOf(t, alice); len(pending) != 0 || len(broken) != 0 {
		t.Fatalf("the outbox holds %d pending and %v broken; want the refused copy gone", len(pending), broken)
	}
	// The sealed file itself, which the listing above does not show
	// without its record.
	if entries, _ := os.ReadDir(filepath.Join(alice.home, "outbox")); len(entries) != 0 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the outbox directory holds %v; want nothing left of the refused send", names)
	}
}

// Only a changed attachment loses the stream package's prefix: any other
// stream the sender's sources could not make keeps its words, prefix and
// all, so the trim says what the stream package says and no less.
func TestOnlyAChangedAttachmentLosesTheStreamPrefix(t *testing.T) {
	other := fmt.Errorf("%w: the attachments produced more bytes than the manifest declares", stream.ErrForm)
	if got, want := streamFormErr(other).Error(), "stream: malformed: the attachments produced more bytes than the manifest declares"; got != want {
		t.Errorf("another form error says %q, want %q", got, want)
	}
	changed := fmt.Errorf("%w: f.bin %w", stream.ErrForm, stream.ErrChanged)
	err := streamFormErr(changed)
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || err.Error() != "f.bin changed while it was being sent; send it again" {
		t.Errorf("a changed attachment says %v", err)
	}
}
