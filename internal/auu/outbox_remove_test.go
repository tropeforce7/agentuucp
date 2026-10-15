package auu

import (
	"os"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A drop that cannot remove the copy's record says so and is not a drop
// (G43, R59): the copy still waits, is not marked given up, and nothing
// says "dropped". The removal's errors were thrown away, so a person was
// told a copy was dropped that the next 'send --resume' delivered. Once
// the outbox can be written, the drop goes through and the resume sends
// nothing of it.
func TestOutboxDropRefusesWhatItCannotRemove(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob, _ := threePeers(t)
	id, _ := sealCopies(t, alice, "bob", "carol")
	s, _, _ := alice.opened()
	dir := outboxDir(s)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	out, err := alice.tryRun("outbox", "drop", id, "bob")
	if err == nil {
		t.Fatalf("the drop succeeded with the outbox unwritable: %s", out)
	}
	if strings.Contains(out, "dropped the") || !strings.Contains(err.Error(), "was not dropped") {
		t.Fatalf("the refused drop said %q, %v", out, err)
	}
	waiting, broken := outboxOf(t, alice)
	if len(waiting) != 2 || len(broken) != 0 {
		t.Fatalf("after the refused drop: %d waiting, %v broken; want both copies still whole", len(waiting), broken)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	alice.run("outbox", "drop", id, "bob")
	alice.run("send", "--resume", "--json")
	for _, m := range bob.inboxJSON().Messages {
		if m.ID == id {
			t.Fatal("the copy dropped once the outbox could be written was delivered by send --resume")
		}
	}
}

// A copy sent whose outbox record cannot be removed after it is said, with
// the record's path and that the next resume would send it, and the send
// still succeeds (G43, R59): the record and its bytes were left without a
// word, to be sent again.
func TestASentCopyWhoseRecordStaysIsSaid(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob, _ := threePeers(t)
	id, _ := sealCopies(t, alice, "bob", "carol")
	s, _, _ := alice.opened()
	dir := outboxDir(s)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	var runErr error
	said := captureStderr(t, func() { _, runErr = alice.tryRun("send", "--resume", "--json") })
	if runErr != nil {
		t.Fatalf("the resume failed: %v\n%s", runErr, said)
	}
	if !strings.Contains(said, "could not be removed") || !strings.Contains(said, "would send that copy") {
		t.Fatalf("the record left behind was said as:\n%s", said)
	}
	delivered := false
	for _, m := range bob.inboxJSON().Messages {
		delivered = delivered || m.ID == id
	}
	if !delivered {
		t.Fatal("the copy was not sent")
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 2 {
		t.Fatalf("%d records left; want both, since neither could be removed", len(waiting))
	}
}

// A refused drop leaves the copy waiting in its sent record too, so that
// auu read says it waits, which it does (G43, R59a).
func TestARefusedDropLeavesTheSentCopyWaiting(t *testing.T) {
	skipUnlessPermissionsHold(t)
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 100
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol")
	out, _ := us[0].tryRun("send", "--to", "bob,carol", "--json", "hello")
	id := sentMany(t, out).ID
	s, _, _ := us[0].opened()
	dir := outboxDir(s)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := us[0].tryRun("outbox", "drop", id[:8], "carol"); err == nil {
		t.Fatal("the drop succeeded with the outbox unwritable")
	}
	if m := us[0].stored(store.Sent, id); m.Copies[0].Dropped || m.Copies[1].Dropped {
		t.Fatalf("a refused drop marked a copy given up: %+v", m.Copies)
	}
}
