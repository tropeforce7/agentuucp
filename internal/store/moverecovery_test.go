package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAFailedStreamMoveDoesNotPublishTheInboxRecord(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix directory permissions as an ordinary user")
	}
	s := newStore(t)
	id := strings.Repeat("a", 32)
	m := stored(id, time.Now().UTC())
	m.Streamed = true
	if err := s.Save(Quarantine, m); err != nil {
		t.Fatal(err)
	}
	src := s.AttachmentDir(Quarantine, id)
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "0"), []byte("verified payload"), 0600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(src)
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0700) })
	err := s.Move(Quarantine, Inbox, id)
	if err == nil {
		t.Fatal("move should fail to rename out of non-writable quarantine")
	}
	t.Logf("move failed: %v", err)
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(src, "0")); err != nil || string(got) != "verified payload" {
		t.Fatalf("source should survive: %q %v", got, err)
	}
	// Find answers the box whose record is there; quarantine trust asks the
	// quarantine by name (TestTrustFindsTheQuarantinedRecordBesideAnInboxOne).
	box, _, err := s.Find(id)
	if err != nil {
		t.Fatal(err)
	}
	if box != Quarantine {
		t.Errorf("after failed move Find selects %s; retrying quarantine trust will refuse this message", box)
	}
	if _, err := os.Stat(filepath.Join(s.AttachmentDir(Inbox, id), "0")); !os.IsNotExist(err) {
		t.Fatalf("expected attachment still absent from inbox, got %v", err)
	}
	if rec, err := s.Holding(Inbox, id); err != nil || rec != nil {
		t.Errorf("failed move published incomplete destination record: present=%v err=%v", rec != nil, err)
	}
	// Direct Move can recover once permissions are restored; the CLI lookup
	// is what prevents the ordinary user retry from reaching it.
	if err := s.Move(Quarantine, Inbox, id); err != nil {
		t.Fatalf("direct retry control: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(s.AttachmentDir(Inbox, id), "0")); err != nil || string(got) != "verified payload" {
		t.Fatalf("retry payload: %q %v", got, err)
	}
}
