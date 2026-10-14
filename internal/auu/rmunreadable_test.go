package auu

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAnUnreadableRemovalKeepsTheRecordUntilTheLeftBehindEntryIsSaved(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix permissions as ordinary user")
	}
	alice, bob, st := peered(t)
	alice.run("send", "--to", "bob", "--subject", "remove locally", "payload")
	bob.run("inbox", "--json")
	s, _, _ := bob.opened()
	m := recordOf(t, bob, "inbox", "remove locally")
	path := filepath.Join(bob.home, "inbox", m.Inner.ID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A JSON record with a key the strict reader rejects, but its independently
	// validated relay/id fields remain available to RemoveByID's recovery path.
	raw = append([]byte("{\"review_unknown\":true,"), raw[1:]...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	relayDir := s.RelayDir(r)
	if err := os.Chmod(relayDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(relayDir, 0700) })
	if _, err := bob.tryRun("rm", "--local-only", m.Inner.ID); err == nil {
		t.Fatal("left-behind write should fail")
	}
	if err := os.Chmod(relayDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("failed removal already destroyed the only retry record: %v", err)
	}
	if _, err := bob.tryRun("rm", "--local-only", m.Inner.ID); err != nil {
		t.Errorf("retry after permissions restored: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the retried removal left the record: %v", err)
	}
	left, err := s.LeftBehind(r.Name)
	if err != nil || len(left) != 1 {
		t.Errorf("no durable left-behind record: %v %v", left, err)
	}
	if rows := adv2RowIDs(t, st, bob.exportFingerprint()); len(rows) != 1 {
		t.Fatalf("relay control: %v", rows)
	}
}
