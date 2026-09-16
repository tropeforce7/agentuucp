package pki

import (
	"bytes"
	"crypto/mldsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

func TestCreateTightensAnExistingDirectory(t *testing.T) {
	// An operator who ran mkdir first gets 0755, and this directory is about
	// to hold the keys everything rests on.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatalf("Create in a 0755 directory: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != dirMode {
		t.Errorf("directory is mode %04o after Create, want %04o", perm, dirMode)
	}
	// And it loads, which it would not have at 0755.
	if _, err := Open(dir, []byte(testSecret)); err != nil {
		t.Errorf("Open after Create: %v", err)
	}
}

func TestOpenRefusesADirectoryOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, []byte(testSecret))
	if err == nil {
		t.Fatal("a world-readable authority was opened")
	}
	for _, want := range []string{dir, "0755"} {
		if !contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestCreateRefusesADirectoryHoldingAnythingElse(t *testing.T) {
	// A mistyped --dir. Nothing in it may be touched: not its mode, and
	// not by having an authority written among its files.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now())
	if err == nil {
		t.Fatal("an authority was created in a directory holding other files")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("error %q does not say why", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("the refused directory's mode was changed to %04o", perm)
	}
	if _, err := os.Stat(filepath.Join(dir, anchorKeyFile)); err == nil {
		t.Error("a key was written into the refused directory")
	}
}

// TestEncodeBundleIsWhatWriteBundleWrites: a bundle sent down a pipe with
// --out - must be the same bytes a file would hold, or a relay could load
// one form and not the other. WriteBundle is implemented on EncodeBundle,
// which is what makes this an identity rather than a coincidence.
func TestEncodeBundleIsWhatWriteBundleWrites(t *testing.T) {
	s := TestStore(t, mldsa.MLDSA65())
	b, _, err := s.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, written) {
		t.Fatalf("EncodeBundle gives %d bytes and WriteBundle wrote %d; they differ", len(encoded), len(written))
	}
	// Equality alone is what the implementation guarantees; the format is
	// pinned against an oracle computed here, so a change to either shows.
	oracle, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, append(oracle, '\n')) {
		t.Fatal("the bundle encoding is not indented JSON with a trailing newline")
	}
	// And the bytes are a bundle a relay loads, not merely equal.
	if _, err := LoadBundle(path); err != nil {
		t.Fatal(err)
	}
}

// TestRecordBundlePathFindsTheRelayByAnyHost: the relay is the one a
// rotation finds, so a bundle written for the same hosts in another order
// updates the same record rather than filing a second one; the empty path
// is how "it went to standard output" is recorded and it clears what was
// there.
func TestRecordBundlePathFindsTheRelayByAnyHost(t *testing.T) {
	s := TestStore(t, mldsa.MLDSA65())
	hosts := []string{"relay.example.com", "10.0.0.5"}
	if _, _, err := s.IssueRelay(hosts, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A record from before the field has none: it decodes as unknown.
	rec, err := s.Record("relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.BundlePath != "" {
		t.Fatalf("a fresh record already has a bundle path %q", rec.BundlePath)
	}

	want := filepath.Join(t.TempDir(), "relay-bundle.json")
	if err := s.RecordBundlePath(hosts, want); err != nil {
		t.Fatal(err)
	}
	rec, err = s.Record("relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.BundlePath != want {
		t.Fatalf("recorded %q, want %q", rec.BundlePath, want)
	}

	// The hosts in another order, and only the second of them, find the
	// same record. The empty path clears it.
	other := filepath.Join(t.TempDir(), "again.json")
	if err := s.RecordBundlePath([]string{"10.0.0.5", "relay.example.com"}, other); err != nil {
		t.Fatal(err)
	}
	if rec, _ = s.Record("relay.example.com"); rec.BundlePath != other {
		t.Errorf("reordered hosts recorded %q, want %q", rec.BundlePath, other)
	}
	if err := s.RecordBundlePath([]string{"10.0.0.5"}, ""); err != nil {
		t.Fatal(err)
	}
	if rec, _ = s.Record("relay.example.com"); rec.BundlePath != "" {
		t.Errorf("standard output did not clear the path: %q", rec.BundlePath)
	}
	relays, err := s.Relays()
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 {
		t.Errorf("the store now has %d relays, want 1: %v", len(relays), relays)
	}
	// Nothing else about the record was disturbed.
	if len(rec.ClientInts) != 1 || len(rec.Hosts) != 2 {
		t.Errorf("recording a path changed the record: %+v", rec)
	}

	// A relay nothing was issued to has no record to put a path in, and a
	// relative path is not a place show could look.
	if err := s.RecordBundlePath([]string{"nobody.example.com"}, want); err == nil {
		t.Error("a path was recorded for a relay nothing was issued to")
	}
	if err := s.RecordBundlePath(hosts, "relative.json"); err == nil {
		t.Error("a relative path was recorded")
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), relaysDir, "nobody.example.com")); err == nil {
		t.Error("the refused relay got a directory")
	}
}
