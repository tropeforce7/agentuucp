package pki

import (
	"bytes"
	"crypto/mldsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestARelayIssuedInAnotherCaseIsTheSameRecord: a DNS name is one name in
// any case (S62), so a rotation that spells the relay's host in capitals,
// or lists its hosts in another order and case, finds the record the first
// issue filed, keeps its retired client intermediate, and files under the
// one lower-case directory. It used to compare hosts byte for byte and
// keep the case in the directory's name, so on a filesystem that folds
// case the second issue wrote a fresh record over the first, the retired
// intermediate lost, and on one that does not it filed a second relay.
func TestARelayIssuedInAnotherCaseIsTheSameRecord(t *testing.T) {
	s := TestStore(t, mldsa.MLDSA65())
	if _, err := s.IssueRelay([]string{"relay.example.com", "b.example"}, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	// No host of a rotation is spelled as the record has it, so only the
	// fold finds the record: the record keeps the hosts the last issue
	// gave.
	for i, hosts := range [][]string{{"RELAY.example.com"}, {"B.example", "Relay.Example.COM"}} {
		if _, err := s.IssueRelay(hosts, 1, time.Now()); err != nil {
			t.Fatal(err)
		}
		relays, err := s.Relays()
		if err != nil {
			t.Fatal(err)
		}
		if len(relays) != 1 || relays[0] != "relay.example.com" {
			t.Fatalf("after %v the store files %v; want the one relay.example.com", hosts, relays)
		}
		rec, err := s.Record("RELAY.EXAMPLE.COM")
		if err != nil {
			t.Fatal(err)
		}
		if want := i + 2; len(rec.ClientInts) != want {
			t.Fatalf("after %v the record holds %d client intermediates; want %d, the retired kept", hosts, len(rec.ClientInts), want)
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.Dir(), relaysDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "relay.example.com" {
		t.Fatalf("the relays directory holds %v", entries)
	}
}

// TestARecordDirectoryFromBeforeTheFoldIsRefusedByName: an auu-ca from
// before S62 filed a record under its host as given, capitals and all. Read
// under its lower-case name it would be another relay's record, or none,
// and its retired intermediates lost, so a listed directory whose name is
// not its own lower-case form is refused by name, saying what it should be
// called, at every lookup that lists the records, and nothing is read from
// it or written. Two directories in two cases, which a filesystem that
// does not fold can hold, are refused the same way. The rule is by name,
// so the test plants the directory on every platform: where the disk
// folds, the planted name is the only one there.
func TestARecordDirectoryFromBeforeTheFoldIsRefusedByName(t *testing.T) {
	for _, pair := range []bool{false, true} {
		s := TestStore(t, mldsa.MLDSA65())
		relays := filepath.Join(s.Dir(), relaysDir)
		if pair {
			if _, err := s.IssueRelay([]string{"relay.example.com"}, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		old := filepath.Join(relays, "RELAY.example.com")
		if err := os.MkdirAll(old, 0o700); err != nil {
			t.Fatal(err)
		}
		kept := []byte(`{"hosts":["RELAY.example.com"],"client_intermediates":[],"updated":"2026-01-01T00:00:00Z","bundle_path":""}`)
		if err := os.WriteFile(filepath.Join(old, relayRecordFile), kept, 0o600); err != nil {
			t.Fatal(err)
		}
		if pair {
			if entries, _ := os.ReadDir(relays); len(entries) != 2 {
				// The disk folds the two names into one directory, so there
				// is no pair to refuse here; the single name is the case
				// above.
				t.Log("the disk folds RELAY.example.com onto relay.example.com, so no pair is planted")
				continue
			}
		}
		before := snapshot(t, s.Dir())
		_, err := s.Relays()
		_, _, ferr := s.FindRecord([]string{"relay.example.com"})
		_, ierr := s.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
		for what, e := range map[string]error{"Relays": err, "FindRecord": ferr, "IssueRelay": ierr} {
			if e == nil || !strings.Contains(e.Error(), old+" was filed by an auu-ca from before") ||
				!strings.Contains(e.Error(), "rename it to "+filepath.Join(relays, "relay.example.com")) {
				t.Errorf("pair %v: %s with an old record directory: %v", pair, what, e)
			}
		}
		if after := snapshot(t, s.Dir()); !sameSnapshot(before, after) {
			t.Errorf("pair %v: a refused old record directory changed the store", pair)
		}
	}
}

func snapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = data
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}
