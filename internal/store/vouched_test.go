package store

import (
	"os"
	"strings"
	"testing"
)

// Removing a peer edits the file and leaves every other line as it was
// written. The file has two entries added on a peer's word, each with its
// vouched-for comment above it, a comment a person wrote by hand, a blank
// line and a plain entry; removing the second vouched peer takes that
// entry and its comment and nothing else, every other line byte for byte.
// The RemovePeer before this rewrote the file from the parsed entries, and
// every comment went whenever any peer did.
func TestRemovingAPeerKeepsEveryOtherLine(t *testing.T) {
	s := newStore(t)
	alice, bob, carol := peer(t, "alice"), peer(t, "bob"), peer(t, "carol")
	noteA := VouchedPrefix + "vic (1111111111111111) on 2026-09-29"
	noteB := VouchedPrefix + "vic (2222222222222222) on 2026-09-30"
	file := "# my peers, kept by hand\n" +
		noteA + "\n" +
		alice.ExportLine() + "\n" +
		"\n" +
		noteB + "\n" +
		bob.ExportLine() + "\n" +
		carol.ExportLine() + "\n"
	if err := os.WriteFile(s.path(peersFile), []byte(file), fileMode); err != nil {
		t.Fatal(err)
	}

	removed, err := s.RemovePeer(bob.Fingerprint())
	if err != nil || !removed {
		t.Fatalf("RemovePeer: %v, %v", removed, err)
	}
	got, err := os.ReadFile(s.path(peersFile))
	if err != nil {
		t.Fatal(err)
	}
	want := "# my peers, kept by hand\n" +
		noteA + "\n" +
		alice.ExportLine() + "\n" +
		"\n" +
		carol.ExportLine() + "\n"
	if string(got) != want {
		t.Fatalf("after removing bob the file is\n%s\nwant\n%s", got, want)
	}

	// A peer with no comment above it takes no comment with it, even when
	// the line above is one: the hand comment above alice's note stays when
	// a plain entry is removed, and so does alice's note.
	if _, err := s.RemovePeer(carol.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(s.path(peersFile))
	if want := "# my peers, kept by hand\n" + noteA + "\n" + alice.ExportLine() + "\n" + "\n"; string(got) != want {
		t.Fatalf("after removing carol the file is\n%s\nwant\n%s", got, want)
	}
	// Removing somebody who is not there changes nothing.
	if removed, err := s.RemovePeer(bob.Fingerprint()); err != nil || removed {
		t.Fatalf("removing an absent peer: %v, %v", removed, err)
	}
	if again, _ := os.ReadFile(s.path(peersFile)); string(again) != string(got) {
		t.Fatalf("removing an absent peer changed the file:\n%s", again)
	}
}

// A note is written directly above the entry it is about, in the same
// write, and only a note of the one shape this program writes is taken.
func TestAPeerAddedOnAVouchCarriesItsNote(t *testing.T) {
	s := newStore(t)
	alice, bob := peer(t, "alice"), peer(t, "bob")
	if _, err := s.AddPeer(alice); err != nil {
		t.Fatal(err)
	}
	note := VouchedPrefix + "alice (" + alice.Fingerprint()[:16] + ") on 2026-10-01"
	if added, err := s.AddPeerNoted(bob, note); err != nil || !added {
		t.Fatalf("AddPeerNoted: %v, %v", added, err)
	}
	got, _ := os.ReadFile(s.path(peersFile))
	if want := alice.ExportLine() + "\n" + note + "\n" + bob.ExportLine() + "\n"; string(got) != want {
		t.Fatalf("the file is\n%s\nwant\n%s", got, want)
	}
	peers, err := s.Peers()
	if err != nil || len(peers) != 2 {
		t.Fatalf("the file with a note reads as %d peers: %v", len(peers), err)
	}
	for _, bad := range []string{"", "# a comment of some other kind", note + "\n# a second line", "vouched for by alice"} {
		carol := peer(t, "carol")
		if _, err := s.AddPeerNoted(carol, bad); err == nil || !strings.Contains(err.Error(), "a peer's note is one line beginning") {
			t.Errorf("note %q: %v; want the refusal", bad, err)
		}
	}
	if again, _ := os.ReadFile(s.path(peersFile)); string(again) != string(got) {
		t.Fatalf("a refused note changed the file:\n%s", again)
	}
}
