package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// leftAt is an entry for a relay id, with a message id made from it.
func leftAt(relayID int64) LeftEntry {
	return LeftEntry{RelayID: relayID, ID: strings.Repeat(string(rune('a'+relayID%6)), 32),
		Received: time.Date(2026, 10, 1, 2, 3, 4, 0, time.UTC), Size: 100 + relayID, From: aSigner}
}

// The left-behind file is the only record that this machine removed a
// message here and left it on the relay on purpose; without it the next
// fetch would call the home damaged.

func TestLeftBehindRecordsAndPrunes(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const name = "work"
	if ids, err := s.LeftBehind(name); err != nil || len(ids) != 0 {
		t.Fatalf("a relay with no file: %v %v", ids, err)
	}
	if err := s.AddLeftBehind(name, leftAt(7)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLeftBehind(name, leftAt(3)); err != nil {
		t.Fatal(err)
	}
	// The same relay id again changes nothing, whatever else it says.
	other := leftAt(7)
	other.Size = 1
	if err := s.AddLeftBehind(name, other); err != nil {
		t.Fatal(err)
	}
	ids, err2 := s.LeftBehind(name)
	if err2 != nil || len(ids) != 2 || ids[0] != leftAt(3) || ids[1] != leftAt(7) {
		t.Fatalf("LeftBehind = %v, %v; want 3 and 7 as written", ids, err2)
	}
	path := filepath.Join(s.relayDir(name), leftBehindFile)
	info, err3 := os.Stat(path)
	if err3 != nil {
		t.Fatal(err3)
	}
	// Go's FileMode on Windows says nothing about who can read a file; the
	// mode is Unix's, and the Windows job reported 666.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("the file is mode %04o, want 0600", perm)
	}
	want := "3 " + leftAt(3).ID + " 2026-10-01T02:03:04Z 103 " + aSigner + "\n7 " + leftAt(7).ID + " 2026-10-01T02:03:04Z 107 " + aSigner + "\n"
	if raw, err := os.ReadFile(path); err != nil || string(raw) != want {
		t.Fatalf("the file is %q (%v), want %q: one message per line, ascending by relay id", raw, err, want)
	}
	// It counts as left there, beside the records that carry a flag.
	if n, err := s.LeftOn(name); err != nil || n != 2 {
		t.Fatalf("LeftOn = %d (%v), want the two ids", n, err)
	}
	// Pruned to nothing: the file goes rather than sitting there empty.
	if err := s.SetLeftBehind(name, []LeftEntry{leftAt(7)}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.LeftOn(name); err != nil || n != 1 {
		t.Fatalf("LeftOn after the prune = %d (%v)", n, err)
	}
	if err := s.SetLeftBehind(name, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the file is still there with nothing to remember: %v", err)
	}
	if n, err := s.LeftOn(name); err != nil || n != 0 {
		t.Fatalf("LeftOn with the file gone = %d (%v)", n, err)
	}
}

// A file that is not entries is damaged and names itself: it is small, it
// is this machine's, and a guess at it would be a sentence about mail that
// is not there. A file of bare relay ids is the shape from before a line
// said which message it was, refused by name with what deleting it costs.
func TestADamagedLeftBehindFileIsDamaged(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const name = "work"
	if err := s.AddLeftBehind(name, leftAt(1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.relayDir(name), leftBehindFile)
	good := "1 " + leftAt(1).ID + " 2026-10-01T02:03:04Z 101 " + aSigner + "\n"
	for _, tc := range []struct{ text, want string }{
		{good + "not-an-entry\n", path + ` has "not-an-entry" on line 2, which is not a message left on the relay`},
		{"3\n7\n", path + " has a relay id alone on line 1: delete it; it was written before this file named each " +
			"message by its own id, and without it a message you removed here alone may come back once"},
		{good + "2 " + leftAt(1).ID + " yesterday 101 -\n", path + ` has "2 ` + leftAt(1).ID + ` yesterday 101 -" on line 2`},
		{good + "2 not-an-id 2026-10-01T02:03:04Z 101 -\n", path + ` has "2 not-an-id 2026-10-01T02:03:04Z 101 -" on line 2`},
		{good + "2 " + leftAt(1).ID + " 2026-10-01T02:03:04Z 101 - extra\n", path + ` has "2 ` + leftAt(1).ID + ` 2026-10-01T02:03:04Z 101 - extra" on line 2`},
		{good + "2  " + leftAt(1).ID + " 2026-10-01T02:03:04Z 101 -\n", path + ` has "2  ` + leftAt(1).ID},
		{good + "2 " + leftAt(1).ID + " 2026-10-01T02:03:04Z 101\n", path + ` has "2 ` + leftAt(1).ID + ` 2026-10-01T02:03:04Z 101" on line 2`},
		{good + "2 " + leftAt(1).ID + " 2026-10-01T02:03:04Z 101 ../" + aSigner[3:] + "\n", path + ` has "2 ` + leftAt(1).ID},
		{good + "2 " + leftAt(1).ID + " 2026-10-01T02:03:04Z 101 " + strings.ToUpper(aSigner) + "\n", path + ` has "2 ` + leftAt(1).ID},
	} {
		if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.LeftBehind(name)
		if err == nil || !errors.Is(err, ErrDamaged) || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%q: %v, want ErrDamaged beginning %q", tc.text, err, tc.want)
		}
		if _, err := s.LeftOn(name); err == nil || !errors.Is(err, ErrDamaged) {
			t.Errorf("LeftOn over %q: %v", tc.text, err)
		}
	}
}
