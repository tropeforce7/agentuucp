package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

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
	if err := s.AddLeftBehind(name, 7); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLeftBehind(name, 3); err != nil {
		t.Fatal(err)
	}
	// The same id again changes nothing.
	if err := s.AddLeftBehind(name, 7); err != nil {
		t.Fatal(err)
	}
	ids, err2 := s.LeftBehind(name)
	if err2 != nil || len(ids) != 2 || ids[0] != 3 || ids[1] != 7 {
		t.Fatalf("LeftBehind = %v, %v; want 3 and 7", ids, err2)
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
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "3\n7\n" {
		t.Fatalf("the file is %q (%v), want one id per line, ascending", raw, err)
	}
	// It counts as left there, beside the records that carry a flag.
	if n, err := s.LeftOn(name); err != nil || n != 2 {
		t.Fatalf("LeftOn = %d (%v), want the two ids", n, err)
	}
	// Pruned to nothing: the file goes rather than sitting there empty.
	if err := s.SetLeftBehind(name, []int64{7}); err != nil {
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

// A file that is not ids is damaged and names itself: it is small, it is
// this machine's, and a guess at it would be a sentence about mail that is
// not there.
func TestADamagedLeftBehindFileIsDamaged(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const name = "work"
	if err := s.AddLeftBehind(name, 1); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.relayDir(name), leftBehindFile)
	if err := os.WriteFile(path, []byte("1\nnot-an-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err2 := s.LeftBehind(name)
	err = err2
	if err == nil || !errors.Is(err, ErrDamaged) {
		t.Fatalf("a damaged file: %v, want ErrDamaged", err)
	}
	if want := path + ` has "not-an-id" on line 2, which is not a message id`; err.Error()[:len(want)] != want {
		t.Fatalf("the sentence is %q, want it to begin %q", err, want)
	}
	if _, err := s.LeftOn(name); err == nil || !errors.Is(err, ErrDamaged) {
		t.Fatalf("LeftOn over a damaged file: %v", err)
	}
}
