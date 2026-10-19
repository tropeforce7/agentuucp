//go:build unix

package regular

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestLimitAPlantedEntryIsRefusedByItsHandle: under a name that
// passes every name rule, a FIFO, a symbolic link to a device, a symbolic
// link to a regular file, a socket and a directory are each refused — the link as a
// link, not followed to what it points at — through Open, Create,
// OpenFile for append and ReadFile, with no byte written and no entry
// removed, and a witness file beside them untouched.
//
// The Windows half is TestLimitAPlantedLinkIsRefusedOnWindows: there a FIFO and a socket
// cannot be planted under a file's name, and what is planted is a
// symbolic link and a junction, opened with the reparse-point flag (S57).
func TestLimitAPlantedEntryIsRefusedByItsHandle(t *testing.T) {
	// A Unix socket's path is short by the platform's rule (104 bytes on
	// macOS), and a test's temporary directory is not, so the names here
	// are relative to it.
	dir := t.TempDir()
	t.Chdir(dir)
	witness := "witness"
	if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := "target.txt"
	if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := "fifo.txt"
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	toDevice := "device.txt"
	if err := os.Symlink(os.DevNull, toDevice); err != nil {
		t.Fatal(err)
	}
	toFile := "link.txt"
	if err := os.Symlink(filepath.Join(dir, target), toFile); err != nil {
		t.Fatal(err)
	}
	sock := "s.txt"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// A socket cannot be opened by open(2) at all: the platform refuses
	// it itself (ENXIO or EOPNOTSUPP), and that error passes through, so
	// for the socket the assertion is the refusal and not the sentence.
	plants := []struct {
		path, what string
		sentence   bool
	}{
		{fifo, "a named pipe", true},
		{toDevice, "a symbolic link", true},
		{toFile, "a symbolic link", true},
		{sock, "a socket", false},
	}
	for _, p := range plants {
		for _, try := range []struct {
			name string
			call func() (*os.File, error)
		}{
			{"Open", func() (*os.File, error) { return Open(p.path) }},
			{"OpenFile for append", func() (*os.File, error) { return OpenFile(p.path, os.O_WRONLY|os.O_APPEND, 0) }},
			{"Dir", func() (*os.File, error) { return Dir(p.path) }},
		} {
			// Dir follows a link, so for the two links it answers by what
			// they resolve to: a device and a regular file, each not a
			// directory; the sentence then names that, not the link.
			if try.name == "Dir" && p.what == "a symbolic link" {
				f, err := try.call()
				if f != nil {
					f.Close()
				}
				if err == nil || !strings.Contains(err.Error(), "not a directory") {
					t.Errorf("Dir of %s: %v, want a refusal naming what it resolves to", p.path, err)
				}
				continue
			}
			// Open of a FIFO for writing with nobody reading is the
			// platform's own refusal, ENXIO, passed through; every other
			// open of a plant is the handle's sentence. Neither blocks:
			// the first version of this test hung here, which is what
			// O_NONBLOCK in the helper is for.
			f, err := try.call()
			if p.what == "a named pipe" && try.name == "OpenFile for append" {
				if err == nil || f != nil {
					t.Errorf("append to a FIFO: %v, want the platform's refusal", err)
				}
				if f != nil {
					f.Close()
				}
				t.Logf("append to the FIFO: %v", err)
				continue
			}
			if f != nil {
				f.Close()
				t.Errorf("%s of %s returned a file", try.name, p.path)
			}
			var me *ModeError
			switch {
			case err == nil:
				t.Errorf("%s of %s succeeded", try.name, p.path)
			case !p.sentence:
				t.Logf("%s of %s: %v", try.name, p.path, err)
			case !errors.As(err, &me) || !strings.Contains(err.Error(), "is "+p.what):
				t.Errorf("%s of %s: %v, want the sentence naming %s", try.name, p.path, err, p.what)
			}
		}
		if _, err := Create(p.path, 0o600); !errors.Is(err, os.ErrExist) {
			t.Errorf("Create over %s: %v, want ErrExist", p.what, err)
		}
		if _, err := os.Lstat(p.path); err != nil {
			t.Errorf("%s was removed by a refusal: %v", p.path, err)
		}
	}
	if data, _ := os.ReadFile(target); string(data) != "target\n" {
		t.Errorf("the link's target was written through: %q", data)
	}
	if data, _ := os.ReadFile(witness); string(data) != "keep me\n" {
		t.Errorf("the witness was touched: %q", data)
	}
	// Dir follows a link to a directory, since the handle is the
	// directory's, and refuses a link to a file by what it resolves to.
	if err := os.Mkdir("realdir", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("realdir", "dirlink"); err != nil {
		t.Fatal(err)
	}
	if d, err := Dir("dirlink"); err != nil {
		t.Errorf("Dir of a link to a directory: %v, want it followed", err)
	} else {
		d.Close()
	}
	if d, err := Dir(toFile); err == nil || !strings.Contains(err.Error(), "is a regular file, not a directory") {
		if d != nil {
			d.Close()
		}
		t.Errorf("Dir of a link to a file: %v, want the mode sentence", err)
	}
	// A directory planted under a valid file name: Open refuses it by its
	// handle, Create finds it standing there, and it is left as it was.
	if err := os.Mkdir("planted.txt", 0o700); err != nil {
		t.Fatal(err)
	}
	if f, err := Open("planted.txt"); err == nil || !strings.Contains(err.Error(), "is a directory, not a regular file") {
		if f != nil {
			f.Close()
		}
		t.Errorf("Open of a planted directory: %v, want the mode sentence", err)
	}
	if _, err := Create("planted.txt", 0o600); !errors.Is(err, os.ErrExist) {
		t.Errorf("Create over a planted directory: %v, want ErrExist", err)
	}
	if fi, err := os.Lstat("planted.txt"); err != nil || !fi.IsDir() {
		t.Errorf("the planted directory was touched: %v", err)
	}
	// And a dangling link under the name is a link, not a missing file:
	// Create must not make the target.
	dangling := "dangling.txt"
	if err := os.Symlink("nowhere", dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dangling, 0o600); !errors.Is(err, os.ErrExist) {
		t.Errorf("Create over a dangling link: %v, want ErrExist", err)
	}
	if _, err := os.Stat("nowhere"); err == nil {
		t.Errorf("Create over a dangling link made its target")
	}
}
