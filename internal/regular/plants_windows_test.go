package regular

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLimitAPlantedLinkIsRefusedOnWindows, the Windows half of
// TestLimitAPlantedEntryIsRefusedByItsHandle: every open carries
// FILE_FLAG_OPEN_REPARSE_POINT, so a symbolic link to a regular
// file under a name is refused as a link through Open, OpenFile for
// append and ReadFile, Create refuses it as an existing entry, and the
// file it points at and a witness beside it are untouched (S57). A
// junction is a mount point: at a file's name it is refused saying so,
// and Dir, which follows a link to a directory, still opens through it. A
// plain file opens as it always did, and a file compact compresses, a
// reparse point of another tag, is read as itself or refused by its mode,
// whichever Windows makes it, logged.
//
// A symbolic link needs the privilege or developer mode, and the test
// skips that part with the reason where os.Symlink fails; a junction needs
// neither and is made with cmd's mklink /J, since the standard library
// makes none. A FIFO and a socket cannot be planted under a file's name
// here, which is the unix half's.
func TestLimitAPlantedLinkIsRefusedOnWindows(t *testing.T) {
	dir := t.TempDir()
	witness := filepath.Join(dir, "witness")
	if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("plain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(plain); err != nil || string(data) != "plain\n" {
		t.Fatalf("a plain file: %q, %v", data, err)
	}

	t.Run("a symbolic link to a regular file", func(t *testing.T) {
		target := filepath.Join(dir, "target.txt")
		if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.txt")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("no symbolic link can be made here (the privilege or developer mode): %v", err)
		}
		for _, try := range []struct {
			name string
			call func() error
		}{
			{"Open", func() error { f, err := Open(link); closeIf(f); return err }},
			{"OpenFile for append", func() error {
				f, err := OpenFile(link, os.O_WRONLY|os.O_APPEND, 0)
				if f != nil {
					f.Write([]byte("written through\n"))
				}
				closeIf(f)
				return err
			}},
			{"ReadFile", func() error { _, err := ReadFile(link); return err }},
		} {
			// An open of the link's own object for writing may be the
			// platform's refusal rather than the handle's, passed through
			// as it came; either is a refusal, and the target below is the
			// proof nothing went through. Which it was is logged.
			var me *ModeError
			err := try.call()
			switch {
			case err == nil:
				t.Errorf("%s of a link succeeded", try.name)
			case try.name == "OpenFile for append" && !errors.As(err, &me):
				t.Logf("%s of a link, refused by the platform: %v", try.name, err)
			case !errors.As(err, &me) || !strings.Contains(err.Error(), "is a symbolic link, not a regular file"):
				t.Errorf("%s of a link: %v, want it refused as a link", try.name, err)
			default:
				t.Logf("%s of a link: %v", try.name, err)
			}
		}
		if f, err := Create(link, 0o600); !errors.Is(err, os.ErrExist) {
			closeIf(f)
			t.Errorf("Create over a link: %v, want ErrExist", err)
		}
		if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the link was removed or replaced: %v", err)
		}
		if data, _ := os.ReadFile(target); string(data) != "target\n" {
			t.Errorf("the link's target was written through: %q", data)
		}

		// The agent log's open, O_CREATE|O_TRUNC: with the flag, Go's
		// truncate inside the open touches the link's own object and never
		// the target, and a dangling link's target is not made. What
		// became of the link's entry is Windows's to say, and logged: if
		// the truncate stripped its reparse data, the handle reads as a
		// plain empty file and is used, which is safe, since it is the
		// program's own name and nothing of the target is in it.
		for _, c := range []struct{ name, to string }{
			{"to a regular file", target},
			{"to a name that is not there", filepath.Join(dir, "not-yet.txt")},
		} {
			link := filepath.Join(dir, "log-link-"+strings.ReplaceAll(c.name, " ", "-"))
			if err := os.Symlink(c.to, link); err != nil {
				t.Fatal(err)
			}
			f, err := OpenFile(link, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			closeIf(f)
			entry := "gone"
			if info, lerr := os.Lstat(link); lerr == nil {
				entry = info.Mode().String()
			}
			t.Logf("O_CREATE|O_TRUNC through a link %s: %v; the link's entry is now %s", c.name, err, entry)
		}
		if data, _ := os.ReadFile(target); string(data) != "target\n" {
			t.Errorf("a truncating open through a link emptied its target: %q", data)
		}
		if _, err := os.Lstat(filepath.Join(dir, "not-yet.txt")); !os.IsNotExist(err) {
			t.Errorf("a creating open through a dangling link made its target: %v", err)
		}
	})

	t.Run("a junction", func(t *testing.T) {
		real := filepath.Join(dir, "realdir")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(dir, "junction")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, real).CombinedOutput(); err != nil {
			t.Skipf("no junction can be made here: %v\n%s", err, out)
		}
		f, err := Open(junction)
		closeIf(f)
		var me *ModeError
		if !errors.As(err, &me) || me.Reparse != ReparseDirectory || !strings.Contains(err.Error(), "is a mount point or another directory's reparse point") {
			t.Errorf("Open of a junction: %v, want it refused as a mount point", err)
		}
		t.Logf("Open of a junction: %v", err)
		d, err := Dir(junction)
		if err != nil {
			t.Errorf("Dir through a junction: %v, want it followed", err)
		}
		closeIf(d)
	})

	// A file compact /exe compresses is a reparse point of another tag
	// (WOF), opened again without the flag. What Go then reports of it is
	// Windows's to say, and the log is the record: the open either reads
	// the file's own bytes or is refused by its mode, as an open of it
	// was before.
	t.Run("a compressed file", func(t *testing.T) {
		packed := filepath.Join(dir, "packed.exe")
		body := []byte(strings.Repeat("the file's own bytes\n", 4096))
		if err := os.WriteFile(packed, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("compact", "/c", "/exe:xpress4k", packed).CombinedOutput(); err != nil {
			t.Skipf("compact could not compress the file here: %v\n%s", err, out)
		}
		info, _ := os.Lstat(packed)
		data, err := ReadFile(packed)
		var me *ModeError
		switch {
		case err == nil && string(data) != string(body):
			t.Errorf("a compressed file read as %d bytes that are not its own", len(data))
		case err != nil && !errors.As(err, &me):
			t.Errorf("a compressed file: %v, want its bytes or a refusal by its mode", err)
		}
		t.Logf("a compressed file (Lstat mode %v): read %d bytes, %v", info.Mode(), len(data), err)
	})

	if data, _ := os.ReadFile(witness); string(data) != "keep me\n" {
		t.Errorf("the witness was touched: %q", data)
	}
}

func closeIf(f *os.File) {
	if f != nil {
		f.Close()
	}
}
