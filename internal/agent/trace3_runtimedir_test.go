//go:build unix

// Off Windows: the link the runtime directory refuses is planted with
// os.Symlink, which on Windows needs a privilege a test cannot count on,
// and the mode the tests read is a Unix mode Windows does not keep, so
// there the runtime directory is the Lstat-only twin and is not run here.

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortBase is a short XDG_RUNTIME_DIR for the test, as runtimeDirFor makes
// one: t.TempDir on macOS can push a socket path past 104 bytes.
func shortBase(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

// looseTarget is a directory this user owns, mode 0755, somewhere other
// than the runtime base.
func looseTarget(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil { // past the umask
		t.Fatal(err)
	}
	return target
}

func permOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func entriesOf(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestARuntimeDirectoryThatIsALinkIsRefused (trace 3, F16): a link planted
// at the base's auu entry, pointing at a directory this user owns, is
// refused by name; the target keeps its mode, and the agent makes no
// socket, lock or log in it. A dangling link is named as a link too, since
// the path is looked at before MkdirAll, and a file there is not a
// directory.
func TestARuntimeDirectoryThatIsALinkIsRefused(t *testing.T) {
	t.Run("a link to this user's directory", func(t *testing.T) {
		base := shortBase(t)
		target := looseTarget(t)
		link := filepath.Join(base, runtimeSubdir)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		dir, err := runtimeDir()
		if err == nil {
			t.Fatalf("a symlink planted at %s was accepted as the runtime directory %q; its target is now mode %04o",
				link, dir, permOf(t, target))
		}
		if !strings.Contains(err.Error(), link+" is a symbolic link") {
			t.Fatalf("refusal = %q, want it to name %s as a symbolic link", err, link)
		}
		if got := permOf(t, target); got != 0o755 {
			t.Fatalf("the link's target is mode %04o after the refusal, want 0755 untouched", got)
		}
		// The agent's own start goes through the same door and leaves
		// nothing in the target.
		if l, err := Listen(t.TempDir()); err == nil {
			l.Close()
			t.Fatal("Listen served under a runtime directory that is a link")
		} else if !strings.Contains(err.Error(), "is a symbolic link") {
			t.Fatalf("Listen's refusal = %q, want the link named", err)
		}
		if names := entriesOf(t, target); len(names) != 0 {
			t.Fatalf("the link's target holds %v after the refusal, want nothing (no socket, lock or log)", names)
		}
		if got := permOf(t, target); got != 0o755 {
			t.Fatalf("the link's target is mode %04o after Listen, want 0755 untouched", got)
		}
	})

	t.Run("a dangling link", func(t *testing.T) {
		base := shortBase(t)
		target := filepath.Join(t.TempDir(), "not-yet")
		link := filepath.Join(base, runtimeSubdir)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, err := runtimeDir()
		if err == nil || !strings.Contains(err.Error(), link+" is a symbolic link") {
			t.Fatalf("runtimeDir over a dangling link = %v, want it named as a symbolic link", err)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("the dangling link's target was made: Lstat = %v", err)
		}
	})

	t.Run("a regular file", func(t *testing.T) {
		base := shortBase(t)
		file := filepath.Join(base, runtimeSubdir)
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runtimeDir()
		if err == nil || !strings.Contains(err.Error(), file+" is not a directory") {
			t.Fatalf("runtimeDir over a regular file = %v, want %q", err, file+" is not a directory")
		}
	})
}

// TestARuntimeDirectoryOfThisUsersIsTakenAndMade0700: a directory at the
// path this user owns with a loose mode is taken and made 0700 through the
// handle, one already 0700 is left so, and one that is not there is made
// 0700.
func TestARuntimeDirectoryOfThisUsersIsTakenAndMade0700(t *testing.T) {
	t.Run("loose", func(t *testing.T) {
		base := shortBase(t)
		want := filepath.Join(base, runtimeSubdir)
		if err := os.Mkdir(want, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(want, 0o755); err != nil {
			t.Fatal(err)
		}
		dir, err := runtimeDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != want {
			t.Fatalf("runtimeDir = %q, want %q", dir, want)
		}
		if got := permOf(t, dir); got != 0o700 {
			t.Fatalf("a 0755 runtime directory is mode %04o after runtimeDir, want 0700", got)
		}
	})
	t.Run("group loose", func(t *testing.T) {
		base := shortBase(t)
		want := filepath.Join(base, runtimeSubdir)
		if err := os.Mkdir(want, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(want, 0o750); err != nil {
			t.Fatal(err)
		}
		dir, err := runtimeDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != want {
			t.Fatalf("runtimeDir = %q, want %q", dir, want)
		}
		if got := permOf(t, dir); got != 0o700 {
			t.Fatalf("a 0750 runtime directory is mode %04o after runtimeDir, want 0700", got)
		}
	})
	t.Run("already 0700", func(t *testing.T) {
		base := shortBase(t)
		want := filepath.Join(base, runtimeSubdir)
		if err := os.Mkdir(want, 0o700); err != nil {
			t.Fatal(err)
		}
		dir, err := runtimeDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != want {
			t.Fatalf("runtimeDir = %q, want %q", dir, want)
		}
		if got := permOf(t, dir); got != 0o700 {
			t.Fatalf("mode %04o, want 0700", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		base := shortBase(t)
		want := filepath.Join(base, runtimeSubdir)
		dir, err := runtimeDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != want {
			t.Fatalf("runtimeDir = %q, want %q", dir, want)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("made %v, want a directory of mode 0700", info.Mode())
		}
	})
}

// TestALinkPutAfterTheLookIsRefusedByTheOpen: the race the O_NOFOLLOW open
// guards, a link at the path after notALink looked. holdRuntimeDir is
// called on the link directly; the open refuses it (ELOOP on Linux,
// ENOTDIR on darwin, either is a refusal) and the target keeps its mode.
func TestALinkPutAfterTheLookIsRefusedByTheOpen(t *testing.T) {
	base := shortBase(t)
	target := looseTarget(t)
	link := filepath.Join(base, runtimeSubdir)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := holdRuntimeDir(link)
	if err == nil {
		t.Fatalf("holdRuntimeDir followed the link at %s; its target is now mode %04o", link, permOf(t, target))
	}
	if !strings.Contains(err.Error(), "could not be opened as a directory of its own") {
		t.Fatalf("refusal = %q, want the open's refusal", err)
	}
	if got := permOf(t, target); got != 0o755 {
		t.Fatalf("the link's target is mode %04o after the refusal, want 0755 untouched", got)
	}
}
