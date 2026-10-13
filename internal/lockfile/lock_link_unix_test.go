//go:build unix

package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/regular"
)

// TestLimitALockFileIsNeverOpenedThroughALink: a symbolic link at the lock
// path is refused as a link, never followed. One to a file of this user's
// own leaves that file as it was, its bytes and its mode, and one to a
// path that does not exist does not make it; the link itself stays where
// it was put.
func TestLimitALockFileIsNeverOpenedThroughALink(t *testing.T) {
	refused := func(t *testing.T, path string, err error) {
		t.Helper()
		var me *regular.ModeError
		if err == nil {
			t.Fatalf("Try took the lock through a symbolic link at %s", path)
		}
		if !errors.As(err, &me) || !strings.Contains(err.Error(), "is a symbolic link, not a regular file") {
			t.Fatalf("Try through a link = %v, want the link refused as one", err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the link at the lock path is gone or changed: %v, %v", info, err)
		}
	}

	t.Run("to a file of this user's own", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "precious")
		if err := os.WriteFile(target, []byte("keep me"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o644); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "lock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		l, err := Try(path)
		if err == nil {
			l.Release()
		}
		refused(t, path, err)
		b, err := os.ReadFile(target)
		if err != nil || string(b) != "keep me" {
			t.Fatalf("the link's target holds %q (%v), want %q untouched", b, err, "keep me")
		}
		if info, _ := os.Stat(target); info.Mode().Perm() != 0o644 {
			t.Fatalf("the link's target is mode %04o, want 0644 untouched", info.Mode().Perm())
		}
	})

	t.Run("to a missing path", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "not-yet")
		path := filepath.Join(dir, "lock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		l, err := Try(path)
		if err == nil {
			l.Release()
		}
		refused(t, path, err)
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("the dangling link's target was made: Lstat = %v", err)
		}
	})
}
