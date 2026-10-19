package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/regular"
)

// TestLimitALockFileIsNeverOpenedThroughALinkOnWindows, the Windows half
// of TestLimitALockFileIsNeverOpenedThroughALink: CreateFile carries
// FILE_FLAG_OPEN_REPARSE_POINT, so a symbolic link at the lock path
// is opened as itself and refused by regular's sentence for a link, the
// file it points at unchanged and a path it names that does not exist not
// made; the link stays where it was put (S57). A symbolic link needs the
// privilege or developer mode, and the test skips with the reason where
// os.Symlink fails.
func TestLimitALockFileIsNeverOpenedThroughALinkOnWindows(t *testing.T) {
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
		if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "lock")
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("no symbolic link can be made here (the privilege or developer mode): %v", err)
		}
		l, err := Try(path)
		if err == nil {
			l.Release()
		}
		refused(t, path, err)
		if data, err := os.ReadFile(target); err != nil || string(data) != "keep me" {
			t.Fatalf("the link's target is now %q, %v", data, err)
		}
	})
	t.Run("to a path that does not exist", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "not-yet")
		path := filepath.Join(dir, "lock")
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("no symbolic link can be made here (the privilege or developer mode): %v", err)
		}
		l, err := Try(path)
		if err == nil {
			l.Release()
		}
		refused(t, path, err)
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("the lock made the link's target: %v", err)
		}
	})
}
