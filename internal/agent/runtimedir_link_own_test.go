//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// F16 as the first review stated it, which had no test in the archive: a
// link planted at the runtime directory's path to a directory of this
// user's own is followed, and the target made 0700. Self-contained so it
// builds at the fix's parent.
func TestARuntimeDirectoryLinkToOwnDirectoryIsRefused(t *testing.T) {
	base, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	t.Setenv("XDG_RUNTIME_DIR", base)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(target, 0o755)
	if err := os.Symlink(target, filepath.Join(base, "auu")); err != nil {
		t.Fatal(err)
	}
	dir, err := runtimeDir()
	if err == nil {
		t.Errorf("a link at the runtime directory's path was taken: runtimeDir = %s", dir)
	}
	if info, _ := os.Stat(target); info != nil && info.Mode().Perm() != 0o755 {
		t.Errorf("the link's target was changed to %04o", info.Mode().Perm())
	}
}
