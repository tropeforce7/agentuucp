//go:build !unix

package agent

import (
	"fmt"
	"io/fs"
	"os"
)

// holdRuntimeDir on a system with no O_NOFOLLOW for a directory: the path
// is looked at without following a link, again after MkdirAll, and must be
// a directory this user owns. Its mode is the system's to keep, as it
// always was here.
func holdRuntimeDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("agent: %s is a symbolic link, not a directory; remove it, or set XDG_RUNTIME_DIR to a directory of your own", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("agent: %s is not a directory; set XDG_RUNTIME_DIR to a directory of your own", dir)
	}
	if !ownedByMe(info) {
		return notOwned(dir)
	}
	return nil
}
