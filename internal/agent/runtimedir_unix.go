//go:build unix

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// holdRuntimeDir opens the runtime directory itself, never through a link,
// and judges and changes what it opened: the owner and the mode from the
// handle, and a loose mode made 0700 through the handle, so a link put at
// the path after notALink looked is refused by the open rather than
// followed. darwin answers ENOTDIR rather than ELOOP for a link opened so,
// which is why notALink names a link from Lstat first.
func holdRuntimeDir(dir string) error {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("agent: %s could not be opened as a directory of its own: %w; set XDG_RUNTIME_DIR to a directory of your own", dir, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("agent: %s is not a directory; remove it, or set XDG_RUNTIME_DIR to a directory of your own", dir)
	}
	if !ownedByMe(info) {
		return notOwned(dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := f.Chmod(0o700); err != nil {
			return fmt.Errorf("agent: %s is mode %04o and could not be made 0700: %w", dir, perm, err)
		}
	}
	return nil
}
