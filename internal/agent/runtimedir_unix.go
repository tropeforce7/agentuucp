//go:build unix

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// holdRuntimeDir opens the runtime directory itself, never through a link,
// and judges what it opened: the owner and the mode from the handle, so a
// link put at the path after notALink looked is refused by the open rather
// than followed. A mode open to anyone else is refused, not mended: what
// another user put there while it was open, a socket bound to take the
// passphrase, would outlast a chmod, so the person looks before it is
// used. darwin answers ENOTDIR rather than ELOOP for a link opened so,
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
		return fmt.Errorf("agent: %s is mode %04o: the agent's directory is yours alone, and one "+
			"other users can reach may hold what they put there; look at what is in it and make "+
			"it 0700 (chmod 0700 %s), or set XDG_RUNTIME_DIR to a directory of your own", dir, perm, dir)
	}
	return nil
}
