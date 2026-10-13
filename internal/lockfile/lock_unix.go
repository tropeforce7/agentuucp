//go:build !windows

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/tropeforce7/agentuucp/internal/regular"
)

// Lock is a held lock: flock on the file, released by Release or by the
// kernel when the process exits.
type Lock struct{ f *os.File }

// Try takes the lock or reports ErrHeld at once.
func Try(path string) (*Lock, error) {
	// Never through a link: a lock file another user linked to a file of
	// this user's would be opened, and created, where they chose.
	f, err := regular.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// Release lets the lock go. A nil or released lock is nothing to release.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
