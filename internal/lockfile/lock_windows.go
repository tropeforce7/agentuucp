package lockfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errSharingViolation is ERROR_SHARING_VIOLATION, which the syscall package
// does not name: the answer to opening a file another handle has open with
// no sharing allowed.
const errSharingViolation = syscall.Errno(32)

// Lock is a held lock. Windows has no flock; what it has is sharing modes,
// and a file opened with none lets nobody else open it until the handle is
// closed, which the kernel does for a process that dies. That is flock's
// shape: held for the holder's lifetime, never stale. The project is not
// tested on Windows by hand; CI runs the agent's tests there. See
// IMPLEMENTATION_NOTES.md.
type Lock struct{ f *os.File }

// Try takes the lock or reports ErrHeld at once.
func Try(path string) (*Lock, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errSharingViolation) {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return &Lock{f: os.NewFile(uintptr(h), path)}, nil
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
