package lockfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/tropeforce7/agentuucp/internal/regular"
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

// Try takes the lock or reports ErrHeld at once. CreateFile carries
// FILE_FLAG_OPEN_REPARSE_POINT, as regular's opens do on Windows, so a
// link at the path is opened as itself and the handle refused as one, by
// regular's sentence, and a directory, a junction among them, is one
// CreateFile opens for neither reading nor writing without backup
// semantics and refuses itself: the lock is never taken through a link,
// as on unix, where it is opened through regular (S57). A file with
// another tag is the lock file all the same, since nothing is read from
// it.
func Try(path string) (*Lock, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, errSharingViolation) {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := regular.NotALink(path, fi); err != nil {
		f.Close()
		return nil, err
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
