package regular

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// ModeError is the one error of this package's own: the name opened, and
// the mode its handle reported, which is not the regular file (or, from
// Dir, the directory) that was asked for.
type ModeError struct {
	Path string
	Mode fs.FileMode
	// WantDir says Dir asked, so the sentence says a directory was wanted.
	WantDir bool
	// Handed says an exclusive create succeeded and the platform handed
	// back a device under the name, as Windows does for CON; nothing was
	// written and nothing was removed.
	Handed bool
}

func (e *ModeError) Error() string {
	what := describe(e.Mode)
	switch {
	case e.Handed:
		return fmt.Sprintf("%q is %s the platform opened under that name, not a regular file; nothing was written and it was not removed", e.Path, what)
	case e.WantDir:
		return fmt.Sprintf("%q is %s, not a directory", e.Path, what)
	}
	return fmt.Sprintf("%q is %s, not a regular file", e.Path, what)
}

// describe is a mode in words.
func describe(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "a regular file"
	case m.IsDir():
		return "a directory"
	case m&fs.ModeSymlink != 0:
		return "a symbolic link"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0, m&fs.ModeCharDevice != 0:
		return "a device"
	}
	return fmt.Sprintf("mode %v", m)
}

// OpenFile is os.OpenFile with O_NOFOLLOW and O_NONBLOCK where the
// platform has them (a link is refused rather than followed; a FIFO opens
// rather than blocks, so its handle can be asked), and then the handle
// check: the file is returned only if its handle says it is a regular
// file, settled back into blocking mode. The open's own error is returned
// exactly as os gave it, so errors.Is(err, os.ErrNotExist) and
// errors.Is(err, os.ErrExist) hold; a symbolic link refused by O_NOFOLLOW
// is a *ModeError. When the handle is not a regular file it is closed,
// and if this call made the entry (O_CREATE|O_EXCL succeeded) and what it
// made is not a device the platform handed back, the entry is removed.
func OpenFile(path string, flag int, perm fs.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|openFlags, perm)
	if err != nil {
		return nil, linkOr(path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	mode := fi.Mode()
	if mode.IsRegular() {
		settle(f)
		return f, nil
	}
	f.Close()
	made := flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL
	device := mode&(fs.ModeDevice|fs.ModeCharDevice) != 0
	if made && !device {
		os.Remove(path)
	}
	return nil, &ModeError{Path: path, Mode: mode, Handed: made && device}
}

// Open opens the named regular file for reading.
func Open(path string) (*os.File, error) {
	return OpenFile(path, os.O_RDONLY, 0)
}

// Create makes the named file, which must not exist, for writing: an
// existing entry under the name, whatever it is, is os.ErrExist.
func Create(path string, perm fs.FileMode) (*os.File, error) {
	return OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

// ReadFile reads the whole of the named regular file. A caller with a
// size cap applies it as it did.
func ReadFile(path string) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Dir opens the named directory, for a sync of its entries: the handle
// must say it is a directory. A symbolic link that resolves to a
// directory is followed, since what is synced is the directory the
// handle is on and an operator's home or authority behind a link is a
// directory all the same; a link to anything else is refused by the
// handle as what it points at.
func Dir(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|dirFlags, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi.IsDir() {
		settle(f)
		return f, nil
	}
	f.Close()
	return nil, &ModeError{Path: path, Mode: fi.Mode(), WantDir: true}
}

// linkOr is the open's error as os gave it, unless the platform refused a
// symbolic link under the name (ELOOP or EMLINK from O_NOFOLLOW) and
// Lstat confirms one, in which case it is the *ModeError for a link.
func linkOr(path string, err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) && isLoop(errno) {
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return &ModeError{Path: path, Mode: fi.Mode()}
		}
	}
	return err
}
