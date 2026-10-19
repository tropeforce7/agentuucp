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
	// Reparse says what a Windows reparse point under the name was, where
	// the mode alone does not: a directory's, a mount point among them,
	// or one that was another file when it was opened again (S57).
	Reparse Reparse
}

// Reparse is what an open found a Windows reparse point to be, beyond its
// mode. Go reports a symbolic link as fs.ModeSymlink and every other tag,
// a mount point among them, as fs.ModeIrregular, and the handle's
// attributes tell a directory's from a file's.
type Reparse int

const (
	// ReparseNone is no reparse point, or one the mode says enough of.
	ReparseNone Reparse = iota
	// ReparseDirectory is a reparse point on a directory: a mount point
	// (a junction), or a directory with another tag.
	ReparseDirectory
	// ReparseChanged is a reparse point opened without the flag that
	// reached another file than the one opened with it.
	ReparseChanged
)

func (e *ModeError) Error() string {
	what := describe(e.Mode)
	switch {
	case e.Reparse == ReparseDirectory:
		return fmt.Sprintf("%q is a mount point or another directory's reparse point, not a regular file", e.Path)
	case e.Reparse == ReparseChanged:
		return fmt.Sprintf("%q is a reparse point that named another file when it was opened again, not a regular file", e.Path)
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
//
// On Windows the open carries FILE_FLAG_OPEN_REPARSE_POINT, so a reparse
// point under the name is opened as itself and judge decides from its
// handle: a symbolic link is refused as one, as O_NOFOLLOW refuses it on
// unix; a reparse point on a directory, a mount point among them, is
// refused saying so; and any other tag, a deduplicated file Go reports as
// regular among them, is never read or written through that handle, which
// would be the reparse point's own data and not the file's, but opened
// again without the flag, for the platform to open the file it stands for.
// That handle must be on the same file as the first, and is then judged
// as an open's always was: a deduplicated file is used, while a tag Go
// reports as irregular, a cloud placeholder among them, is refused, as it
// was before (S57).
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
	switch v, kind := judge(mode, attributesOf(fi)); v {
	case use:
		settle(f)
		return f, nil
	case reopen:
		f.Close()
		return openAgain(path, flag, perm, fi)
	case refuseReparse:
		f.Close()
		return nil, &ModeError{Path: path, Mode: mode, Reparse: kind}
	}
	f.Close()
	made := flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL
	device := mode&(fs.ModeDevice|fs.ModeCharDevice) != 0
	if made && !device {
		os.Remove(path)
	}
	return nil, &ModeError{Path: path, Mode: mode, Handed: made && device}
}

// verdict is what an open does with the handle it got.
type verdict int

const (
	use verdict = iota
	refuse
	refuseReparse
	reopen
)

// The two file attributes judge reads, as Windows numbers them; elsewhere
// attributesOf is zero and neither is ever set.
const (
	attributeDirectory    = 0x10
	attributeReparsePoint = 0x400
)

// judge is what the handle an open got says to do: use a regular file
// that is no reparse point; open again a regular file that is one, a
// deduplicated file, since the handle is on its reparse data; refuse a
// reparse point on a directory, saying what it is; open again any other
// reparse point Go reports as irregular, a symbolic link excepted, which
// its mode already names and refuse refuses as one; and refuse everything
// else by its mode, as before.
func judge(mode fs.FileMode, attributes uint32) (verdict, Reparse) {
	reparse := attributes&attributeReparsePoint != 0
	switch {
	case mode.IsRegular() && !reparse:
		return use, ReparseNone
	case mode.IsRegular():
		return reopen, ReparseNone
	case mode&fs.ModeIrregular == 0 || !reparse:
		return refuse, ReparseNone
	case attributes&attributeDirectory != 0:
		return refuseReparse, ReparseDirectory
	}
	return reopen, ReparseNone
}

// openAgain opens a reparse point that is neither a link nor a
// directory's without the flag, so that the platform opens the file it
// stands for. The handle must be on the file the flagged open found: one
// on another, a link put under the name in between, is refused. Then the
// handle is judged as any open's is. Nothing is made, and nothing is
// truncated through this open, before both: the name stood when the
// flagged open found it, so the open again does not create, and a
// truncate the caller asked for is made on the handle once it has been
// judged, never through a name that may by then be a link. The flagged
// open has truncated already, as Go does inside an open with O_TRUNC, and
// what it emptied is the object at the name, the reparse point's own,
// never a target.
func openAgain(path string, flag int, perm fs.FileMode, first fs.FileInfo) (*os.File, error) {
	f, err := os.OpenFile(path, flag&^(os.O_CREATE|os.O_EXCL|os.O_TRUNC), perm)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !os.SameFile(first, fi) {
		f.Close()
		return nil, &ModeError{Path: path, Mode: first.Mode(), Reparse: ReparseChanged}
	}
	if fi.Mode().IsRegular() {
		if flag&os.O_TRUNC != 0 {
			if err := f.Truncate(0); err != nil {
				f.Close()
				return nil, err
			}
		}
		settle(f)
		return f, nil
	}
	f.Close()
	return nil, &ModeError{Path: path, Mode: fi.Mode()}
}

// NotALink refuses a handle that is a symbolic link or a directory's
// reparse point, by the sentence an open would give, for a caller that
// opens by its own means and asks the handle after: the lock file on
// Windows, whose open is CreateFile with no sharing.
func NotALink(path string, fi fs.FileInfo) error {
	mode := fi.Mode()
	if mode&fs.ModeSymlink != 0 {
		return &ModeError{Path: path, Mode: mode}
	}
	if _, kind := judge(mode, attributesOf(fi)); kind == ReparseDirectory {
		return &ModeError{Path: path, Mode: mode, Reparse: kind}
	}
	return nil
}

// Open opens the named regular file for reading.
func Open(path string) (*os.File, error) {
	return OpenFile(path, os.O_RDONLY, 0)
}

// Create makes the named file, which must not exist, for writing: an
// existing entry under the name, whatever it is, is os.ErrExist — except
// a directory on Windows, which CreateFile refuses for writing as access
// denied and Go reports as syscall.EISDIR; Linux and macOS answer EEXIST
// for a directory as for anything else. A caller asking whether a name
// stands asks for both.
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
