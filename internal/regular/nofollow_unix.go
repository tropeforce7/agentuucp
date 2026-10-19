//go:build unix

package regular

import (
	"io/fs"
	"os"
	"syscall"
)

// openFlags is what every open here carries beyond the caller's flags.
// O_NOFOLLOW refuses a symbolic link under the name rather than following
// it; where the platform reports that refusal as an errno of its own —
// ELOOP on Linux and macOS, EMLINK on FreeBSD — isLoop says so and the
// error becomes a *ModeError naming a symbolic link. O_NONBLOCK is what
// lets the handle be asked at all: open(2) of a FIFO for reading blocks
// until a writer arrives, and for writing until a reader does, so without
// it a planted pipe would hold the program forever before Stat ran. With
// it a FIFO opens at once for reading and is refused by its mode, and
// for writing is refused by the platform (ENXIO, passed through); on a
// regular file the flag changes nothing, and settle clears it once the
// handle has been checked, so the file behaves as os.Open's would.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// dirFlags is what Dir carries: O_NONBLOCK for the same reason, and no
// O_NOFOLLOW, since a link that resolves to a directory is a directory
// and the handle check says so of whatever the link resolves to.
const dirFlags = syscall.O_NONBLOCK

func isLoop(errno syscall.Errno) bool { return errno == syscall.ELOOP || errno == syscall.EMLINK }

// settle puts a checked regular file back into blocking mode. Fd has no
// side effect here: os only marks a file it put into non-blocking mode
// itself, and this one was opened that way by the flag.
func settle(f *os.File) {
	syscall.SetNonblock(int(f.Fd()), false)
}

// attributesOf is zero: there are no reparse points here, and judge
// never reopens.
func attributesOf(fs.FileInfo) uint32 { return 0 }
