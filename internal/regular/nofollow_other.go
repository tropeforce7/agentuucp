//go:build !unix

package regular

import (
	"os"
	"syscall"
)

// Windows has neither O_NOFOLLOW nor O_NONBLOCK on a path: a create there
// is exclusive, which refuses an existing link as an existing entry (Go
// opens with CREATE_NEW and FILE_FLAG_OPEN_REPARSE_POINT, so a link is
// not followed), and the handle check stands alone for an open, where a
// link to a regular file is followed and a link to anything else is
// refused as what it points at.
const openFlags = 0

const dirFlags = 0

func isLoop(syscall.Errno) bool { return false }

func settle(*os.File) {}
