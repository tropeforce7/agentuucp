package regular

import (
	"io/fs"
	"os"
	"syscall"
)

// Windows has neither O_NOFOLLOW nor O_NONBLOCK on a path. What it has is
// FILE_FLAG_OPEN_REPARSE_POINT, which Go passes through os.OpenFile in
// the flag's high bits: a reparse point under the name is opened as
// itself rather than followed, and OpenFile's judge decides from that
// handle, refusing a symbolic link and a directory's reparse point and
// opening any other tag again without the flag (S57). A create is
// exclusive, and Go already adds the flag to one, so an existing link is
// refused as an existing entry.
const openFlags = syscall.FILE_FLAG_OPEN_REPARSE_POINT

// dirFlags is what Dir carries: nothing, since a link that resolves to a
// directory is a directory and the handle says so of what it reaches.
const dirFlags = 0

func isLoop(syscall.Errno) bool { return false }

func settle(*os.File) {}

// attributesOf is the handle's file attributes, which say whether a
// reparse point is on a directory.
func attributesOf(fi fs.FileInfo) uint32 {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes
	}
	return 0
}
