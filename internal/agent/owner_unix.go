//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// ownedByMe says whether a directory belongs to this user. The runtime
// directory is shared only when it is somebody else's, and a directory of
// the right mode but the wrong owner is exactly that.
func ownedByMe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Getuid()
}
