package agent

import (
	"fmt"
	"net"
	"syscall"
)

// peerUID is the uid of the process at the other end of a Unix socket, from
// SO_PEERCRED: the kernel's answer, not the peer's claim.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			gerr = fmt.Errorf("agent: SO_PEERCRED: %w", err)
			return
		}
		uid = int(cred.Uid)
	}); err != nil {
		return -1, err
	}
	return uid, gerr
}
