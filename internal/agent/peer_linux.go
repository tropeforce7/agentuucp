package agent

import (
	"fmt"
	"net"
	"syscall"
)

// havePeerCred is true: the kernel says who is at the other end.
const havePeerCred = true

// peerCred is the credentials of the process at the other end of a Unix
// socket, from SO_PEERCRED: the kernel's answer, not the peer's claim. It
// carries the uid, the primary gid and the pid; the supplementary groups
// are not in it, and a caller that wants them reads them through os/user.
func peerCred(conn *net.UnixConn) (Cred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Cred{UID: -1, GID: -1, PID: -1}, err
	}
	c := Cred{UID: -1, GID: -1, PID: -1}
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			gerr = fmt.Errorf("agent: SO_PEERCRED: %w", err)
			return
		}
		c = Cred{UID: int(cred.Uid), GID: int(cred.Gid), PID: int(cred.Pid)}
	}); err != nil {
		return Cred{UID: -1, GID: -1, PID: -1}, err
	}
	return c, gerr
}
