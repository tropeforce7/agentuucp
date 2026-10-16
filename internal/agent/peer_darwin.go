package agent

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// xucred is what LOCAL_PEERCRED fills in: sys/ucred.h's struct xucred.
type xucred struct {
	Version uint32
	UID     uint32
	Ngroups int16
	Groups  [16]uint32
}

const (
	solLocal       = 0
	localPeerCred  = 1
	localPeerPID   = 2
	xucredVersion0 = 0
)

// havePeerCred is true: the kernel says who is at the other end.
const havePeerCred = true

// peerCred is the credentials of the process at the other end of a Unix
// socket, from LOCAL_PEERCRED and LOCAL_PEERPID: the kernel's answer, not
// the peer's claim. The xucred carries the peer's whole group list, the
// first of which is its primary group. The getsockopts are made through
// syscall directly because the syscall package exports no getsockopt that
// takes a struct on darwin.
func peerCred(conn *net.UnixConn) (Cred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Cred{UID: -1, GID: -1, PID: -1}, err
	}
	c := Cred{UID: -1, GID: -1, PID: -1}
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		var cred xucred
		size := uint32(unsafe.Sizeof(cred))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred,
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)
		if e != 0 {
			gerr = fmt.Errorf("agent: LOCAL_PEERCRED: %w", e)
			return
		}
		if cred.Version != xucredVersion0 {
			gerr = fmt.Errorf("agent: LOCAL_PEERCRED: xucred version %d, expected %d", cred.Version, xucredVersion0)
			return
		}
		c.UID = int(cred.UID)
		n := int(cred.Ngroups)
		if n > len(cred.Groups) {
			n = len(cred.Groups)
		}
		for i := range n {
			c.Groups = append(c.Groups, int(cred.Groups[i]))
		}
		if n > 0 {
			c.GID = c.Groups[0]
		}
		var pid uint32
		psize := uint32(unsafe.Sizeof(pid))
		if _, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerPID,
			uintptr(unsafe.Pointer(&pid)), uintptr(unsafe.Pointer(&psize)), 0); e == 0 {
			c.PID = int(pid)
		}
	}); err != nil {
		return Cred{UID: -1, GID: -1, PID: -1}, err
	}
	return c, gerr
}
