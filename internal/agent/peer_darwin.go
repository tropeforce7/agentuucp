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
	xucredVersion0 = 0
)

// peerUID is the uid of the process at the other end of a Unix socket, from
// LOCAL_PEERCRED: the kernel's answer, not the peer's claim. The getsockopt
// is made through syscall directly because the syscall package exports no
// getsockopt that takes a struct on darwin.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
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
		uid = int(cred.UID)
	}); err != nil {
		return -1, err
	}
	return uid, gerr
}
