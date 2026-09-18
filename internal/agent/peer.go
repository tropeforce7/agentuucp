package agent

import "net"

// Cred is what the kernel says about the process at the other end of a
// Unix socket: never the peer's claim. PID is -1 where the platform does
// not say, and Groups is the peer's group list where the platform gives it
// with the credentials (macOS) and nil elsewhere.
type Cred struct {
	UID, GID, PID int
	Groups        []int
}

// PeerCred is the credentials of the peer, for the agent and for the
// key-holding proxy's control socket, which admit a caller by uid before
// reading a byte.
func PeerCred(conn *net.UnixConn) (Cred, error) {
	return peerCred(conn)
}

// peerUID is what the agent checks: the uid alone.
func peerUID(conn *net.UnixConn) (int, error) {
	c, err := peerCred(conn)
	return c.UID, err
}
