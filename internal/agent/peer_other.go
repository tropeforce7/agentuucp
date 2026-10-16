//go:build !(darwin || linux)

package agent

import (
	"net"
	"os"
)

// havePeerCred is false here: an AF_UNIX socket on Windows carries no
// peer credentials, and the agent says so once, in its own log.
const havePeerCred = false

// peerCred cannot be answered on this platform. What stands between
// another user and the socket is the runtime directory,
// %LOCALAPPDATA%\auu, which is the user's own; so the connection is taken
// to be the user's. Against a process of the same user the answer would
// be the same on every platform. It says nothing itself: the client that
// asks before it sends is a command whose standard error is its user's,
// and the line is the agent's to say (Server.Handle).
func peerCred(*net.UnixConn) (Cred, error) {
	return Cred{UID: os.Getuid(), GID: os.Getgid(), PID: -1}, nil
}
