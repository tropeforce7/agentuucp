//go:build !(darwin || linux)

package agent

import (
	"log"
	"net"
	"os"
	"sync"
)

var noPeerCredOnce sync.Once

// peerCred cannot be answered on this platform: an AF_UNIX socket on
// Windows carries no peer credentials. What stands between another user
// and the socket is the runtime directory, %LOCALAPPDATA%\auu, which is the
// user's own; so the connection is taken to be the user's, and the agent
// says once that it is relying on the directory. Against a process of the
// same user the answer would be the same on every platform.
func peerCred(*net.UnixConn) (Cred, error) {
	noPeerCredOnce.Do(func() {
		log.Printf("agent: no peer credentials on this platform; relying on the runtime directory's permissions")
	})
	return Cred{UID: os.Getuid(), GID: os.Getgid(), PID: -1}, nil
}
