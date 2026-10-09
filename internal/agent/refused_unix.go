//go:build !windows

package agent

import "syscall"

// refusedErrnos are what connecting to a socket nobody listens on, to one
// that is not there, or to a file that is not a socket comes back as.
// ENOTSOCK is what macOS returns when the file at the path is not a
// socket, as when a plain file has replaced the agent's socket; Linux
// returns ECONNREFUSED for that.
var refusedErrnos = []error{syscall.ECONNREFUSED, syscall.ENOENT, syscall.ENOTSOCK}
