//go:build !windows

package agent

import "syscall"

// refusedErrnos are what connecting to a socket nobody listens on, or
// that is not there, comes back as.
var refusedErrnos = []error{syscall.ECONNREFUSED, syscall.ENOENT}
