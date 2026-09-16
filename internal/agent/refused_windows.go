package agent

import "syscall"

// wsaeConnRefused is WSAECONNREFUSED, which is what connecting to an
// AF_UNIX socket nobody listens on comes back as on Windows; the syscall
// package's ECONNREFUSED there is an invented number that Winsock never
// returns.
const wsaeConnRefused = syscall.Errno(10061)

// refusedErrnos are what connecting to a socket nobody listens on, or
// that is not there, comes back as.
var refusedErrnos = []error{wsaeConnRefused, syscall.ERROR_FILE_NOT_FOUND, syscall.ENOENT}
