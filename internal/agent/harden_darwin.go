package agent

import (
	"fmt"
	"syscall"
)

// Harden makes this process unreadable by its neighbours: no core file, and
// PT_DENY_ATTACH, after which a debugger cannot attach and one already
// attached ends the process. A failure is a failure: an agent that cannot
// protect its memory should not offer to hold keys.
func Harden() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("agent: RLIMIT_CORE: %w", err)
	}
	if _, _, e := syscall.Syscall(syscall.SYS_PTRACE, uintptr(syscall.PT_DENY_ATTACH), 0, 0); e != 0 {
		return fmt.Errorf("agent: PT_DENY_ATTACH: %w", e)
	}
	hardened = true
	return nil
}

var hardened bool

// Hardened reports whether Harden has taken effect. macOS offers nothing to
// read back, so this is whether the call returned without error.
func Hardened() (bool, error) { return hardened, nil }
