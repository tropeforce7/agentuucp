package agent

import (
	"fmt"
	"syscall"
)

// Harden makes this process unreadable by its neighbours: no core file, and
// PR_SET_DUMPABLE off, which is what stops another process of the same user
// attaching with ptrace or reading /proc/<pid>/mem. A failure is a failure:
// an agent that cannot protect its memory should not offer to hold keys.
func Harden() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("agent: RLIMIT_CORE: %w", err)
	}
	if _, _, e := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); e != 0 {
		return fmt.Errorf("agent: PR_SET_DUMPABLE: %w", e)
	}
	return nil
}

// Hardened reports whether Harden has taken effect on this process, for the
// test that proves it: PR_GET_DUMPABLE.
func Hardened() (bool, error) {
	r, _, e := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if e != 0 {
		return false, fmt.Errorf("agent: PR_GET_DUMPABLE: %w", e)
	}
	return r == 0, nil
}
