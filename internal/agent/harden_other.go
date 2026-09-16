//go:build !(darwin || linux)

package agent

import (
	"log"
	"sync"
)

var fallbackOnce sync.Once

// Harden has nothing to do on this platform: there is no equivalent of
// PR_SET_DUMPABLE or PT_DENY_ATTACH in the syscall package, and no core
// limit to set. It says so once. What protects the agent's memory here is
// the operating system's own rule that one user's process does not read
// another's; against a process of the same user there is nothing.
func Harden() error {
	fallbackOnce.Do(func() {
		log.Printf("agent: no memory hardening on this platform; another process of this user can read this one")
	})
	return nil
}

// Hardened is false here: nothing was applied.
func Hardened() (bool, error) { return false, nil }
