//go:build !windows

package auu

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// watchTestParent ends this helper when the test process that started the
// run is gone, so an interrupted, killed or timed-out run leaves nothing
// behind; see parentEnv. kill with signal 0 asks whether the pid exists
// without signalling it: ESRCH is gone, and EPERM is a process that exists
// and belongs to somebody else, which is alive as far as this is concerned.
//
// A pid the system has given to another process by the time this looks
// keeps the helper running, which is what every helper did before this
// existed, and nothing worse.
func watchTestParent() {
	pid, ok := testParent()
	if !ok {
		return
	}
	go func() {
		for {
			if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
				os.Exit(3)
			}
			time.Sleep(parentPoll)
		}
	}()
}
