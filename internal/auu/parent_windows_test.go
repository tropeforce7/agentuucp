package auu

import (
	"fmt"
	"os"
)

// watchTestParent ends this helper when the test process that started the
// run is gone; see parentEnv. FindProcess opens the process by its pid, and
// failing to is a parent already gone. Wait waits on that handle whether or
// not the process is this one's parent, and returns when it exits.
//
// A Wait that fails for any other reason leaves the helper running and says
// so once: a helper that guessed wrong there would end agents in a passing
// run, where one that stays is what every helper did before this existed.
// A pid the system has given to another process by the time this looks
// keeps the helper running too, and nothing worse.
func watchTestParent() {
	pid, ok := testParent()
	if !ok {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		os.Exit(3)
	}
	go func() {
		if _, err := p.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "auu test helper: cannot wait for the test process %d, so not watching it: %v\n", pid, err)
			return
		}
		os.Exit(3)
	}()
}
