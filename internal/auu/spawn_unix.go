//go:build !windows

package auu

import (
	"os"
	"os/exec"
	"syscall"
)

// spawnDetached runs exe with args as a daemon for a home: its own session,
// so a closed terminal does not take it with it; standard input from
// /dev/null; output to the log. AUU_HOME is set so the child serves the
// home the parent opened, whichever way the parent found it, and
// agentChildEnv so that it never starts another.
func spawnDetached(exe string, args []string, home string, logFile *os.File) error {
	cmd := exec.Command(exe, args...)
	cmd.Env = agentEnviron(home)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Released, not waited for: the child outlives this process, and a
	// process nobody waits for is reaped by init.
	return cmd.Process.Release()
}
