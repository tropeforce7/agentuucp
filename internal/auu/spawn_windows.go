package auu

import (
	"os"
	"os/exec"
	"syscall"
)

// spawnDetached runs exe with args detached from this console. The project
// is not tested on Windows; see IMPLEMENTATION_NOTES.md.
func spawnDetached(exe string, args []string, home string, logFile *os.File) error {
	cmd := exec.Command(exe, args...)
	cmd.Env = agentEnviron(home)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	const createNewProcessGroup, detachedProcess = 0x00000200, 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup | detachedProcess}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
