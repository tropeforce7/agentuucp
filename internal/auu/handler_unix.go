//go:build !windows

package auu

import (
	"os/exec"
	"syscall"
)

// shellCommand is a channel's exec line as a command, through the platform
// shell so that a line with arguments, a pipeline or a redirection is what
// the owner wrote rather than what Go's argument splitting made of it.
func shellCommand(line string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", line)
}

// ownProcessGroup puts the shell in a process group of its own, so that
// everything it starts can be killed with it. Killing /bin/sh alone leaves
// the handler — a Claude Code session, say — running with nobody to wait
// for it, which is what a timeout is for.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup kills the shell and everything it started. The negative pid is
// the group, which is the shell's own because ownProcessGroup made it one.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		// The group is gone, or was never made: the process itself is
		// still worth killing.
		cmd.Process.Kill()
	}
}
