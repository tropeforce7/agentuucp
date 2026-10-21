package auu

import (
	"os/exec"
	"strconv"
	"syscall"
)

// shellCommand is a channel's exec line as a command, through the platform
// shell.
//
// The command line is built by hand rather than left to os/exec's
// quoting. Go quotes arguments the way CommandLineToArgvW unquotes them,
// and cmd.exe is the documented exception: it unquotes differently, so an
// exec line that begins with a quoted path — which is every line naming a
// program whose path might hold a space — arrives quoted again and cmd
// cannot run it. `cmd /S /C "LINE"` is the form that works: /S makes cmd
// strip exactly the outer pair of quotes and take the rest as written.
// exec.Command resolves cmd.exe on the PATH; CmdLine is what is actually
// passed, and Args is left alone.
//
// The project is not tested on Windows beyond what CI runs; the
// implementation notes say so.
func shellCommand(line string) *exec.Cmd {
	cmd := exec.Command("cmd")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd /S /C "` + line + `"`}
	return cmd
}

// ownProcessGroup is a process group of the command's own. Windows has
// nothing to set here: what stands in for the group is taskkill's walk of
// the process tree, which needs no preparation.
func ownProcessGroup(cmd *exec.Cmd) {}

// killGroup kills the shell and everything it started. Windows has no
// process group to signal, so the tree is walked instead: taskkill /T finds
// the children of a pid and /F ends each of them. Killing the shell alone
// leaves the handler running with nobody waiting for it — and, on Windows,
// leaves it holding the file its output was going to, which is how a test's
// temporary directory came to be undeletable. Where taskkill is not there
// to be run, the shell itself is killed and what it started may outlive it.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := kill.Run(); err != nil {
		cmd.Process.Kill()
	}
}

// openNonblock is nothing on Windows, where opening a pipe by name does
// not wait on a writer the way a Unix FIFO does.
const openNonblock = 0
