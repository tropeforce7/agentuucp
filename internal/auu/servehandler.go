package auu

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// Running a handler, and the two hooks around it.
//
// Everything a program serve runs is run the same way: through the platform
// shell, in the worktree, in a process group of its own, with its output on
// disk rather than down a pipe. The pipe is the part that matters. A
// handler that has started something of its own — and a Claude Code session
// starts several — leaves that child holding the write end, so a Wait after
// a kill would never return. Files have no such end to hold.

// The facts of one message, as the programs are told them.
type runFacts struct {
	m       *store.Stored
	channel string
	relay   string
	mode    string
	turn    int

	worktree   string
	base       string
	threadDir  string
	channelDir string
	// attachments is where the asker's files were put, empty when there
	// were none.
	attachments string
}

// programRun is how one program ended: its exit status, and the word the
// next one is told it by.
type programRun struct {
	exit     int
	timedOut bool
}

// status is what AUU_STATUS says: the exit status as a decimal, or the word
// for a run that was killed.
func (r programRun) status() string {
	if r.timedOut {
		return "timeout"
	}
	return strconv.Itoa(r.exit)
}

// ok says the program said nothing was wrong.
func (r programRun) ok() bool { return !r.timedOut && r.exit == 0 }

// statusBefore is what an after hook is told when the handler never ran.
const statusBefore = "before"

// env is the environment a program is given: the process's own, less
// anything that would collide, plus what serve has to say.
//
// withMessage is the handler; a hook is not shown the message, so the
// subject and the attachments are left out of its environment rather than
// emptied, and its standard input is nothing at all. status is the after
// hook's AUU_STATUS, empty for the others.
func (f runFacts) env(withMessage bool, status string) []string {
	set := map[string]string{
		"AUU_MESSAGE_ID":  f.m.Inner.ID,
		"AUU_THREAD_ID":   f.m.Inner.Body.Thread,
		"AUU_IN_REPLY_TO": f.m.Inner.Body.InReplyTo,
		"AUU_TYPE":        f.m.Inner.Body.Type,
		"AUU_FROM":        f.m.Inner.From,
		"AUU_FROM_NAME":   f.m.SenderName,
		"AUU_CHANNEL":     f.channel,
		"AUU_RELAY":       f.relay,
		"AUU_TURN":        strconv.Itoa(f.turn),
		"AUU_MODE":        f.mode,
		"AUU_WORKTREE":    f.worktree,
		"AUU_BASE":        f.base,
		"AUU_THREAD_DIR":  f.threadDir,
		"AUU_CHANNEL_DIR": f.channelDir,
	}
	if withMessage {
		set["AUU_SUBJECT"] = f.m.Inner.Body.Subject
		set["AUU_ATTACHMENTS"] = f.attachments
	}
	if status != "" {
		set["AUU_STATUS"] = status
	}
	// Anything the parent already had under one of these names is dropped
	// rather than left to a rule about which duplicate wins.
	out := make([]string, 0, len(os.Environ())+len(set))
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if _, ours := set[name]; ours {
			continue
		}
		if !withMessage && (name == "AUU_SUBJECT" || name == "AUU_ATTACHMENTS") {
			continue
		}
		if status == "" && name == "AUU_STATUS" {
			continue
		}
		out = append(out, kv)
	}
	for _, name := range sortedKeys(set) {
		out = append(out, name+"="+set[name])
	}
	return out
}

// sortedKeys is the map's keys in order, so that two runs build the same
// environment in the same order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// runProgram runs one line through the shell and waits for it, killing its
// whole process group at the timeout or when the context ends. stdin,
// stdout and stderr are files or nil; nothing here is a pipe.
//
// An error is a program that could not be started or waited for, or the
// context's own when the operator stopped serve while this was running: a
// handler killed that way leaves the message exactly as it was. A program
// that ran and failed is not an error: it is a status the caller acts on.
func runProgram(ctx context.Context, line, dir string, env []string, stdin, stdout, stderr *os.File, timeout time.Duration) (programRun, error) {
	cmd := shellCommand(line)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	ownProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return programRun{}, fmt.Errorf("could not start %q: %v", line, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var run programRun
	select {
	case err := <-done:
		run.exit = exitStatus(err)
		if run.exit < 0 {
			return run, fmt.Errorf("waiting for %q: %v", line, err)
		}
	case <-timer.C:
		killGroup(cmd)
		// Nothing holds a pipe, so the wait returns as soon as the shell
		// itself is gone.
		<-done
		run.timedOut = true
	case <-ctx.Done():
		killGroup(cmd)
		<-done
		return run, ctx.Err()
	}
	return run, nil
}

// exitStatus is a Wait's error as a status: 0 for none, the program's own
// for an exit, and -1 for a failure that is not the program's.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

// prefixedTo copies a program's output file to serve's standard error with
// the thread's short id in front of every line, which is what tells two
// threads' output apart in a journal. Live output is not possible while the
// output is a file, and the documentation says so.
func prefixedTo(w *os.File, path, prefix string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		fmt.Fprintf(w, "%s: %s\n", prefix, scan.Text())
	}
}

// firstLine is the first line of a file, for the sentence that says why a
// message was not answered. Empty when there is nothing to say.
func firstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		if line := strings.TrimSpace(scan.Text()); line != "" {
			return line
		}
	}
	return ""
}

// createTrunc makes one of the run's files, empty.
func createTrunc(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

// runFile names one of a message's files in the thread's directory.
func runFile(threadDir, kind, id string) string {
	return filepath.Join(threadDir, kind+"-"+id+".txt")
}
