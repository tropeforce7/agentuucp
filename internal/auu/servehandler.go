package auu

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/regular"
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
	// keptDir is serve's own directory for the thread, where the run
	// files, the kept reply, its patch and its sealed envelope are; no
	// program is told of it (S56).
	keptDir string
	// attachments is where the asker's files were put, empty when there
	// were none.
	attachments string
	// proxied says a key-holding proxy is configured: the credential
	// variables serve inherited are dropped from every program's
	// environment, and the handler alone is given the proxy's two.
	proxied bool
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
		// Who else a message to several went to, as its sender listed
		// them, the asker among them only when they sent themselves a
		// copy: fingerprints, separated by spaces, which carry no word of
		// the sender's. Empty for a message to one (P7).
		"AUU_RECIPIENTS":  strings.Join(recipientsOf(f.m), " "),
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
	inherited := os.Environ()
	if f.proxied {
		// A unit that still hands serve the real key must not hand it on
		// through serve: the proxy holds it, and the handler gets a token.
		inherited = withoutCredentials(inherited)
	}
	out := make([]string, 0, len(inherited)+len(set))
	for _, kv := range inherited {
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
	return runCommand(ctx, shellCommand(line), line, dir, env, stdin, stdout, stderr, timeout)
}

// runCommand is runProgram for a command already built: the shell's line
// for serve, a program and its arguments for handle. name is what its
// sentences call it. Its directory, environment and three streams are set
// here, over anything the caller set, since where and with what a program
// runs is the runner's. The process group, the timer, the kill and the
// wait are this one piece of code for both.
func runCommand(ctx context.Context, cmd *exec.Cmd, name, dir string, env []string, stdin, stdout, stderr *os.File, timeout time.Duration) (programRun, error) {
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	ownProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return programRun{}, fmt.Errorf("could not start %q: %v", name, err)
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
			return run, fmt.Errorf("waiting for %q: %v", name, err)
		}
	case <-timer.C:
		killGroup(cmd)
		// Nothing holds a pipe, so the wait returns as soon as the program
		// it started is gone.
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
// output is a file, and the documentation says so. A line over
// maxLogLine is cut with a mark that says how much of it is not shown, and
// the lines after it are copied (G49, R64): a scanner's cap ended the copy
// there without a word. A read that fails is said, with the file's path.
func prefixedTo(w *os.File, path, prefix string) {
	f, err := regular.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	err = eachLine(f, func(text string, cut int64) bool {
		// A handler's words, which a peer's message may have shaped, reach
		// the host's terminal or journal escaped, as every other print of
		// a string from outside does (P1).
		text = identity.PrintableText(text)
		if cut > 0 {
			fmt.Fprintf(w, "%s: %s [cut: %d more bytes of this line are not shown]\n", prefix, text, cut)
		} else {
			fmt.Fprintf(w, "%s: %s\n", prefix, text)
		}
		return true
	})
	if err != nil {
		fmt.Fprintf(w, "%s: [the rest of %s could not be read: %v]\n", prefix, path, err)
	}
}

// firstLine is the first line of a file, for the sentence that says why a
// message was not answered. Empty when there is nothing to say. A first
// line over maxLogLine is given cut, with a mark that says so.
func firstLine(path string) string {
	f, err := regular.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var first string
	eachLine(f, func(text string, cut int64) bool {
		if line := strings.TrimSpace(text); line != "" {
			first = line
			if cut > 0 {
				first += " [cut]"
			}
			return false
		}
		return true
	})
	return first
}

// maxLogLine is the most of one line of a program's output that serve
// prints: the scanner's cap it replaces.
const maxLogLine = 1024 * 1024

// eachLine gives line every line of r without its line ending, as a
// scanner of lines does, until line returns false: a line ends at a
// newline, a carriage return before it or before the end of the file is
// not part of it, and a last line with no newline is a line. A line over
// maxLogLine is given its first maxLogLine bytes, less a rune the cut would
// split, and cut is how many bytes of it are not given; reading goes on
// from the line's end. A read that fails ends it with the error, after
// the line it was reading.
func eachLine(r io.Reader, line func(text string, cut int64) bool) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var kept []byte
	var cut int64
	var last byte
	open := false
	for {
		piece, err := br.ReadSlice('\n')
		ended := err == nil
		if ended {
			piece = piece[:len(piece)-1]
		}
		if len(piece) > 0 {
			open, last = true, piece[len(piece)-1]
			room := maxLogLine - len(kept)
			if len(piece) > room {
				cut += int64(len(piece) - room)
				piece = piece[:room]
			}
			kept = append(kept, piece...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if ended || open {
			if last == '\r' {
				if cut > 0 {
					cut--
				} else {
					kept = kept[:len(kept)-1]
				}
			}
			if cut > 0 {
				for range utf8.UTFMax {
					r, size := utf8.DecodeLastRune(kept)
					if len(kept) == 0 || r != utf8.RuneError || size > 1 {
						break
					}
					kept = kept[:len(kept)-1]
					cut++
				}
			}
			if !line(string(kept), cut) {
				return nil
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		kept, cut, last, open = kept[:0], 0, 0, false
	}
}

// createNew makes one of the run's files, empty, under a name of the
// run's own in serve's kept directory for a thread. A file from an earlier attempt at
// the same message is removed first, and the create is then exclusive
// and by the handle: the program never opens what already stood under
// the name, and whatever the remove could not take — a directory with
// something in it, a device the platform answers to — is "already
// exists" or the handle's refusal, never written into.
func createNew(path string) (*os.File, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return regular.Create(path, 0o600)
}

// writeNew is createNew with the contents written and the file closed;
// on any error after the create, what this call made is removed.
func writeNew(path string, data []byte) error {
	f, err := createNew(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// runFile names one of a message's run files in serve's kept directory
// for its thread.
func runFile(keptDir, kind, id string) string {
	return filepath.Join(keptDir, kind+"-"+id+".txt")
}
