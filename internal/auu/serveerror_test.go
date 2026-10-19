package auu

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// An error that ends a serve run reaches the host's terminal escaped
// (S60): handle's errors carry git's words, or a hook's, about a tree the
// handler wrote. git 2.54 replaces a control byte in its own fatal line
// with '?', so the git here is one that does not: a script ahead of the
// real git on the PATH that fails 'worktree prune', which every new
// worktree is made after, with an escape sequence and a bell, and passes
// every other command to the real git by its absolute path, so the route
// is serve's own, through ensureWorktree, gitRun, handle, round and Main.
// The run still ends as an error of serve's, and nothing raw is printed.
// The script is sh, so the test runs off Windows, where serve's other
// shell tests run too.
func TestServeEscapesTheErrorThatEndsItsRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in git is a shell script")
	}
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on the PATH")
	}
	alice, bob := newExpert(t, modeSideCopy)
	t.Setenv(handlerScript, "echo:an answer")
	alice.ask(t, "jostle", "a question", "the first")

	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = worktree ] && [ \"$2\" = prune ]; then\n" +
		"\tprintf 'fatal: \\033[31mred\\007 bell\\n' >&2\n" +
		"\texit 128\n" +
		"fi\n" +
		"exec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var runErr error
	said := captureStderr(t, func() { _, runErr = bob.tryRun("serve", "--once") })
	if runErr == nil {
		t.Fatalf("serve --once ran on past a git that failed; it said:\n%s", said)
	}
	for _, raw := range []string{"\x1b", "\a"} {
		if strings.Contains(said, raw) || strings.Contains(runErr.Error(), raw) {
			t.Errorf("serve printed %q raw:\n%q\n%q", raw, said, runErr.Error())
		}
	}
	if !strings.Contains(runErr.Error(), `fatal: \x1b[31mred\a bell`) {
		t.Errorf("the error does not carry git's words escaped: %q", runErr.Error())
	}
	var p *printableError
	if !errors.As(runErr, &p) {
		t.Errorf("the run's error is not handle's escaped one: %#v", runErr)
	}
}

// The escaped error unwraps to the one it escapes, so the code an exit
// error carries is the code the run ends with, and its words are printable
// on one line; an exit error is kept the outermost.
func TestAPrintableErrorKeepsWhatItWraps(t *testing.T) {
	inner := &exitError{code: exitTransport, err: errors.New("relay said \x1b]0;title\a\nand more")}
	var err error = &printableError{inner}
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("errors.As lost the exit code: %v", err)
	}
	if got, want := err.Error(), `relay said \x1b]0;title\a\nand more`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	// An exit error leaving handle or the sweep stays the outermost, so
	// whatever asks the run's error for its type and code still finds it,
	// and it says its words escaped.
	out, ok := escaped(inner).(*exitError)
	if !ok || out.code != exitTransport {
		t.Fatalf("escaped(an exit error) = %#v; want an exit error with its code", escaped(inner))
	}
	if got, want := out.Error(), `relay said \x1b]0;title\a\nand more`; got != want {
		t.Errorf("the escaped exit error says %q, want %q", got, want)
	}
	if escaped(nil) != nil {
		t.Error("escaped(nil) is not nil")
	}
}

// The sweep's error leaves escaped too: a worktree the handler made that
// will not be removed, a directory it named with an escape sequence and a
// bell and took the write permission off, is named in the error with the
// file in it that would not go. git's own remove fails first, and the
// removal after it says the path as it is.
func TestServeEscapesTheSweepsError(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob := newExpert(t, modeSideCopy)
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	stuck := filepath.Join(bob.home, "serve", "worktrees", sent.Thread, "\x1b[31mred\a")
	if err := os.MkdirAll(stuck, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stuck, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stuck, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(stuck, 0o700) })

	bob.row.ThreadTTL = "1ms"
	bob.write(t)
	time.Sleep(5 * time.Millisecond)
	var runErr error
	said := captureStderr(t, func() { _, runErr = bob.tryRun("serve", "--once") })
	if runErr == nil {
		t.Fatalf("the sweep removed a worktree it could not; serve said:\n%s", said)
	}
	for _, raw := range []string{"\x1b", "\a"} {
		if strings.Contains(said, raw) || strings.Contains(runErr.Error(), raw) {
			t.Errorf("serve printed %q raw:\n%q\n%q", raw, said, runErr.Error())
		}
	}
	if !strings.Contains(runErr.Error(), `\x1b[31mred\a`) {
		t.Errorf("the error does not name the stuck directory escaped: %q", runErr.Error())
	}
}
