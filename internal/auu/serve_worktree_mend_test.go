package auu

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A handler can damage its worktree in ways the remake alone does not
// mend: a directory it took the permissions off, a registration it locked
// in git, a tree that cannot be removed at all. Each was once an error that
// ended every later round with nothing written in the ledger, so a
// supervisor restarted serve into the same message for good. These are the
// review's tests of that (the second adversarial pass over F9), under names
// that say what they now prove, with the move-aside and the unmendable
// path beside them.

// damagedThenAsked runs one ask whose handler first does damage to its
// worktree, then sends a second, ordinary ask, and gives the second.
// Everything under bob's serve root, the moved-aside copies included, is
// given its permissions back and its user-immutable flags cleared at
// cleanup, so the test's own temporary directories can be removed.
func damagedThenAsked(t *testing.T, damage string) (alice *user, bob *expert, second sentJSON) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shell here is cmd /c")
	}
	alice, bob = newExpert(t, modeReadOnly)
	serveRoot := filepath.Join(bob.home, "serve")
	t.Cleanup(func() { giveBack(serveRoot) })
	bob.row.Exec = damage + "; " + helperLine(t, "handler")
	bob.write(t)
	first := alice.ask(t, "jostle", "first", "please do as the message says")
	bob.serve(t)
	alice.replyOn(t, first.Thread)

	bob.row.Exec = helperLine(t, "handler")
	bob.write(t)
	second = alice.ask(t, "jostle", "second", "an ordinary question")
	return alice, bob, second
}

// giveBack clears the user-immutable flag under root, on darwin, and gives
// every directory under it its permissions back. Walk calls the function
// on a directory before it reads it, so one with mode 000 is opened before
// it is descended into.
func giveBack(root string) {
	if runtime.GOOS == "darwin" {
		exec.Command("chflags", "-R", "nouchg", root).Run()
	}
	filepath.Walk(root, func(p string, info os.FileInfo, _ error) error {
		if info != nil && info.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
}

// serveTwiceAnswering runs two rounds after the damage and fails unless
// both go through, the second message is answered on its thread and
// written down as answered, and the first round's stderr has every one of
// want in it. It gives the first round's stderr.
func serveTwiceAnswering(t *testing.T, alice *user, bob *expert, second sentJSON, want ...string) string {
	t.Helper()
	var first string
	for i := 1; i <= 2; i++ {
		var out string
		var err error
		stderr := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once") })
		e := bob.ledgerOf(t).Messages[second.ID]
		// The review's assertion: a round that stops writes the message
		// down first, or the next start meets it again.
		if err != nil && (e == nil || e.Failures == 0) {
			t.Fatalf("round %d: serve stopped (%v) with nothing written against %s, so the next start meets it again\nstdout: %s\nstderr: %s",
				i, err, second.ID[:12], out, stderr)
		}
		if err != nil {
			t.Fatalf("round %d: serve stopped: %v\nstderr: %s", i, err, stderr)
		}
		if i == 1 {
			first = stderr
		}
	}
	for _, w := range want {
		if !strings.Contains(first, w) {
			t.Errorf("the first round's stderr does not say %q:\n%s", w, first)
		}
	}
	if reply := alice.replyOn(t, second.Thread); reply.Text != "the expert has spoken" || reply.InReplyTo != second.ID {
		t.Errorf("the reply to the second ask: %+v", reply)
	}
	e := bob.ledgerOf(t).Messages[second.ID]
	if e == nil || e.Handled.IsZero() || e.Failures != 0 || e.Reply == "" {
		t.Fatalf("the ledger does not have the second ask answered: %+v", e)
	}
	return first
}

// movedAsideLine is what moveAside says on stderr.
func movedAsideLine(path, aside string) string {
	return fmt.Sprintf("worktree %s could not be removed and was moved aside to %s; remove it by hand", path, aside)
}

// remadeLine is what handle says of a worktree made again.
func remadeLine(path string) string {
	return fmt.Sprintf("worktree %s was not a git worktree and was made again", path)
}

// noneAside fails if anything was moved aside in the serve root.
func noneAside(t *testing.T, serveRoot string) {
	t.Helper()
	if matches, _ := filepath.Glob(filepath.Join(serveRoot, "*.damaged-*")); len(matches) != 0 {
		t.Errorf("something was moved aside: %v", matches)
	}
}

// The handler takes every permission off its own worktree. git cannot be
// started there, which lostWorktree takes as a directory that is no longer
// a worktree; the permissions are given back, the directory removed and
// the worktree made again, and the second ask is answered in it.
func TestAHandlerThatLocksItsWorktreeDirDoesNotStopTheExpert(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not kept out by mode bits")
	}
	alice, bob, second := damagedThenAsked(t, "chmod 000 .")
	wt := filepath.Join(bob.home, "serve", "worktrees", "jostle")
	serveTwiceAnswering(t, alice, bob, second, remadeLine(wt))
	noneAside(t, filepath.Join(bob.home, "serve"))
	if lost, err := lostWorktree(bob.dir, wt); err != nil || lost {
		t.Errorf("the worktree was not made again: lost %v err %v", lost, err)
	}
}

// The handler locks its worktree with git and removes .git. The prune
// passes a locked registration by, and git refuses to add a worktree where
// it holds one, so the lock is taken off first; the directory is removed
// whole and nothing is moved aside.
func TestAHandlerThatLocksItsWorktreeInGitDoesNotStopTheExpert(t *testing.T) {
	alice, bob, second := damagedThenAsked(t, "git worktree lock --reason x . && rm -f .git")
	// The made-again line shows the lock was taken and the worktree lost,
	// since without the lock the handler's && would have removed nothing.
	wt := filepath.Join(bob.home, "serve", "worktrees", "jostle")
	stderr := serveTwiceAnswering(t, alice, bob, second, remadeLine(wt))
	if strings.Contains(stderr, "moved aside") {
		t.Errorf("a directory that could be removed was moved aside:\n%s", stderr)
	}
	noneAside(t, filepath.Join(bob.home, "serve"))
}

// The handler removes .git and takes the permissions off a directory inside
// its worktree: the first removal fails, the permissions are given back,
// the second removes it, and the worktree is made again with nothing moved
// aside.
func TestAHandlerThatTakesThePermissionsOffInsideItsWorktreeDoesNotStopTheExpert(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not kept out by mode bits")
	}
	alice, bob, second := damagedThenAsked(t, "rm -f .git && mkdir -p x/y && chmod 000 x")
	wt := filepath.Join(bob.home, "serve", "worktrees", "jostle")
	serveTwiceAnswering(t, alice, bob, second, remadeLine(wt))
	noneAside(t, filepath.Join(bob.home, "serve"))
	if lost, err := lostWorktree(bob.dir, wt); err != nil || lost {
		t.Errorf("the worktree was not made again: lost %v err %v", lost, err)
	}
}

// skipUnlessImmutable skips where the test cannot make a tree its owner
// cannot remove even with every permission given back.
func skipUnlessImmutable(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("only root can make a tree its owner cannot remove; darwin's user-immutable flag can")
	}
}

// The handler removes .git and leaves a file with darwin's user-immutable
// flag on it, which no permission given back lets the removal past: the
// worktree is moved aside to the first free name in the serve root, said,
// and made again, and the next ask is answered. The flag is on the file,
// not the directory, so the directory itself can still be renamed.
func TestAWorktreeThatCannotBeRemovedIsMovedAsideAndTheExpertGoesOn(t *testing.T) {
	skipUnlessImmutable(t)
	alice, bob, second := damagedThenAsked(t, "rm -f .git && touch stuck && chflags uchg stuck")
	wt := filepath.Join(bob.home, "serve", "worktrees", "jostle")
	aside := filepath.Join(bob.home, "serve", "jostle.damaged-1")
	serveTwiceAnswering(t, alice, bob, second, movedAsideLine(wt, aside), remadeLine(wt))
	if _, err := os.Lstat(filepath.Join(aside, "stuck")); err != nil {
		t.Errorf("the moved-aside copy is not at %s: %v", aside, err)
	}
	if lost, err := lostWorktree(bob.dir, wt); err != nil || lost {
		t.Errorf("the worktree was not made again: lost %v err %v", lost, err)
	}
}

// What the fix removes when a link stands at the worktree's path is the
// link alone, never what it points at: a link to a directory outside the
// serve root, a link to the channel's checkout itself, and a link to
// another thread's worktree.
func TestALinkAtAWorktreePathIsRemovedAloneAndNotItsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	checkout := repo(t)
	root := t.TempDir()
	other := filepath.Join(root, "worktrees", "other")
	if _, _, err := ensureWorktree(checkout, other); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	keep := filepath.Join(outside, "precious")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{outside, checkout, other} {
		path := filepath.Join(root, "worktrees", "t")
		os.RemoveAll(path)
		git(t, checkout, "worktree", "prune")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(checkout, path)
		if err != nil || !made || !remade {
			t.Fatalf("link to %s: made %v remade %v err %v", target, made, remade, err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("link to %s: the path is still a link", target)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a file outside the serve root went with the link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(checkout, "README")); err != nil {
		t.Errorf("the checkout lost its README: %v", err)
	}
	if lost, err := lostWorktree(checkout, other); err != nil || lost {
		t.Errorf("the other thread's worktree is no longer one: lost %v err %v", lost, err)
	}
}

// skipUnlessPermissionsHold skips where a mode bit does not keep the test
// out: as root, which reads and writes through them, and on Windows.
func skipUnlessPermissionsHold(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not Windows permissions")
	}
	if os.Geteuid() == 0 {
		t.Skip("root is not kept out by mode bits")
	}
}

// unremovableAt puts a directory at path, inside no repository, that
// cannot be removed even after openUp: a file in it with darwin's
// user-immutable flag. The flag is cleared at cleanup.
func unremovableAt(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	stuck := filepath.Join(path, "stuck")
	if err := os.WriteFile(stuck, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("chflags", "uchg", stuck).CombinedOutput(); err != nil {
		t.Fatalf("chflags uchg: %v\n%s", err, out)
	}
	t.Cleanup(func() { giveBack(filepath.Dir(filepath.Dir(path))) })
	openUp(path)
	if err := os.RemoveAll(path); err == nil {
		t.Fatal("the fixture was removed, so it tests nothing")
	}
}

// A worktree that can be neither removed nor moved aside, because the
// serve root will not take the rename, is an unmendableError, and what
// stood at the path is left where it was.
func TestAnUnmendableWorktreeIsAnUnmendableErrorWhenTheRootRefusesTheRename(t *testing.T) {
	skipUnlessImmutable(t)
	if os.Geteuid() == 0 {
		t.Skip("root is not kept out by mode bits")
	}
	checkout := repo(t)
	root := t.TempDir()
	path := filepath.Join(root, "worktrees", "t")
	unremovableAt(t, path)
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(root, 0o700) })
	made, remade, err := ensureWorktree(checkout, path)
	var unmendable *unmendableError
	if !errors.As(err, &unmendable) {
		t.Fatalf("ensureWorktree: made %v remade %v err %v (%T), want an unmendableError", made, remade, err, err)
	}
	if made || remade {
		t.Errorf("made %v remade %v with nothing made", made, remade)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("the error does not carry the rename's refusal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(path, "stuck")); err != nil {
		t.Errorf("what stood at the path is gone: %v", err)
	}
	noneAside(t, root)
}

// takeAsideNames makes <root>/<base>.damaged-1 to -n, as earlier copies
// moved aside would have.
func takeAsideNames(t *testing.T, root, base string, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("%s.damaged-%d", base, i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// maxAside names are looked past and no more: with one fewer taken the
// worktree goes to the last, and with all of them taken it is an
// unmendableError that says so.
func TestAnUnmendableWorktreeIsAnUnmendableErrorWhenEveryAsideNameIsTaken(t *testing.T) {
	skipUnlessImmutable(t)
	checkout := repo(t)
	t.Run("one free", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "worktrees", "t")
		unremovableAt(t, path)
		takeAsideNames(t, root, "t", maxAside-1)
		last := filepath.Join(root, fmt.Sprintf("t.damaged-%d", maxAside))
		var made bool
		var err error
		stderr := captureStderr(t, func() { made, _, err = ensureWorktree(checkout, path) })
		if err != nil || !made {
			t.Fatalf("made %v err %v", made, err)
		}
		if _, err := os.Lstat(filepath.Join(last, "stuck")); err != nil {
			t.Errorf("the worktree was not moved to the last name: %v", err)
		}
		if !strings.Contains(stderr, movedAsideLine(path, last)) {
			t.Errorf("stderr does not name %s:\n%s", last, stderr)
		}
	})
	t.Run("none free", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "worktrees", "t")
		unremovableAt(t, path)
		takeAsideNames(t, root, "t", maxAside)
		_, _, err := ensureWorktree(checkout, path)
		var unmendable *unmendableError
		if !errors.As(err, &unmendable) {
			t.Fatalf("err %v (%T), want an unmendableError", err, err)
		}
		if want := fmt.Sprintf("t.damaged-1 to -%d are all taken", maxAside); !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
		if _, err := os.Lstat(filepath.Join(path, "stuck")); err != nil {
			t.Errorf("what stood at the path is gone: %v", err)
		}
	})
}

// What cannot be mended is the message's failure and not the run's: the
// round ends as any round with a failure does, the message has one
// failure written against it and no answer, and stderr says why.
func TestAnUnmendableWorktreeIsTheMessagesFailureNotTheRuns(t *testing.T) {
	skipUnlessImmutable(t)
	_, bob, second := damagedThenAsked(t, "rm -f .git && touch stuck && chflags uchg stuck")
	takeAsideNames(t, filepath.Join(bob.home, "serve"), "jostle", maxAside)
	var err error
	stderr := captureStderr(t, func() { _, err = bob.tryRun("serve", "--once") })
	// The round's own exit for a message that failed, not the run stopped.
	if err == nil || err.Error() != "1 message went unanswered; the failures are above, and the next round tries again" {
		t.Fatalf("serve: %v, want the round's own failure\nstderr: %s", err, stderr)
	}
	e := bob.ledgerOf(t).Messages[second.ID]
	if e == nil || e.Failures != 1 || !e.Handled.IsZero() || e.Reply != "" || e.Tried.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("the ledger does not have one failure against the second ask: %+v", e)
	}
	if want := "could not be removed or moved aside"; !strings.Contains(stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, stderr)
	}
}

// openUp gives every directory under a path its permissions back, one
// nested two deep under another with mode 000 included, and never follows
// a link: the directory a link inside points at keeps its mode.
func TestLimitOpenUpGivesDirectoriesBackAndFollowsNoLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not Windows permissions, and symlinks")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(outside, 0o700) })
	path := filepath.Join(root, "wt")
	a := filepath.Join(path, "a")
	b := filepath.Join(a, "b")
	if err := os.MkdirAll(filepath.Join(b, "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{b, a} {
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { giveBack(root) })
	openUp(path)
	for _, dir := range []string{path, a, b, filepath.Join(b, "c")} {
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s is %o after openUp, want 700", dir, got)
		}
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o500 {
		t.Errorf("the directory outside, behind a link, is %o after openUp, want 500 untouched", got)
	}
}

// A directory git cannot be started in is the directory's trouble, not
// git's: gitAsk says so with errCannotStartIn, and lostWorktree takes it
// for a directory that is no longer a worktree.
func TestGitAskInADirectoryItCannotStartInIsErrCannotStartIn(t *testing.T) {
	skipUnlessPermissionsHold(t)
	checkout := repo(t)
	path := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o700) })
	_, answered, err := gitAsk(path, "--show-toplevel")
	if !errors.Is(err, errCannotStartIn) || answered {
		t.Fatalf("gitAsk: answered %v err %v, want errCannotStartIn", answered, err)
	}
	if lost, err := lostWorktree(checkout, path); err != nil || !lost {
		t.Errorf("lostWorktree: lost %v err %v, want lost", lost, err)
	}
	// The checkout's own question is still the host's: a checkout git
	// cannot start in is an error and not a lost worktree.
	if lost, err := lostWorktree(path, checkout); err == nil {
		t.Errorf("lostWorktree with the checkout locked: lost %v and no error", lost)
	}
}
