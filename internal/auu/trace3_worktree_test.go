package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The third adversarial trace's finding on a worktree git has lost: a
// handler that took .git out of a read-only channel's worktree stopped the
// expert for good, since every later message on the channel met a worktree
// ensureWorktree refused, and the refusal ended the run before anything was
// written against the message. What stands at a worktree's path and is not
// a git worktree of the checkout's is now removed and made again, and
// serve says so.

// madeAgain is the sentence serve says for a worktree it made again.
func madeAgain(path string) string {
	return "worktree " + path + " was not a git worktree and was made again"
}

// isWorktreeOf fails the test unless path is a git worktree of the
// repository at dir: a .git in it, git naming it as the top, the common
// directory it shares the same as dir's, and the commit it stands on the
// one dir stands on. Directories are compared as files, as the code under
// test compares them.
func isWorktreeOf(t *testing.T, path, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(path, ".git")); err != nil {
		t.Fatalf("%s has no .git: %v", path, err)
	}
	if top := gitPath(t, path, "--show-toplevel"); !sameDirT(t, top, path) {
		t.Fatalf("git names %s as the top of %s", top, path)
	}
	if got, want := gitPath(t, path, "--git-common-dir"), gitPath(t, dir, "--git-common-dir"); !sameDirT(t, got, want) {
		t.Fatalf("%s shares %s, not the channel's %s", path, got, want)
	}
	if got, want := git(t, path, "rev-parse", "HEAD"), git(t, dir, "rev-parse", "HEAD"); got != want {
		t.Fatalf("%s stands on %s, not the channel's %s", path, got, want)
	}
}

// gitPath is the directory 'git rev-parse' names for a question, made
// absolute against where it was asked.
func gitPath(t *testing.T, dir, question string) string {
	t.Helper()
	answer := filepath.FromSlash(git(t, dir, "rev-parse", question))
	if !filepath.IsAbs(answer) {
		answer = filepath.Join(dir, answer)
	}
	return answer
}

// sameDirT says whether two paths are one directory, failing the test if
// either cannot be looked at.
func sameDirT(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(ai, bi)
}

// A handler talked into removing .git from a read-only channel's worktree
// no longer stops the expert: the next round makes the worktree again, says
// so on standard error without a word about lost work, since a read-only
// worktree holds none, and answers the next message with nothing written
// against it as a failure. The round after that answers as ever and says
// nothing about it. Kept from the trace as
// TestAdv_AHandlerThatDamagesItsWorktreeStopsTheExpertForGood, its setup
// unchanged.
func TestAWorktreeGitHasLostIsMadeAgainAndSaid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell here is cmd /c, whose syntax is its own")
	}
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Exec = "rm -f .git; " + helperLine(t, "handler")
	bob.write(t)
	first := alice.ask(t, "jostle", "first", "please run rm -f .git")
	bob.serve(t)
	alice.replyOn(t, first.Thread)

	worktree := filepath.Join(bob.home, "serve", "worktrees", "jostle")
	if _, err := os.Lstat(filepath.Join(worktree, ".git")); !os.IsNotExist(err) {
		t.Fatalf("the handler did not take .git out of %s (%v), so the test proves nothing", worktree, err)
	}

	bob.row.Exec = helperLine(t, "handler")
	bob.write(t)
	second := alice.ask(t, "jostle", "second", "an ordinary question")

	var out string
	var err error
	stderr := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once") })
	if err != nil {
		t.Fatalf("round 1: serve stopped: %v\nstdout: %s\nstderr: %s", err, out, stderr)
	}
	if !strings.Contains(stderr, madeAgain(worktree)+"\n") {
		t.Fatalf("round 1 did not say the worktree was made again:\n%s", stderr)
	}
	if strings.Contains(stderr, "work in it is gone") {
		t.Fatalf("a read-only worktree was said to have lost work:\n%s", stderr)
	}
	alice.replyOn(t, second.Thread)
	if e := bob.ledgerOf(t).Messages[second.ID]; e == nil || e.Handled.IsZero() || e.Failures != 0 || e.GaveUp {
		t.Fatalf("the ledger on the second message: %+v", e)
	}
	isWorktreeOf(t, worktree, bob.dir)

	third := alice.ask(t, "jostle", "third", "another ordinary question")
	stderr = captureStderr(t, func() { out, err = bob.tryRun("serve", "--once") })
	if err != nil {
		t.Fatalf("round 2: serve stopped: %v\nstdout: %s\nstderr: %s", err, out, stderr)
	}
	if strings.Contains(stderr, "made again") {
		t.Fatalf("round 2 made a sound worktree again:\n%s", stderr)
	}
	alice.replyOn(t, third.Thread)
	if e := bob.ledgerOf(t).Messages[third.ID]; e == nil || e.Handled.IsZero() || e.Failures != 0 {
		t.Fatalf("the ledger on the third message: %+v", e)
	}
}

// A side-copy thread's worktree that is no longer the channel's — its .git
// removed between turns, or a handler having run 'rm -rf .git && git init'
// in it — is made again and serve says the thread's work in it is gone,
// which it is: the file the first turn wrote is not in the new worktree.
// Where .git was removed between turns it is made again on the thread's
// next message; where a handler ran 'git init', its own turn fails, and
// the worktree is made again when that failed message is tried again, in
// the round that answers the next message. Either way the next message
// is answered. The thread's base is recorded afresh as the commit the new
// worktree stands on, which the channel moved past the old base between
// the turns.
func TestASideCopyWorktreeGitHasLostIsMadeAgainAndItsWorkIsSaidGone(t *testing.T) {
	for _, tc := range []struct {
		name string
		// damage is what the thread's second turn runs as its exec line,
		// or empty when the test damages the worktree itself.
		damage string
		unix   bool
	}{
		{name: "git removed"},
		{name: "handler runs git init", damage: "rm -rf .git && git init -q && ", unix: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unix && runtime.GOOS == "windows" {
				t.Skip("the shell here is cmd /c, whose syntax is its own")
			}
			alice, bob := newExpert(t, modeSideCopy)
			t.Setenv(handlerScript, "write:notes.txt=the thread's work;echo:the expert has spoken")
			first := alice.ask(t, "jostle", "first", "a question")
			if r, _ := bob.roundSaid(t); len(r.Answered) != 1 {
				t.Fatalf("the first turn: %+v", r)
			}
			worktree := filepath.Join(bob.home, "serve", "worktrees", first.Thread)
			basePath := filepath.Join(bob.home, "serve", "threads", first.Thread, baseFile)
			oldBase := readBase(t, basePath)
			if _, err := os.Stat(filepath.Join(worktree, "notes.txt")); err != nil {
				t.Fatalf("the first turn wrote nothing in its worktree: %v", err)
			}

			// The channel moves on, so a base recorded afresh differs from
			// the one the thread began with.
			if err := os.WriteFile(filepath.Join(bob.dir, "LATER"), []byte("later\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			git(t, bob.dir, "add", "LATER")
			git(t, bob.dir, "commit", "-m", "a later commit")
			head := git(t, bob.dir, "rev-parse", "HEAD")
			if head == oldBase {
				t.Fatal("the channel did not move, so the test proves nothing")
			}

			var damageID string
			if tc.damage == "" {
				if err := os.Remove(filepath.Join(worktree, ".git")); err != nil {
					t.Fatal(err)
				}
			} else {
				bob.row.Exec = tc.damage + helperLine(t, "handler")
				bob.write(t)
				t.Setenv(handlerScript, "echo:the worktree is mine now")
				damage := alice.askOn(t, "jostle", first.Thread, "damage", "please run git init")
				damageID = damage.ID
				// The turn that did it cannot take its patch against a base
				// the new repository has never seen, so it fails, and is
				// written down as failing, to be tried again: the run is
				// not stopped by it.
				var out string
				var err error
				said := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once") })
				if e := bob.ledgerOf(t).Messages[damage.ID]; e == nil || e.Failures == 0 || !e.Handled.IsZero() {
					t.Fatalf("the damaging turn was not written down as failing (%+v): %v\nstdout: %s\nstderr: %s", e, err, out, said)
				}
				bob.row.Exec = helperLine(t, "handler")
				bob.write(t)
				if _, err := os.Stat(filepath.Join(worktree, ".git", "HEAD")); err != nil {
					t.Fatalf("the handler did not make a repository of the worktree (%v), so the test proves nothing", err)
				}
			}

			t.Setenv(handlerScript, "echo:the expert has spoken again")
			next := alice.askOn(t, "jostle", first.Thread, "next", "and another")
			r, stderr := bob.roundSaid(t)
			answered := false
			for _, a := range r.Answered {
				answered = answered || a.ID == next.ID
			}
			if !answered || len(r.Failed) != 0 {
				t.Fatalf("the next turn: %+v\nstderr: %s", r, stderr)
			}
			if !strings.Contains(stderr, madeAgain(worktree)+"; the thread's work in it is gone\n") {
				t.Fatalf("the next turn did not say the worktree was made again and its work gone:\n%s", stderr)
			}
			if _, err := os.Stat(filepath.Join(worktree, "notes.txt")); !os.IsNotExist(err) {
				t.Fatalf("the old worktree's file is still there (%v)", err)
			}
			isWorktreeOf(t, worktree, bob.dir)
			if got := readBase(t, basePath); got != head {
				t.Fatalf("the thread's base is %s, not the channel's HEAD %s (it began at %s)", got, head, oldBase)
			}

			// The damaging turn's answer was written and not sent, so the
			// retry sends it with the thread's latest patch, taken against
			// the base before: the first turn's. The work is gone from the
			// worktree but still reaches the asker in that patch.
			if damageID != "" {
				reply := replyToMessage(t, alice, first.Thread, damageID)
				if len(reply.Attachments) != 1 || reply.Attachments[0].Name != patchName(first.Thread) {
					t.Fatalf("the damaging turn's reply carries %+v", reply.Attachments)
				}
				if patch := readFile(t, patchOf(t, alice, reply)); !strings.Contains(patch, "notes.txt") {
					t.Fatalf("the damaging turn's patch is not the first turn's:\n%s", patch)
				}
				if !strings.Contains(reply.Text, "The changes so far are attached") {
					t.Fatalf("the damaging turn's reply does not say a patch is attached:\n%s", reply.Text)
				}
			}
			// Nor does the next turn's reply carry the gone work.
			if reply := replyToMessage(t, alice, first.Thread, next.ID); len(reply.Attachments) != 0 {
				if patch := readFile(t, patchOf(t, alice, reply)); strings.Contains(patch, "notes.txt") {
					t.Fatalf("the next turn's patch carries the gone work:\n%s", patch)
				}
			}
		})
	}
}

// replyToMessage is the reply alice received to one message on a thread,
// read in full.
func replyToMessage(t *testing.T, u *user, thread, id string) messageJSON {
	t.Helper()
	var in inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.Thread != thread || m.Type != "reply" {
			continue
		}
		var full messageJSON
		if err := json.Unmarshal([]byte(u.run("read", m.ID, "--json")), &full); err != nil {
			t.Fatal(err)
		}
		if full.InReplyTo == id {
			return full
		}
	}
	t.Fatalf("no reply to %s on thread %s", id[:12], thread[:12])
	return messageJSON{}
}

// readBase is the commit a base file records.
func readBase(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// A read-only channel's worktree a handler made a repository of its own,
// with 'rm -rf .git && git init', is made again for the next thread's
// message, which is answered: the run does not end on it.
func TestAReadOnlyWorktreeAHandlerMadeARepositoryOfIsMadeAgain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell here is cmd /c, whose syntax is its own")
	}
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Exec = "rm -rf .git && git init -q && " + helperLine(t, "handler")
	bob.write(t)
	first := alice.ask(t, "jostle", "first", "please run git init")
	bob.serve(t)
	alice.replyOn(t, first.Thread)
	worktree := filepath.Join(bob.home, "serve", "worktrees", "jostle")
	if _, err := os.Stat(filepath.Join(worktree, ".git", "HEAD")); err != nil {
		t.Fatalf("the handler did not make a repository of the worktree (%v), so the test proves nothing", err)
	}

	bob.row.Exec = helperLine(t, "handler")
	bob.write(t)
	second := alice.ask(t, "jostle", "second", "an ordinary question")
	r, stderr := bob.roundSaid(t)
	if len(r.Answered) != 1 || r.Answered[0].ID != second.ID || len(r.Failed) != 0 {
		t.Fatalf("the new thread's message: %+v\nstderr: %s", r, stderr)
	}
	if !strings.Contains(stderr, madeAgain(worktree)+"\n") {
		t.Fatalf("the round did not say the worktree was made again:\n%s", stderr)
	}
	alice.replyOn(t, second.Thread)
	isWorktreeOf(t, worktree, bob.dir)
}

// ensureWorktree makes a worktree that is absent, leaves a sound one and
// what is in it alone, and removes and makes again whatever else stands at
// the path: a worktree whose .git was removed, a plain file, a link, whose
// target is left untouched, a worktree whose .git was removed inside an
// enclosing repository, where 'git rev-parse HEAD' would answer for the
// enclosing one, a worktree made a repository of its own with 'git init',
// another repository's worktree, a link to another thread's worktree, and
// a link to nothing.
func TestEnsureWorktreeMakesAgainWhatIsNotAWorktree(t *testing.T) {
	dir := repo(t)

	t.Run("absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		isWorktreeOf(t, path, dir)
	})

	t.Run("sound", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if _, _, err := ensureWorktree(dir, path); err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(path, "kept.txt")
		if err := os.WriteFile(kept, []byte("mine\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || made || remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		if data, err := os.ReadFile(kept); err != nil || string(data) != "mine\n" {
			t.Fatalf("the file in a sound worktree: %q, %v", data, err)
		}
	})

	t.Run("git removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if _, _, err := ensureWorktree(dir, path); err != nil {
			t.Fatal(err)
		}
		old := filepath.Join(path, "old.txt")
		if err := os.WriteFile(old, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(path, ".git")); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		if _, err := os.Stat(old); !os.IsNotExist(err) {
			t.Fatalf("the old worktree's file survived (%v)", err)
		}
		isWorktreeOf(t, path, dir)
	})

	t.Run("a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("not a worktree\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		isWorktreeOf(t, path, dir)
	})

	t.Run("a link", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("a symbolic link needs a privilege there")
		}
		elsewhere := t.TempDir()
		precious := filepath.Join(elsewhere, "precious.txt")
		if err := os.WriteFile(precious, []byte("keep me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, path); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			t.Fatalf("what stands at the path: %v, %v", info, err)
		}
		if data, err := os.ReadFile(precious); err != nil || string(data) != "keep me\n" {
			t.Fatalf("the link's target was touched: %q, %v", data, err)
		}
		if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 1 {
			t.Fatalf("the link's target holds %v (%v)", entries, err)
		}
		isWorktreeOf(t, path, dir)
	})

	t.Run("inside an enclosing repository", func(t *testing.T) {
		root := t.TempDir()
		git(t, root, "init", "-b", "main")
		if err := os.WriteFile(filepath.Join(root, "dotfile"), []byte("the home's own\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		git(t, root, "add", "dotfile")
		git(t, root, "commit", "-m", "the enclosing repository")
		path := filepath.Join(root, "worktrees", "w")
		if _, _, err := ensureWorktree(dir, path); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(path, ".git")); err != nil {
			t.Fatal(err)
		}
		// The old question would have passed: git finds the enclosing
		// repository by looking upward.
		if got := git(t, path, "rev-parse", "HEAD"); got != git(t, root, "rev-parse", "HEAD") {
			t.Fatalf("rev-parse HEAD in the damaged worktree gave %s, not the enclosing HEAD, so the test proves nothing", got)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		isWorktreeOf(t, path, dir)
	})

	// A worktree a handler made a repository of its own, with .git removed
	// and 'git init' run there, is git's top of something, but not of the
	// channel's repository, and is made again as the channel's.
	t.Run("git init", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if _, _, err := ensureWorktree(dir, path); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(path, ".git")); err != nil {
			t.Fatal(err)
		}
		git(t, path, "init", "-q")
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		isWorktreeOf(t, path, dir)
	})

	// A sound worktree of another repository at the path is not the
	// channel's, and is made again as the channel's.
	t.Run("another repository's worktree", func(t *testing.T) {
		other := repo(t)
		if err := os.WriteFile(filepath.Join(other, "OTHER"), []byte("another project\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		git(t, other, "add", "OTHER")
		git(t, other, "commit", "-m", "another project's commit")
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		git(t, other, "worktree", "add", "--detach", path, "HEAD")
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		isWorktreeOf(t, path, dir)
		if _, err := os.Stat(filepath.Join(path, "OTHER")); !os.IsNotExist(err) {
			t.Fatalf("the other repository's file is still there (%v)", err)
		}
	})

	// A link to another thread's sound worktree is not this path's
	// worktree: what stands at the path is looked at without following the
	// link, so the link is removed and a worktree made in its place, and
	// the other worktree is left as it was. Followed, the link would be
	// taken for a sound worktree and a handler would run in another
	// thread's.
	t.Run("link to another worktree", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("a symbolic link needs a privilege there")
		}
		root := t.TempDir()
		other := filepath.Join(root, "worktrees", "other")
		if _, _, err := ensureWorktree(dir, other); err != nil {
			t.Fatal(err)
		}
		theirs := filepath.Join(other, "theirs.txt")
		if err := os.WriteFile(theirs, []byte("another thread's work\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "worktrees", "w")
		if err := os.Symlink(other, path); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			t.Fatalf("what stands at the path: %v, %v", info, err)
		}
		isWorktreeOf(t, path, dir)
		isWorktreeOf(t, other, dir)
		if data, err := os.ReadFile(theirs); err != nil || string(data) != "another thread's work\n" {
			t.Fatalf("the other worktree's file: %q, %v", data, err)
		}
		if _, err := os.Stat(filepath.Join(path, "theirs.txt")); !os.IsNotExist(err) {
			t.Fatalf("the other worktree's file is in this one (%v)", err)
		}
	})

	// A link to nothing is removed and a worktree made in its place, and
	// the name it pointed at is not made.
	t.Run("dangling link", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("a symbolic link needs a privilege there")
		}
		root := t.TempDir()
		nowhere := filepath.Join(root, "nowhere")
		path := filepath.Join(root, "worktrees", "w")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(nowhere, path); err != nil {
			t.Fatal(err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err != nil || !made || !remade {
			t.Fatalf("made %v, remade %v, err %v", made, remade, err)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			t.Fatalf("what stands at the path: %v, %v", info, err)
		}
		isWorktreeOf(t, path, dir)
		if _, err := os.Lstat(nowhere); !os.IsNotExist(err) {
			t.Fatalf("the link's target was made (%v)", err)
		}
	})
}

// lostWorktree says a sound worktree of the checkout is not lost, however
// the path to it is spelled: through a link to its parent, or, where the
// filesystem ignores case, with a letter in another case. It says a
// directory is lost when no repository holds it, when the repository git
// finds for it is an enclosing one whose top is not the directory, and when
// it is a repository of its own made with 'git init'. A checkout git will
// not answer for is an error, not a verdict on the directory.
func TestLostWorktreeAsksWhoseTopTheDirectoryIs(t *testing.T) {
	dir := repo(t)

	parent := filepath.Join(t.TempDir(), "Home")
	sound := filepath.Join(parent, "w")
	if _, _, err := ensureWorktree(dir, sound); err != nil {
		t.Fatal(err)
	}
	if lost, err := lostWorktree(dir, sound); err != nil || lost {
		t.Fatalf("a sound worktree: lost %v, err %v", lost, err)
	}

	plain := t.TempDir()
	if lost, err := lostWorktree(dir, plain); err != nil || !lost {
		t.Fatalf("a plain directory: lost %v, err %v", lost, err)
	}

	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if lost, err := lostWorktree(dir, nested); err != nil || !lost {
		t.Fatalf("a directory inside another repository: lost %v, err %v", lost, err)
	}

	initialised := t.TempDir()
	git(t, initialised, "init", "-q")
	if lost, err := lostWorktree(dir, initialised); err != nil || !lost {
		t.Fatalf("a repository of its own: lost %v, err %v", lost, err)
	}

	t.Run("through a link", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("a symbolic link needs a privilege there")
		}
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(parent, link); err != nil {
			t.Fatal(err)
		}
		if lost, err := lostWorktree(dir, filepath.Join(link, "w")); err != nil || lost {
			t.Fatalf("a sound worktree through a link: lost %v, err %v", lost, err)
		}
	})

	t.Run("in another case", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("a filesystem that ignores case is the default only on darwin")
		}
		other := filepath.Join(filepath.Dir(parent), "home", "w")
		if _, err := os.Stat(other); err != nil {
			t.Skipf("this filesystem tells case apart: %v", err)
		}
		if lost, err := lostWorktree(dir, other); err != nil || lost {
			t.Fatalf("a sound worktree in another case: lost %v, err %v", lost, err)
		}
	})

	t.Run("a checkout that is not a repository", func(t *testing.T) {
		notRepo := t.TempDir()
		// Git is not to find a repository above either directory.
		t.Setenv("GIT_CEILING_DIRECTORIES", strings.Join([]string{filepath.Dir(notRepo), filepath.Dir(plain)}, string(os.PathListSeparator)))
		lost, err := lostWorktree(notRepo, sound)
		if err == nil || lost {
			t.Fatalf("a checkout that is not a repository: lost %v, err %v", lost, err)
		}
		// The checkout is asked first: a path git refuses as well is not
		// called lost while the checkout has not answered.
		lost, err = lostWorktree(notRepo, plain)
		if err == nil || lost {
			t.Fatalf("a checkout that is not a repository, with a plain directory: lost %v, err %v", lost, err)
		}
	})
}

// A git that cannot be started has said nothing about what stands at a
// worktree's path, so nothing there is removed: a worktree whose .git was
// removed is kept with its file, and lostWorktree gives an error rather
// than calling it lost, and a plain file is kept unchanged, since the prune
// that proves git runs fails before anything is removed. Git is made
// unfindable inside each subtest alone, so the fixtures are made with it
// and PATH is back before anything else needs it.
func TestAGitThatCannotRunRemovesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git is found by more than PATH there")
	}
	dir := repo(t)

	t.Run("a worktree git has lost", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if _, _, err := ensureWorktree(dir, path); err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(path, "kept.txt")
		if err := os.WriteFile(kept, []byte("mine\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(path, ".git")); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", t.TempDir())

		if lost, err := lostWorktree(dir, path); err == nil || lost {
			t.Fatalf("lostWorktree with no git: lost %v, err %v", lost, err)
		}
		made, remade, err := ensureWorktree(dir, path)
		if err == nil || made || remade {
			t.Fatalf("ensureWorktree with no git: made %v, remade %v, err %v", made, remade, err)
		}
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			t.Fatalf("the directory is gone: %v, %v", info, err)
		}
		if data, err := os.ReadFile(kept); err != nil || string(data) != "mine\n" {
			t.Fatalf("the file in it: %q, %v", data, err)
		}
	})

	t.Run("a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worktrees", "w")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("not a worktree\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", t.TempDir())

		made, remade, err := ensureWorktree(dir, path)
		if err == nil || made || remade {
			t.Fatalf("ensureWorktree with no git: made %v, remade %v, err %v", made, remade, err)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("what stands at the path: %v, %v", info, err)
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "not a worktree\n" {
			t.Fatalf("the file: %q, %v", data, err)
		}
	})
}
