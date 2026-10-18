package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLimitServesGitDoesNotReadTheWorktreesGitFile: a side copy's worktree
// is the handler's, its .git file among it, and so is the directory git
// keeps the worktree's index and HEAD in, since a handler that commits in
// its worktree writes there. serve's 'git add' after the handler ran on
// both, and read the configuration of whatever repository they named (F1,
// tracer A's CONCERN-3, and the second reader's commondir and
// config.worktree plants): a handler that pointed either at a repository
// of its own, with a filesystem monitor, a clean filter and a hook set
// there, had serve run all three as its own account. Now a worktree whose
// .git was changed is the message's failure, and the patch is taken from
// the checkout's own repository with an index of serve's own, so neither
// is read: nothing planted runs, and where the plant left the worktree
// answering as serve's, the answer goes with the handler's change in it,
// the attribute naming a filter the operator's own configuration does not
// define doing nothing.
//
// It runs on Windows too, where the hook path serve gives git is NUL and
// git runs the planted commands, if it ran them, through its own shell.
func TestLimitServesGitDoesNotReadTheWorktreesGitFile(t *testing.T) {
	for _, plant := range []string{".git", "commondir", "config.worktree"} {
		t.Run(plant, func(t *testing.T) {
			alice, bob := newExpert(t, modeSideCopy)
			planted := t.TempDir()
			ran := map[string]string{
				"monitor": filepath.Join(planted, "fsmonitor-ran"),
				"filter":  filepath.Join(planted, "filter-ran"),
				"hook":    filepath.Join(planted, "hook-ran"),
			}
			evil := filepath.Join(planted, "evil.git")
			git(t, planted, "init", "--bare", evil)
			git(t, planted, "--git-dir="+evil, "config", "core.bare", "false")
			monitor := filepath.Join(planted, "fsmonitor.sh")
			if err := os.WriteFile(monitor, []byte("#!/bin/sh\ntouch '"+ran["monitor"]+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			hooks := filepath.Join(planted, "hooks")
			if err := os.Mkdir(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hooks, "post-index-change"), []byte("#!/bin/sh\ntouch '"+ran["hook"]+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			git(t, planted, "--git-dir="+evil, "config", "core.fsmonitor", monitor)
			git(t, planted, "--git-dir="+evil, "config", "filter.x.clean", "touch '"+ran["filter"]+"'; cat")
			git(t, planted, "--git-dir="+evil, "config", "core.hooksPath", hooks)
			// The handler's whole part: a change, the attribute that names
			// the filter, and the plant.
			script := "write:one.txt=a change;write:.gitattributes=* filter=x;"
			switch plant {
			case ".git":
				script += "write:.git=gitdir: " + evil
			case "commondir":
				script += "plant:commondir=" + evil
			case "config.worktree":
				// The operator's repository reads a worktree's own
				// configuration once this is set, which sparse-checkout
				// sets.
				git(t, bob.dir, "config", "extensions.worktreeConfig", "true")
				script += "plant:config.worktree=" + ran["filter"]
			}
			t.Setenv(handlerScript, script+";echo:an answer")
			sent := alice.ask(t, "jostle", "a question", "the first")
			said := captureStderr(t, func() { bob.tryRun("serve", "--once") })
			for what, marker := range ran {
				if _, err := os.Stat(marker); err == nil {
					t.Errorf("serve's git ran the planted %s", what)
				}
			}
			if plant == ".git" {
				if !strings.Contains(said, "was not answered") || !strings.Contains(said, "is no longer the git worktree serve made") {
					t.Fatalf("the failure was said as:\n%s", said)
				}
				if out := alice.run("inbox", "--json"); strings.Contains(out, `"type": "reply"`) {
					t.Fatalf("a reply went out:\n%s", out)
				}
				return
			}
			reply := alice.replyOn(t, sent.Thread)
			if got := readFile(t, patchOf(t, alice, reply)); !strings.Contains(got, "one.txt") {
				t.Fatalf("the reply went with:\n%s\nserve said:\n%s", got, said)
			}
		})
	}
}

// TestLimitASideCopyOfASparseCheckoutIsRefused: the patch is taken with an
// index serve makes from the base, which holds every file of the base, so
// on a sparse checkout, whose worktrees git makes sparse too, every file
// the checkout leaves out would read as deleted and go to the asker as a
// deletion the handler never made. A side copy served from one is that
// message's failure, naming the setting, which is asked of the operator's
// checkout; a thread begun after the checkout is made full again answers
// with the handler's change and nothing else.
func TestLimitASideCopyOfASparseCheckoutIsRefused(t *testing.T) {
	// sparse-checkout's --no-cone is from git 2.35, newer than serve needs.
	if line, err := gitOutput("", "--version"); err != nil || !gitAtLeast(line, 2, 35) {
		t.Skipf("git 2.35 or later makes the sparse checkout: %q %v", line, err)
	}
	alice, bob := newExpert(t, modeSideCopy)
	git(t, bob.dir, "sparse-checkout", "set", "--no-cone", "/nothing-here/")
	t.Setenv(handlerScript, "write:one.txt=a change;echo:an answer")
	alice.ask(t, "jostle", "a question", "the first")
	said := captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if !strings.Contains(said, "was not answered") || !strings.Contains(said, "core.sparseCheckout is true") {
		t.Fatalf("the failure was said as:\n%s", said)
	}
	if out := alice.run("inbox", "--json"); strings.Contains(out, `"type": "reply"`) {
		t.Fatalf("a reply went out:\n%s", out)
	}
	git(t, bob.dir, "sparse-checkout", "disable")
	sent := alice.ask(t, "jostle", "another question", "on a thread of its own")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	got := readFile(t, patchOf(t, alice, alice.replyOn(t, sent.Thread)))
	if !strings.Contains(got, "one.txt") || strings.Contains(got, "deleted file") {
		t.Fatalf("the patch from a full checkout:\n%s", got)
	}
}

// TestLimitTheRepositoryServesGitReadsIsNamedAbsolutely: patchFor names the
// checkout's repository and the worktree to git in its environment, and git
// resolves a relative GIT_DIR or GIT_WORK_TREE against the directory it
// runs in, which is the worktree. A checkout named relatively, by a
// relative --config and dir, or a worktree under a relative AUU_HOME, gave
// a GIT_DIR inside the worktree, where the handler can make a repository of
// its own with a clean filter set (the reviewer's pre-read of 45). Both are
// made absolute first: the filter planted at the relative spelling never
// runs, and the patch carries the handler's change.
func TestLimitTheRepositoryServesGitReadsIsNamedAbsolutely(t *testing.T) {
	for _, relative := range []string{"checkout", "checkout and worktree"} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			git(t, root, "init", "-q", "proj")
			if err := os.WriteFile(filepath.Join(root, "proj", "a.txt"), []byte("a\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			git(t, filepath.Join(root, "proj"), "add", "a.txt")
			git(t, filepath.Join(root, "proj"), "commit", "-q", "-m", "base")
			base := git(t, filepath.Join(root, "proj"), "rev-parse", "HEAD")
			git(t, filepath.Join(root, "proj"), "worktree", "add", "-q", "--detach", filepath.Join(root, "wt"))
			// The handler's change, and its repository at the relative
			// spelling of the checkout's, with the objects the base needs
			// and a filter.
			if err := os.WriteFile(filepath.Join(root, "wt", "one.txt"), []byte("a change\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := copyTree(filepath.Join(root, "proj", ".git"), filepath.Join(root, "wt", "proj", ".git")); err != nil {
				t.Fatal(err)
			}
			ran := filepath.Join(t.TempDir(), "filter-ran")
			git(t, root, "--git-dir="+filepath.Join(root, "wt", "proj", ".git"), "config", "filter.x.clean", "touch '"+filepath.ToSlash(ran)+"' && cat")
			if err := os.WriteFile(filepath.Join(root, "wt", ".gitattributes"), []byte("* filter=x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			worktree := filepath.Join(root, "wt")
			if relative != "checkout" {
				worktree = "wt"
			}
			ch := &serveChannel{Dir: "proj", Mode: modeSideCopy}
			path, err := patchFor(ch, worktree, base, "state", "0123456789abcdef")
			if _, err := os.Stat(ran); err == nil {
				t.Fatal("serve's git ran the filter of the repository planted in the worktree")
			}
			if err != nil {
				t.Fatal(err)
			}
			if path == "" || !strings.Contains(readFile(t, path), "one.txt") {
				t.Fatalf("the patch at %q does not carry the handler's change", path)
			}
		})
	}
}

// TestLimitServesGitStartsNothingInARepositoryTheHandlerMade: add -A asks a
// submodule's own repository whether it is modified by running git status
// in it, which reads that repository's configuration and runs a clean
// filter it names; no -c of serve's reaches a filter name the handler
// chose. A base of the handler's own, a commit in the object store the
// worktree shares, can hold a submodule entry where the handler made a
// repository, and serve's add then ran its filter (F1, the second reader
// of A-3's fix). Now every submodule entry of serve's index is marked
// skip-worktree before add -A, and the filter does not run: the answer
// goes with the handler's change and with nothing for the repository. A
// repository at a path the base does not hold, or in place of a file the
// base holds, starts nothing either; add -A records it as a submodule
// entry, which is taken out again, so the patch carries no commit id the
// asker does not have, and a replaced file goes as deleted.
func TestLimitServesGitStartsNothingInARepositoryTheHandlerMade(t *testing.T) {
	t.Run("a submodule entry in the base", func(t *testing.T) {
		alice, bob := newExpert(t, modeSideCopy)
		ran := filepath.Join(t.TempDir(), "filter-ran")
		// The first turn plants the repository and the base, which serve
		// reads back at the next.
		t.Setenv(handlerScript, "write:one.txt=a change;plant:gitlink="+ran+";echo:the first answer")
		sent := alice.ask(t, "jostle", "a question", "the first")
		bob.serve(t)
		reply := alice.replyOn(t, sent.Thread)
		t.Setenv(handlerScript, "write:two.txt=another change;echo:the second answer")
		alice.run("reply", reply.ID[:12], "and one more thing")
		said := captureStderr(t, func() { bob.tryRun("serve", "--once") })
		if _, err := os.Stat(ran); err == nil {
			t.Fatal("serve's git ran the filter of the repository the handler made")
		}
		got := readFile(t, patchOf(t, alice, replyWith(t, alice, "the second answer", said)))
		if !strings.Contains(got, "two.txt") || strings.Contains(got, "Subproject") {
			t.Fatalf("the second answer went with:\n%s", got)
		}
	})
	for _, at := range []string{"a repository the base does not hold", "a repository in place of a file of the base"} {
		t.Run(at, func(t *testing.T) {
			alice, bob := newExpert(t, modeSideCopy)
			if at != "a repository the base does not hold" {
				if err := os.WriteFile(filepath.Join(bob.dir, "sub"), []byte("a file\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				git(t, bob.dir, "add", "sub")
				git(t, bob.dir, "commit", "-q", "-m", "a file at sub")
			}
			ran := filepath.Join(t.TempDir(), "filter-ran")
			t.Setenv(handlerScript, "write:one.txt=a change;plant:nested="+ran+";echo:an answer")
			sent := alice.ask(t, "jostle", "a question", "the first")
			bob.serve(t)
			if _, err := os.Stat(ran); err == nil {
				t.Fatal("serve's git ran the filter of the repository the handler made")
			}
			got := readFile(t, patchOf(t, alice, alice.replyOn(t, sent.Thread)))
			if !strings.Contains(got, "one.txt") || strings.Contains(got, "Subproject") || strings.Contains(got, "160000") {
				t.Fatalf("the answer went with:\n%s", got)
			}
			// The file the repository replaced goes as deleted, which is
			// what the worktree holds; nothing of the repository goes.
			if wantSub := at != "a repository the base does not hold"; strings.Contains(got, "a/sub") != wantSub || wantSub && !strings.Contains(got, "deleted file mode 100644") {
				t.Fatalf("the answer went with:\n%s", got)
			}
		})
	}
}

// replyWith is the reply in u's inbox whose words begin with text, as
// serve's note on the patch follows them.
func replyWith(t *testing.T, u *user, text, said string) messageJSON {
	t.Helper()
	var in inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.Type != "reply" {
			continue
		}
		var full messageJSON
		if err := json.Unmarshal([]byte(u.run("read", m.ID, "--json")), &full); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(full.Text, text+"\n") {
			return full
		}
	}
	t.Fatalf("no reply says %q; serve said:\n%s", text, said)
	return messageJSON{}
}
