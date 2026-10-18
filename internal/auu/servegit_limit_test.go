package auu

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLimitTheBaseIsARevision: the base a worktree stands on is recorded
// in a file in the thread's directory, or the channel's in read-only, both
// of which the handler writes, and it went to git as a bare argument: a
// handler that wrote --output=<path> there made serve's git write the diff
// to that path (F1, tracer A's TestProbeABaseIsAGitOption). It is now held
// to a commit id when it is read back, 40 or 64 lowercase hex characters,
// and one that is not is the message's failure, naming the file, with
// nothing written where it pointed and nothing handed to the handler as
// AUU_BASE.
func TestLimitTheBaseIsARevision(t *testing.T) {
	ok := []string{strings.Repeat("0", 40), strings.Repeat("f", 40), strings.Repeat("a", 64), "0123456789abcdef0123456789abcdef01234567"}
	bad := []string{
		"", strings.Repeat("0", 39), strings.Repeat("0", 41), strings.Repeat("0", 63), strings.Repeat("0", 65),
		strings.Repeat("A", 40), strings.Repeat("0", 39) + "g", "--output=/tmp/x", "-p", "HEAD", "main",
		strings.Repeat("0", 39) + " ", "..", strings.Repeat("0", 20) + "/" + strings.Repeat("0", 19),
	}
	for _, v := range ok {
		if !validBase(v) {
			t.Errorf("validBase refused %q", v)
		}
	}
	for _, v := range bad {
		if validBase(v) {
			t.Errorf("validBase took %q", v)
		}
	}
	for _, mode := range []string{modeSideCopy, modeReadOnly} {
		t.Run(mode, func(t *testing.T) {
			alice, bob := newExpert(t, mode)
			t.Setenv(handlerScript, "write:one.txt=a change;echo:the first answer")
			sent := alice.ask(t, "jostle", "a question", "the first")
			bob.serve(t)
			reply := alice.replyOn(t, sent.Thread)
			// What a handler can write between the two turns.
			state := filepath.Join(bob.home, "serve", "threads", sent.Thread)
			if mode == modeReadOnly {
				state = filepath.Join(bob.home, "serve", "channels", "jostle")
			}
			written := filepath.Join(t.TempDir(), "written-by-git")
			if err := os.WriteFile(filepath.Join(state, baseFile), []byte("--output="+written+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "runs")
			t.Setenv(handlerScript, "append:"+marker+";write:two.txt=another change;echo:the second answer")
			alice.run("reply", reply.ID[:12], "and one more thing")
			said := captureStderr(t, func() { bob.tryRun("serve", "--once") })
			if _, err := os.Stat(written); err == nil {
				t.Fatalf("git wrote %s", written)
			}
			if !strings.Contains(said, "was not answered") || !strings.Contains(said, "its base file "+filepath.Join(state, baseFile)) {
				t.Fatalf("the failure was said as:\n%s", said)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("the handler ran on a base that is not a commit id")
			}
			if got := readFile(t, filepath.Join(state, baseFile)); got != "--output="+written+"\n" {
				t.Fatalf("the base file was rewritten: %q", got)
			}
		})
	}
}

// plantInWorktree is what a handler that can run git in its worktree can
// do to the directory git keeps the worktree's index and HEAD in, inside
// the checkout's repository, for the test handler's plant step; it runs
// in the worktree.
//
//	commondir=REPO     copy that directory aside and point .git at the
//	                   copy, which still names the checkout's repository,
//	                   so the worktree answers as serve's; then point the
//	                   directory's own commondir at REPO, given the
//	                   checkout's objects so that it resolves
//	config.worktree=M  write the directory's config.worktree with a clean
//	                   filter that touches M
func plantInWorktree(kind, value string) error {
	dotGit, err := os.ReadFile(".git")
	if err != nil {
		return err
	}
	admin := strings.TrimSpace(strings.TrimPrefix(string(dotGit), "gitdir:"))
	switch kind {
	case "commondir":
		named, err := os.ReadFile(filepath.Join(admin, "commondir"))
		if err != nil {
			return err
		}
		common := strings.TrimSpace(string(named))
		if !filepath.IsAbs(common) {
			common = filepath.Join(admin, common)
		}
		aside := value + "-admin"
		if err := copyTree(admin, aside); err != nil {
			return err
		}
		if err := copyTree(filepath.Join(common, "objects"), filepath.Join(value, "objects")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(aside, "commondir"), []byte(common+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(".git", []byte("gitdir: "+aside+"\n"), 0o600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(admin, "commondir"), []byte(value+"\n"), 0o600)
	case "config.worktree":
		text := "[filter \"x\"]\n\tclean = touch '" + value + "' && cat\n"
		return os.WriteFile(filepath.Join(admin, "config.worktree"), []byte(text), 0o600)
	}
	return fmt.Errorf("no plant %q", kind)
}

// copyTree copies a directory of regular files and directories.
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o600)
	})
}

// TestLimitGitVersion: serve needs git 2.24 or later, for the base after
// --end-of-options, and says so at its check rather than failing every
// side copy's patch. The version line is git's own; a number git did not
// write as one, too large for an int or not a number at all, is left to
// fail where git is used, and a negative one is older than anything.
func TestLimitGitVersion(t *testing.T) {
	for line, want := range map[string]bool{
		"git version 2.24.0":                 true,
		"git version 2.24":                   true,
		"git version 2.23.9":                 false,
		"git version 2.17.1":                 false,
		"git version 1.99.0":                 false,
		"git version 3.0.0":                  true,
		"git version 2.54.0":                 true,
		"git version 2.39.5 (Apple Git-154)": true,
		"git version 2.45.1.windows.1":       true,
		"git version -1.30":                  false,
		"git version 2.-1":                   false,
		"git version 99999999999999999999.0": true,
		"git version 2.99999999999999999999": true,
		"git version two.twenty":             true,
		"git version 2":                      true,
		"git":                                true,
		"":                                   true,
	} {
		if got := gitAtLeast(line, 2, 24); got != want {
			t.Errorf("gitAtLeast(%q) is %v, want %v", line, got, want)
		}
	}
}
