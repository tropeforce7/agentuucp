package auu

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
//	nested=M           make a repository at sub whose own configuration
//	                   has a clean filter that touches M (nestedRepository)
//	gitlink=M          that, and a commit of the handler's own holding it
//	                   as a submodule entry, its id written to the thread's
//	                   base file
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
	case "nested":
		_, err := nestedRepository(value)
		return err
	case "gitlink":
		baseFile := filepath.Join(os.Getenv("AUU_THREAD_DIR"), baseFile)
		head, err := nestedRepository(value)
		if err != nil {
			return err
		}
		// A commit of the handler's own, in the object store the
		// worktree shares, holding the repository as a submodule entry,
		// made with an index of its own so the worktree's is untouched.
		env := append(os.Environ(), "GIT_INDEX_FILE="+filepath.Join(filepath.Dir(baseFile), "plant-index"))
		steps := [][]string{
			{"read-tree", os.Getenv("AUU_BASE")},
			{"update-index", "--add", "--cacheinfo", "160000," + head + ",sub"},
			{"write-tree"},
		}
		var tree string
		for _, args := range steps {
			if tree, err = plantGit(".", env, args...); err != nil {
				return err
			}
		}
		commit, err := plantGit(".", env, "commit-tree", tree, "-p", os.Getenv("AUU_BASE"), "-m", "a base of the handler's own")
		if err != nil {
			return err
		}
		return os.WriteFile(baseFile, []byte(commit+"\n"), 0o600)
	}
	return fmt.Errorf("no plant %q", kind)
}

// nestedRepository makes a repository at sub in the working directory, in
// place of a file there if there is one,
// with a clean filter in its own configuration that touches marker, an
// attribute naming it, and a file whose stat no longer matches its index,
// so that a git status run in it would run the filter; it answers with
// the repository's commit.
func nestedRepository(marker string) (string, error) {
	// A file the base holds at sub is replaced by the repository.
	if err := os.Remove("sub"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if _, err := plantGit(".", nil, "init", "-q", "sub"); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join("sub", "f"), []byte("x\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join("sub", ".gitattributes"), []byte("* filter=x\n"), 0o600); err != nil {
		return "", err
	}
	for _, args := range [][]string{
		{"add", "."}, {"commit", "-q", "-m", "nested"},
		{"config", "filter.x.clean", "touch '" + filepath.ToSlash(marker) + "' && cat"},
	} {
		if _, err := plantGit("sub", nil, args...); err != nil {
			return "", err
		}
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join("sub", "f"), later, later); err != nil {
		return "", err
	}
	return plantGit("sub", nil, "rev-parse", "HEAD")
}

// plantGit is git as a handler runs it, in dir, with env when one is
// given, answering with what it printed.
func plantGit(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{
		"-c", "user.email=handler@example.invalid", "-c", "user.name=handler",
		"-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
	}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
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

// TestLimitAChannelIsNotNamedAsAThread: a read-only channel's worktree is
// worktrees/<channel>, in the directory a side copy's worktrees/<thread>
// are in, and a thread id is 32 hex characters a sender chooses, so a
// channel named as one shared a thread's directory, and letting that
// thread go removed it (F7, tracer A's A-4). serve check refuses a channel
// named with 32 hex characters, in either case, since the filesystem may
// fold it; 31 and 33 of them, and 32 characters with one that is not hex,
// are names like any other.
func TestLimitAChannelIsNotNamedAsAThread(t *testing.T) {
	dir := repo(t)
	check := func(name string) error {
		cfg := &serveConfig{
			V:        1,
			path:     filepath.Join(t.TempDir(), "serve.json"),
			Channels: map[string]*serveChannel{name: {Dir: dir, Exec: "cat", Mode: modeReadOnly, MaxTurns: 1}},
		}
		return cfg.check()
	}
	id := "0123456789abcdef0123456789abcdef"
	for _, name := range []string{id, strings.ToUpper(id), "0123456789ABCdef0123456789abcdef"} {
		if err := check(name); err == nil || !strings.Contains(err.Error(), "the shape of a thread id") {
			t.Errorf("channel %q: %v", name, err)
		}
	}
	for _, name := range []string{id[:31], id + "0", id[:31] + "g", id[:31] + "-"} {
		if err := check(name); err != nil {
			t.Errorf("channel %q was refused: %v", name, err)
		}
	}
}
