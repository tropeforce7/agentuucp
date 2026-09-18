package auu

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/message"
)

// The worktrees a handler answers in.
//
// The checkout the owner works in is never written. Every handler runs in a
// git worktree made from it: one per channel where the mode is read-only,
// since those answers belong to nobody's thread and one warm copy serves
// every ask, and one per thread where it is side-copy, since there the
// thread's change is the thread's.
//
// A read-only channel's worktree is moved to the checkout's HEAD at each
// new thread's first message, so that slow-moving code is followed without
// anybody writing a hook. Untracked scratch survives that move and tracked
// edits do not, which in a mode that returns no patch is what they were
// always worth.

// baseFile records the commit a worktree was made from or moved to. It is
// read back rather than asked of git again, so that a handler which commits
// in its worktree does not move the base a patch will be taken against.
const baseFile = "base"

// worktreeFor makes sure the worktree for this message exists and is where
// it should be, and answers with its path and the commit it stands on.
//
// stateDir is where the base is recorded: the channel's directory in
// read-only, the thread's in side-copy. newThread says this is the first
// message serve has handled on the thread, which is when a read-only
// channel's copy is moved forward.
func worktreeFor(root string, ch *serveChannel, thread, stateDir string, newThread bool) (path, base string, err error) {
	// Checked again where the id becomes a path, though handle has refused
	// a bad one before this: a failure here cannot happen.
	if err := message.ValidID(thread); err != nil {
		return "", "", fmt.Errorf("thread id is %v", err)
	}
	name := thread
	if ch.Mode == modeReadOnly {
		name = ch.name
	}
	path = filepath.Join(root, "worktrees", name)
	made, err := ensureWorktree(ch.Dir, path)
	if err != nil {
		return "", "", err
	}
	// Read-only: each new thread starts from what the checkout is at now.
	// A copy just made is already there.
	if ch.Mode == modeReadOnly && newThread && !made {
		head, err := gitOutput(ch.Dir, "rev-parse", "HEAD")
		if err != nil {
			return "", "", err
		}
		if _, err := gitRun(path, "checkout", "--detach", "-f", head); err != nil {
			return "", "", err
		}
		made = true
	}
	basePath := filepath.Join(stateDir, baseFile)
	if made {
		head, err := gitOutput(path, "rev-parse", "HEAD")
		if err != nil {
			return "", "", err
		}
		if err := os.WriteFile(basePath, []byte(head+"\n"), 0o600); err != nil {
			return "", "", err
		}
		return path, head, nil
	}
	recorded, err := os.ReadFile(basePath)
	if err != nil {
		// The record is gone, which a hand-tidied home can do: the worktree
		// is where it is, and that is the honest answer.
		head, err := gitOutput(path, "rev-parse", "HEAD")
		if err != nil {
			return "", "", err
		}
		return path, head, os.WriteFile(basePath, []byte(head+"\n"), 0o600)
	}
	return path, strings.TrimSpace(string(recorded)), nil
}

// ensureWorktree makes the worktree if it is not there, and says whether it
// had to. A directory that has gone from under git — a tidied home, a full
// disk — leaves a registration behind, so the prune comes first; git
// refuses to add over a registration it still believes in.
func ensureWorktree(dir, path string) (made bool, err error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		if _, err := gitOutput(path, "rev-parse", "HEAD"); err != nil {
			return false, fmt.Errorf("%s is not a git worktree: %v", path, err)
		}
		return false, nil
	}
	if _, err := gitRun(dir, "worktree", "prune"); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if _, err := gitRun(dir, "worktree", "add", "--detach", path, "HEAD"); err != nil {
		return false, err
	}
	return true, nil
}

// gitRun runs git in a directory and gives what it said, which is what the
// failure names: git's own words are better than any this could invent.
func gitRun(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		said := strings.TrimSpace(string(out))
		if said == "" {
			said = err.Error()
		}
		return "", fmt.Errorf("git %s in %s: %s", strings.Join(args, " "), dir, said)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitOutput is for a command whose standard output is the answer, so a
// warning git writes to standard error cannot end up inside a commit id.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var said strings.Builder
	cmd.Stderr = &said
	out, err := cmd.Output()
	if err != nil {
		text := strings.TrimSpace(said.String())
		if text == "" {
			text = err.Error()
		}
		return "", fmt.Errorf("git %s in %s: %s", strings.Join(args, " "), dir, text)
	}
	return strings.TrimSpace(string(out)), nil
}

// patchName is what the asker sees the change under: the thread's short id,
// so that two patches from two threads never collide in a downloads folder.
func patchName(thread string) string { return shortID(thread) + ".patch" }

// patchFor is a side copy's whole change so far, written beside the reply
// and answered with its path, or nothing at all when there is nothing to
// send and in read-only, which returns no patch by definition.
//
// It is taken against the commit the worktree was made from, read back from
// the file the worktree recorded it in rather than asked of git: a handler
// that commits in its worktree moves HEAD, and the patch must not move with
// it. For a side copy that base never changes — the worktree is made once
// at the thread's first message and reused — which is what makes every
// turn's patch cumulative and the latest one complete.
//
// 'git add -A' is what makes an untracked file part of it, and what makes
// an ignored one not: a handler that writes its answer where .gitignore
// says nothing lives will find it does not travel.
func patchFor(ch *serveChannel, worktree, base, threadDir, thread string) (string, error) {
	path := filepath.Join(threadDir, patchName(thread))
	if ch.Mode != modeSideCopy {
		return "", nil
	}
	if _, err := gitRun(worktree, "add", "-A"); err != nil {
		return "", err
	}
	// --binary, so that a change to a file that is not text applies on the
	// other side as well as reads.
	diff, err := gitRaw(worktree, "diff", "--cached", "--binary", base)
	if err != nil {
		return "", err
	}
	if len(diff) == 0 {
		// Nothing changed this turn or any turn before it. An older
		// patch, if there is one, is not this answer's.
		os.Remove(path)
		return "", nil
	}
	if err := os.WriteFile(path, diff, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// keptPatch is the patch of an answer that was written and not sent, for
// the round that sends it: it is re-attached rather than made again, since
// nothing has run in the worktree since and one answer is one answer.
func keptPatch(threadDir, thread string) string {
	path := filepath.Join(threadDir, patchName(thread))
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return path
	}
	return ""
}

// gitRaw is gitOutput without the trimming, for a command whose output is
// bytes rather than a word: a patch that lost its last newline is a patch
// that may not apply.
func gitRaw(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var said strings.Builder
	cmd.Stderr = &said
	out, err := cmd.Output()
	if err != nil {
		text := strings.TrimSpace(said.String())
		if text == "" {
			text = err.Error()
		}
		return nil, fmt.Errorf("git %s in %s: %s", strings.Join(args, " "), dir, text)
	}
	return out, nil
}
