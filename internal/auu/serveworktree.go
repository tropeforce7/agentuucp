package auu

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
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
// it should be, and answers with its path and the commit it stands on, and
// whether what stood at the path was not a git worktree of the checkout's
// and was removed and made again, which handle says.
//
// stateDir is where the base is recorded: the channel's directory in
// read-only, the thread's in side-copy. newThread says this is the first
// message serve has handled on the thread, which is when a read-only
// channel's copy is moved forward.
func worktreeFor(root string, ch *serveChannel, thread, stateDir string, newThread bool) (path, base string, remade bool, err error) {
	// Checked again where the id becomes a path, though handle has refused
	// a bad one before this: a failure here cannot happen.
	if err := message.ValidID(thread); err != nil {
		return "", "", false, fmt.Errorf("thread id is %v", err)
	}
	name := thread
	if ch.Mode == modeReadOnly {
		name = ch.name
	}
	path = filepath.Join(root, "worktrees", name)
	made, remade, err := ensureWorktree(ch.Dir, path)
	if err != nil {
		return "", "", false, err
	}
	// Read-only: each new thread starts from what the checkout is at now.
	// A copy just made is already there.
	if ch.Mode == modeReadOnly && newThread && !made {
		head, err := gitOutput(ch.Dir, "rev-parse", "HEAD")
		if err != nil {
			return "", "", false, err
		}
		if _, err := gitRun(path, "checkout", "--detach", "-f", head); err != nil {
			return "", "", false, err
		}
		made = true
	}
	basePath := filepath.Join(stateDir, baseFile)
	if made {
		head, err := gitOutput(path, "rev-parse", "HEAD")
		if err != nil {
			return "", "", false, err
		}
		if err := writeNew(basePath, []byte(head+"\n")); err != nil {
			return "", "", false, err
		}
		return path, head, remade, nil
	}
	recorded, err := regular.ReadFile(basePath)
	if err != nil {
		// The record is gone, which a hand-tidied home can do: the worktree
		// is where it is, and that is the honest answer.
		head, err := gitOutput(path, "rev-parse", "HEAD")
		if err != nil {
			return "", "", false, err
		}
		return path, head, false, writeNew(basePath, []byte(head+"\n"))
	}
	return path, strings.TrimSpace(string(recorded)), false, nil
}

// ensureWorktree makes the worktree if it is not there, and says whether it
// had to, and whether what stood at the path was not a git worktree of the
// checkout's and was removed first. A directory that has gone from under
// git — a tidied home, a full disk — leaves a registration behind, so the
// prune comes first; git refuses to add over a registration it still
// believes in.
//
// What stands at the path and is not a git worktree of the checkout's — a
// directory a handler took .git out of or made a repository of its own, a
// file, a link — is removed and the worktree made again, rather than
// refused: a read-only channel's worktree is every thread's on the channel,
// and a refusal here ends the run before anything is written against the
// message, so one handler talked into removing .git would stop the expert
// for good. Making it again writes nothing to the ledger: a turn that
// failed for the damage was counted there as any failed turn is, and the
// message in hand is not made to answer for what stood here.
func ensureWorktree(dir, path string) (made, remade bool, err error) {
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			lost, err := lostWorktree(dir, path)
			if err != nil {
				return false, false, err
			}
			if !lost {
				return false, false, nil
			}
		}
		// For a file or a link git has not been asked anything yet: the
		// prune shows it runs before anything is removed, so a git that
		// cannot start never costs what stands here.
		if _, err := gitRun(dir, "worktree", "prune"); err != nil {
			return false, false, err
		}
		if err := os.RemoveAll(path); err != nil {
			return false, false, err
		}
		remade = true
	}
	if _, err := gitRun(dir, "worktree", "prune"); err != nil {
		return false, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, false, err
	}
	if _, err := gitRun(dir, "worktree", "add", "--detach", path, "HEAD"); err != nil {
		return false, false, err
	}
	return true, remade, nil
}

// lostWorktree says whether a directory is no longer a git worktree of the
// checkout's. 'rev-parse HEAD' is not the question: git looks upward for a
// repository, so a worktree whose .git was removed inside a home that is
// itself under a repository — a dotfiles checkout — would pass, and the
// handler would run in the enclosing one. The directory is the checkout's
// worktree when git, asked there, names that directory as the top and the
// checkout's own repository as the one it shares, so that a directory a
// handler made a repository of its own with 'git init' is not taken for
// it. A git that ran and refused to answer there is taken as saying the
// directory is not one, since the checkout has just been answered for and
// whatever made git refuse is the directory's; a git that could not be run
// has said nothing, and that is an error, as is a checkout git will not
// answer for.
//
// Directories are compared as files, not as names: a home reached by a
// name in another case, or under a link, is the same directory, and taken
// for another it would be removed at every message.
func lostWorktree(dir, path string) (bool, error) {
	shared, answered, err := gitAsk(dir, "--git-common-dir")
	if err != nil {
		return false, err
	}
	if !answered {
		return false, fmt.Errorf("git rev-parse --git-common-dir in %s: the checkout is not a git repository", dir)
	}
	top, answered, err := gitAsk(path, "--show-toplevel")
	if err != nil {
		return false, err
	}
	if !answered || !sameDir(top, path) {
		return true, nil
	}
	common, answered, err := gitAsk(path, "--git-common-dir")
	if err != nil {
		return false, err
	}
	return !answered || !sameDir(common, shared), nil
}

// gitAsk asks 'git rev-parse' one question about a directory and answers
// with the path git gave, made absolute, since a repository's own common
// directory is given relative to where it was asked. answered is false
// when git ran and refused, which is how it says a directory is not in a
// repository and how lostWorktree reads every refusal; an error is git that
// could not be run.
func gitAsk(dir, question string) (answer string, answered bool, err error) {
	cmd := exec.Command("git", "rev-parse", question)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("git rev-parse %s in %s: %v", question, dir, err)
	}
	answer = filepath.FromSlash(strings.TrimSpace(string(out)))
	if !filepath.IsAbs(answer) {
		answer = filepath.Join(dir, answer)
	}
	return answer, true, nil
}

// sameDir says whether two paths name one directory, by what the system
// says of each rather than by how they are spelled. A path that cannot be
// looked at is not the same as anything.
func sameDir(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
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
// turn's patch cumulative and the latest one complete. The one exception
// is a worktree that was not a git worktree of the checkout's and was made
// again (ensureWorktree): the thread's work went with it and the base is
// recorded afresh. An answer already written and not sent still goes with
// the thread's latest patch (keptPatch), taken against the base before;
// every patch made after is measured from the new one.
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
	if err := writeNew(path, diff); err != nil {
		return "", err
	}
	return path, nil
}

// keptPatch is the patch of an answer that was written and not sent, for
// the round that sends it: it is re-attached rather than made again, since
// nothing has run in the worktree since and one answer is one answer. It
// is the thread's latest patch, which is that answer's unless a later turn
// on the thread took one first or its own could not be taken; a worktree
// made again in between holds none of the work, and the patch still does.
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
