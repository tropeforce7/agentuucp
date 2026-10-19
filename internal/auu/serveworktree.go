package auu

import (
	"errors"
	"fmt"
	"io/fs"
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

// validBase says whether a recorded base is a commit id as git writes one:
// 40 lowercase hex characters, or 64 in a repository of SHA-256 objects.
// The file is in a directory the handler writes, and the base goes to git
// as an argument: a handler that wrote --output=<path> there made serve's
// git write the diff to that path (F1, A-2). The shape does not say where
// the commit came from: a handler's own commit, in the object store the
// worktree shares with the checkout, is a valid base, which is why the
// index patchFor makes from it is never trusted to run anything.
func validBase(base string) bool {
	if len(base) != 40 && len(base) != 64 {
		return false
	}
	for i := 0; i < len(base); i++ {
		if c := base[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// leftByHandlerError is something in a directory the handler writes that
// serve will not act on: the message's failure, as an unmendable worktree
// is (G10), so that it is retried and given up on rather than met at
// every start, and never rewritten without a word.
type leftByHandlerError struct{ what string }

func (e *leftByHandlerError) Error() string { return e.what }

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
	base = strings.TrimSpace(string(recorded))
	if !validBase(base) {
		return "", "", false, &leftByHandlerError{fmt.Sprintf(
			"its base file %s does not hold a commit id, 40 or 64 lowercase hex characters, and was not used; the file is serve's own", basePath)}
	}
	return path, base, false, nil
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
//
// A handler can also leave what will not be mended: a registration it
// locked, which the prune passes over and the add then refuses, is
// unlocked first; a directory that cannot be removed is moved aside under
// the serve root, the worktrees directory's parent, and said; and what
// still cannot be removed or moved is an unmendableError, which handle
// counts against the message in hand rather than ending the run. What is
// the host's — git not there, the checkout git will not answer for, a
// prune or an add that fails — is an error as before.
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
		// cannot start never costs what stands here. A lock the handler
		// put on the registration would keep it from the prune; a path
		// git holds no lock for refuses the unlock, which says nothing.
		gitRun(dir, "worktree", "unlock", path)
		if _, err := gitRun(dir, "worktree", "prune"); err != nil {
			return false, false, err
		}
		if err := os.RemoveAll(path); err != nil {
			// What the handler took the permissions off is serve's own, so
			// they are given back and the removal tried once more before
			// the path is moved aside.
			openUp(path)
			if err := os.RemoveAll(path); err != nil {
				if err := moveAside(path); err != nil {
					return false, false, err
				}
			}
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

// openUp makes every directory under path, path among them, the owner's
// to read, write and enter again, so that what a handler took the
// permissions off can be removed. A link is never followed: the walk
// stats each entry without following it and directories alone are
// changed. Each directory is changed before the walk reads it, which is
// what lets it go on into one that was 000. Failures are left for the
// removal after to report.
//
// A directory swapped for a link between the walk's look and the chmod
// would have the chmod follow it, and the walk go on through it, onto a
// subtree of the serve user's.
// That is nothing the handler could not do itself: it runs as the serve
// user and can chmod any directory that user owns.
func openUp(path string) {
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
}

// unmendableError is a worktree's path that could be neither removed nor
// moved aside: what a handler left there is the message's failure, never
// the run's.
type unmendableError struct {
	path string
	err  error
}

func (e *unmendableError) Error() string {
	return fmt.Sprintf("its worktree %s could not be removed or moved aside: %v", e.path, e.err)
}

func (e *unmendableError) Unwrap() error { return e.err }

// maxAside is how many moved-aside copies of one worktree are looked past
// for a free name before the path is given up as unmendable.
const maxAside = 1000

// moveAside renames a worktree that cannot be removed to
// <name>.damaged-<n> in the serve root, n the first that is free, and says
// where on the console for a person to remove. The name is the worktree's
// own, a thread id or a channel name already held to its rule, and the
// place is outside worktrees/ and threads/, so nothing serve keeps is ever
// named by it.
func moveAside(path string) error {
	root := filepath.Dir(filepath.Dir(path))
	for n := 1; n <= maxAside; n++ {
		aside := filepath.Join(root, fmt.Sprintf("%s.damaged-%d", filepath.Base(path), n))
		if _, err := os.Lstat(aside); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := os.Rename(path, aside); err != nil {
			return &unmendableError{path: path, err: err}
		}
		fmt.Fprintf(os.Stderr, "%s: worktree %s could not be removed and was moved aside to %s; remove it by hand\n",
			prog, path, aside)
		return nil
	}
	return &unmendableError{path: path, err: fmt.Errorf("%s.damaged-1 to -%d are all taken", filepath.Base(path), maxAside)}
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
// whatever made git refuse is the directory's, and so is a git that could
// not be started there, in a directory a handler took the permissions off;
// a git that is not there at all has said nothing, and that is an error, as
// is a checkout git will not answer for or cannot be started in.
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
	if errors.Is(err, errCannotStartIn) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !answered || !sameDir(top, path) {
		return true, nil
	}
	common, answered, err := gitAsk(path, "--git-common-dir")
	if errors.Is(err, errCannotStartIn) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !answered || !sameDir(common, shared), nil
}

// errCannotStartIn is git, which is there, failing to start in the
// directory it was asked about: the directory is the trouble, not git.
var errCannotStartIn = errors.New("git could not be started there")

// gitAsk asks 'git rev-parse' one question about a directory and answers
// with the path git gave, made absolute, since a repository's own common
// directory is given relative to where it was asked. answered is false
// when git ran and refused, which is how it says a directory is not in a
// repository and how lostWorktree reads every refusal. An error is git that
// could not be run: one wrapping errCannotStartIn when git is there and the
// directory would not let it start, any other when git is not there or
// the host would not start it.
func gitAsk(dir, question string) (answer string, answered bool, err error) {
	cmd := exec.Command("git", "rev-parse", question)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", false, nil
		}
		// A directory that will not be entered fails the start with its
		// permission or its absence; git missing is ErrNotFound before
		// any start, and a fork the host refused is neither.
		if !errors.Is(err, exec.ErrNotFound) && (errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist)) {
			return "", false, fmt.Errorf("git rev-parse %s in %s: %w: %v", question, dir, errCannotStartIn, err)
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
	return gitRunWith(dir, nil, args...)
}

// gitRunWith is gitRun as a call says.
func gitRunWith(dir string, call *gitCall, args ...string) (string, error) {
	cmd := gitCommand(dir, call, args)
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
// the patch taken for it (keptPatch), against the base before; every patch
// made after is measured from the new one.
//
// It is written in the answer's own directory, dir, under the thread's
// name: a later turn's patch never stands in for this one, and the asker
// still sees the thread's name. The directory is made when the patch has
// been taken, whether or not there was a change, and not before, so that
// it is there exactly when the answer's patch is. A run that stopped
// between taking the patch and keeping the reply leaves a patch the retry
// takes again over, since writeNew removes what stood under the name
// before its exclusive create.
//
// 'git add -A' is what makes an untracked file part of it, and what makes
// an ignored one not: a handler that writes its answer where .gitignore
// says nothing lives will find it does not travel.
//
// The worktree is the handler's, its .git file among it, and so is the
// directory git keeps the worktree's index and HEAD in, inside the
// checkout's repository, since a handler that commits in its worktree
// writes there. git run on either reads the configuration of whatever
// repository they name: a handler that pointed the .git file, or that
// directory's commondir, at a repository of its own, with a filesystem
// monitor, a clean filter or a hook set there, had serve's 'git add' run
// its command as the serve account (F1, A-3). So the worktree is first
// asked whether it is still the one serve made, as before every handler
// run, and what is not is the message's failure (G10); and then the patch
// is taken with neither: git is given the checkout's own repository, the
// worktree as the tree to read, and an index of serve's own made from the
// base, and is told to run no monitor, no hook, no external diff and no
// text conversion, with whatever git variables serve was started with
// left out. The configuration read is the operator's, and the worktree's
// own index is not touched.
func patchFor(ch *serveChannel, worktree, base, dir, thread string) (string, error) {
	path := filepath.Join(dir, patchName(thread))
	if ch.Mode != modeSideCopy {
		return "", nil
	}
	lost, err := lostWorktree(ch.Dir, worktree)
	if err != nil {
		return "", err
	}
	if lost {
		return "", fmt.Errorf("its worktree %s is no longer the git worktree serve made: its .git was changed, and nothing was run in it", worktree)
	}
	// An index made from the base has no file left out of a sparse
	// checkout, so every such file would read as deleted in the patch.
	// The setting is the operator's checkout's, asked of it.
	sparse, err := gitRun(ch.Dir, "config", "--type=bool", "--default=false", "core.sparseCheckout")
	if err != nil {
		return "", err
	}
	if sparse == "true" {
		return "", fmt.Errorf("the checkout %s is sparse (core.sparseCheckout is true), where a side copy's patch would carry every file it leaves out as deleted; serve a side copy from a full checkout", ch.Dir)
	}
	common, answered, err := gitAsk(ch.Dir, "--git-common-dir")
	if err != nil {
		return "", err
	}
	if !answered {
		return "", fmt.Errorf("git rev-parse --git-common-dir in %s: the checkout is not a git repository", ch.Dir)
	}
	// git resolves a relative GIT_DIR or GIT_WORK_TREE against the
	// directory it runs in, which is the worktree the handler fills, so a
	// relative checkout or AUU_HOME would let the handler choose the
	// repository serve's git reads its settings from.
	if common, err = filepath.Abs(common); err != nil {
		return "", err
	}
	if worktree, err = filepath.Abs(worktree); err != nil {
		return "", err
	}
	// Made under the system's temporary directory, private to this
	// account, and never where the handler writes.
	scratch, err := os.MkdirTemp("", "auu-patch-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(scratch)
	// diff.ignoreSubmodules=all leaves out of the diff a submodule entry at
	// a path the base does not hold, behind the force-remove below; that
	// step alone keeps out one in place of a file of the base, which the
	// setting still diffs.
	call := &gitCall{
		global: []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "diff.ignoreSubmodules=all"},
		env: append(withoutGitVariables(os.Environ()),
			"GIT_DIR="+common, "GIT_WORK_TREE="+worktree, "GIT_INDEX_FILE="+filepath.Join(scratch, "index")),
	}
	// The base after --end-of-options, so that it is never an option,
	// though it was held to a commit id when it was read back.
	if _, err := gitRunWith(worktree, call, "read-tree", "--end-of-options", base); err != nil {
		return "", err
	}
	// add -A asks a submodule's own repository whether it is modified, by
	// running git status in it, which reads that repository's
	// configuration and runs a clean filter it names. The base can be a
	// commit of the handler's own, so a submodule entry in it can stand
	// where the handler made a repository: each is marked skip-worktree,
	// and add -A does not look at its path.
	links, err := submodulesIn(worktree, call)
	if err != nil {
		return "", err
	}
	if len(links) > 0 {
		if _, err := gitRunWith(worktree, call, append([]string{"update-index", "--skip-worktree", "--"}, links...)...); err != nil {
			return "", err
		}
	}
	if _, err := gitRunWith(worktree, call, "add", "-A"); err != nil {
		return "", err
	}
	// add -A records a repository the handler made at a path the base
	// does not hold as a submodule entry, by reading its HEAD and running
	// nothing; it is taken out again, so that the patch carries no commit
	// id the asker does not have.
	after, err := submodulesIn(worktree, call)
	if err != nil {
		return "", err
	}
	inBase := make(map[string]bool, len(links))
	for _, p := range links {
		inBase[p] = true
	}
	var added []string
	for _, p := range after {
		if !inBase[p] {
			added = append(added, p)
		}
	}
	if len(added) > 0 {
		if _, err := gitRunWith(worktree, call, append([]string{"update-index", "--force-remove", "--"}, added...)...); err != nil {
			return "", err
		}
	}
	// --binary, so that a change to a file that is not text applies on the
	// other side as well as reads.
	diff, err := gitRawWith(worktree, call, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv", "--end-of-options", base)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if len(diff) == 0 {
		// Nothing changed this turn or any turn before it. A patch an
		// earlier attempt at this answer left, if there is one, is not
		// this one's, and is not left beside the reply to be sent with it.
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		return "", nil
	}
	if err := writeNew(path, diff); err != nil {
		return "", err
	}
	return path, nil
}

// keptPatch is the patch of an answer that was written and not sent, for
// the round that sends it: it is re-attached rather than made again, since
// nothing has run in the worktree for this answer since and one answer is
// one answer. It is the one in the answer's own directory, so a later
// turn's is never it, and a worktree made again in between holds none of
// the work while the patch still does. A side copy's answer with no such
// directory has no patch taken for it, and is not kept (G37, R53).
//
// The patch is asked about by its own entry. Anything there that is not a
// regular file, a link an older serve's handler put in its place among
// them, is given as the patch, so that the send refuses it by name and the
// message fails for it: a link here was followed, and the file it named
// was attached to the reply (F1, A-1). The directory is serve's kept one,
// which the handler is never told of (S56).
func keptPatch(ch *serveChannel, dir, thread string) (string, bool) {
	if ch.Mode != modeSideCopy {
		return "", true
	}
	if _, err := os.Stat(dir); err != nil {
		return "", false
	}
	path := filepath.Join(dir, patchName(thread))
	info, err := os.Lstat(path)
	if err != nil || (info.Mode().IsRegular() && info.Size() == 0) {
		return "", true
	}
	return path, true
}

// gitRaw is gitOutput without the trimming, for a command whose output is
// bytes rather than a word: a patch that lost its last newline is a patch
// that may not apply.
func gitRaw(dir string, args ...string) ([]byte, error) {
	return gitRawWith(dir, nil, args...)
}

// submodulesIn is the path of every submodule entry, mode 160000, in the
// index a call names. A path is given to git as git wrote it, after --,
// and never opened here.
func submodulesIn(dir string, call *gitCall) ([]string, error) {
	out, err := gitRawWith(dir, call, "ls-files", "-z", "--stage")
	if err != nil {
		return nil, err
	}
	var links []string
	for _, entry := range strings.Split(string(out), "\x00") {
		info, path, ok := strings.Cut(entry, "\t")
		if ok && strings.HasPrefix(info, "160000 ") {
			links = append(links, path)
		}
	}
	return links, nil
}

// gitCall is how one of serve's git commands is run when serve's own way
// is not enough: options for git itself before the command, which an
// error leaves out, since what failed is the command, in git's words; and
// the whole environment it runs in.
type gitCall struct {
	global []string
	env    []string
}

// withoutGitVariables is an environment with every GIT_ variable taken
// out, in any case, since Windows does not tell names apart by it.
func withoutGitVariables(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(strings.ToUpper(kv), "GIT_") {
			out = append(out, kv)
		}
	}
	return out
}

// gitCommand is git in a directory, as a call says when there is one.
func gitCommand(dir string, call *gitCall, args []string) *exec.Cmd {
	if call != nil {
		args = append(append([]string(nil), call.global...), args...)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if call != nil && call.env != nil {
		cmd.Env = call.env
	}
	return cmd
}

// gitRawWith is gitRaw as a call says.
func gitRawWith(dir string, call *gitCall, args ...string) ([]byte, error) {
	cmd := gitCommand(dir, call, args)
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
