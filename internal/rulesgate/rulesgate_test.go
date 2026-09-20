package rulesgate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The gate test. .claude/hooks/rules-gate.sh is sh and awk, which no Go
// test covers by accident, so this one runs it as Claude Code runs it:
// from a directory, with the hook's JSON on stdin, and reads the exit
// code and standard error back. Each row of the table is one command a
// session might run against a temporary repository with a change staged:
// the plain commit with no record, with a record that says ready, with
// one that does not; the forms that commit something other than the
// index; the amend, gated over the whole commit it makes; the commands
// that are not a commit though the word is in them; the diff that
// changed after its record was written; a commit named through -C or cd
// from elsewhere; and the input the hook must let through. It skips
// where sh or git is absent, and on Windows, where the hook does not run.

// The two sentences the gate refuses with when the command is wrong
// before the index is looked at.
const (
	indexSentence   = "commit from the index: stage with git add, run /rules-review, then git commit with no -a and no paths"
	aloneSentence   = "run git commit on its own: the gate reads the index when the call starts and the commit would read it later, so nothing but cd may come before it"
	literalSentence = "the command, or git's subcommand, is not a literal word; the gate cannot read it"
)

// ready is a record the gate accepts; notReady is one it repeats.
const (
	ready    = "# Rules review: a change\nDiff: x, 1 file\n## What the change touches\n- nothing\nVerdict: ready\n"
	notReady = "# Rules review: a change\nVerdict: not ready\nmissing: the test for ValidID at MIN\n"
)

// hookInput is what Claude Code writes to the hook's stdin
// (code.claude.com/docs/en/hooks): the fields the gate reads and the ones
// it must step over, in an order that puts the description, which may
// itself say "git commit", before the command.
type hookInput struct {
	SessionID     string    `json:"session_id"`
	CWD           string    `json:"cwd"`
	HookEventName string    `json:"hook_event_name"`
	ToolName      string    `json:"tool_name"`
	ToolInput     toolInput `json:"tool_input"`
	ToolUseID     string    `json:"tool_use_id"`
}

type toolInput struct {
	Description     string `json:"description"`
	Timeout         int    `json:"timeout"`
	RunInBackground bool   `json:"run_in_background"`
	Command         string `json:"command"`
}

// TestTheGateReadsTheCommandAsShDoes is the table: each row is a command,
// the record on disk, and what the gate must say.
func TestTheGateReadsTheCommandAsShDoes(t *testing.T) {
	gate := gatePath(t)
	rows := []struct {
		name    string
		command string
		tool    string // the tool name; "" is Bash
		record  string // "" for none, else the text of the record for the diff
		empty   bool   // stage nothing
		want    int    // the exit code
		says    string // a substring of standard error, with {hash} for the diff's hash; "" means no output at all
	}{
		{name: "a commit with no record", command: "git commit -m x", want: 2,
			says: "no rules review for the staged diff ({hash}): run /rules-review"},
		{name: "a commit whose record says ready", command: "git commit -m x", record: ready, want: 0},
		{name: "blank lines after the verdict are not the last line", command: "git commit -m x",
			record: ready + "\n  \n\t\n", want: 0},
		{name: "a record that says not ready is repeated", command: "git commit -m x", record: notReady, want: 2,
			says: "the rules review for {hash} says: missing: the test for ValidID at MIN; fix and run /rules-review again"},
		{name: "a verdict that is not the last line is not the verdict", command: "git commit -m x",
			record: "Verdict: ready\nbut one more thing\n", want: 2, says: "says: but one more thing"},
		{name: "a verdict with trailing words is not the verdict", command: "git commit -m x",
			record: "Verdict: ready enough\n", want: 2, says: "says: Verdict: ready enough"},

		// The index rule: whether or not a record exists.
		{name: "-am", command: "git commit -am x", record: ready, want: 2, says: indexSentence},
		{name: "-a -m", command: "git commit -a -m x", want: 2, says: indexSentence},
		{name: "--all", command: "git commit --all -m x", record: ready, want: 2, says: indexSentence},
		{name: "-qa, a cluster with a in it", command: "git commit -qa -m x", record: ready, want: 2, says: indexSentence},
		{name: "a pathspec after --", command: "git commit -m x -- a.txt", record: ready, want: 2, says: indexSentence},
		{name: "a bare pathspec", command: "git commit -m x a.txt", record: ready, want: 2, says: indexSentence},
		{name: "--only", command: "git commit --only -m x", want: 2, says: indexSentence},
		{name: "-o", command: "git commit -o -m x", record: ready, want: 2, says: indexSentence},
		{name: "--include", command: "git commit --include -m x", record: ready, want: 2, says: indexSentence},
		{name: "-i", command: "git commit -i -m x", record: ready, want: 2, says: indexSentence},
		{name: "--interactive", command: "git commit --interactive", record: ready, want: 2, says: indexSentence},
		{name: "--patch", command: "git commit --patch", record: ready, want: 2, says: indexSentence},
		{name: "-p", command: "git commit -p", record: ready, want: 2, says: indexSentence},
		{name: "--pathspec-from-file", command: "git commit --pathspec-from-file=list -m x", record: ready, want: 2, says: indexSentence},
		{name: "a lone dash is a pathspec", command: "git commit -m x -", record: ready, want: 2, says: indexSentence},
		{name: "-mall is a message, not -a", command: "git commit -mall", record: ready, want: 0},
		{name: "-F takes the next word", command: "git commit -F notes.txt", record: ready, want: 0},
		{name: "--message takes the next word", command: "git commit --message x", record: ready, want: 0},

		// Nothing staged.
		{name: "nothing staged is git's to refuse", command: "git commit -m x", empty: true, want: 0},

		// Not a commit, though the word is there.
		{name: "git status", command: "git status", want: 0},
		{name: "go test", command: "go test ./...", want: 0},
		{name: "the word in double quotes", command: `echo "git commit -a"`, want: 0},
		{name: "the word in single quotes", command: `echo 'git commit -a'`, want: 0},
		{name: "the word as an argument", command: "git log --grep=commit", want: 0},
		{name: "commit-tree is another command", command: "git commit-tree HEAD^{tree} </dev/null", want: 0},
		{name: "the word in a comment", command: "# git commit -a", want: 0},
		{name: "the word in a here-document", command: "cat <<EOF\ngit commit -a\nEOF", want: 0},
		{name: "the word in a here-document with a quoted delimiter", command: "cat <<'X'\ngit commit -a\nX\n", want: 0},
		{name: "the word in a here-string", command: "cat <<< 'git commit -a'", want: 0},
		{name: "the word after a backslash newline in a message", command: "echo one \\\n git commit", want: 0},

		// A commit whose message, not its options, carries the words.
		{name: "a message from a here-document that mentions -a", record: ready, want: 0,
			command: "git commit -q -F - <<'EOF'\nSay why -a is refused.\ngit commit -a is not the index.\nEOF\ngit log -1"},
		{name: "a message with operators in it", command: `git commit -m "one && two | three; four & five"`, record: ready, want: 0},
		{name: "a message with a quote in it", command: `git commit -m "the sender's command"`, record: ready, want: 0},
		{name: "a message that is not ASCII", command: `git commit -m "café — naïve, 日本語"`, record: ready, want: 0},
		{name: "redirections are not pathspecs", command: "git commit -m x >/dev/null 2>&1", record: ready, want: 0},
		{name: "a redirection with a separate target", command: "git commit -m x > out.txt", record: ready, want: 0},
		{name: "a command after the commit", command: "git commit -m x && git log -1", record: ready, want: 0},
		{name: "a command after the commit, with a semicolon", command: "git commit -m x; git status", record: ready, want: 0},

		// Nothing but cd before the commit.
		{name: "git add before the commit", command: "git add a.txt && git commit -m x", record: ready, want: 2, says: aloneSentence},
		{name: "git status before the commit", command: "git status && git commit -m x", record: ready, want: 2, says: aloneSentence},
		{name: "two commits in one call", command: "git commit -m x && git commit -m y", record: ready, want: 2, says: aloneSentence},
		{name: "a subshell around the commit", command: "(git commit -m x)", record: ready, want: 0},
		{name: "an if around the commit", command: "if git commit -m x; then echo ok; fi", record: ready, want: 0},

		// Another shell does not hide the commit.
		{name: "sh -c", command: "sh -c 'git commit -am x'", record: ready, want: 2, says: indexSentence},
		{name: "bash -c", command: `bash -c "git commit -m x"`, want: 2, says: "no rules review for the staged diff ({hash})"},
		{name: "bash -lc", command: `bash -lc "git commit -m x"`, want: 2, says: "no rules review"},
		{name: "eval", command: "eval git commit -am x", record: ready, want: 2, says: indexSentence},

		// Things in front of git.
		{name: "time, an assignment and git -c", command: "FOO=1 time git -c commit.gpgsign=false commit -m x", want: 2, says: "no rules review"},
		{name: "the full path to git", command: "/usr/bin/git commit -m x", want: 2, says: "no rules review"},
		{name: "env in front", command: "env FOO=1 git commit -m x", want: 2, says: "no rules review"},
		{name: "env with a GIT_ variable in front", command: "env GIT_AUTHOR_NAME=a git commit -m x", want: 2, says: "a GIT_ variable in front of git commit is refused"},
		{name: "git --no-pager", command: "git --no-pager commit -m x", want: 2, says: "no rules review"},

		// A word the gate cannot read as a command or a subcommand: the
		// shell expands, the gate does not, and each of these ran a
		// commit past the gate as "not a commit" before the rule.
		{name: "the subcommand in a variable", command: "x=commit; git $x -m msg", record: ready, want: 2, says: literalSentence},
		{name: "the subcommand from a substitution", command: "git $(echo commit) -m msg", record: ready, want: 2, says: literalSentence},
		{name: "the subcommand from a backtick", command: "git `echo commit` -m msg", record: ready, want: 2, says: literalSentence},
		{name: "the subcommand in an assignment's variable", command: "sub=commit git $sub -m x", record: ready, want: 2, says: literalSentence},
		{name: "the command in a variable", command: "g=git; $g commit -m x", record: ready, want: 2, says: literalSentence},
		{name: "both in variables", command: "g=git; x=commit; $g $x -m x", record: ready, want: 2, says: literalSentence},
		{name: "the command from a substitution", command: "$(echo git) commit -m x", record: ready, want: 2, says: literalSentence},
		{name: "half the subcommand from a substitution", command: "git com$(echo mit) -m x", record: ready, want: 2, says: literalSentence},
		{name: "-C from a substitution", command: "git -C $(pwd) commit -m x", record: ready, want: 2, says: literalSentence},
		{name: "--git-dir= from a substitution", command: "git --git-dir=$(pwd)/.git commit -m x", record: ready, want: 2, says: literalSentence},
		{name: "the subcommand absent", command: "git", want: 2, says: literalSentence},
		{name: "eval of a variable", command: `eval "$cmd"`, want: 2, says: literalSentence},
		// A commit inside a substitution is the commit the shell runs, and
		// is gated as one: inside double quotes too.
		{name: "a commit inside a substitution", command: `echo "$(git commit -m x)"`, want: 2, says: "no rules review for the staged diff ({hash})"},
		{name: "a commit inside an assigned substitution", command: `x="$(git commit -m x)"`, want: 2, says: "no rules review"},
		{name: "a commit inside backticks", command: "x=`git commit -m x`", want: 2, says: "no rules review"},
		{name: "a commit inside a substitution, with a record", command: `x=$(git commit -m x)`, record: ready, want: 0},
		{name: "a commit whose message is a substitution runs another command", command: `git commit -m "$(cat msg.txt)"`, record: ready, want: 2, says: aloneSentence},
		// A substitution elsewhere in a command is not the gate's concern.
		{name: "a substitution as an argument", command: "echo $(date) world", want: 0},
		{name: "a substitution in a path", command: "cat $(git rev-parse --git-dir)/HEAD", want: 0},
		{name: "a substitution assigned", command: "x=$(git rev-parse HEAD); echo $x", want: 0},
		{name: "a substitution in a for", command: "for f in $(ls); do echo $f; done", want: 0},
		{name: "a variable as an argument", command: `git commit -m "fixes $bug"`, record: ready, want: 0},
		{name: "a quoted parenthesis inside a substitution", command: `echo "$(echo "(")"`, want: 0},
		{name: "the literal spellings are still read", command: `git "commit" -m x`, want: 2, says: "no rules review"},
		{name: "a split literal is still read", command: "git 'co''mmit' -m x", want: 2, says: "no rules review"},

		// A directory the gate cannot enter.
		{name: "a variable names the directory", command: "cd $REPO && git commit -m x", record: ready, want: 2,
			says: "the gate could not enter $REPO"},
		{name: "a directory that does not exist", command: "cd /nonexistent-for-the-gate && git commit -m x", record: ready, want: 2,
			says: "could not enter /nonexistent-for-the-gate"},

		// Not the Bash tool.
		{name: "a tool that is not Bash", tool: "Read", command: "git commit -am x", want: 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			repo := newRepo(t, !row.empty)
			hash := hashOf(t, repo, "")
			if row.record != "" {
				writeRecord(t, repo, hash, row.record)
			}
			tool := row.tool
			if tool == "" {
				tool = "Bash"
			}
			code, stdout, stderr := runGate(t, gate, repo, input(t, tool, row.command))
			if code != row.want {
				t.Fatalf("exit %d, want %d\nstdout: %q\nstderr: %q", code, row.want, stdout, stderr)
			}
			if stdout != "" {
				t.Errorf("the gate wrote to standard output: %q", stdout)
			}
			if row.says == "" {
				if stderr != "" {
					t.Errorf("a pass must say nothing; it said %q", stderr)
				}
				return
			}
			want := strings.ReplaceAll(row.says, "{hash}", hash)
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr %q\ndoes not contain %q", stderr, want)
			}
		})
	}
}

// TestAnAmendIsGatedOverTheWholeCommit: --amend makes a commit whose diff
// is the index against HEAD^, so that is what is hashed. A message-only
// amend hashes to the record the commit was gated on; an amend that adds
// work needs a record over the whole; an amend of a commit with no
// parent is refused.
func TestAnAmendIsGatedOverTheWholeCommit(t *testing.T) {
	gate := gatePath(t)

	t.Run("a commit with no parent", func(t *testing.T) {
		repo := newRepo(t, false)
		code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit --amend --no-edit"))
		if code != 2 || !strings.Contains(stderr, "no parent") {
			t.Fatalf("exit %d, stderr %q; want 2 and a refusal naming the missing parent", code, stderr)
		}
	})

	t.Run("a message-only amend hashes to the record the commit was gated on", func(t *testing.T) {
		repo := newRepo(t, true)
		before := hashOf(t, repo, "")
		writeRecord(t, repo, before, ready)
		if code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit -m second")); code != 0 {
			t.Fatalf("the commit itself: exit %d, %q", code, stderr)
		}
		git(t, repo, "commit", "-q", "-m", "second")
		if after := hashOf(t, repo, "HEAD^"); after != before {
			t.Fatalf("git diff --cached HEAD^ after the commit hashes to %s; before it, git diff --cached hashed to %s", after, before)
		}
		if got := gateHash(t, gate, repo, "--amend"); got != before {
			t.Fatalf("--hash --amend printed %s, want %s", got, before)
		}
		for _, command := range []string{"git commit --amend --no-edit", `git commit --amend -m "new words"`} {
			if code, _, stderr := runGate(t, gate, repo, input(t, "Bash", command)); code != 0 || stderr != "" {
				t.Errorf("%s: exit %d, stderr %q; want 0 and silence, since the record for the whole commit exists", command, code, stderr)
			}
		}
		removeRecord(t, repo, before)
		code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit --amend --no-edit"))
		if code != 2 || !strings.Contains(stderr, "no rules review for the whole amended commit, git diff --cached HEAD^ ("+before+")") {
			t.Fatalf("without the record: exit %d, stderr %q; want 2 naming the hash of the whole commit", code, stderr)
		}
	})

	t.Run("an amend that adds work needs a record over the whole", func(t *testing.T) {
		repo := newRepo(t, true)
		first := hashOf(t, repo, "")
		git(t, repo, "commit", "-q", "-m", "second")
		stage(t, repo, "b.txt", "three\n")
		whole := hashOf(t, repo, "HEAD^")
		alone := hashOf(t, repo, "")
		if whole == first || whole == alone {
			t.Fatalf("the whole commit's hash %s equals the first commit's %s or the new work's %s", whole, first, alone)
		}
		if got := gateHash(t, gate, repo, "--amend"); got != whole {
			t.Fatalf("--hash --amend printed %s, want %s", got, whole)
		}
		writeRecord(t, repo, first, ready)
		writeRecord(t, repo, alone, ready)
		code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit --amend --no-edit"))
		if code != 2 || !strings.Contains(stderr, "("+whole+")") {
			t.Fatalf("with records for the first commit and the new work alone: exit %d, stderr %q; want 2 naming %s", code, stderr, whole)
		}
		writeRecord(t, repo, whole, ready)
		if code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit --amend --no-edit")); code != 0 || stderr != "" {
			t.Fatalf("with the record for the whole: exit %d, stderr %q; want 0 and silence", code, stderr)
		}
	})

	t.Run("an amend with -a is still -a", func(t *testing.T) {
		repo := newRepo(t, true)
		git(t, repo, "commit", "-q", "-m", "second")
		code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit --amend -a --no-edit"))
		if code != 2 || !strings.Contains(stderr, indexSentence) {
			t.Fatalf("exit %d, stderr %q; want 2 and the index sentence", code, stderr)
		}
	})
}

// TestARecordIsForOneDiff: the record is named by the diff's hash, so a
// change staged after the record was written has no record.
func TestARecordIsForOneDiff(t *testing.T) {
	gate := gatePath(t)
	repo := newRepo(t, true)
	first := hashOf(t, repo, "")
	writeRecord(t, repo, first, ready)
	if code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit -m x")); code != 0 {
		t.Fatalf("with the record: exit %d, %q", code, stderr)
	}
	stage(t, repo, "a.txt", "two, then three\n")
	second := hashOf(t, repo, "")
	if second == first {
		t.Fatal("staging more did not change the hash")
	}
	code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "git commit -m x"))
	if code != 2 || !strings.Contains(stderr, "("+second+")") || strings.Contains(stderr, first) {
		t.Fatalf("after staging more: exit %d, stderr %q; want 2 naming %s and not %s", code, stderr, second, first)
	}
}

// TestTheGateReadsTheIndexTheCommitWould: a commit named through -C, or
// after a cd, from a directory that is not the repository, is gated on
// that repository's index; and a directory with a space in its name is
// one word when quoted.
func TestTheGateReadsTheIndexTheCommitWould(t *testing.T) {
	gate := gatePath(t)
	elsewhere := t.TempDir()
	parent := t.TempDir()
	repo := filepath.Join(parent, "with space")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	initRepo(t, repo, true)
	hash := hashOf(t, repo, "")
	for _, command := range []string{
		`git -C "` + repo + `" commit -m x`,
		`git -C '` + repo + `' commit -m x`,
		`cd "` + repo + `" && git commit -m x`,
		`cd '` + repo + `'; git commit -m x`,
		`cd ` + strings.ReplaceAll(repo, " ", `\ `) + ` && git commit -m x`,
	} {
		code, _, stderr := runGate(t, gate, elsewhere, input(t, "Bash", command))
		if code != 2 || !strings.Contains(stderr, "("+hash+")") {
			t.Errorf("%s from elsewhere without a record: exit %d, stderr %q; want 2 naming %s", command, code, stderr, hash)
		}
	}
	writeRecord(t, repo, hash, ready)
	for _, command := range []string{
		`git -C "` + repo + `" commit -m x`,
		`cd "` + repo + `" && git commit -m x`,
	} {
		if code, _, stderr := runGate(t, gate, elsewhere, input(t, "Bash", command)); code != 0 || stderr != "" {
			t.Errorf("%s from elsewhere with the record: exit %d, stderr %q; want 0 and silence", command, code, stderr)
		}
	}
	code, _, stderr := runGate(t, gate, elsewhere, input(t, "Bash", "git commit -m x"))
	if code != 2 || !strings.Contains(stderr, "found no repository") {
		t.Errorf("a commit from a directory that is no repository: exit %d, stderr %q; want 2 saying so", code, stderr)
	}
}

// TestTheHashIsSHA256OverTheDiff: --hash prints the first sixteen hex
// characters of SHA-256 over git diff --cached, --record the record's path
// under the repository's git directory, and the record the gate looks for
// is that one.
func TestTheHashIsSHA256OverTheDiff(t *testing.T) {
	gate := gatePath(t)
	repo := newRepo(t, true)
	hash := hashOf(t, repo, "")
	if len(hash) != 16 {
		t.Fatalf("hash %q is not sixteen characters", hash)
	}
	if got := gateHash(t, gate, repo, ""); got != hash {
		t.Fatalf("--hash printed %q, want %q", got, hash)
	}
	plain := sha256.Sum256([]byte(git(t, repo, "diff", "--cached")))
	if got := hex.EncodeToString(plain[:])[:16]; got != hash {
		t.Fatalf("the plain git diff --cached hashes to %s, the gate's to %s; in a repository with no external diff and no textconv they must agree", got, hash)
	}
	want := filepath.Join(gitDir(t, repo), "rules-review", hash+".md")
	cmd := exec.Command("sh", gate, "--record")
	cmd.Dir = repo
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("--record printed %q, want %q", got, want)
	}
	for _, args := range [][]string{{"--bogus"}, {"--hash", "--bogus"}, {"--hash", "--amend", "extra"}} {
		cmd := exec.Command("sh", append([]string{gate}, args...)...)
		cmd.Dir = repo
		if err := cmd.Run(); err == nil {
			t.Errorf("rules-gate.sh %v succeeded; want a usage error", args)
		}
	}
}

// TestUnreadableInputIsLetThroughOnlyWhenItNamesNoCommit: what is not
// the hook's JSON, or is JSON without a command, is let through with a
// line on standard error only when its text has no "commit" in it, so
// that a gate that misread its input does not stop every command and
// does not let a commit through unread either; and the escapes JSON may
// use for a command are decoded before the command is read.
func TestUnreadableInputIsLetThroughOnlyWhenItNamesNoCommit(t *testing.T) {
	gate := gatePath(t)
	repo := newRepo(t, true)
	for _, stdin := range []string{
		"",
		"garbage",
		`{"tool_name":"Bash"}`,
		`{"tool_name":"Bash","tool_input":{"description":"run the suite"}}`,
		// Truncated JSON that names go test.
		`{"tool_name":"Bash","tool_input":{"command":"go test ./..."`,
		`{"tool_name":"Bash","tool_input":{"command":"go test ./...\u"}}`,
	} {
		code, stdout, stderr := runGate(t, gate, repo, stdin)
		if code != 0 || stdout != "" || !strings.Contains(stderr, "letting the command through") {
			t.Errorf("stdin %q: exit %d, stdout %q, stderr %q; want 0 and the line that says the command was let through", stdin, code, stdout, stderr)
		}
	}
	for _, stdin := range []string{
		// Truncated JSON whose text has git commit in it.
		`{"tool_name":"Bash","tool_input":{"command":"git commit -m x"`,
		`{"tool_name":"Bash","tool_input":{"command":"git commit -m x\u"}}`,
		// JSON without a command, whose description mentions one.
		`{"tool_name":"Bash","tool_input":{"description":"git commit -am x"}}`,
		// Not JSON at all, in any case.
		"garbage COMMIT garbage",
	} {
		code, stdout, stderr := runGate(t, gate, repo, stdin)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "will not let a commit through unread") {
			t.Errorf("stdin %q: exit %d, stdout %q, stderr %q; want 2 and the sentence that refuses a commit unread", stdin, code, stdout, stderr)
		}
	}
	hash := hashOf(t, repo, "")
	for _, stdin := range []string{
		// Go's encoder writes <, > and & as \u003c, \u003e and \u0026.
		`{"tool_name":"Bash","tool_input":{"command":"git commit -q -F - \u003c\u003c'EOF'\nline one \u0026\u0026 two\nEOF"}}`,
		// A surrogate pair in the message, and an escaped quote.
		`{"tool_name":"Bash","tool_input":{"command":"git commit -m \"\ud83d\ude00 \u00e9\""}}`,
		// The fields in another order, with the description first.
		`{"tool_input":{"description":"git status","command":"git commit -m x"},"cwd":"/x","tool_name":"Bash"}`,
		// Pretty-printed.
		"{\n  \"tool_name\": \"Bash\",\n  \"tool_input\": {\n    \"command\": \"git commit -m x\"\n  }\n}\n",
	} {
		code, _, stderr := runGate(t, gate, repo, stdin)
		if code != 2 || !strings.Contains(stderr, "("+hash+")") {
			t.Errorf("stdin %q: exit %d, stderr %q; want 2 naming %s", stdin, code, stderr, hash)
		}
	}
	// A description that says commit does not make a readable command one.
	stdin := `{"tool_name":"Bash","tool_input":{"description":"git commit -am x","command":"git status"}}`
	if code, _, stderr := runGate(t, gate, repo, stdin); code != 0 || stderr != "" {
		t.Errorf("stdin %q: exit %d, stderr %q; want 0 and silence", stdin, code, stderr)
	}
}

// TestTheGateRunsNothingItReads: the command is read, not run. A command
// that would leave a file behind leaves none, whether the gate refuses it
// or lets it through.
func TestTheGateRunsNothingItReads(t *testing.T) {
	gate := gatePath(t)
	repo := newRepo(t, true)
	writeRecord(t, repo, hashOf(t, repo, ""), ready)
	for _, command := range []string{
		"touch gate-ran-this && git commit -m x",
		"git commit -m x && touch gate-ran-this",
		"git commit -m x; touch gate-ran-this",
		"git commit -m \"$(touch gate-ran-this)\"",
		"git commit -m `touch gate-ran-this`",
		"echo `touch gate-ran-this`",
	} {
		runGate(t, gate, repo, input(t, "Bash", command))
		if _, err := os.Stat(filepath.Join(repo, "gate-ran-this")); err == nil {
			t.Fatalf("%s: the gate ran the command it was given", command)
		}
	}
}

// TestTheCommandDoesNotChooseHowTheGateRunsGit: the second reader's
// finding. git runs a command named by core.fsmonitor whenever it reads
// the index, by diff.external and by a driver's textconv when it diffs,
// and the gate runs its own git before the person is asked about the
// command, on the refuse path too. So a -c in the command does not reach
// the gate's git, a repository's own config does not either, --exec-path
// does not pick the gate's git, and a GIT_ variable in front of the
// command is refused: on neither the pass path nor the refuse path is a
// marker left behind.
func TestTheCommandDoesNotChooseHowTheGateRunsGit(t *testing.T) {
	gate := gatePath(t)
	marker := func(t *testing.T, repo, command string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(repo, "gate-ran-this")); err == nil {
			t.Fatalf("%s: git ran a command the configuration named", command)
		}
	}
	commands := []string{
		"git -c core.fsmonitor='touch gate-ran-this' commit -m x",
		"git -c 'core.fsmonitor=touch gate-ran-this' -c diff.external='touch gate-ran-this' commit -m x",
		"git -c diff.evil.textconv='touch gate-ran-this' commit -m x",
		"git --exec-path=/nonexistent-for-the-gate commit -m x",
		"git -c core.fsmonitor='touch gate-ran-this' --no-pager commit -m x",
	}
	t.Run("a -c in the command, refused and passed", func(t *testing.T) {
		for _, command := range commands {
			repo := newRepo(t, true)
			stage(t, repo, ".gitattributes", "a.txt diff=evil\n")
			hash := hashOf(t, repo, "")
			code, _, stderr := runGate(t, gate, repo, input(t, "Bash", command))
			if code != 2 || !strings.Contains(stderr, "("+hash+")") {
				t.Errorf("%s without a record: exit %d, stderr %q; want 2 naming %s", command, code, stderr, hash)
			}
			marker(t, repo, command)
			writeRecord(t, repo, hash, ready)
			if code, _, stderr := runGate(t, gate, repo, input(t, "Bash", command)); code != 0 || stderr != "" {
				t.Errorf("%s with the record: exit %d, stderr %q; want 0 and silence", command, code, stderr)
			}
			marker(t, repo, command)
		}
	})
	t.Run("the repository's own configuration", func(t *testing.T) {
		elsewhere := t.TempDir()
		for _, command := range []string{"git commit -m x", "cd {repo} && git commit -m x", "git -C {repo} commit -m x"} {
			repo := newRepo(t, true)
			stage(t, repo, ".gitattributes", "a.txt diff=evil\n")
			git(t, repo, "config", "core.fsmonitor", "touch gate-ran-this")
			git(t, repo, "config", "diff.external", "touch gate-ran-this")
			git(t, repo, "config", "diff.evil.textconv", "touch gate-ran-this")
			hash := hashOf(t, repo, "")
			command = strings.ReplaceAll(command, "{repo}", repo)
			dir := repo
			if strings.Contains(command, repo) {
				dir = elsewhere
			}
			code, _, stderr := runGate(t, gate, dir, input(t, "Bash", command))
			if code != 2 || !strings.Contains(stderr, "("+hash+")") {
				t.Errorf("%s without a record: exit %d, stderr %q; want 2 naming %s", command, code, stderr, hash)
			}
			marker(t, repo, command)
			writeRecord(t, repo, hash, ready)
			if code, _, stderr := runGate(t, gate, dir, input(t, "Bash", command)); code != 0 || stderr != "" {
				t.Errorf("%s with the record: exit %d, stderr %q; want 0 and silence", command, code, stderr)
			}
			marker(t, repo, command)
		}
	})
	t.Run("a GIT_ variable in front", func(t *testing.T) {
		repo := newRepo(t, true)
		writeRecord(t, repo, hashOf(t, repo, ""), ready)
		for _, command := range []string{
			"GIT_DIR=/elsewhere/.git git commit -m x",
			"GIT_INDEX_FILE=other git commit -m x",
			"env GIT_WORK_TREE=/elsewhere git commit -m x",
			"FOO=1 GIT_CONFIG_PARAMETERS=\"'core.fsmonitor=touch gate-ran-this'\" git commit -m x",
		} {
			code, _, stderr := runGate(t, gate, repo, input(t, "Bash", command))
			if code != 2 || !strings.Contains(stderr, "a GIT_ variable in front of git commit is refused") {
				t.Errorf("%s: exit %d, stderr %q; want 2 and the GIT_ sentence", command, code, stderr)
			}
			marker(t, repo, command)
		}
		// A variable that is not git's is only a word in front.
		if code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "FOO=1 git commit -m x")); code != 0 || stderr != "" {
			t.Errorf("FOO=1 git commit -m x with the record: exit %d, stderr %q; want 0 and silence", code, stderr)
		}
	})
}

// TestWhatTheGateRepeatsIsText: the two values a refusal repeats, a
// directory from the command and the last line of a record, reach
// standard error with control bytes made question marks, so that a
// terminal shows them rather than obeys them.
func TestWhatTheGateRepeatsIsText(t *testing.T) {
	gate := gatePath(t)
	repo := newRepo(t, true)
	hash := hashOf(t, repo, "")
	code, _, stderr := runGate(t, gate, repo, input(t, "Bash", "cd /no\x1b[31msuch\a && git commit -m x"))
	if code != 2 || strings.ContainsAny(stderr, "\x1b\a") || !strings.Contains(stderr, "could not enter /no?[31msuch?") {
		t.Errorf("a directory with an escape sequence in it: exit %d, stderr %q; want 2 and the sequence as question marks", code, stderr)
	}
	writeRecord(t, repo, hash, "Verdict: not ready\nsee \x1b[31mthe test\a\n")
	code, _, stderr = runGate(t, gate, repo, input(t, "Bash", "git commit -m x"))
	if code != 2 || strings.ContainsAny(stderr, "\x1b\a") || !strings.Contains(stderr, "says: see ?[31mthe test?;") {
		t.Errorf("a record whose last line has an escape sequence: exit %d, stderr %q; want 2 and the sequence as question marks", code, stderr)
	}
}

// gatePath is the hook script, found above this test, and the skip when
// it cannot run here.
func gatePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the hook is sh, which does not run on Windows")
	}
	for _, tool := range []string{"sh", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on the PATH", tool)
		}
	}
	gate := filepath.Join(moduleRoot(t), ".claude", "hooks", "rules-gate.sh")
	if _, err := os.Stat(gate); err != nil {
		t.Fatal(err)
	}
	return gate
}

// moduleRoot is the directory holding go.mod above this test.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

// gitEnv is the environment for every git here, the gate's included: no
// global or system configuration, so the diff and its hash are the ones
// git makes by default on every machine.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=rulesgate", "GIT_AUTHOR_EMAIL=rulesgate@example.com",
		"GIT_COMMITTER_NAME=rulesgate", "GIT_COMMITTER_EMAIL=rulesgate@example.com",
	)
}

// git runs one git command in dir and fails the test if it fails.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// newRepo is a repository with one commit, and with a change to a.txt
// staged when staged is true.
func newRepo(t *testing.T, staged bool) string {
	t.Helper()
	repo := t.TempDir()
	initRepo(t, repo, staged)
	return repo
}

func initRepo(t *testing.T, repo string, staged bool) {
	t.Helper()
	git(t, repo, "init", "-q")
	stage(t, repo, "a.txt", "one\n")
	git(t, repo, "commit", "-q", "-m", "init")
	if staged {
		stage(t, repo, "a.txt", "two\n")
	}
}

// stage writes a file and adds it to the index.
func stage(t *testing.T, repo, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "--", name)
}

// hashOf is what the gate must compute: the first sixteen hex characters
// of SHA-256 over git diff --cached with --no-ext-diff and --no-textconv,
// against base when base is not empty. In a repository whose
// configuration names no external diff and no textconv that is the plain
// diff, which TestTheHashIsSHA256OverTheDiff also checks.
func hashOf(t *testing.T, repo, base string) string {
	t.Helper()
	args := []string{"-c", "core.fsmonitor=false", "diff", "--cached", "--no-ext-diff", "--no-textconv"}
	if base != "" {
		args = append(args, base)
	}
	sum := sha256.Sum256([]byte(git(t, repo, args...)))
	return hex.EncodeToString(sum[:])[:16]
}

func gitDir(t *testing.T, repo string) string {
	t.Helper()
	return strings.TrimSpace(git(t, repo, "rev-parse", "--absolute-git-dir"))
}

func writeRecord(t *testing.T, repo, hash, text string) {
	t.Helper()
	dir := filepath.Join(gitDir(t, repo), "rules-review")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hash+".md"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeRecord(t *testing.T, repo, hash string) {
	t.Helper()
	if err := os.Remove(filepath.Join(gitDir(t, repo), "rules-review", hash+".md")); err != nil {
		t.Fatal(err)
	}
}

// input is the hook's stdin for one command, encoded as Go encodes JSON,
// which writes <, > and & as \u escapes.
func input(t *testing.T, tool, command string) string {
	t.Helper()
	b, err := json.Marshal(hookInput{
		SessionID: "s", CWD: "/x", HookEventName: "PreToolUse", ToolName: tool,
		ToolInput: toolInput{Description: "git commit, or not", Timeout: 120000, Command: command},
		ToolUseID: "toolu_01",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runGate runs the hook from dir with stdin and returns its exit code,
// standard output and standard error.
func runGate(t *testing.T, gate, dir, stdin string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("sh", gate)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("running the gate: %v", err)
		}
		code = exit.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

// gateHash is what --hash, or --hash --amend, prints from repo.
func gateHash(t *testing.T, gate, repo, amend string) string {
	t.Helper()
	args := []string{gate, "--hash"}
	if amend != "" {
		args = append(args, amend)
	}
	cmd := exec.Command("sh", args...)
	cmd.Dir = repo
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rules-gate.sh %v: %v", args[1:], err)
	}
	return strings.TrimSpace(string(out))
}
