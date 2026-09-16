package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// editor installs a shell script as AUU_EDITOR. The script sees the draft's
// path as $1, exactly as a real editor would.
func editor(t *testing.T, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "editor.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUU_EDITOR", path)
}

func twoPeers(t *testing.T) (alice, bob *user) {
	t.Helper()
	relayURL := startRelay(t)
	alice = newUser(t, "alice", relayURL)
	bob = newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	return alice, bob
}

// firstMessage fetches and returns bob's first message with its text.
func firstMessage(t *testing.T, u *user) (subject, text string) {
	t.Helper()
	var got inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("%d messages, want 1: %+v", len(got.Messages), got.Fetch)
	}
	var m messageJSON
	if err := json.Unmarshal([]byte(u.run("read", got.Messages[0].ID, "--json")), &m); err != nil {
		t.Fatal(err)
	}
	return m.Subject, m.Text
}

// The editor writes the message; the subject came from the flag.
func TestSendEditComposesInTheEditor(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf 'written in the editor\n' >> "$1"`)
	alice.run("send", "--to", "bob", "--subject", "from the flag", "--edit")
	subject, text := firstMessage(t, bob)
	if subject != "from the flag" || text != "written in the editor" {
		t.Fatalf("subject %q text %q", subject, text)
	}
}

// Without --subject, the first line is the subject and the rest the message,
// as a commit's first line is its summary.
func TestSendEditFirstLineIsTheSubject(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf 'A subject line\n\nThe body,\nover two lines.\n' > "$1"`)
	alice.run("send", "--to", "bob", "--edit")
	subject, text := firstMessage(t, bob)
	if subject != "A subject line" {
		t.Fatalf("subject %q", subject)
	}
	if text != "The body,\nover two lines." {
		t.Fatalf("text %q", text)
	}
}

// Comment lines are dropped, trailing whitespace goes, blank lines inside the
// message stay.
func TestSendEditStripsCommentsLikeGit(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf '\n\nfirst   \n# a comment\n\nthird\t\n\n\n' > "$1"`)
	alice.run("send", "--to", "bob", "--subject", "s", "--edit")
	_, text := firstMessage(t, bob)
	if text != "first\n\nthird" {
		t.Fatalf("text %q", text)
	}
}

// Text given with --edit is the starting point, and the template describes
// the message: recipient, subject, attachments.
func TestSendEditSeedsAndDescribes(t *testing.T) {
	alice, bob := twoPeers(t)
	file := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	editor(t, `grep -q '^the seed$' "$1" || exit 11
grep -q '^# Message to bob' "$1" || exit 12
grep -q '^# Subject: s   (edit the subject here; keep the #)$' "$1" || exit 13
grep -q '^# Attachments: notes.txt' "$1" || exit 14
printf 'and more\n' >> "$1"`)
	alice.run("send", "--to", "bob", "--subject", "s", "--attach", file, "--edit", "the seed")
	// The blank line is git's too: the seed sits above the cursor line, and
	// what is typed below the comments is a paragraph after it.
	_, text := firstMessage(t, bob)
	if text != "the seed\n\nand more" {
		t.Fatalf("text %q", text)
	}
}

// An empty message sends nothing, says so, and leaves the draft.
func TestSendEditEmptyAborts(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf '# only comments\n' > "$1"`)
	_, err := alice.tryRun("send", "--to", "bob", "--subject", "s", "--edit")
	if err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Fatalf("err %v", err)
	}
	var got inboxJSON
	json.Unmarshal([]byte(bob.run("inbox", "--json")), &got)
	if got.Fetch.Delivered != 0 {
		t.Fatal("an empty message was sent")
	}
	if _, err := os.Stat(filepath.Join(alice.home, composeFile)); err != nil {
		t.Fatalf("the draft was not kept: %v", err)
	}
}

// An editor that fails is reported, with the draft's whereabouts, and
// nothing is sent.
func TestSendEditEditorFailure(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `exit 3`)
	_, err := alice.tryRun("send", "--to", "bob", "--subject", "s", "--edit")
	if err == nil || !strings.Contains(err.Error(), "editor") || !strings.Contains(err.Error(), composeFile) {
		t.Fatalf("err %v", err)
	}
	var got inboxJSON
	json.Unmarshal([]byte(bob.run("inbox", "--json")), &got)
	if got.Fetch.Delivered != 0 {
		t.Fatal("a message was sent after the editor failed")
	}
}

// A send that the relay refuses after composing keeps the cleaned message
// where --body-file can find it, with the original exit code.
func TestSendEditKeepsTheDraftWhenTheRelayRefuses(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	// bob has an identity but has not registered: the relay has no mailbox
	// for him, so alice's post is refused after she has composed it.
	bob := &user{t: t, home: t.TempDir()}
	bob.run("init", "--name", "bob", "--relay", relayURL)
	alice.run("peers", "add", bob.exportLine())

	editor(t, `printf 'Subject\n\ntyped once\n' > "$1"`)
	_, err := alice.tryRun("send", "--to", "bob", "--edit")
	if err == nil || !strings.Contains(err.Error(), "kept at") {
		t.Fatalf("err %v", err)
	}
	draft, readErr := os.ReadFile(filepath.Join(alice.home, composeFile))
	if readErr != nil || string(draft) != "typed once\n" {
		t.Fatalf("draft %q, %v", draft, readErr)
	}
	// And it can be sent again from the draft once the way is open.
	bob.run("register")
	bob.run("peers", "add", alice.exportLine())
	alice.run("send", "--to", "bob", "--subject", "Subject", "--body-file", filepath.Join(alice.home, composeFile))
	subject, text := firstMessage(t, bob)
	if subject != "Subject" || text != "typed once\n" {
		t.Fatalf("resent as %q %q", subject, text)
	}
}

// Reply composes too, with the original named in the template.
func TestReplyEdit(t *testing.T) {
	alice, bob := twoPeers(t)
	alice.run("send", "--to", "bob", "--subject", "question", "the question")
	var got inboxJSON
	json.Unmarshal([]byte(bob.run("inbox", "--json")), &got)
	editor(t, `grep -q '^# Reply to .* from alice: "question"' "$1" || exit 21
printf 'the answer\n' >> "$1"`)
	bob.run("reply", got.Messages[0].ID, "--edit")
	subject, text := firstMessage(t, alice)
	if subject != "question" || text != "the answer" {
		t.Fatalf("reply %q %q", subject, text)
	}
}

// The editor is chosen in git's order, with the program's own variable first.
func TestEditorOrder(t *testing.T) {
	for _, v := range []string{"AUU_EDITOR", "VISUAL", "EDITOR"} {
		t.Setenv(v, "")
	}
	if got := editorFor(store.Config{}); got != "vi" {
		t.Fatalf("with nothing set: %q", got)
	}
	t.Setenv("EDITOR", "nano")
	if got := editorFor(store.Config{}); got != "nano" {
		t.Fatalf("EDITOR: %q", got)
	}
	t.Setenv("VISUAL", "emacs")
	if got := editorFor(store.Config{}); got != "emacs" {
		t.Fatalf("VISUAL over EDITOR: %q", got)
	}
	if got := editorFor(store.Config{Editor: "hx"}); got != "hx" {
		t.Fatalf("config over VISUAL: %q", got)
	}
	t.Setenv("AUU_EDITOR", "code --wait")
	if got := editorFor(store.Config{Editor: "hx"}); got != "code --wait" {
		t.Fatalf("AUU_EDITOR over everything: %q", got)
	}
	t.Setenv("AUU_EDITOR", "   ")
	if got := editorFor(store.Config{Editor: "hx"}); got != "hx" {
		t.Fatalf("a blank variable counts as unset: %q", got)
	}
}

func TestStripCommentsAndSplitSubject(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"# only\n# comments\n", ""},
		{"\n\n\nx\n\n\n", "x"},
		{"a  \r\nb\t\r\n", "a\nb"},
		{"a\n\n\nb", "a\n\n\nb"},
		{"#x\na\n#y\nb\n#z", "a\nb"},
		{" # not a comment: leading space", " # not a comment: leading space"},
	}
	for _, c := range cases {
		if got := stripComments(c.in); got != c.want {
			t.Errorf("stripComments(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	split := []struct{ in, subject, body string }{
		{"only a subject", "only a subject", ""},
		{"s\nbody", "s", "body"},
		{"s\n\nbody", "s", "body"},
		{"s\n\n\n\nbody\nmore", "s", "body\nmore"},
		{"  padded  \nbody", "padded", "body"},
	}
	for _, c := range split {
		s, b := splitSubject(c.in)
		if s != c.subject || b != c.body {
			t.Errorf("splitSubject(%q) = %q, %q; want %q, %q", c.in, s, b, c.subject, c.body)
		}
	}
}
