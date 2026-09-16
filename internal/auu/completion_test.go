package auu

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// completions runs __complete for a user and returns value -> description.
func completions(t *testing.T, u *user, words ...string) map[string]string {
	t.Helper()
	out := u.run(append([]string{"__complete"}, words...)...)
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		value, desc, _ := strings.Cut(line, "\t")
		got[value] = desc
	}
	return got
}

func TestCompleteSubcommandsAndSecondWords(t *testing.T) {
	relayURL := startRelay(t)
	u := newUser(t, "me", relayURL)
	all := completions(t, u, "")
	for _, want := range []string{"send", "reply", "inbox", "read", "peers", "quarantine", "completion"} {
		if _, ok := all[want]; !ok {
			t.Errorf("subcommand %q not offered", want)
		}
	}
	if _, ok := all["__complete"]; ok {
		t.Error("the hidden command is offered")
	}
	if got := completions(t, u, "re"); len(got) != 4 ||
		got["read"] == "" || got["reply"] == "" || got["register"] == "" || got["relay"] == "" {
		t.Errorf("prefix re: %v", got)
	}
	if got := completions(t, u, "relay", ""); len(got) != 6 || got["default"] == "" || got["rm"] == "" {
		t.Errorf("relay subwords: %v", got)
	}
	if got := completions(t, u, "peers", ""); len(got) != 4 || got["rm"] == "" {
		t.Errorf("peers subwords: %v", got)
	}
	if got := completions(t, u, "quarantine", "t"); len(got) != 1 || got["trust"] == "" {
		t.Errorf("quarantine t: %v", got)
	}
}

// Your example: "auu read 88<tab>" completes the id, with the subject beside it.
func TestCompleteMessageIds(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	me.run("send", "--to", "self", "--subject", "Foo Gap", "is there one?")
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	id := got.Messages[0].ID

	c := completions(t, me, "read", id[:2])
	desc, ok := c[id[:12]]
	if !ok || !strings.Contains(desc, "Foo Gap") || !strings.Contains(desc, "me") {
		t.Fatalf("read %s: %v", id[:2], c)
	}
	// Nothing else starts that way, and a prefix that matches nothing is empty.
	if len(c) != 1 || len(completions(t, me, "read", "zzzz")) != 0 {
		t.Fatalf("read: %v", c)
	}
	// Typed past twelve characters, the whole id is offered.
	if c := completions(t, me, "read", id[:20]); len(c) != 1 {
		t.Fatalf("a long prefix: %v", c)
	}
	// extract and reply see it too; reply also offers the thread.
	if c := completions(t, me, "extract", ""); c[id[:12]] == "" {
		t.Fatalf("extract: %v", c)
	}
	c = completions(t, me, "reply", "")
	if c[id[:12]] == "" || !strings.HasPrefix(c[got.Messages[0].Thread[:12]], "thread:") {
		t.Fatalf("reply: %v", c)
	}
}

func TestCompletePeersThreadsAndFlagValues(t *testing.T) {
	alice, bob := twoPeers(t)
	first := sentOf(t, alice.run("send", "--to", "bob", "--subject", "q", "--json", "one"))

	c := completions(t, alice, "send", "--to", "")
	if c["bob"] == "" || c["self"] == "" || len(c) != 2 {
		t.Fatalf("--to: %v", c)
	}
	if c := completions(t, alice, "send", "--to", "b"); len(c) != 1 || c["bob"] == "" {
		t.Fatalf("--to b: %v", c)
	}
	if c := completions(t, alice, "wait", "--thread", ""); !strings.Contains(c[first.Thread[:12]], "q") {
		t.Fatalf("--thread: %v", c)
	}
	if c := completions(t, alice, "send", "--type", ""); len(c) != 2 || c["ask"] == "" {
		t.Fatalf("--type: %v", c)
	}
	if c := completions(t, alice, "send", "--attach", ""); len(c) != 1 || c["__files"] != "" {
		t.Fatalf("--attach should hand over to the shell: %v", c)
	}
	if c := completions(t, alice, "peers", "rm", ""); len(c) != 1 || c["bob"] == "" {
		t.Fatalf("peers rm: %v", c)
	}
	// A bool flag before the cursor does not swallow the next word.
	if c := completions(t, alice, "send", "--edit", ""); len(c) != 0 {
		t.Fatalf("after a bool flag: %v", c)
	}
	_ = bob
}

// Flags come from the commands themselves.
func TestCompleteFlagsAreTheRealOnes(t *testing.T) {
	relayURL := startRelay(t)
	u := newUser(t, "me", relayURL)
	c := completions(t, u, "send", "-")
	for _, want := range []string{"--to", "--subject", "--attach", "--edit", "--json", "--stream", "--resume"} {
		if _, ok := c[want]; !ok {
			t.Errorf("send: %s not offered: %v", want, c)
		}
	}
	if c["--to"] == "" {
		t.Error("a flag's usage text is its description")
	}
	if c := completions(t, u, "inbox", "--"); c["--json"] == "" || c["--no-fetch"] == "" {
		t.Errorf("inbox: %v", c)
	}
	if c := completions(t, u, "quarantine", "ls", "--j"); len(c) != 1 || c["--json"] == "" {
		t.Errorf("quarantine ls --j: %v", c)
	}
	// The sentinel is never offered, and asking for flags ran nothing.
	if _, ok := c[flagsSentinel]; ok {
		t.Error("the sentinel leaked")
	}
}

func TestCompletionScripts(t *testing.T) {
	relayURL := startRelay(t)
	u := newUser(t, "me", relayURL)
	zsh := u.run("completion", "zsh")
	if !strings.HasPrefix(zsh, "#compdef auu\n") || !strings.Contains(zsh, "compdef _auu auu") {
		t.Fatalf("zsh script:\n%s", zsh[:80])
	}
	bash := u.run("completion", "bash")
	if !strings.Contains(bash, "complete -F _auu auu") {
		t.Fatalf("bash script:\n%s", bash[:80])
	}
	if _, err := u.tryRun("completion", "fish"); err == nil {
		t.Fatal("an unsupported shell was accepted")
	}
	if _, err := u.tryRun("completion"); err == nil {
		t.Fatal("no shell was accepted")
	}
}

// The bash script, for real: build the binary, source the script into bash,
// and complete "auu read 88" the way a keypress would. bash 3.2 on macOS is
// the oldest anyone has, so the script stays within it.
func TestBashCompletionEndToEnd(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain to build the binary")
	}
	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "auu"), "../../cmd/auu")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building auu: %v\n%s", err, out)
	}

	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	me.run("send", "--to", "self", "--subject", "Foo Gap", "x")
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	id := got.Messages[0].ID

	// eval rather than source <(...): bash 3.2's source reads nothing from
	// a pipe, which is also why the install instructions say eval.
	script := `eval "$(auu completion bash)"
COMP_WORDS=(auu read ` + id[:2] + `); COMP_CWORD=2; _auu; printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(auu send --to ''); COMP_CWORD=3; _auu; printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(auu send --attach ''); COMP_CWORD=3; _auu; printf 'files:%s\n' "${#COMPREPLY[@]}"`
	cmd := exec.Command(bashPath, "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AUU_HOME="+me.home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 3 || lines[0] != id[:12] || lines[1] != "self" || !strings.HasPrefix(lines[2], "files:") {
		t.Fatalf("bash completion gave:\n%s", out)
	}
}

// The zsh script, for real. zsh's completion system cannot be driven from a
// pipe, but the function can be called with the line set by hand and the two
// compsys helpers it uses stubbed to print what they would have offered.
func TestZshCompletionEndToEnd(t *testing.T) {
	zshPath, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain to build the binary")
	}
	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "auu"), "../../cmd/auu")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building auu: %v\n%s", err, out)
	}

	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	me.run("send", "--to", "self", "--subject", "Foo: Gap", "x") // a colon, which zsh must see escaped
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	id := got.Messages[0].ID

	// A bare shell, as in the field: nothing has run compinit, and the
	// script must cope. HOME is a temp dir so compinit's dump lands there.
	script := `eval "$(auu completion zsh)"
(( $+functions[compdef] )) || { print "compdef missing after eval"; exit 1 }
_describe() { shift 3; print -rl -- "${(@P)1}" }
_files() { print __FILES }
words=(auu read ` + id[:2] + `); CURRENT=3; _auu
words=(auu send --to ""); CURRENT=4; _auu
words=(auu send --attach ""); CURRENT=4; _auu`
	cmd := exec.Command(zshPath, "-f", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AUU_HOME="+me.home, "HOME="+bin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 {
		t.Fatalf("zsh completion gave %d lines:\n%s", len(lines), out)
	}
	// value:description, with the description's colon escaped for _describe.
	if lines[0] != id[:12]+`:Foo\: Gap — me (inbox)` {
		t.Fatalf("read: %q", lines[0])
	}
	if lines[1] != "self:a note to yourself" || lines[2] != "__FILES" {
		t.Fatalf("--to / --attach: %q, %q", lines[1], lines[2])
	}
}
