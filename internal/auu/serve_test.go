package auu

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// auu serve, from the file to the reply.
//
// Every handler in these tests is this test binary, run again with
// -test.run=TestServeHelperProcess and told what to do by an environment
// variable serve passes through. That keeps shell syntax out of the exec
// line, so the same tests run where the shell is cmd /c as where it is
// /bin/sh -c. Two tests are deliberately Unix-only and say so: the one that
// proves there is a shell at all, and the one that proves a handler's
// children are killed with it.

const (
	handlerScript = "AUU_TEST_HANDLER"
	beforeScript  = "AUU_TEST_BEFORE"
	afterScript   = "AUU_TEST_AFTER"
)

// TestServeHelperProcess is the handler, the before hook and the after
// hook. It is not a test: it runs only when serve has started this binary
// again, and it always ends by exiting, so that the testing framework never
// prints a word into what serve is about to send as a reply.
//
// The script is a list of steps separated by ';':
//
//	echo:TEXT      print TEXT and a newline
//	cat            copy standard input to standard output
//	env            print every AUU_ variable, one per line
//	environ:PATH   write the whole environment to a file, one per line
//	ask            POST to $ANTHROPIC_BASE_URL/v1/messages with the key it
//	               was given, and print the status and the answer
//	save:PATH      write $ANTHROPIC_BASE_URL to a file
//	askold:PATH    POST to the base URL saved in a file by an earlier
//	               invocation, and print the status; nothing when there
//	               is no file yet
//	append:PATH    append this program's role and the message id to a file
//	write:NAME     write a file of that name in the working directory
//	write:NAME=TEXT  the same, with the text to put in it
//	binary:NAME    write a file that is not text
//	commit:MSG     commit everything in the working directory
//	sleep:D        wait
//	say:TEXT       print TEXT to standard error
//	exit:N         stop with that status
func TestServeHelperProcess(t *testing.T) {
	role := "handler"
	if args := flag.Args(); len(args) > 0 {
		role = args[len(args)-1]
	}
	script := os.Getenv(map[string]string{
		"handler": handlerScript, "before": beforeScript, "after": afterScript,
	}[role])
	if script == "" {
		t.Skip("not a handler run")
	}
	for _, step := range strings.Split(script, ";") {
		verb, arg, _ := strings.Cut(step, ":")
		switch verb {
		case "echo":
			fmt.Println(arg)
		case "cat":
			io := make([]byte, 64*1024)
			n, _ := os.Stdin.Read(io)
			os.Stdout.Write(io[:n])
		case "env":
			for _, kv := range os.Environ() {
				if strings.HasPrefix(kv, "AUU_") && !strings.HasPrefix(kv, "AUU_TEST_") {
					fmt.Println(kv)
				}
			}
		case "environ":
			os.WriteFile(arg, []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o600)
		case "ask":
			req, err := http.NewRequest("POST", os.Getenv("ANTHROPIC_BASE_URL")+"/v1/messages", strings.NewReader(`{"hello":"there"}`))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(9)
			}
			// The placebo, as Claude Code sends it, and a bearer header a
			// handler might be talked into adding: both must go.
			req.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
			req.Header.Set("authorization", "Bearer placebo")
			req.Header.Set("anthropic-version", "2023-06-01")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(9)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("status %d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		case "save":
			os.WriteFile(arg, []byte(os.Getenv("ANTHROPIC_BASE_URL")+"\n"), 0o600)
		case "askold":
			saved, err := os.ReadFile(arg)
			if err != nil {
				fmt.Println("no saved url")
				continue
			}
			req, _ := http.NewRequest("POST", strings.TrimSpace(string(saved))+"/v1/messages", strings.NewReader(`{}`))
			req.Header.Set("x-api-key", filepath.Base(strings.TrimSpace(string(saved))))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(9)
			}
			resp.Body.Close()
			fmt.Printf("old status %d\n", resp.StatusCode)
		case "append":
			f, err := os.OpenFile(arg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(9)
			}
			fmt.Fprintf(f, "%s %s %s\n", role, os.Getenv("AUU_MESSAGE_ID"), os.Getenv("AUU_TURN"))
			f.Close()
		case "write":
			name, text, ok := strings.Cut(arg, "=")
			if !ok {
				text = "written by the handler"
			}
			os.WriteFile(name, []byte(text+"\n"), 0o600)
		case "binary":
			os.WriteFile(arg, []byte{0x00, 0x01, 0x02, 'a', 0x00, 0xff, '\n'}, 0o600)
		case "commit":
			for _, c := range [][]string{{"add", "-A"}, {"commit", "-m", arg}} {
				cmd := exec.Command("git", append([]string{
					"-c", "user.email=handler@example.invalid", "-c", "user.name=handler",
					"-c", "commit.gpgsign=false"}, c...)...)
				if out, err := cmd.CombinedOutput(); err != nil {
					fmt.Fprintf(os.Stderr, "git %v: %v\n%s", c, err, out)
					os.Exit(9)
				}
			}
		case "sleep":
			d, err := time.ParseDuration(arg)
			if err != nil {
				os.Exit(9)
			}
			time.Sleep(d)
		case "say":
			fmt.Fprintln(os.Stderr, arg)
		case "exit":
			var code int
			fmt.Sscanf(arg, "%d", &code)
			os.Exit(code)
		}
	}
	os.Exit(0)
}

// helperLine is the exec line that runs this binary as a handler or a hook.
// The path is quoted and everything after it is a plain argument, so there
// is no shell syntax in it.
func helperLine(t *testing.T, role string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Quoted by hand: %q would escape a Windows path's separators, and the
	// shell is not Go.
	return fmt.Sprintf(`"%s" -test.run=TestServeHelperProcess %s`, exe, role)
}

// repo is a git repository with one commit in it, which is what a channel
// is served from.
func repo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	// The line endings are the fixture's to decide. A machine with
	// core.autocrlf on — a Windows runner, by default — would check the
	// worktree out with CRLF, and a test about moving a worktree would
	// fail on the newlines instead.
	git(t, dir, "config", "core.autocrlf", "false")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("the project\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "README")
	git(t, dir, "commit", "-m", "the first commit")
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{
		"-c", "user.email=expert@example.invalid", "-c", "user.name=expert",
		"-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// expert is bob: a user with a git checkout, a channel, and a serve.json
// that answers it with this binary.
type expert struct {
	*user
	dir     string
	channel string
	row     *serveChannel
	config  *serveConfig
	path    string
}

// newExpert is alice, and bob serving one channel, with serve having run
// once already: mail that arrives after a first start is the ordinary case,
// and a test whose mail predates one says so by using newExpertCold.
func newExpert(t *testing.T, mode string) (alice *user, bob *expert) {
	t.Helper()
	alice, bob = newExpertCold(t, mode)
	bob.serve(t)
	return alice, bob
}

// newExpertCold is the same without that round, for the tests about what a
// first start does.
func newExpertCold(t *testing.T, mode string) (alice *user, bob *expert) {
	t.Helper()
	relayURL := startRelay(t)
	alice = newUser(t, "alice", relayURL)
	b := newUser(t, "bob", relayURL)
	alice.run("peers", "add", b.exportLine())
	b.run("peers", "add", alice.exportLine())
	b.run("channel", "create", "jostle")
	t.Setenv(handlerScript, "echo:the expert has spoken")
	bob = &expert{user: b, dir: repo(t), channel: "jostle"}
	bob.row = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: mode}
	bob.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": bob.row}}
	bob.path = filepath.Join(b.home, serveFile)
	bob.write(t)
	return alice, bob
}

// write puts the file in bob's home as it stands.
func (e *expert) write(t *testing.T) {
	t.Helper()
	data, err := json.MarshalIndent(e.config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// serve runs one round and fails the test if it did not go through.
func (e *expert) serve(t *testing.T, args ...string) string {
	t.Helper()
	return e.run(append([]string{"serve", "--once"}, args...)...)
}

// round runs one round and gives its report.
func (e *expert) round(t *testing.T, args ...string) roundJSON {
	t.Helper()
	var out roundJSON
	if err := json.Unmarshal([]byte(e.serve(t, append(args, "--json")...)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ledgerOf is what serve wrote down.
func (e *expert) ledgerOf(t *testing.T) *ledger {
	t.Helper()
	l, err := loadLedger(filepath.Join(e.home, "serve", ledgerFile))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// ask sends one message to bob's served channel and returns it.
func (u *user) ask(t *testing.T, channel, subject, text string) sentJSON {
	t.Helper()
	var sent sentJSON
	out := u.run("send", "--to", "bob", "--channel", channel, "--subject", subject, "--json", text)
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatal(err)
	}
	return sent
}

// replyTo is the reply alice received on a thread, read in full.
func (u *user) replyOn(t *testing.T, thread string) messageJSON {
	t.Helper()
	var in inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.Thread == thread && m.Type == "reply" {
			var full messageJSON
			if err := json.Unmarshal([]byte(u.run("read", m.ID, "--json")), &full); err != nil {
				t.Fatal(err)
			}
			return full
		}
	}
	t.Fatalf("no reply on thread %s: %+v", thread[:12], in.Messages)
	return messageJSON{}
}

// An ask on a served channel is answered with what the handler printed, on
// the thread it came in on, and written down as answered.
func TestServeAnswersAnAsk(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	sent := alice.ask(t, "jostle", "where is the parser?", "I cannot find it.")

	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID ||
		report.Answered[0].Channel != "jostle" || report.Answered[0].Thread != sent.Thread {
		t.Fatalf("the round: %+v", report)
	}
	if len(report.Failed) != 0 {
		t.Fatalf("failures: %+v", report.Failed)
	}

	reply := alice.replyOn(t, sent.Thread)
	if reply.Text != "the expert has spoken" {
		t.Fatalf("the reply says %q", reply.Text)
	}
	if reply.InReplyTo != sent.ID || reply.Subject != "where is the parser?" {
		t.Fatalf("the reply: %+v", reply)
	}

	// Written down, and the ask marked read, since the reply is the
	// acknowledgement.
	entry := bob.ledgerOf(t).Messages[sent.ID]
	if entry == nil || entry.Handled.IsZero() || entry.Reply == "" ||
		entry.Thread != sent.Thread || entry.Channel != "jostle" {
		t.Fatalf("the ledger entry: %+v", entry)
	}
	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.ID == sent.ID && !m.Read {
			t.Fatal("the ask is still unread after it was answered")
		}
	}
	// And a second round has nothing to do: the ledger, not the mark, is
	// what says so.
	if again := bob.round(t); len(again.Answered) != 0 || len(again.Failed) != 0 {
		t.Fatalf("the second round: %+v", again)
	}
}

// The handler is given the message on standard input and its facts in the
// environment, in the worktree, which is also where it is run.
func TestServeHandsTheHandlerTheMessage(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	t.Setenv(handlerScript, "cat;echo:;echo:--;env")
	sent := alice.ask(t, "jostle", "the subject", "the question itself")
	bob.serve(t)

	reply := alice.replyOn(t, sent.Thread)
	text, env, _ := strings.Cut(reply.Text, "\n--\n")
	if text != "the question itself" {
		t.Fatalf("standard input was %q", text)
	}
	vars := map[string]string{}
	for _, line := range strings.Split(env, "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			vars[name] = value
		}
	}
	for name, want := range map[string]string{
		"AUU_MESSAGE_ID":  sent.ID,
		"AUU_THREAD_ID":   sent.Thread,
		"AUU_IN_REPLY_TO": "",
		"AUU_TYPE":        "ask",
		"AUU_SUBJECT":     "the subject",
		"AUU_FROM_NAME":   "alice",
		"AUU_CHANNEL":     "jostle",
		"AUU_TURN":        "1",
		"AUU_MODE":        modeSideCopy,
		"AUU_ATTACHMENTS": "",
	} {
		if vars[name] != want {
			t.Errorf("%s is %q, want %q", name, vars[name], want)
		}
	}
	if vars["AUU_FROM"] != alice.exportFingerprint() {
		t.Errorf("AUU_FROM is %q", vars["AUU_FROM"])
	}
	// The relay by name, which is what auu itself reads the variable as.
	if vars["AUU_RELAY"] == "" {
		t.Error("AUU_RELAY is empty")
	}
	// The worktree is the working directory, is not the checkout, and
	// stands on a commit that is in it.
	if vars["AUU_WORKTREE"] == "" || vars["AUU_WORKTREE"] == bob.dir {
		t.Errorf("AUU_WORKTREE is %q, the checkout is %q", vars["AUU_WORKTREE"], bob.dir)
	}
	if vars["AUU_BASE"] != git(t, bob.dir, "rev-parse", "HEAD") {
		t.Errorf("AUU_BASE is %q", vars["AUU_BASE"])
	}
	if _, err := os.Stat(filepath.Join(vars["AUU_WORKTREE"], "README")); err != nil {
		t.Errorf("the worktree has no README: %v", err)
	}
	for _, name := range []string{"AUU_THREAD_DIR", "AUU_CHANNEL_DIR"} {
		if info, err := os.Stat(vars[name]); err != nil || !info.IsDir() {
			t.Errorf("%s is %q, which is not a directory (%v)", name, vars[name], err)
		}
	}
	if vars["AUU_THREAD_DIR"] == vars["AUU_CHANNEL_DIR"] {
		t.Error("the thread's directory and the channel's are the same")
	}
}

// What serve will not answer: a note, a reply to somebody else's message, a
// message on a channel it does not serve, a stranger's mail in quarantine,
// and a thread that has had its turns.
func TestServeLeavesWhatItMayNotAnswer(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	note := alice.run("send", "--to", "bob", "--channel", "jostle", "--type", "note",
		"--subject", "for information", "--json", "no answer wanted")
	var sentNote sentJSON
	if err := json.Unmarshal([]byte(note), &sentNote); err != nil {
		t.Fatal(err)
	}
	// An ask serve does answer, to have something to compare against.
	other := alice.ask(t, "jostle", "for the expert", "the first")
	// An ask on a channel that is not served.
	bob.run("channel", "create", "elsewhere")
	unserved := alice.ask(t, "elsewhere", "another channel", "not yours")

	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != other.ID {
		t.Fatalf("the round answered %+v", report.Answered)
	}
	led := bob.ledgerOf(t)
	if led.Messages[sentNote.ID] != nil {
		t.Error("a note was written down as work")
	}
	if led.Messages[unserved.ID] != nil {
		t.Error("a message on an unserved channel was written down")
	}

	// bob writes to alice by hand, and alice answers him on the served
	// channel. It is a reply to bob's own message rather than to anything
	// serve sent, so serve leaves the conversation to the two of them.
	var byHand sentJSON
	if err := json.Unmarshal([]byte(bob.run("send", "--to", "alice", "--subject", "by hand", "--json", "mine, not the expert's")), &byHand); err != nil {
		t.Fatal(err)
	}
	alice.run("inbox")
	alice.run("reply", byHand.ID[:12], "--channel", "jostle", "answering you, not it")
	again := bob.round(t)
	if len(again.Answered) != 0 {
		t.Fatalf("a reply to a message serve did not send was answered: %+v", again.Answered)
	}
}

// A follow-up is a reply to serve's own reply, and it is the thread's next
// turn. max_turns is where a conversation stops.
func TestServeAnswersAFollowUpUntilTheTurnsRunOut(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.MaxTurns = 2
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "turns")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")

	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)

	// Note the follow-up carries no channel: a reply goes to the
	// recipient's default, whatever the ask was addressed to, and the
	// channel that answered the thread is what answers the rest of it.
	alice.run("reply", first.ID[:12], "and one more thing")
	bob.serve(t)
	// Two turns are all this channel allows, so a third message is left.
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	var second string
	for _, m := range in.Messages {
		if m.Thread == sent.Thread && m.Type == "reply" && m.ID != first.ID {
			second = m.ID
		}
	}
	if second == "" {
		t.Fatalf("the follow-up was not answered: %+v", in.Messages)
	}
	alice.run("reply", second[:12], "and another")
	report := bob.round(t)
	if len(report.Answered) != 0 {
		t.Fatalf("a thread past its turns was answered: %+v", report.Answered)
	}
	lines := strings.Count(readFile(t, marker), "\n")
	if lines != 2 {
		t.Fatalf("the handler ran %d times, want 2\n%s", lines, readFile(t, marker))
	}
	if !strings.Contains(readFile(t, marker), " 2\n") {
		t.Fatalf("no turn 2 in:\n%s", readFile(t, marker))
	}
}

// The turns are counted at the run and not only when the round is drawn up
// (G36, R52): two asks on one thread with one turn left, both pending when
// the round began, are one answer, and the other is left as pending leaves
// one past its turns: not settled, not failed, not reported, and unread.
func TestServeCountsTheTurnsAtEachRunOfARound(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.MaxTurns = 1
	bob.write(t)
	first := alice.ask(t, "jostle", "one thread", "first question")
	second := alice.askOn(t, "jostle", first.Thread, "one thread", "second question")
	report := bob.round(t)
	if len(report.Answered) != 1 || len(report.Failed) != 0 || len(report.Skipped) != 0 {
		t.Fatalf("one round on a thread of one turn: %+v; want one answer and nothing else", report)
	}
	led := bob.ledgerOf(t)
	if n := led.answered(first.Thread); n != 1 {
		t.Fatalf("the ledger counts %d turns on a thread of one", n)
	}
	if e, ok := led.Messages[second.ID]; ok {
		t.Fatalf("the message past its turn has a ledger entry: %+v", e)
	}
	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range in.Messages {
		if m.ID == second.ID {
			found = true
			if m.Read {
				t.Fatal("the message past its turn was marked read")
			}
		}
	}
	if !found {
		t.Fatal("the message past its turn is not in the inbox")
	}
}

// A handler that fails leaves the message unread and unanswered, counts the
// attempt, and gives up when the count runs out.
func TestServeCountsFailuresAndGivesUp(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Retries = 2
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:the handler could not;exit:3")
	sent := alice.ask(t, "jostle", "a question", "the first")

	for attempt := 1; attempt <= 2; attempt++ {
		out, err := bob.tryRun("serve", "--once", "--json")
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage {
			t.Fatalf("attempt %d ended %v\n%s", attempt, err, out)
		}
		var report roundJSON
		json.Unmarshal([]byte(out), &report)
		if len(report.Failed) != 1 || report.Failed[0].ID != sent.ID {
			t.Fatalf("attempt %d: %+v", attempt, report)
		}
		entry := bob.ledgerOf(t).Messages[sent.ID]
		if entry.Failures != attempt || !entry.Handled.IsZero() {
			t.Fatalf("attempt %d wrote %+v", attempt, entry)
		}
		if gaveUp := attempt == 2; entry.GaveUp != gaveUp {
			t.Fatalf("attempt %d: gave_up is %v", attempt, entry.GaveUp)
		}
	}
	// Given up: the handler is not run again.
	if report := bob.round(t); len(report.Failed) != 0 || len(report.Answered) != 0 {
		t.Fatalf("a message given up on was tried again: %+v", report)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 2 {
		t.Fatalf("the handler ran %d times, want 2", runs)
	}
	// And it is still unread, so the owner's inbox shows it for what it is.
	var in inboxJSON
	json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in)
	for _, m := range in.Messages {
		if m.ID == sent.ID && m.Read {
			t.Fatal("a message nobody answered was marked read")
		}
	}
}

// A handler with nothing to say is an answer: the message is settled and no
// reply goes out.
func TestServeSendsNothingWhenTheHandlerSaysNothing(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "say:nothing to add")
	sent := alice.ask(t, "jostle", "a question", "the first")
	report := bob.round(t)
	if len(report.Answered) != 1 {
		t.Fatalf("the round: %+v", report)
	}
	entry := bob.ledgerOf(t).Messages[sent.ID]
	if entry.Handled.IsZero() || entry.Reply != "" {
		t.Fatalf("the entry: %+v", entry)
	}
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	for _, m := range in.Messages {
		if m.Type == "reply" {
			t.Fatalf("a reply went out: %+v", m)
		}
	}
}

// The hooks run around the handler, are not shown the message, and can
// refuse the answer.
func TestServeRunsTheHooksAroundTheHandler(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	order := filepath.Join(t.TempDir(), "order")
	bob.row.Before = helperLine(t, "before")
	bob.row.After = helperLine(t, "after")
	bob.write(t)
	t.Setenv(beforeScript, "append:"+order+";env;say:before ran")
	t.Setenv(handlerScript, "append:"+order+";echo:answered")
	t.Setenv(afterScript, "append:"+order+";env")

	sent := alice.ask(t, "jostle", "a question", "the first")
	stderr := captureStderr(t, func() { bob.serve(t) })
	lines := strings.Split(strings.TrimSpace(readFile(t, order)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "before ") ||
		!strings.HasPrefix(lines[1], "handler ") || !strings.HasPrefix(lines[2], "after ") {
		t.Fatalf("the order was:\n%s", readFile(t, order))
	}
	// A hook's output is never a reply, and both its streams are printed
	// with the thread's short id in front.
	reply := alice.replyOn(t, sent.Thread)
	if reply.Text != "answered" {
		t.Fatalf("the reply carries a hook's output:\n%s", reply.Text)
	}
	prefix := shortID(sent.Thread) + ": "
	if !strings.Contains(stderr, prefix+"before ran") {
		t.Fatalf("the hook's output was not printed prefixed:\n%s", stderr)
	}
	// The before hook is not shown the message.
	if strings.Contains(stderr, "AUU_SUBJECT") || strings.Contains(stderr, "AUU_ATTACHMENTS") {
		t.Fatalf("a hook saw the message:\n%s", stderr)
	}
	if !strings.Contains(stderr, prefix+"AUU_CHANNEL=jostle") {
		t.Fatalf("a hook was not told the channel:\n%s", stderr)
	}
}

// The after hook is told how the handler ended, in every way it can end.
func TestServeTellsTheAfterHookTheStatus(t *testing.T) {
	for _, row := range []struct {
		name, handler, timeout, want string
	}{
		// The two that run to the end are given a timeout no process
		// start can miss: the hooks run under the channel's timeout too,
		// and under the race detector this binary takes its time.
		{"answered", "echo:done", "10s", "0"},
		{"failed", "exit:4", "10s", "4"},
		{"timeout", "sleep:30s", "2s", "timeout"},
	} {
		t.Run(row.name, func(t *testing.T) {
			alice, bob := newExpert(t, modeReadOnly)
			bob.row.After = helperLine(t, "after")
			bob.row.Timeout = row.timeout
			bob.write(t)
			t.Setenv(handlerScript, row.handler)
			t.Setenv(afterScript, "env")
			alice.ask(t, "jostle", "a question", "the first")
			stderr := captureStderr(t, func() { bob.tryRun("serve", "--once") })
			if !strings.Contains(stderr, "AUU_STATUS="+row.want) {
				t.Fatalf("the after hook was told:\n%s", stderr)
			}
		})
	}
}

// A before hook that fails stops the handler, tells the after hook so, and
// makes the message a failure.
func TestServeStopsWhenTheBeforeHookFails(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "ran")
	bob.row.Before = helperLine(t, "before")
	bob.row.After = helperLine(t, "after")
	bob.write(t)
	t.Setenv(beforeScript, "say:the base would not come;exit:1")
	t.Setenv(handlerScript, "append:"+marker+";echo:should not run")
	t.Setenv(afterScript, "env")

	sent := alice.ask(t, "jostle", "a question", "the first")
	var stderr string
	out, err := "", error(nil)
	stderr = captureStderr(t, func() { out, err = bob.tryRun("serve", "--once") })
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage {
		t.Fatalf("the round ended %v\n%s", err, out)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the handler ran after the before hook failed")
	}
	if !strings.Contains(stderr, "AUU_STATUS="+statusBefore) {
		t.Fatalf("the after hook was not told the handler never ran:\n%s", stderr)
	}
	if !strings.Contains(stderr, "was not answered: before exited 1: the base would not come") {
		t.Fatalf("the failure was said as:\n%s", stderr)
	}
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry.Failures != 1 || !entry.Handled.IsZero() {
		t.Fatalf("the entry: %+v", entry)
	}
}

// An after hook that fails is a gate: the handler's answer does not go out,
// and the message is tried again.
func TestServeWithholdsTheReplyWhenTheAfterHookFails(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.After = helperLine(t, "after")
	bob.write(t)
	t.Setenv(handlerScript, "echo:the tests are red")
	t.Setenv(afterScript, "say:the tests did not pass;exit:1")

	sent := alice.ask(t, "jostle", "a question", "the first")
	stderr := captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if !strings.Contains(stderr, "after exited 1: the tests did not pass") {
		t.Fatalf("the failure was said as:\n%s", stderr)
	}
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	for _, m := range in.Messages {
		if m.Type == "reply" {
			t.Fatal("a reply went out past a red after hook")
		}
	}
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry.Failures != 1 {
		t.Fatalf("the entry: %+v", entry)
	}
}

// A reply the handler wrote and serve could not send is kept, and sent on
// the next round without running the handler again. The send fails here for
// the reason easiest to arrange exactly — the recipient is no longer a peer
// — since what is under test is the reply that was kept.
func TestServeKeepsAReplyItCouldNotSend(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:an answer worth keeping")

	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times", runs)
	}
	kept := filepath.Join(bob.home, "serve", "threads", sent.Thread, "reply-"+sent.ID+".txt")
	if text := strings.TrimSpace(readFile(t, kept)); text != "an answer worth keeping" {
		t.Fatalf("the kept reply is %q", text)
	}
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry.Failures != 1 || !entry.Handled.IsZero() {
		t.Fatalf("the entry: %+v", entry)
	}

	// Put right, the next round sends what is on disk and runs nothing.
	bob.run("peers", "add", alice.exportLine())
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the round: %+v", report)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times in all, want 1", runs)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "an answer worth keeping" {
		t.Fatalf("the reply is %q", reply.Text)
	}
}

// Read-only: one worktree for the channel, shared by every thread, moved to
// the checkout's HEAD when a new thread starts. Untracked scratch survives
// the move; a tracked edit does not.
func TestServeSharesOneWorktreeInReadOnly(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "env;write:scratch.txt")
	first := alice.ask(t, "jostle", "one", "the first thread")
	bob.serve(t)
	firstVars := envOf(t, alice.replyOn(t, first.Thread).Text)

	// The project moves on, and the worktree keeps a tracked edit that a
	// read-only answer was never going to return.
	if err := os.WriteFile(filepath.Join(firstVars["AUU_WORKTREE"], "README"), []byte("edited by the handler\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bob.dir, "NEWS"), []byte("a second commit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, bob.dir, "add", "NEWS")
	git(t, bob.dir, "commit", "-m", "the second commit")
	head := git(t, bob.dir, "rev-parse", "HEAD")

	second := alice.ask(t, "jostle", "two", "the second thread")
	bob.serve(t)
	secondVars := envOf(t, alice.replyOn(t, second.Thread).Text)

	if secondVars["AUU_WORKTREE"] != firstVars["AUU_WORKTREE"] {
		t.Fatalf("two threads got two worktrees: %q and %q", firstVars["AUU_WORKTREE"], secondVars["AUU_WORKTREE"])
	}
	if secondVars["AUU_CHANNEL_DIR"] != firstVars["AUU_CHANNEL_DIR"] {
		t.Fatalf("the channel's directory moved: %q and %q", firstVars["AUU_CHANNEL_DIR"], secondVars["AUU_CHANNEL_DIR"])
	}
	if secondVars["AUU_THREAD_DIR"] == firstVars["AUU_THREAD_DIR"] {
		t.Fatal("two threads shared one thread directory")
	}
	if secondVars["AUU_BASE"] != head || firstVars["AUU_BASE"] == head {
		t.Fatalf("the base is %q, the checkout is at %q", secondVars["AUU_BASE"], head)
	}
	tree := secondVars["AUU_WORKTREE"]
	if data := readFile(t, filepath.Join(tree, "README")); data != "the project\n" {
		t.Fatalf("a tracked edit survived the move: %q", data)
	}
	if _, err := os.Stat(filepath.Join(tree, "scratch.txt")); err != nil {
		t.Fatalf("untracked scratch did not survive the move: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree, "NEWS")); err != nil {
		t.Fatalf("the worktree did not follow the checkout: %v", err)
	}
}

// Side copy: a worktree per thread, made once and reused, standing on the
// commit it was made from however the checkout moves on.
func TestServeGivesEveryThreadItsOwnWorktreeInSideCopy(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	t.Setenv(handlerScript, "env")
	first := alice.ask(t, "jostle", "one", "the first thread")
	bob.serve(t)
	firstVars := envOf(t, alice.replyOn(t, first.Thread).Text)
	base := git(t, bob.dir, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(bob.dir, "NEWS"), []byte("a second commit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, bob.dir, "add", "NEWS")
	git(t, bob.dir, "commit", "-m", "the second commit")

	second := alice.ask(t, "jostle", "two", "the second thread")
	bob.serve(t)
	secondVars := envOf(t, alice.replyOn(t, second.Thread).Text)
	if secondVars["AUU_WORKTREE"] == firstVars["AUU_WORKTREE"] {
		t.Fatal("two threads of a side copy shared one worktree")
	}
	if firstVars["AUU_BASE"] != base {
		t.Fatalf("the first thread's base is %q, want %q", firstVars["AUU_BASE"], base)
	}

	// A follow-up on the first thread reuses that thread's worktree, at the
	// base it was made from, and is the thread's second turn.
	reply := alice.replyOn(t, first.Thread)
	alice.run("reply", reply.ID[:12], "and one more thing")
	bob.serve(t)
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	var followUp messageJSON
	for _, m := range in.Messages {
		if m.Thread == first.Thread && m.Type == "reply" && m.ID != reply.ID {
			if err := json.Unmarshal([]byte(alice.run("read", m.ID, "--json")), &followUp); err != nil {
				t.Fatal(err)
			}
		}
	}
	vars := envOf(t, followUp.Text)
	if vars["AUU_WORKTREE"] != firstVars["AUU_WORKTREE"] || vars["AUU_BASE"] != base {
		t.Fatalf("the follow-up ran in %q at %q", vars["AUU_WORKTREE"], vars["AUU_BASE"])
	}
	if vars["AUU_TURN"] != "2" {
		t.Fatalf("the follow-up is turn %q", vars["AUU_TURN"])
	}
	if vars["AUU_IN_REPLY_TO"] != reply.ID {
		t.Fatalf("AUU_IN_REPLY_TO is %q", vars["AUU_IN_REPLY_TO"])
	}
}

// A first start leaves the mail that is already there, says how many, and
// writes it all down so that a channel added later is not a year of
// answers either. --backlog answers it instead, and only then.
func TestServeLeavesTheMailOfAFirstStart(t *testing.T) {
	alice, bob := newExpertCold(t, modeReadOnly)
	sent := alice.ask(t, "jostle", "a question", "the first")
	// And a note, which was never work: it is written down so that it is
	// not answered later, and not reported as something left undone.
	var note sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--channel", "jostle",
		"--type", "note", "--subject", "for information", "--json", "no answer wanted")), &note); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")

	var report roundJSON
	stderr := captureStderr(t, func() {
		if err := json.Unmarshal([]byte(bob.serve(t, "--json")), &report); err != nil {
			t.Fatal(err)
		}
	})
	if len(report.Answered) != 0 || len(report.Skipped) != 1 || report.Skipped[0].ID != sent.ID {
		t.Fatalf("the first round: %+v", report)
	}
	if !strings.Contains(stderr, "1 message already in the inbox, left alone") ||
		!strings.Contains(stderr, "--backlog") {
		t.Fatalf("the first start said:\n%s", stderr)
	}
	led := bob.ledgerOf(t)
	if !led.Messages[sent.ID].Skipped {
		t.Fatal("the message was not written down as skipped")
	}
	if e := led.Messages[note.ID]; e == nil || !e.Skipped {
		t.Fatalf("the note was not written down: %+v", e)
	}
	// And it stays left alone.
	if again := bob.round(t); len(again.Answered) != 0 {
		t.Fatalf("skipped mail was answered later: %+v", again)
	}
	// --backlog now says there is no backlog: this home has a ledger.
	out, err := bob.tryRun("serve", "--once", "--backlog")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage ||
		!strings.Contains(err.Error(), "there is no backlog to answer") {
		t.Fatalf("--backlog with a ledger: %v\n%s", err, out)
	}
}

// --backlog on a first start answers what is there.
func TestServeAnswersTheBacklogWhenAsked(t *testing.T) {
	alice, bob := newExpertCold(t, modeReadOnly)
	sent := alice.ask(t, "jostle", "a question", "the first")
	report := bob.round(t, "--backlog")
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the round: %+v", report)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "the expert has spoken" {
		t.Fatalf("the reply: %+v", reply)
	}
}

// Messages are answered one at a time, oldest first, whatever channel they
// are on.
func TestServeAnswersOneAtATimeOldestFirst(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.run("channel", "create", "second")
	bob.config.Channels["second"] = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: modeReadOnly}
	bob.write(t)
	order := filepath.Join(t.TempDir(), "order")
	t.Setenv(handlerScript, "append:"+order+";echo:answered")

	first := alice.ask(t, "jostle", "one", "the first")
	second := alice.ask(t, "second", "two", "the second")
	third := alice.ask(t, "jostle", "three", "the third")
	report := bob.round(t)
	if len(report.Answered) != 3 {
		t.Fatalf("the round: %+v", report)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, order)), "\n") {
		fields := strings.Fields(line)
		ids = append(ids, fields[1])
	}
	want := []string{first.ID, second.ID, third.ID}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("the handler ran in the order %v, want %v", ids, want)
		}
	}
}

// One serve per home: the second says who is holding the lock.
func TestServeRefusesASecondServeInOneHome(t *testing.T) {
	_, bob := newExpert(t, modeReadOnly)
	root := filepath.Join(bob.home, "serve")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	held, err := takeServeLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	out, err := bob.tryRun("serve", "--once")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport {
		t.Fatalf("a second serve ended %v\n%s", err, out)
	}
	if !strings.Contains(err.Error(), "another auu serve is running in this home") {
		t.Fatalf("the refusal is %q", err.Error())
	}
	// The pid comes from the lock file, which on Windows nobody can open
	// while it is held: the lock is a handle with no sharing allowed, so
	// neither the holder's write nor this reader's read gets through. The
	// sentence is the same and says one less thing.
	if runtime.GOOS != "windows" && !strings.Contains(err.Error(), fmt.Sprintf("pid %d", os.Getpid())) {
		t.Fatalf("the refusal does not name the holder: %q", err.Error())
	}
}

// Every refusal the file can earn names the file, the channel and the
// field, since somebody is looking at the file when they read it.
func TestServeCheckRefusesABadFile(t *testing.T) {
	_, bob := newExpert(t, modeReadOnly)
	good := bob.dir
	for _, row := range []struct {
		name, file, want string
	}{
		{"no dir", `{"v":1,"channels":{"jostle":{"exec":"x"}}}`, `channel "jostle": dir is required`},
		{"no exec", `{"v":1,"channels":{"jostle":{"dir":"` + jsonPath(good) + `"}}}`, `channel "jostle": exec is required`},
		{"not a repository", `{"v":1,"channels":{"jostle":{"dir":"` + jsonPath(os.TempDir()) + `","exec":"x"}}}`, "is not a git repository"},
		{"unknown mode", `{"v":1,"channels":{"jostle":{"dir":"` + jsonPath(good) + `","exec":"x","mode":"read-write"}}}`, `mode "read-write" is neither`},
		{"bad duration", `{"v":1,"channels":{"jostle":{"dir":"` + jsonPath(good) + `","exec":"x","timeout":"soon"}}}`, `timeout "soon" is not a length of time`},
		{"unknown field", `{"v":1,"channels":{"jostle":{"dir":"` + jsonPath(good) + `","exec":"x","retires":3}}}`, "retires"},
		{"wrong version", `{"v":2,"channels":{}}`, "understands version 1"},
		{"no channels", `{"v":1,"channels":{}}`, "serves nothing"},
		{"bad name", `{"v":1,"channels":{"Jostle/1":{"dir":"` + jsonPath(good) + `","exec":"x"}}}`, `channel "Jostle/1"`},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "serve.json")
			if err := os.WriteFile(path, []byte(row.file), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := bob.tryRun("serve", "check", "--config", path)
			var exit *exitError
			if !errors.As(err, &exit) || exit.code != exitUsage {
				t.Fatalf("check ended %v\n%s", err, out)
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("the refusal is %q, want %q in it", err.Error(), row.want)
			}
		})
	}
	// A file that is not there at all.
	out, err := bob.tryRun("serve", "check", "--config", filepath.Join(t.TempDir(), "nothing.json"))
	if err == nil || !strings.Contains(err.Error(), "an expert host is one file") {
		t.Fatalf("a missing file: %v\n%s", err, out)
	}
}

// check fills in what the file left out and says what it would serve.
func TestServeCheckSaysWhatItWouldServe(t *testing.T) {
	_, bob := newExpert(t, modeSideCopy)
	out := bob.run("serve", "check")
	for _, want := range []string{
		"jostle: side-copy in " + bob.dir,
		"exec:    " + bob.row.Exec,
		"limits:  timeout 30m0s, max_turns 50, retries 3, thread_ttl 168h0m0s",
		"is good for 1 channel",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("check printed:\n%s\nwant %q", out, want)
		}
	}
}

// Mail on a served channel stays on the relay unless its owner says
// otherwise, and a mailbox that fills refuses the askers. Both commands say
// so, by name.
func TestServeWarnsAboutMailKeptOnTheRelay(t *testing.T) {
	_, bob := newExpert(t, modeReadOnly)
	stderr := captureStderr(t, func() { bob.run("serve", "check") })
	if !strings.Contains(stderr, `"jostle"`) || !strings.Contains(stderr, "channel keep NAME off") {
		t.Fatalf("check said:\n%s", stderr)
	}
	stderr = captureStderr(t, func() { bob.serve(t) })
	if !strings.Contains(stderr, `"jostle"`) {
		t.Fatalf("serve said:\n%s", stderr)
	}
	// Turned off, there is nothing to warn about.
	bob.run("channel", "keep", "jostle", "off")
	stderr = captureStderr(t, func() { bob.run("serve", "check") })
	if strings.Contains(stderr, "channel keep NAME off") {
		t.Fatalf("check warned about a channel that keeps nothing:\n%s", stderr)
	}
}

// The exec line goes through the platform shell, which on Unix means a
// pipeline in it is a pipeline. Unix only: cmd /c is another language, and
// the project is not tested on Windows.
func TestServeRunsTheExecLineThroughTheShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell here is cmd /c, whose syntax is its own")
	}
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Exec = "printf 'one\\ntwo\\n' | tr a-z A-Z"
	bob.write(t)
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "ONE\nTWO" {
		t.Fatalf("the reply is %q", reply.Text)
	}
}

// A handler past its timeout is killed with everything it started, so that
// a Claude Code session does not outlive the serve that called it. Unix
// only: the group is a Unix idea, and Windows is best effort.
func TestServeKillsTheHandlersChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no process group to kill")
	}
	alice, bob := newExpert(t, modeReadOnly)
	pidFile := filepath.Join(t.TempDir(), "pid")
	bob.row.Exec = fmt.Sprintf("sleep 60 & echo $! > %s; sleep 60", pidFile)
	bob.row.Timeout = "2s"
	bob.write(t)
	alice.ask(t, "jostle", "a question", "the first")

	began := time.Now()
	stderr := captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if took := time.Since(began); took > 20*time.Second {
		t.Fatalf("the round took %s: the kill did not end the wait", took)
	}
	if !strings.Contains(stderr, "was killed at the timeout") {
		t.Fatalf("the failure was said as:\n%s", stderr)
	}
	pid := 0
	fmt.Sscanf(strings.TrimSpace(readFile(t, pidFile)), "%d", &pid)
	if pid == 0 {
		t.Fatal("the handler never started its child")
	}
	// The child is gone, or on its way: signal 0 says whether it is there.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscallKill(pid); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the handler's child (pid %d) outlived the kill", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// syscallKill asks whether a process is still there, which is what signal
// zero is for. An error is a process that is gone.
func syscallKill(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.Signal(0))
}

// envOf reads the environment a handler printed.
func envOf(t *testing.T, text string) map[string]string {
	t.Helper()
	vars := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			vars[name] = value
		}
	}
	return vars
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

// jsonPath is a path as it appears inside a JSON string, which on Windows
// means its separators are escaped.
func jsonPath(path string) string {
	data, _ := json.Marshal(path)
	return strings.Trim(string(data), `"`)
}

// The long run, as a second process. It has to be one: the signal that
// stops it is the thing under test, and a test cannot send itself one
// without racing the handler that is about to be taken down. Unix only:
// Windows delivers no SIGTERM.
type service struct {
	cmd    *exec.Cmd
	out    *os.File
	path   string
	t      *testing.T
	waited bool
	err    error
}

// start runs 'auu serve' against a home as a real process, the way a unit
// file would, with its output on a file the test can read as it goes.
func (e *expert) start(t *testing.T, env []string, args ...string) *service {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "serve.log")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"serve"}, args...)...)
	cmd.Env = append([]string{
		"AUU_TEST_HELPER=1",
		parentEnv + "=" + strconv.Itoa(os.Getpid()),
		"AUU_HOME=" + e.home,
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}, env...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	svc := &service{cmd: cmd, out: out, path: path, t: t}
	t.Cleanup(func() {
		if !svc.waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
		out.Close()
	})
	return svc
}

// log is everything the service has printed so far.
func (s *service) log() string {
	s.t.Helper()
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.t.Fatal(err)
	}
	return string(data)
}

// waitFor polls until the service's output holds a string, or gives up.
func (s *service) waitFor(what string) {
	s.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if strings.Contains(s.log(), what) {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("the service never said %q:\n%s", what, s.log())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stop sends the signal a service manager would and waits for the exit.
func (s *service) stop() error {
	s.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		s.t.Fatal(err)
	}
	s.waited = true
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		s.cmd.Process.Kill()
		s.t.Fatalf("the service did not stop when it was told:\n%s", s.log())
		return nil
	}
}

// Running long: the service answers what arrives while it is waiting, says
// nothing for a wake-up with nothing in it, and stops when it is told,
// leaving its lock free and its ledger whole.
func TestServeRunsUntilItIsStopped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM to send")
	}
	alice, bob := newExpert(t, modeReadOnly)
	// A shell line rather than this binary: the service is started with
	// the switch that makes this binary answer as auu, the handler would
	// inherit it, and a test binary told to be auu cannot also be a
	// handler. These two tests are Unix-only anyway.
	bob.row.Exec = "printf 'answered while running\n'"
	bob.write(t)
	svc := bob.start(t, nil, "--json")

	sent := alice.ask(t, "jostle", "a question", "the first")
	reply := alice.awaitReply(t, svc, sent.Thread, "")

	// A follow-up, which arrives on bob's default channel rather than on
	// jostle: a hold narrowed to the served channels would sleep through
	// it for ever.
	alice.run("reply", reply.ID[:12], "and one more thing")
	alice.awaitReply(t, svc, sent.Thread, reply.ID)

	// And a message that is not work at all: the service wakes for it,
	// since the hold has no filter, fetches it, and has nothing to say.
	note := alice.run("send", "--to", "bob", "--channel", "jostle", "--type", "note",
		"--subject", "for information", "--json", "no answer wanted")
	var sentNote sentJSON
	if err := json.Unmarshal([]byte(note), &sentNote); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, func() bool {
		var in inboxJSON
		json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in)
		for _, m := range in.Messages {
			if m.ID == sentNote.ID {
				return true
			}
		}
		return false
	}, func() string { return "the service never fetched the note:\n" + svc.log() })

	if err := svc.stop(); err != nil {
		t.Fatalf("the service exited %v:\n%s", err, svc.log())
	}

	// One object for each round that answered, and nothing for the round
	// that found only the note: a quiet expert writes a quiet log.
	var rounds []roundJSON
	for _, line := range strings.Split(strings.TrimSpace(svc.log()), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var round roundJSON
		if err := json.Unmarshal([]byte(line), &round); err != nil {
			t.Fatalf("a line of the log is not one object: %q\n%s", line, svc.log())
		}
		rounds = append(rounds, round)
	}
	if len(rounds) != 2 {
		t.Fatalf("the log has %d rounds in it, want 2:\n%s", len(rounds), svc.log())
	}
	if len(rounds[0].Answered) != 1 || rounds[0].Answered[0].ID != sent.ID {
		t.Fatalf("the first round: %+v\n%s", rounds[0], svc.log())
	}
	if len(rounds[1].Answered) != 1 || rounds[1].Answered[0].Thread != sent.Thread {
		t.Fatalf("the second round: %+v\n%s", rounds[1], svc.log())
	}

	// The lock went with the process, and the ledger is readable.
	root := filepath.Join(bob.home, "serve")
	lock, err := takeServeLock(root)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	lock.Release()
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry == nil || entry.Handled.IsZero() {
		t.Fatalf("the ledger after the stop: %+v", entry)
	}
}

// A relay that cannot be reached at all does not end the service: it says
// so once and waits for the relay to come back.
func TestServeWaitsForARelayToComeBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM to send")
	}
	srv, _ := startRelayServer(t, relay.Config{})
	alice := newUser(t, "alice", srv.URL)
	b := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", b.exportLine())
	b.run("peers", "add", alice.exportLine())
	b.run("channel", "create", "jostle")
	bob := &expert{user: b, dir: repo(t), channel: "jostle"}
	bob.row = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: modeReadOnly}
	bob.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": bob.row}}
	bob.path = filepath.Join(b.home, serveFile)
	bob.row.Exec = "printf 'answered\n'" // a shell line, as above
	bob.write(t)
	bob.serve(t) // the ledger, while the relay is still there

	srv.Close()
	svc := bob.start(t, nil)
	svc.waitFor("no relay could be reached")
	if err := svc.stop(); err != nil {
		t.Fatalf("the service exited %v:\n%s", err, svc.log())
	}
	if said := strings.Count(svc.log(), "no relay could be reached"); said != 1 {
		t.Fatalf("it said so %d times:\n%s", said, svc.log())
	}
}

// One relay down and another up is not the end of a round: the mail on the
// one that answered is still mail.
func TestServeCarriesOnWhenOneRelayIsDown(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	dead, _ := startRelayServer(t, relay.Config{})
	bob.run("relay", "add", dead.URL, "--name", "spare")
	bob.run("register", "--relay", "spare")
	dead.Close()

	sent := alice.ask(t, "jostle", "a question", "the first")
	var report roundJSON
	stderr := captureStderr(t, func() {
		if err := json.Unmarshal([]byte(bob.serve(t, "--json")), &report); err != nil {
			t.Fatal(err)
		}
	})
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the round: %+v\n%s", report, stderr)
	}
	if !strings.Contains(stderr, "spare could not be reached") {
		t.Fatalf("the dead relay was not mentioned:\n%s", stderr)
	}
}

// serve ls says what is served and what is being held for it.
func TestServeListsWhatIsServed(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)

	var out serveLsJSON
	if err := json.Unmarshal([]byte(bob.run("serve", "ls", "--json")), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Channels) != 1 {
		t.Fatalf("ls --json: %+v", out)
	}
	row := out.Channels[0]
	if row.Name != "jostle" || row.Mode != modeSideCopy || row.Dir != bob.dir || row.Worktree != "" {
		t.Fatalf("the channel row: %+v", row)
	}
	if len(row.Threads) != 1 {
		t.Fatalf("the threads: %+v", row.Threads)
	}
	th := row.Threads[0]
	if th.Thread != sent.Thread || th.Turns != 1 || th.Last.IsZero() ||
		th.Worktree != filepath.Join(bob.home, "serve", "worktrees", sent.Thread) {
		t.Fatalf("the thread row: %+v", th)
	}
	text := bob.run("serve", "ls")
	for _, want := range []string{"jostle: side-copy in " + bob.dir, shortID(sent.Thread), "1 turn", th.Worktree} {
		if !strings.Contains(text, want) {
			t.Fatalf("ls printed:\n%s\nwant %q", text, want)
		}
	}

	// A read-only channel has a worktree of its own and its threads have
	// none.
	_, other := newExpert(t, modeReadOnly)
	other.serve(t)
	var second serveLsJSON
	json.Unmarshal([]byte(other.run("serve", "ls", "--json")), &second)
	if len(second.Channels) != 1 || len(second.Channels[0].Threads) != 0 {
		t.Fatalf("a channel nothing has asked: %+v", second.Channels)
	}
	if !strings.Contains(other.run("serve", "ls"), "no threads yet") {
		t.Fatalf("ls of an idle channel:\n%s", other.run("serve", "ls"))
	}
}

// A thread nothing has touched for its channel's thread_ttl is let go of:
// the state and the worktree, not the ledger's record of it.
func TestServeSweepsAnIdleThread(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	worktree := filepath.Join(bob.home, "serve", "worktrees", sent.Thread)
	patchDir := filepath.Join(threadDir, "patch-"+sent.ID)
	for _, path := range []string{threadDir, worktree, patchDir} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s is not there to sweep: %v", path, err)
		}
	}

	bob.row.ThreadTTL = "1ms"
	bob.write(t)
	time.Sleep(5 * time.Millisecond)
	stderr := captureStderr(t, func() { bob.serve(t) })
	if !strings.Contains(stderr, "thread "+shortID(sent.Thread)+" has been idle") {
		t.Fatalf("the sweep said:\n%s", stderr)
	}
	for _, path := range []string{threadDir, worktree, patchDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived the sweep (%v)", path, err)
		}
	}
	// The ledger keeps the id, so the message is not answered a second
	// time, and git is not left believing in a worktree that has gone.
	if !bob.ledgerOf(t).Messages[sent.ID].Handled.IsZero() == false {
		t.Fatal("the ledger forgot the message")
	}
	if list := git(t, bob.dir, "worktree", "list"); strings.Contains(list, sent.Thread) {
		t.Fatalf("git still believes in the worktree:\n%s", list)
	}
	if again := bob.round(t); len(again.Answered) != 0 {
		t.Fatalf("a swept message was answered again: %+v", again)
	}
}

// The sweep leaves work alone: a message still being tried, and the reply
// that is waiting for a relay to come back, are exactly what the next round
// needs.
func TestServeSweepsNothingThatIsStillWork(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:an answer worth keeping")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	kept := filepath.Join(bob.home, "serve", "threads", sent.Thread, "reply-"+sent.ID+".txt")
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("there is no kept reply to protect: %v", err)
	}

	// Old enough by any measure, and still not swept.
	bob.age(t, sent.Thread, 400*time.Hour)
	bob.row.ThreadTTL = "1ms"
	bob.write(t)
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the kept reply was swept: %v", err)
	}
	// And it is the kept reply that was used: the handler has not run a
	// second time for the same answer.
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times, so the state it needed had gone", runs)
	}

	// And once it is work no longer, it goes.
	bob.run("peers", "add", alice.exportLine())
	bob.serve(t)
	bob.age(t, sent.Thread, 400*time.Hour)
	captureStderr(t, func() { bob.serve(t) })
	if _, err := os.Stat(filepath.Join(bob.home, "serve", "threads", sent.Thread)); !os.IsNotExist(err) {
		t.Fatalf("a settled thread was not swept (%v)", err)
	}
}

// A thread whose channel has left the file is swept on the default, since
// state under the home should not grow for ever because somebody stopped
// serving something.
func TestServeSweepsAThreadWhoseChannelHasGone(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	bob.age(t, sent.Thread, defaultThreadTTL+time.Hour)

	bob.run("channel", "create", "second")
	bob.config.Channels = map[string]*serveChannel{
		"second": {Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: modeReadOnly},
	}
	bob.write(t)
	captureStderr(t, func() { bob.serve(t) })
	if _, err := os.Stat(filepath.Join(bob.home, "serve", "threads", sent.Thread)); !os.IsNotExist(err) {
		t.Fatalf("the thread of a channel that has gone was kept (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(bob.home, "serve", "worktrees", sent.Thread)); !os.IsNotExist(err) {
		t.Fatalf("its worktree was kept (%v)", err)
	}
}

// awaitReply waits for a reply on a thread that is not the one already
// seen, which is how a test follows a conversation a service is having.
func (u *user) awaitReply(t *testing.T, svc *service, thread, notThis string) messageJSON {
	t.Helper()
	var found messageJSON
	waitUntil(t, 30*time.Second, func() bool {
		var in inboxJSON
		json.Unmarshal([]byte(u.run("inbox", "--json")), &in)
		for _, m := range in.Messages {
			if m.Thread == thread && m.Type == "reply" && m.ID != notThis {
				found = m
				return true
			}
		}
		return false
	}, func() string { return "no reply on the thread:\n" + svc.log() })
	return found
}

// waitUntil polls until something is true, or fails with what the caller
// can say about why it was not.
func waitUntil(t *testing.T, limit time.Duration, done func() bool, why func() string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		if done() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(why())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// age moves a thread's ledger entries back in time, which is the only way
// to be a week old inside a test.
func (e *expert) age(t *testing.T, thread string, by time.Duration) {
	t.Helper()
	led := e.ledgerOf(t)
	for _, entry := range led.Messages {
		if entry.Thread != thread {
			continue
		}
		if !entry.Handled.IsZero() {
			entry.Handled = entry.Handled.Add(-by)
		}
		if !entry.Tried.IsZero() {
			entry.Tried = entry.Tried.Add(-by)
		}
	}
	if err := led.save(); err != nil {
		t.Fatal(err)
	}
}

// A thread whose message gave up has no time of its own but the attempt
// that failed last, and that is what the sweep ages it by. Without it the
// state of every expert that ever failed would be kept for ever.
func TestServeSweepsAThreadThatGaveUp(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	bob.row.Retries = 1
	bob.write(t)
	t.Setenv(handlerScript, "say:no;exit:1")
	sent := alice.ask(t, "jostle", "a question", "the first")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })

	entry := bob.ledgerOf(t).Messages[sent.ID]
	if entry == nil || !entry.GaveUp || !entry.Handled.IsZero() || entry.Tried.IsZero() {
		t.Fatalf("the entry: %+v", entry)
	}
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if _, err := os.Stat(threadDir); err != nil {
		t.Fatalf("there is no thread to sweep: %v", err)
	}
	// ls says when it was last touched, which is that attempt.
	var listing serveLsJSON
	json.Unmarshal([]byte(bob.run("serve", "ls", "--json")), &listing)
	if len(listing.Channels[0].Threads) != 1 || listing.Channels[0].Threads[0].Last.IsZero() ||
		listing.Channels[0].Threads[0].Turns != 0 {
		t.Fatalf("ls of a thread that gave up: %+v", listing.Channels[0].Threads)
	}

	bob.age(t, sent.Thread, defaultThreadTTL+time.Hour)
	captureStderr(t, func() { bob.serve(t) })
	if _, err := os.Stat(threadDir); !os.IsNotExist(err) {
		t.Fatalf("the thread was kept (%v)", err)
	}
}

// A signal while a handler is running stops that too: the service does not
// wait out a thirty-minute timeout to answer a service manager, and the
// message it was in the middle of is left exactly as it was. Unix only.
func TestServeStopsAHandlerWithItself(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM to send")
	}
	alice, bob := newExpert(t, modeReadOnly)
	started := filepath.Join(t.TempDir(), "started")
	bob.row.Exec = fmt.Sprintf("printf x > %s; sleep 60", started)
	bob.write(t)
	svc := bob.start(t, nil)

	sent := alice.ask(t, "jostle", "a question", "the first")
	waitUntil(t, 30*time.Second, func() bool {
		_, err := os.Stat(started)
		return err == nil
	}, func() string { return "the handler never started:\n" + svc.log() })

	began := time.Now()
	if err := svc.stop(); err != nil {
		t.Fatalf("the service exited %v:\n%s", err, svc.log())
	}
	if took := time.Since(began); took > 30*time.Second {
		t.Fatalf("stopping took %s: the handler was waited out", took)
	}
	// Nothing written down against the message: the next serve picks it up
	// where this one left it.
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry != nil {
		t.Fatalf("the message was marked in the ledger: %+v", entry)
	}
}

// A service started on a home that has never served answers what arrives
// after it, round after round. The first round is the first start and the
// rest are not, which is only visible against a cold home: every other
// service test here has a ledger before the service begins. Unix only, for
// the signal.
func TestServeColdStartAnswersWhatArrivesAfterIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM to send")
	}
	alice, bob := newExpertCold(t, modeReadOnly)
	bob.row.Exec = "printf 'answered\\n'"
	bob.write(t)
	svc := bob.start(t, nil)
	// The first round is the first start, and mail that arrives before it
	// is a backlog however new it is. The ledger appearing is that round
	// ending, which is the only honest thing to wait for.
	ledgerPath := filepath.Join(bob.home, "serve", ledgerFile)
	waitUntil(t, 30*time.Second, func() bool {
		_, err := os.Stat(ledgerPath)
		return err == nil
	}, func() string { return "the service never finished a round:\n" + svc.log() })

	first := alice.ask(t, "jostle", "one", "the first")
	alice.awaitReply(t, svc, first.Thread, "")
	// And again, since the bug this is here for only shows on the second
	// round: a service that treats every round as a first start skips
	// everything that arrives after it.
	second := alice.ask(t, "jostle", "two", "the second")
	alice.awaitReply(t, svc, second.Thread, "")

	if err := svc.stop(); err != nil {
		t.Fatalf("the service exited %v:\n%s", err, svc.log())
	}
	if strings.Contains(svc.log(), "already in the inbox") {
		t.Fatalf("mail that arrived after the start was called a backlog:\n%s", svc.log())
	}
	led := bob.ledgerOf(t)
	for _, sent := range []sentJSON{first, second} {
		if e := led.Messages[sent.ID]; e == nil || e.Skipped || e.Handled.IsZero() {
			t.Fatalf("%s was not answered: %+v", shortID(sent.ID), e)
		}
	}
}

// Mail already waiting when a cold service starts is left alone and said
// once, and the round after it is an ordinary round.
func TestServeColdStartLeavesWhatWasWaiting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM to send")
	}
	alice, bob := newExpertCold(t, modeReadOnly)
	bob.row.Exec = "printf 'answered\\n'"
	bob.write(t)
	waiting := alice.ask(t, "jostle", "before", "sent before the expert existed")

	svc := bob.start(t, nil)
	svc.waitFor("already in the inbox, left alone")

	after := alice.ask(t, "jostle", "after", "sent once it was running")
	alice.awaitReply(t, svc, after.Thread, "")
	if err := svc.stop(); err != nil {
		t.Fatalf("the service exited %v:\n%s", err, svc.log())
	}
	if said := strings.Count(svc.log(), "already in the inbox"); said != 1 {
		t.Fatalf("the backlog was announced %d times:\n%s", said, svc.log())
	}
	led := bob.ledgerOf(t)
	if e := led.Messages[waiting.ID]; e == nil || !e.Skipped {
		t.Fatalf("what was waiting: %+v", e)
	}
	if e := led.Messages[after.ID]; e == nil || e.Skipped || e.Handled.IsZero() {
		t.Fatalf("what arrived after: %+v", e)
	}
}

// A side copy's reply carries the thread's whole change so far, as a patch
// the asker can apply to a clone at the commit the worktree was made from.

// clone is a copy of the project at a commit, which is what an asker has.
func clone(t *testing.T, from, base string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "--quiet", "-c", "core.autocrlf=false", from, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	git(t, dst, "checkout", "--detach", base)
	return dst
}

// patchOf extracts the patch a reply carries and returns where it was
// written. It fails the test when the reply carries none.
func patchOf(t *testing.T, u *user, reply messageJSON) string {
	t.Helper()
	if len(reply.Attachments) != 1 {
		t.Fatalf("the reply carries %d attachments: %+v", len(reply.Attachments), reply.Attachments)
	}
	dir := t.TempDir()
	u.run("extract", reply.ID, "--out", dir)
	return filepath.Join(dir, reply.Attachments[0].Name)
}

func TestServeAttachesTheThreadsChangeSoFar(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	base := git(t, bob.dir, "rev-parse", "HEAD")
	t.Setenv(handlerScript, "write:one.txt=the first change;echo:done, and the change is attached")

	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	reply := alice.replyOn(t, sent.Thread)
	name := patchName(sent.Thread)
	if len(reply.Attachments) != 1 || reply.Attachments[0].Name != name {
		t.Fatalf("the reply's attachments: %+v", reply.Attachments)
	}
	if !strings.HasSuffix(reply.Text, "The changes so far are attached as "+name+"; apply with git apply.") {
		t.Fatalf("the reply says:\n%s", reply.Text)
	}
	// It applies to what the asker has: a clone at the commit the worktree
	// was made from.
	work := clone(t, bob.dir, base)
	patch := patchOf(t, alice, reply)
	if out, err := exec.Command("git", "-C", work, "apply", "--check", patch).CombinedOutput(); err != nil {
		t.Fatalf("the patch does not apply: %v\n%s\n%s", err, out, readFile(t, patch))
	}

	// A follow-up's patch is cumulative: the first change and the second,
	// against the same base, however the checkout has moved on.
	if err := os.WriteFile(filepath.Join(bob.dir, "NEWS"), []byte("the project moved on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, bob.dir, "add", "NEWS")
	git(t, bob.dir, "commit", "-m", "a second commit")

	t.Setenv(handlerScript, "write:two.txt=the second change;echo:and another")
	alice.run("reply", reply.ID[:12], "and one more thing")
	bob.serve(t)
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	var second messageJSON
	for _, m := range in.Messages {
		if m.Thread == sent.Thread && m.Type == "reply" && m.ID != reply.ID {
			json.Unmarshal([]byte(alice.run("read", m.ID, "--json")), &second)
		}
	}
	if second.ID == "" {
		t.Fatal("the follow-up was not answered")
	}
	cumulative := readFile(t, patchOf(t, alice, second))
	for _, want := range []string{"one.txt", "two.txt"} {
		if !strings.Contains(cumulative, want) {
			t.Fatalf("the cumulative patch leaves out %s:\n%s", want, cumulative)
		}
	}
	if strings.Contains(cumulative, "NEWS") {
		t.Fatalf("the patch carries what the checkout did, not what the thread did:\n%s", cumulative)
	}
	if out, err := exec.Command("git", "-C", clone(t, bob.dir, base), "apply", "--check",
		patchOf(t, alice, second)).CombinedOutput(); err != nil {
		t.Fatalf("the cumulative patch does not apply: %v\n%s", err, out)
	}
}

// A change to a file that is not text travels too, which is what --binary
// is for and what nothing else proves.
func TestServeAttachesABinaryChange(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	base := git(t, bob.dir, "rev-parse", "HEAD")
	t.Setenv(handlerScript, "binary:blob.bin;echo:the binary is attached")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	reply := alice.replyOn(t, sent.Thread)
	patch := patchOf(t, alice, reply)
	if !strings.Contains(readFile(t, patch), "GIT binary patch") {
		t.Fatalf("the patch is not a binary one:\n%s", readFile(t, patch))
	}
	work := clone(t, bob.dir, base)
	if out, err := exec.Command("git", "-C", work, "apply", "--check", patch).CombinedOutput(); err != nil {
		t.Fatalf("the binary patch does not apply: %v\n%s", err, out)
	}
	if out, err := exec.Command("git", "-C", work, "apply", patch).CombinedOutput(); err != nil {
		t.Fatalf("applying it: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(work, "blob.bin"))
	if err != nil || len(got) != 7 || got[0] != 0 || got[5] != 0xff {
		t.Fatalf("the applied file is %v (%v)", got, err)
	}
}

// What a handler commits in its worktree is part of the change, and what
// .gitignore hides is not.
func TestServeAttachesWhatTheHandlerCommittedAndNotWhatIsIgnored(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	if err := os.WriteFile(filepath.Join(bob.dir, ".gitignore"), []byte("ignored.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, bob.dir, "add", ".gitignore")
	git(t, bob.dir, "commit", "-m", "ignore what is not the project's")
	base := git(t, bob.dir, "rev-parse", "HEAD")

	t.Setenv(handlerScript, "write:done.txt=committed by the handler;commit:the handler's own commit;"+
		"write:after.txt=written and not committed;echo:both")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	reply := alice.replyOn(t, sent.Thread)
	patch := readFile(t, patchOf(t, alice, reply))
	for _, want := range []string{"done.txt", "after.txt"} {
		if !strings.Contains(patch, want) {
			t.Fatalf("the patch leaves out %s:\n%s", want, patch)
		}
	}
	if out, err := exec.Command("git", "-C", clone(t, bob.dir, base), "apply", "--check",
		patchOf(t, alice, reply)).CombinedOutput(); err != nil {
		t.Fatalf("the patch does not apply: %v\n%s", err, out)
	}

	// And the ignored file is not in it, however the handler writes it.
	t.Setenv(handlerScript, "write:ignored.txt=not the project's;echo:and again")
	alice.run("reply", reply.ID[:12], "once more")
	bob.serve(t)
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	for _, m := range in.Messages {
		if m.Thread == sent.Thread && m.Type == "reply" && m.ID != reply.ID {
			var second messageJSON
			json.Unmarshal([]byte(alice.run("read", m.ID, "--json")), &second)
			if strings.Contains(readFile(t, patchOf(t, alice, second)), "ignored.txt") {
				t.Fatalf("an ignored file is in the patch:\n%s", readFile(t, patchOf(t, alice, second)))
			}
		}
	}
}

// A read-only channel sends no patch, whatever its handler wrote.
func TestServeSendsNoPatchFromAReadOnlyChannel(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "write:scratch.txt=a test I wrote to find out;echo:the answer alone")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	reply := alice.replyOn(t, sent.Thread)
	if len(reply.Attachments) != 0 {
		t.Fatalf("a read-only answer carries %+v", reply.Attachments)
	}
	if reply.Text != "the answer alone" {
		t.Fatalf("the reply says:\n%s", reply.Text)
	}
}

// A side copy that changes files and says nothing sends nothing: the patch
// goes with an answer and is not one by itself.
func TestServeSendsNothingWhenASideCopyIsSilent(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	t.Setenv(handlerScript, "write:one.txt=changed in silence")
	sent := alice.ask(t, "jostle", "a question", "the first")
	report := bob.round(t)
	if len(report.Answered) != 1 {
		t.Fatalf("the round: %+v", report)
	}
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	for _, m := range in.Messages {
		if m.Type == "reply" {
			t.Fatalf("something went out: %+v", m)
		}
	}
	// The work is still in the worktree, where the sweep will find it.
	tree := filepath.Join(bob.home, "serve", "worktrees", sent.Thread)
	if _, err := os.Stat(filepath.Join(tree, "one.txt")); err != nil {
		t.Fatalf("the change is not in the worktree either: %v", err)
	}
}

// A patch made for an answer that could not be sent is kept with it and
// goes out as it was, without the handler running again.
func TestServeKeepsThePatchWithTheReply(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";write:one.txt=the only change;echo:an answer worth keeping")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })

	patch := filepath.Join(bob.home, "serve", "threads", sent.Thread, "patch-"+sent.ID, patchName(sent.Thread))
	before := readFile(t, patch)
	if !strings.Contains(before, "one.txt") {
		t.Fatalf("the kept patch:\n%s", before)
	}
	// The worktree it was taken from goes, as a tidied home or a pruned
	// checkout would take it: the answer is on disk and does not depend on
	// it any more.
	if err := os.RemoveAll(filepath.Join(bob.home, "serve", "worktrees", sent.Thread)); err != nil {
		t.Fatal(err)
	}
	bob.run("peers", "add", alice.exportLine())
	bob.serve(t)
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times", runs)
	}
	reply := alice.replyOn(t, sent.Thread)
	if got := readFile(t, patchOf(t, alice, reply)); got != before {
		t.Fatalf("the patch that went out is not the one that was kept:\n%s\n---\n%s", got, before)
	}
	if !strings.HasSuffix(reply.Text, "apply with git apply.") {
		t.Fatalf("the resent reply says:\n%s", reply.Text)
	}
}

// A side copy's reply kept without a patch directory of its own, as an auu
// before the answer had one left it, is not sent with whatever patch the
// thread has: it is answered again, and goes with the patch taken for it.
func TestServeAnswersAgainAReplyKeptWithoutItsOwnPatch(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";write:one.txt=the only change;echo:an answer worth keeping")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })

	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if err := os.RemoveAll(filepath.Join(threadDir, "patch-"+sent.ID)); err != nil {
		t.Fatal(err)
	}
	// The thread's patch where the older auu kept it, which is not this
	// answer's.
	if err := os.WriteFile(filepath.Join(threadDir, patchName(sent.Thread)), []byte("not this answer's\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bob.run("peers", "add", alice.exportLine())
	bob.serve(t)
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 2 {
		t.Fatalf("the handler ran %d times; want the answer made again", runs)
	}
	reply := alice.replyOn(t, sent.Thread)
	if got := readFile(t, patchOf(t, alice, reply)); !strings.Contains(got, "one.txt") {
		t.Fatalf("the reply went with:\n%s", got)
	}
}

// A patch that cannot be taken is the message's failure, in git's own
// words: an answer claiming changes the asker cannot see would be worse.
func TestServeFailsWhenThePatchCannotBeBuilt(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	t.Setenv(handlerScript, "write:one.txt=a change;echo:an answer")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	reply := alice.replyOn(t, sent.Thread)

	// The base the worktree recorded is made nonsense of, as a rebase of
	// the checkout would make it, and a follow-up arrives.
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if err := os.WriteFile(filepath.Join(threadDir, baseFile),
		[]byte(strings.Repeat("0", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("reply", reply.ID[:12], "and one more thing")
	stderr := captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if !strings.Contains(stderr, "was not answered") || !strings.Contains(stderr, "git diff") {
		t.Fatalf("the failure was said as:\n%s", stderr)
	}
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	for _, m := range in.Messages {
		if m.Type == "reply" && m.ID != reply.ID {
			t.Fatal("an answer went out without the changes it spoke of")
		}
	}
	var followUp string
	json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in)
	for _, m := range in.Messages {
		if m.Thread == sent.Thread && m.ID != sent.ID {
			followUp = m.ID
		}
	}
	if e := bob.ledgerOf(t).Messages[followUp]; e == nil || e.Failures != 1 {
		t.Fatalf("the entry: %+v", e)
	}
}

// An answer whose patch could not be taken is not kept to be sent without
// it (G37, R53): the retry takes the patch again, and never sends the
// answer with the turn before's. Each attempt is the message's failure
// until the patch can be taken or the retries run out.
func TestServeTakesAFailedPatchAgainOnTheRetry(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	t.Setenv(handlerScript, "write:one.txt=first change;echo:first answer")
	first := alice.ask(t, "jostle", "patch retry", "first question")
	bob.serve(t)
	reply := alice.replyOn(t, first.Thread)

	// The recorded base is made unavailable, as a rewrite of the checkout
	// would make it, and a follow-up with a change of its own arrives.
	threadDir := filepath.Join(bob.home, "serve", "threads", first.Thread)
	basePath := filepath.Join(threadDir, baseFile)
	base := readBase(t, basePath)
	if err := os.WriteFile(basePath, []byte(strings.Repeat("0", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(handlerScript, "write:two.txt=second change;echo:second answer with another change")
	alice.run("reply", reply.ID, "please make the second change")
	for attempt := 1; attempt <= 2; attempt++ {
		out, err := bob.tryRun("serve", "--once", "--json")
		if err == nil {
			t.Fatalf("attempt %d: the patch was taken against a base that is gone", attempt)
		}
		var round roundJSON
		if err := json.Unmarshal([]byte(out), &round); err != nil {
			t.Fatal(err)
		}
		if len(round.Failed) != 1 || len(round.Answered) != 0 {
			t.Fatalf("attempt %d: %+v; want the message failed and nothing answered", attempt, round)
		}
	}
	var in inboxJSON
	if err := json.Unmarshal([]byte(alice.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.Thread == first.Thread && m.Type == "reply" && m.ID != reply.ID {
			t.Fatalf("an answer went out without its own patch: %+v", m)
		}
	}
	var followUp string
	for id, e := range bob.ledgerOf(t).Messages {
		if id != first.ID {
			followUp = id
			if e.Failures != 2 {
				t.Fatalf("the follow-up's entry: %+v; want two failures", e)
			}
		}
	}

	// The base back, the next retry answers with this answer's own patch,
	// which holds the second change.
	if err := os.WriteFile(basePath, []byte(base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := bob.round(t); len(r.Answered) != 1 || len(r.Failed) != 0 {
		t.Fatalf("the retry with the base back: %+v", r)
	}
	got := replyToMessage(t, alice, first.Thread, followUp)
	if len(got.Attachments) != 1 {
		t.Fatalf("the retry's reply carries %+v", got.Attachments)
	}
	if patch := readFile(t, patchOf(t, alice, got)); !strings.Contains(patch, "two.txt") {
		t.Fatalf("the retry's reply went with a patch without the second change:\n%s", patch)
	}
}

// The files an asker sends are put where the handler can read them, and a
// retry finds them already there.
func TestServeGivesTheHandlerTheFilesTheAskerSent(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Retries = 3
	bob.write(t)
	attachment := filepath.Join(t.TempDir(), "failing_test.go")
	if err := os.WriteFile(attachment, []byte("// the test that fails\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The first attempt fails after the files have been unpacked; the
	// second one finds them and answers.
	t.Setenv(handlerScript, "say:not yet;exit:1")
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--channel", "jostle",
		"--subject", "look at this", "--attach", attachment, "--json", "why does it fail?")), &sent); err != nil {
		t.Fatal(err)
	}
	// A run that stopped part way left half of them behind under the name
	// they are unpacked into. It is not the files, and nothing should read
	// it as them.
	in := filepath.Join(bob.home, "serve", "threads", sent.Thread, "in", sent.ID)
	if err := os.MkdirAll(in+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in+".tmp", "failing_test.go"), []byte("half a file"), 0o600); err != nil {
		t.Fatal(err)
	}

	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if got := readFile(t, filepath.Join(in, "failing_test.go")); got != "// the test that fails\n" {
		t.Fatalf("the unpacked file is %q", got)
	}
	if _, err := os.Stat(in + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the half-written directory is still there (%v)", err)
	}

	t.Setenv(handlerScript, "env")
	bob.serve(t)
	vars := envOf(t, alice.replyOn(t, sent.Thread).Text)
	if vars["AUU_ATTACHMENTS"] != in {
		t.Fatalf("AUU_ATTACHMENTS is %q, want %q", vars["AUU_ATTACHMENTS"], in)
	}
	// Still one copy of it, written once.
	entries, err := os.ReadDir(in)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the directory holds %v (%v)", entries, err)
	}
}
