package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// repliesOn is every reply alice holds on a thread, read in full.
func repliesOn(t *testing.T, u *user, thread string) []messageJSON {
	t.Helper()
	var in inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	var out []messageJSON
	for _, m := range in.Messages {
		if m.Thread == thread && m.Type == "reply" {
			var full messageJSON
			if err := json.Unmarshal([]byte(u.run("read", m.ID, "--json")), &full); err != nil {
				t.Fatal(err)
			}
			out = append(out, full)
		}
	}
	return out
}

// Every handled ask gets one reply, on its thread, to its sender, whose
// first line says how the job ended and which attempt of how many: a
// success, a nonzero exit, a timeout, a job that could not be prepared,
// each as section 6 writes it. The script's reply.txt follows a blank
// line, its CRLF folded; one that fails the text rule, that is over the
// route's max_reply_bytes, or that is a link is left out and said. The
// ask is marked read once its reply is recorded, and a second round sends
// nothing more.
func TestEveryHandledAskGetsOneReplyWithTheFirstLine(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["import"].MaxReplyBytes = 64
	bob.write(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("a file the script may not send"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, script, want string
		idempotent         bool
	}{
		{"succeeded", "echo:done", "handle: succeeded (exit 0, attempt 1 of 1)", false},
		{"succeeded with a reply", "reply:imported 3 invoices\r\nall of March", "handle: succeeded (exit 0, attempt 1 of 1)\n\nimported 3 invoices\nall of March", false},
		{"failed", "say:no such table;exit:3", "handle: failed (exit 3, attempt 1 of 1)", false},
		{"failed with a reply", "reply:the table is missing;exit:3", "handle: failed (exit 3, attempt 1 of 1)\n\nthe table is missing", false},
		{"a reply off the text rule", "reply:a\x01b", "handle: succeeded (exit 0, attempt 1 of 1)\nthe script's reply.txt was not included: " + message.ValidText("a\x01b").Error(), false},
		{"a reply over max_reply_bytes", "reply:" + strings.Repeat("x", 65), "handle: succeeded (exit 0, attempt 1 of 1)\nthe script's reply.txt was not included: it is over the route's max_reply_bytes of 64", false},
		{"a reply at max_reply_bytes", "reply:" + strings.Repeat("x", 64), "handle: succeeded (exit 0, attempt 1 of 1)\n\n" + strings.Repeat("x", 64), false},
		{"an idempotent route", "echo:done", "handle: succeeded (exit 0, attempt 1 of 3)", true},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name, script, want string
			idempotent         bool
		}{"a reply that is a link", "replylink:" + outside, "", false})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bob.routes["import"].Idempotent = c.idempotent
			bob.write(t)
			t.Setenv(handlerScript, c.script)
			sent := alice.sendTo(t, "documents", c.name, "the ask")
			report, _, stderr := bob.handleRound(t)
			if len(report.Jobs) != 1 || report.Jobs[0].Reply == "" {
				t.Fatalf("the round reported %+v\n%s", report.Jobs, stderr)
			}
			replies := repliesOn(t, alice, sent.Thread)
			if len(replies) != 1 {
				t.Fatalf("alice holds %d replies on the thread", len(replies))
			}
			got := replies[0]
			want := c.want
			if c.name == "a reply that is a link" {
				if !strings.HasPrefix(got.Text, "handle: succeeded (exit 0, attempt 1 of 1)\nthe script's reply.txt was not included: ") ||
					strings.Contains(got.Text, "may not send") {
					t.Fatalf("a link's reply is %q", got.Text)
				}
			} else if got.Text != want {
				t.Fatalf("the reply is\n%q\nwant\n%q", got.Text, want)
			}
			if got.ID != report.Jobs[0].Reply || got.InReplyTo != sent.ID || got.Subject != c.name {
				t.Fatalf("the reply is %+v", got)
			}
			if job := bob.ledger(t).Jobs[sent.ID]; job.Reply != got.ID || job.ReplySent.IsZero() {
				t.Fatalf("the ledger has %+v", job)
			}
			if rec, err := storeOf(t, bob.user).Load(store.Inbox, sent.ID); err != nil || !rec.Read {
				t.Fatalf("the ask is not marked read (%v)", err)
			}
		})
	}
	// A job that could not be prepared, retries spent: its reply says why,
	// as attempt N of the route's retries.
	bob.routes["import"].Idempotent = false
	bob.routes["import"].Retries = 1
	bob.write(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := alice.sendTo(t, "documents", "bad", "will not unpack", file)
	bob.run("inbox")
	plantBadDigest(t, bob, bad.ID)
	bob.handleRound(t)
	replies := repliesOn(t, alice, bad.Thread)
	if len(replies) != 1 || !strings.HasPrefix(replies[0].Text, "handle: failed (could not prepare: the files it sent could not be unpacked: ") ||
		!strings.HasSuffix(replies[0].Text, ", attempt 1 of 1)") {
		t.Fatalf("the unprepared job's replies: %+v", replies)
	}
	// Nothing more on a second round.
	bob.handleRound(t)
	if n := len(repliesOn(t, alice, bad.Thread)); n != 1 {
		t.Fatalf("a second round sent another reply: %d", n)
	}
}

// A timeout's first line names the route's timeout. Its own test, since
// it waits the two seconds a process is given at the least.
func TestATimedOutJobsReplySaysTheTimeout(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Timeout = "2s"
	bob.write(t)
	t.Setenv(handlerScript, "sleep:30s")
	sent := alice.sendTo(t, "documents", "slow", "takes too long")
	bob.handleRound(t)
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || replies[0].Text != "handle: failed (timeout after 2s, attempt 1 of 1)" {
		t.Fatalf("the replies are %+v", replies)
	}
}

// The reply is sealed once and kept in handle's own directory, so that a
// relay that took the post and lost its answer is posted the same envelope
// under the same id again, and the asker holds one reply; the script ran
// once, and the kept reply, not anything of the script's, is what went.
func TestTheReplyIsSealedOnceAndPostedAgain(t *testing.T) {
	alice, bob := newHandler(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";reply:an answer worth keeping")
	sent := alice.sendTo(t, "documents", "a question", "the first")

	// A gateway in front of bob's relay that passes the first mailbox post
	// through and then loses the relay's answer to it.
	var posts atomic.Int64
	_, _, relays := bob.opened()
	target, err := url.Parse(relays[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && posts.Add(1) == 1 {
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, r)
			http.Error(w, "fixture: the answer was lost", http.StatusBadGateway)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gateway.Close()
	repointRelay(t, bob.user, gateway.URL)

	report, _, stderr := bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobSucceeded || job.Reply != "" || job.ReplyFailures != 1 {
		t.Fatalf("after the lost answer the job is %+v (%+v)\n%s", job, report, stderr)
	}
	kept := bob.keptDir("import", sent.ID)
	if _, err := os.Stat(sealedFile(kept, sent.ID)); err != nil {
		t.Fatalf("the sealed reply is not kept: %v", err)
	}
	// The script's own directory changed after the seal does not change
	// what is sent again.
	if temps, _ := filepath.Glob(filepath.Join(bob.jobDir("import", sent.ID), "attempt-1", "tmp-*")); len(temps) == 1 {
		os.WriteFile(filepath.Join(temps[0], "output", "reply.txt"), []byte("rewritten after the seal"), 0o600)
	}
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	job = bob.ledger(t).Jobs[sent.ID]
	if job.Reply == "" {
		t.Fatalf("the second round did not send the kept reply: %+v", job)
	}
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || replies[0].ID != job.Reply ||
		replies[0].Text != "handle: succeeded (exit 0, attempt 1 of 1)\n\nan answer worth keeping" {
		t.Fatalf("alice holds %+v", replies)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
	if _, err := os.Stat(kept); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a succeeded job's kept directory is still there after its reply")
	}
}

// The ledger records the reply before the ask is marked read: a mark that
// cannot be written ends the run with the reply already recorded, so the
// next round sends nothing again.
func TestTheLedgerIsWrittenBeforeTheReadMark(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob := newHandler(t)
	sent := alice.sendTo(t, "documents", "a question", "the first")
	bob.run("inbox")
	inbox := filepath.Join(bob.home, string(store.Inbox))
	if err := os.Chmod(inbox, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(inbox, 0o700) })
	_, err, stderr := bob.handleRound(t)
	if err == nil {
		t.Fatalf("a read mark that could not be written ended well\n%s", stderr)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job.Reply == "" || job.ReplySent.IsZero() {
		t.Fatalf("the ledger did not record the reply before the mark: %+v", job)
	}
	os.Chmod(inbox, 0o700)
	if rec, err := storeOf(t, bob.user).Load(store.Inbox, sent.ID); err != nil || rec.Read {
		t.Fatalf("the ask was marked read (%v)", err)
	}
	bob.handleRound(t)
	if n := len(repliesOn(t, alice, sent.Thread)); n != 1 {
		t.Fatalf("alice holds %d replies", n)
	}
}

// A reply that cannot be sent is tried at most the route's retries times,
// at serve's backoff, and then the reason is written on the job beside its
// own and nothing more is sent; the script is not run again (A4).
func TestAReplyThatCannotBeSentStopsAfterRetriesAndIsSaid(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Retries = 2
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:no such table;exit:3")
	sent := alice.sendTo(t, "documents", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")

	_, _, stderr := bob.handleRound(t)
	if !strings.Contains(stderr, "the reply to "+sent.ID[:12]+" could not be sent: ") || !strings.Contains(stderr, "(send 1 of 2)") {
		t.Fatalf("the first round said:\n%s", stderr)
	}
	moveClock(t, retryBackoff(1))
	_, _, stderr = bob.handleRound(t)
	if !strings.Contains(stderr, "(given up)") {
		t.Fatalf("the second round said:\n%s", stderr)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job.ReplyFailures != 2 || job.Reply != "" ||
		!strings.HasPrefix(job.Reason, "exited 3: no such table; the reply could not be sent: ") {
		t.Fatalf("the job is %+v", job)
	}
	moveClock(t, retryBackoff(2))
	if _, _, stderr := bob.handleRound(t); strings.Contains(stderr, "could not be sent") {
		t.Fatalf("a reply given up on was tried again:\n%s", stderr)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
}

// The reply's recipient was admitted at the ask and is relied on at the
// send: a peer removed in between makes it the reply's failure, and the
// job's outcome stands; with the peer back, the next due round sends it.
func TestAReplyToARemovedPeerIsAReplyFailureNotTheJobs(t *testing.T) {
	alice, bob := newHandler(t)
	sent := alice.sendTo(t, "documents", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobSucceeded || job.Reply != "" || job.ReplyFailures != 1 {
		t.Fatalf("the job is %+v", job)
	}
	bob.run("peers", "add", alice.exportLine())
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.Reply == "" {
		t.Fatalf("the reply did not go once the peer was back: %+v", job)
	}
	if n := len(repliesOn(t, alice, sent.Thread)); n != 1 {
		t.Fatalf("alice holds %d replies", n)
	}
}

// auu handle run on a home under a passphrase needs the agent unlocked to
// send, since every reply originates: receive scope is refused before
// anything in handle's own words, and locked in the locked sentence, never
// a prompt; send scope runs and replies; and a send scope that ends under
// the run stops it at exit 4 with nothing counted against the job, its
// reply kept, and the next run, under a proper unlock, sends that reply
// without running the script again.
func TestHandleRunNeedsSendScope(t *testing.T) {
	alice, bob := newHandlerCold(t)
	agentEnv(t)
	bob.encrypt()
	const needsSend = "the agent is unlocked to receive, and auu handle run originates every reply: run 'auu unlock --send --ttl 0' at a terminal, which lasts until 'auu lock'"
	_, err := bob.tryRun("handle", "run", "--once")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != needsSend {
		t.Fatalf("handle run in receive scope gave %v, want exit %d and %q", err, exitLocked, needsSend)
	}
	bob.run("lock")
	_, err = bob.tryRun("handle", "run", "--once")
	if !asExit(err, &e) || e.code != exitLocked || !strings.Contains(e.Error(), "your identity is locked") {
		t.Fatalf("handle run with the agent locked gave %v", err)
	}

	bob.run("unlock", "--send", "--ttl", "0", "--passphrase-file", passphraseFile(t, agentPassphrase))
	captureStderr(t, func() { bob.run("handle", "run", "--once") })
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";sleep:2s;reply:handled while sendable")
	sent := alice.sendTo(t, "documents", "a question", "asked while sendable")
	bob.run("unlock", "--send", "--ttl", "1s", "--passphrase-file", passphraseFile(t, agentPassphrase))
	var stderr string
	stderr = captureStderr(t, func() { _, err = bob.tryRun("handle", "run", "--once") })
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != needsSend {
		t.Fatalf("handle run whose send scope ended under it gave %v; stderr:\n%s", err, stderr)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobSucceeded || job.Reply != "" || job.ReplyFailures != 0 {
		t.Fatalf("the job was recorded against: %+v", job)
	}
	bob.run("unlock", "--send", "--ttl", "0", "--passphrase-file", passphraseFile(t, agentPassphrase))
	captureStderr(t, func() { bob.run("handle", "run", "--once") })
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times, want once: the reply was kept", runs)
	}
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || replies[0].Text != "handle: succeeded (exit 0, attempt 1 of 1)\n\nhandled while sendable" {
		t.Fatalf("alice holds %+v", replies)
	}
}

// What a script leaves running when it exits is killed with it, before
// handle reads what it wrote, so that nothing writes into output/ after
// the read: a child that would outlive a script exiting 0 is gone when the
// round ends. Unix only, as the kill at the timeout is.
func TestAScriptsChildrenAreKilledWhenItExits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no process group to kill")
	}
	alice, bob := newHandler(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	bob.routes["import"].Command = []string{"/bin/sh", "-c", "sleep 60 & echo $! > " + pidFile + "; exit 0"}
	bob.write(t)
	sent := alice.sendTo(t, "documents", "quick", "leaves a child")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobSucceeded {
		t.Fatalf("the job is %+v", job)
	}
	pid := 0
	fmt.Sscanf(strings.TrimSpace(readFile(t, pidFile)), "%d", &pid)
	if pid == 0 {
		t.Fatal("the script never started its child")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscallKill(pid); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the script's child (pid %d) outlived it", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The directory a script's reply.txt is read from is the attempt's own
// output/, held from before the script ran: a script that renames it and
// puts a link to another directory in its place, one holding a reply.txt
// of somebody else's, has its own reply read and sent, and never the
// other. Unix only, where a link is made without a privilege.
func TestAScriptCannotPointItsOutputElsewhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a link needs a privilege on Windows")
	}
	alice, bob := newHandler(t)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "reply.txt"), []byte("somebody else's reply"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(handlerScript, "reply:the script's own;swapoutput:"+elsewhere)
	sent := alice.sendTo(t, "documents", "a question", "the first")
	bob.handleRound(t)
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || replies[0].Text != "handle: succeeded (exit 0, attempt 1 of 1)\n\nthe script's own" {
		t.Fatalf("alice holds %+v", replies)
	}
}
