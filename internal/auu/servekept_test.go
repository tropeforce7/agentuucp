package auu

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// keptAnswer is alice's question to a side copy whose answer bob's serve
// wrote, sealed and could not post, a gateway in front of the relay
// refusing every post to a mailbox: the answer, its patch and its sealed
// envelope are kept, and the handler has run once. putRight points bob at
// the relay again.
func keptAnswer(t *testing.T) (alice *user, bob *expert, sent sentJSON, marker string, putRight func()) {
	t.Helper()
	alice, bob = newExpert(t, modeSideCopy)
	marker = filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";write:one.txt=the handler's change;echo:the handler's answer")
	sent = alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	_, _, relays := bob.opened()
	real := relays[0].URL
	target, err := url.Parse(real)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			http.Error(w, "fixture: the gateway refuses the post", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(gateway.Close)
	repointRelay(t, bob.user, gateway.URL)
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	keptDir := filepath.Join(bob.home, "serve", "kept", sent.Thread)
	for _, path := range []string{runFile(keptDir, "reply", sent.ID), sealedFile(keptDir, sent.ID),
		filepath.Join(keptDir, "patch-"+sent.ID, patchName(sent.Thread))} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("nothing was kept, so the test shows nothing: %v", err)
		}
	}
	return alice, bob, sent, marker, func() { repointRelay(t, bob.user, real) }
}

// TestServeKeepsItsAnswerWhereTheHandlerIsNotGiven: serve kept an answer
// it could not send, its patch, its sealed envelope and its run files in
// the thread's directory, which the handler is given to write. A link is
// refused by the open, but a hard link is the file it names: a contained
// handler, or a child it left running, could put one to a file the serve
// account can read at the patch's name, or the reply's, or the envelope's,
// between rounds, or at the output's after it exited, and the retry sent
// that file (S56). Now they are under serve/kept/<thread>/, which no
// program is told of: a hard link to a witness at each old name in the
// thread's directory changes nothing, the retry sends the kept answer
// with the handler's change, nothing of the witness leaves, and the links
// are left as they were.
//
// It runs wherever os.Link does, Windows among them, and skips where the
// filesystem makes no hard link.
func TestServeKeepsItsAnswerWhereTheHandlerIsNotGiven(t *testing.T) {
	alice, bob, sent, marker, putRight := keptAnswer(t)
	const secret = "A FILE ONLY THE SERVE ACCOUNT CAN READ"
	witness := filepath.Join(t.TempDir(), "witness")
	if err := os.WriteFile(witness, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if err := os.MkdirAll(filepath.Join(threadDir, "patch-"+sent.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	plants := []string{
		runFile(threadDir, "reply", sent.ID),
		runFile(threadDir, "out", sent.ID),
		runFile(threadDir, "msg", sent.ID),
		sealedFile(threadDir, sent.ID),
		filepath.Join(threadDir, "patch-"+sent.ID, patchName(sent.Thread)),
	}
	for _, p := range plants {
		// As a handler would: whatever stood under the name goes first.
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Link(witness, p); err != nil {
			t.Skipf("no hard link can be made here: %v", err)
		}
	}

	putRight()
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the retry: %+v", report)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times in all, want 1", runs)
	}
	reply := alice.replyOn(t, sent.Thread)
	if !strings.HasPrefix(reply.Text, "the handler's answer") {
		t.Fatalf("the reply says:\n%s", reply.Text)
	}
	if got := readFile(t, patchOf(t, alice, reply)); !strings.Contains(got, "one.txt") || strings.Contains(got, secret) {
		t.Fatalf("the reply went with:\n%s", got)
	}
	if out := alice.run("read", reply.ID, "--json"); strings.Contains(out, secret) {
		t.Fatalf("the witness reached the asker:\n%s", out)
	}
	if got := readFile(t, witness); got != secret+"\n" {
		t.Fatalf("the witness is now %q", got)
	}
	w, err := os.Stat(witness)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plants {
		if info, err := os.Stat(p); err != nil || !os.SameFile(info, w) {
			t.Errorf("the link at %s was not left as it was: %v", p, err)
		}
	}
}

// asAnOlderServeLeftIt puts a kept answer where a serve before kept/ kept
// it, in the thread's directory, and takes kept/ away, as a home that
// serve has never run in since.
func asAnOlderServeLeftIt(t *testing.T, bob *expert, sent sentJSON) {
	t.Helper()
	keptDir := filepath.Join(bob.home, "serve", "kept", sent.Thread)
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	for _, name := range []string{"patch-" + sent.ID, "sealed-" + sent.ID + ".json", "reply-" + sent.ID + ".txt"} {
		if err := os.Rename(filepath.Join(keptDir, name), filepath.Join(threadDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(bob.home, "serve", "kept")); err != nil {
		t.Fatal(err)
	}
}

// sealedID is the id of the envelope kept for an answer.
func sealedID(t *testing.T, path string) string {
	t.Helper()
	var k keptSeal
	if err := json.Unmarshal([]byte(readFile(t, path)), &k); err != nil || k.Inner == nil {
		t.Fatalf("the kept envelope %s: %v", path, err)
	}
	return k.Inner.ID
}

// TestServeMovesAnOlderServesKeptAnswerOnce: a home an older serve ran in
// holds an answer it could not send in the thread's directory. The first
// serve of this one moves it into kept/ before any round, and the retry
// sends it as that serve sealed it, under the same id, with its patch and
// without running the handler; the thread's directory no longer holds it.
// A link an older handler put at the patch's name is moved as the link,
// and the send refuses it by name, as it did.
func TestServeMovesAnOlderServesKeptAnswerOnce(t *testing.T) {
	t.Run("an answer", func(t *testing.T) {
		alice, bob, sent, marker, putRight := keptAnswer(t)
		id := sealedID(t, sealedFile(filepath.Join(bob.home, "serve", "kept", sent.Thread), sent.ID))
		asAnOlderServeLeftIt(t, bob, sent)

		putRight()
		report := bob.round(t)
		if len(report.Answered) != 1 {
			t.Fatalf("the retry: %+v", report)
		}
		if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
			t.Fatalf("the handler ran %d times in all, want 1", runs)
		}
		reply := alice.replyOn(t, sent.Thread)
		if reply.ID != id {
			t.Fatalf("the reply went as %s, not as the envelope kept for it, %s", reply.ID, id)
		}
		if got := readFile(t, patchOf(t, alice, reply)); !strings.Contains(got, "one.txt") {
			t.Fatalf("the reply went with:\n%s", got)
		}
		threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
		for _, name := range []string{"patch-" + sent.ID, "sealed-" + sent.ID + ".json", "reply-" + sent.ID + ".txt"} {
			if _, err := os.Lstat(filepath.Join(threadDir, name)); !os.IsNotExist(err) {
				t.Errorf("%s is still in the thread's directory: %v", name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(bob.home, "serve", "kept.tmp")); !os.IsNotExist(err) {
			t.Errorf("kept.tmp is left: %v", err)
		}
	})
	t.Run("a link at the patch", func(t *testing.T) {
		alice, bob, sent, _, putRight := keptAnswer(t)
		asAnOlderServeLeftIt(t, bob, sent)
		const secret = "TOP SECRET KEY MATERIAL"
		target := filepath.Join(t.TempDir(), "id_secret")
		if err := os.WriteFile(target, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		patch := filepath.Join(bob.home, "serve", "threads", sent.Thread, "patch-"+sent.ID, patchName(sent.Thread))
		if err := os.Remove(patch); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, patch); err != nil {
			t.Skipf("no symbolic link can be made here: %v", err)
		}
		putRight()
		said := captureStderr(t, func() { bob.tryRun("serve", "--once") })
		if !strings.Contains(said, "is a symbolic link, which is not followed") || !strings.Contains(said, patchName(sent.Thread)) {
			t.Fatalf("the failure does not name the link:\n%s", said)
		}
		if out := alice.run("inbox", "--json"); strings.Contains(out, `"type": "reply"`) || strings.Contains(out, secret) {
			t.Fatalf("something reached the asker:\n%s", out)
		}
	})
}

// TestServeMovesNothingAHandlerLeavesInItsThreadDirectory: once kept/ is
// there, a thread's directory is never read for a kept answer. A handler
// that failed its turn knows its message id, and a reply and a patch it
// put in its thread's directory under that id stay there unread: the
// retry runs the handler and sends what it says.
func TestServeMovesNothingAHandlerLeavesInItsThreadDirectory(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:1")
	sent := alice.ask(t, "jostle", "a question", "the first")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry.Failures != 1 {
		t.Fatalf("the first turn did not fail: %+v", entry)
	}

	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	patchDir := filepath.Join(threadDir, "patch-"+sent.ID)
	if err := os.MkdirAll(patchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := map[string]string{
		runFile(threadDir, "reply", sent.ID):            "THE PLANTED ANSWER\n",
		filepath.Join(patchDir, patchName(sent.Thread)): "THE PLANTED PATCH\n",
	}
	for path, text := range planted {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv(handlerScript, "append:"+marker+";write:one.txt=the handler's change;echo:the handler's answer")
	bob.serve(t)
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 2 {
		t.Fatalf("the handler ran %d times in all, want 2", runs)
	}
	reply := alice.replyOn(t, sent.Thread)
	if !strings.HasPrefix(reply.Text, "the handler's answer") {
		t.Fatalf("the reply says:\n%s", reply.Text)
	}
	if got := readFile(t, patchOf(t, alice, reply)); strings.Contains(got, "PLANTED") || !strings.Contains(got, "one.txt") {
		t.Fatalf("the reply went with:\n%s", got)
	}
	for path, text := range planted {
		if got := readFile(t, path); got != text {
			t.Errorf("%s is now %q", path, got)
		}
	}
}

// TestServeFinishesAMoveThatStoppedPartWay: a start that stopped while it
// moved an older serve's answer leaves kept.tmp with part of it, and the
// thread's directory with the rest, the reply among it since the reply
// goes last. The next start goes on from there: the answer goes out with
// its patch, under the id it was sealed with.
func TestServeFinishesAMoveThatStoppedPartWay(t *testing.T) {
	alice, bob, sent, marker, putRight := keptAnswer(t)
	id := sealedID(t, sealedFile(filepath.Join(bob.home, "serve", "kept", sent.Thread), sent.ID))
	asAnOlderServeLeftIt(t, bob, sent)
	partWay := filepath.Join(bob.home, "serve", "kept.tmp", sent.Thread)
	if err := os.MkdirAll(partWay, 0o700); err != nil {
		t.Fatal(err)
	}
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if err := os.Rename(filepath.Join(threadDir, "patch-"+sent.ID), filepath.Join(partWay, "patch-"+sent.ID)); err != nil {
		t.Fatal(err)
	}

	putRight()
	report := bob.round(t)
	if len(report.Answered) != 1 {
		t.Fatalf("the retry: %+v", report)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times in all, want 1", runs)
	}
	reply := alice.replyOn(t, sent.Thread)
	if reply.ID != id {
		t.Fatalf("the reply went as %s, not as the envelope kept for it, %s", reply.ID, id)
	}
	if got := readFile(t, patchOf(t, alice, reply)); !strings.Contains(got, "one.txt") {
		t.Fatalf("the reply went with:\n%s", got)
	}
}

// TestServeSweepsAKeptDirectoryWhoseThreadIsGone: serve's kept directory
// for a thread goes with the thread, and one whose thread's directory was
// removed by hand is let go of by the sweep once it is idle, so kept/ does
// not grow for ever; one with an answer still waiting to go is kept.
func TestServeSweepsAKeptDirectoryWhoseThreadIsGone(t *testing.T) {
	t.Run("settled", func(t *testing.T) {
		alice, bob := newExpert(t, modeReadOnly)
		t.Setenv(handlerScript, "echo:an answer")
		sent := alice.ask(t, "jostle", "a question", "the first")
		bob.serve(t)
		keptDir := filepath.Join(bob.home, "serve", "kept", sent.Thread)
		if _, err := os.Stat(keptDir); err != nil {
			t.Fatalf("no kept directory, so the test shows nothing: %v", err)
		}
		if err := os.RemoveAll(filepath.Join(bob.home, "serve", "threads", sent.Thread)); err != nil {
			t.Fatal(err)
		}
		bob.row.ThreadTTL = "1ms"
		bob.write(t)
		time.Sleep(5 * time.Millisecond)
		bob.serve(t)
		if _, err := os.Stat(keptDir); !os.IsNotExist(err) {
			t.Fatalf("the kept directory of a thread that is gone survived the sweep: %v", err)
		}
	})
	t.Run("waiting", func(t *testing.T) {
		_, bob, sent, marker, _ := keptAnswer(t)
		keptDir := filepath.Join(bob.home, "serve", "kept", sent.Thread)
		id := sealedID(t, sealedFile(keptDir, sent.ID))
		if err := os.RemoveAll(filepath.Join(bob.home, "serve", "threads", sent.Thread)); err != nil {
			t.Fatal(err)
		}
		bob.row.ThreadTTL = "1ms"
		bob.write(t)
		time.Sleep(5 * time.Millisecond)
		captureStderr(t, func() { bob.tryRun("serve", "--once") })
		// The round after the sweep finds the kept answer and tries it
		// again without running the handler, under the id it was sealed
		// with; an answer the sweep let go of is made afresh.
		if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
			t.Fatalf("the handler ran %d times in all, want 1: the sweep let go of an answer still waiting to go", runs)
		}
		if got := sealedID(t, sealedFile(keptDir, sent.ID)); got != id {
			t.Fatalf("the answer is sealed as %s now, was %s: the sweep let go of it", got, id)
		}
	})
}
