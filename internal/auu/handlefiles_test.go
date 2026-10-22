package auu

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
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
)

// The files the script leaves in output/attachments/ come back with the
// reply, in name order, each the bytes the script wrote by its digest at
// the asker's extract. They are copied into handle's kept directory when
// the reply is composed and sealed from there: a relay that loses the
// answer to the first post is posted the same envelope again, and the
// attempt's own files changed after the seal change nothing that is sent.
func TestFilesInTheAttachmentsDirectoryComeBackWithTheReply(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "attach:b.csv=two,rows;attach:a.txt=one line")
	sent := alice.sendTo(t, "documents", "convert these", "please")

	var posts atomic.Int64
	_, _, relays := bob.opened()
	target, err := url.Parse(relays[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && posts.Add(1) == 1 {
			proxy.ServeHTTP(httptest.NewRecorder(), r)
			http.Error(w, "fixture: the answer was lost", http.StatusBadGateway)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gateway.Close()
	repointRelay(t, bob.user, gateway.URL)

	bob.handleRound(t)
	kept := filepath.Join(bob.keptDir("import", sent.ID), "attach-1")
	for name, want := range map[string]string{"a.txt": "one line", "b.csv": "two,rows"} {
		if got := readFile(t, filepath.Join(kept, name)); got != want {
			t.Fatalf("the kept %s holds %q", name, got)
		}
	}
	// What the script left is changed after the seal.
	temps, _ := filepath.Glob(filepath.Join(bob.jobDir("import", sent.ID), "attempt-1", "tmp-*"))
	if len(temps) != 1 {
		t.Fatalf("the attempt's temporary directories: %v", temps)
	}
	os.WriteFile(filepath.Join(temps[0], "output", "attachments", "a.txt"), []byte("rewritten"), 0o600)
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)

	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 {
		t.Fatalf("alice holds %d replies", len(replies))
	}
	got := replies[0].Attachments
	if len(got) != 2 || got[0].Name != "a.txt" || got[1].Name != "b.csv" {
		t.Fatalf("the reply carries %+v", got)
	}
	out := t.TempDir()
	alice.run("extract", replies[0].ID, "--out", out)
	for _, c := range []struct{ name, want string }{{"a.txt", "one line"}, {"b.csv", "two,rows"}} {
		data := readFile(t, filepath.Join(out, c.name))
		sum := sha256.Sum256([]byte(c.want))
		if data != c.want {
			t.Errorf("%s extracted as %q", c.name, data)
		}
		for _, a := range got {
			if a.Name == c.name && a.SHA256 != hex.EncodeToString(sum[:]) {
				t.Errorf("%s's digest is %s", c.name, a.SHA256)
			}
		}
	}
	if _, err := os.Stat(bob.keptDir("import", sent.ID)); !os.IsNotExist(err) {
		t.Fatal("a succeeded job's kept directory is still there after its reply")
	}
}

// A file the sender's rule would not take, by its name, or that is not a
// regular file, is left out of the reply and named in it with why; the
// rest go. An empty directory attaches nothing and says nothing.
func TestAFileNamedPastTheSendersRuleIsLeftOutAndSaid(t *testing.T) {
	alice, bob := newHandler(t)
	// Windows will not create a file named with a control character or a
	// device's name, nor a link here, so on Windows the rule for those two
	// names is shown by the limits walk instead.
	script := "attach:fine.txt=fine;attach:.hidden=hidden;attach:FINE.TXT=folds;attachdir:sub"
	wants := []string{
		`the script's file ".hidden" was left out: its name is not one a sender may use`,
		`the script's file "sub" was left out: it is a directory`,
	}
	if runtime.GOOS != "windows" {
		script += ";attach:a\x01b=control;attach:CON=device;attachlink:link=" + bob.path
		wants = append(wants,
			`the script's file "a\x01b" was left out: its name is not one a sender may use`,
			`the script's file "CON" was left out: its name is not one a sender may use`)
	}
	t.Setenv(handlerScript, script)
	sent := alice.sendTo(t, "documents", "convert these", "please")
	bob.handleRound(t)
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 {
		t.Fatalf("alice holds %d replies", len(replies))
	}
	reply := replies[0]
	if len(reply.Attachments) != 1 || !strings.EqualFold(reply.Attachments[0].Name, "fine.txt") {
		t.Fatalf("the reply carries %+v", reply.Attachments)
	}
	for _, want := range wants {
		if !strings.Contains(reply.Text, want) {
			t.Errorf("the reply does not say %q:\n%s", want, reply.Text)
		}
	}
	// FINE.TXT sorts before fine.txt, so where the disk keeps the two
	// apart it is fine.txt that folds onto it and is left out by that rule;
	// where the disk takes them as one, the script wrote one file.
	if folds := diskFolds(t, t.TempDir(), "fine.txt", "FINE.TXT"); !folds &&
		!strings.Contains(reply.Text, `the script's file "fine.txt" was left out: its name is another file's where case does not count`) {
		t.Errorf("the pair that folds is not said:\n%s", reply.Text)
	}
	if runtime.GOOS != "windows" && !strings.Contains(reply.Text, `the script's file "link" was left out: it is not a regular file`) {
		t.Errorf("the link is not said:\n%s", reply.Text)
	}
	if strings.Contains(reply.Text, bob.home) {
		t.Errorf("the reply names a path of bob's:\n%s", reply.Text)
	}

	// Nothing in the directory: no files, and nothing said of them.
	t.Setenv(handlerScript, "echo:done")
	quiet := alice.sendTo(t, "documents", "nothing", "back")
	bob.handleRound(t)
	if r := repliesOn(t, alice, quiet.Thread); len(r) != 1 || r[0].Text != "handle: succeeded (exit 0, attempt 1 of 1)" || len(r[0].Attachments) != 0 {
		t.Fatalf("an empty directory's reply: %+v", r)
	}
}

// TestLimitMaxReplyBytesBoundsTextAndFilesTogether: a route's
// max_reply_bytes bounds the script's reply text and its files together,
// in name order: files that bring the whole to the cap go, the one that
// would pass it by a byte is left out and said, a later one that fits
// still goes, and 0 is no cap.
func TestLimitMaxReplyBytesBoundsTextAndFilesTogether(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].MaxReplyBytes = 10
	bob.write(t)
	// 4 bytes of text, then a 6-byte file: 10, at the cap. Then a 1-byte
	// file, one over, and nothing after it fits either.
	t.Setenv(handlerScript, "reply:text;attachbig:a.bin=6;attachbig:b.bin=1")
	sent := alice.sendTo(t, "documents", "at the cap", "please")
	bob.handleRound(t)
	reply := repliesOn(t, alice, sent.Thread)[0]
	if len(reply.Attachments) != 1 || reply.Attachments[0].Name != "a.bin" || reply.Attachments[0].Size != 6 {
		t.Fatalf("at the cap the reply carries %+v", reply.Attachments)
	}
	if !strings.Contains(reply.Text, `the script's file "b.bin" was left out: with the reply's text and the files before it, it is over the route's max_reply_bytes of 10`) {
		t.Fatalf("the file one over is not said:\n%s", reply.Text)
	}
	// A file over the cap on its own, and a smaller one after it that fits.
	t.Setenv(handlerScript, "attachbig:a.bin=11;attachbig:b.bin=10")
	sent = alice.sendTo(t, "documents", "one over", "please")
	bob.handleRound(t)
	reply = repliesOn(t, alice, sent.Thread)[0]
	if len(reply.Attachments) != 1 || reply.Attachments[0].Name != "b.bin" {
		t.Fatalf("one over the cap the reply carries %+v", reply.Attachments)
	}
	// No cap.
	bob.routes["import"].MaxReplyBytes = 0
	bob.write(t)
	t.Setenv(handlerScript, "reply:text;attachbig:a.bin=40000;attachbig:b.bin=40000")
	sent = alice.sendTo(t, "documents", "no cap", "please")
	bob.handleRound(t)
	if reply := repliesOn(t, alice, sent.Thread)[0]; len(reply.Attachments) != 2 {
		t.Fatalf("with no cap the reply carries %+v", reply.Attachments)
	}

	// The copy's own bound at its edges and the type's extremes: a budget
	// of what a file is takes it, one less leaves it, and the type's
	// maximum, and the maximum less one, take it with no byte past to stop
	// at and no wrap.
	from := t.TempDir()
	if err := os.WriteFile(filepath.Join(from, "f"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(from)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	seen, err := root.Lstat("f")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		budget int64
		taken  bool
	}{{5, true}, {4, false}, {0, false}, {-1, true}, {math.MaxInt64, true}, {math.MaxInt64 - 1, true}} {
		to := filepath.Join(t.TempDir(), "f")
		n, why, err := keepFile(root, "f", seen, to, c.budget)
		if err != nil {
			t.Fatalf("budget %d: %v", c.budget, err)
		}
		if c.taken && (why != "" || n != 5 || readFile(t, to) != "12345") {
			t.Errorf("budget %d: %d copied, %q; want it whole", c.budget, n, why)
		}
		if !c.taken {
			if _, err := os.Stat(to); why != "over" || !os.IsNotExist(err) {
				t.Errorf("budget %d: %q, the copy left %v; want it over and gone", c.budget, why, err)
			}
		}
	}
}

// A reply over the stream threshold goes as a stream, on its own, and the
// asker extracts it whole; one the asker's relay refuses — their default
// channel takes no streams — is a reply failure, said, with the job's
// outcome standing.
func TestALargeReplyGoesAsAStreamAndARefusedOneIsSaid(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "attachbig:big.bin=200000")
	sent := alice.sendTo(t, "documents", "a big one", "please")
	bob.handleRound(t)
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || len(replies[0].Attachments) != 1 || replies[0].Attachments[0].Size != 200000 {
		t.Fatalf("the big reply: %+v", replies)
	}
	out := t.TempDir()
	alice.run("extract", replies[0].ID, "--out", out)
	if got := readFile(t, filepath.Join(out, "big.bin")); len(got) != 200000 {
		t.Fatalf("the extracted file is %d bytes", len(got))
	}

	alice.run("channel", "update", "default", "--no-streams")
	refused := alice.sendTo(t, "documents", "another big one", "please")
	_, _, stderr := bob.handleRound(t)
	job := bob.ledger(t).Jobs[refused.ID]
	if job.State != jobSucceeded || job.Reply != "" || job.ReplyFailures != 1 {
		t.Fatalf("the refused reply's job is %+v\n%s", job, stderr)
	}
	if !strings.Contains(stderr, "the reply to "+refused.ID[:12]+" could not be sent: ") {
		t.Fatalf("the refusal was not said:\n%s", stderr)
	}
}

// A run that stops between a job's end and the composing of its reply
// leaves nothing of what the script wrote kept: the next round composes
// the reply with the first line and says so, attaches nothing, and the
// asker holds one reply.
func TestAReplyComposedAfterAStopSaysTheScriptsWordsWereNotKept(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "reply:words that are lost;attach:a.txt=a file that is lost")
	sent := alice.sendTo(t, "documents", "a question", "please")
	stopped := errors.New("stopped")
	beforeCompose = func() error { return stopped }
	_, err, _ := bob.handleRound(t)
	beforeCompose = nil
	if !errors.Is(err, stopped) {
		t.Fatalf("the planted stop: %v", err)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobSucceeded || job.Reply != "" {
		t.Fatalf("after the stop the job is %+v", job)
	}
	bob.handleRound(t)
	replies := repliesOn(t, alice, sent.Thread)
	want := "handle: succeeded (exit 0, attempt 1 of 1)\nthe script's reply.txt and files were not kept: the run stopped before they were"
	if len(replies) != 1 || replies[0].Text != want || len(replies[0].Attachments) != 0 {
		t.Fatalf("alice holds %+v", replies)
	}
}
