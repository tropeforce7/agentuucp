package auu

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// A route's caps, the log cut, keep_failed and the sweep.

// pausedRoute pauses bob's route, so that what it admits stays queued and
// counts against its caps.
func pausedRoute(t *testing.T, bob *handlerHost) {
	t.Helper()
	bob.run("handle", "pause", "import")
}

// TestLimitMaxQueuedHoldsAdmission: a route takes asks up to its
// max_queued, the jobs queued counted: at the cap every ask is taken, one
// over waits in the inbox, said once in the round, and is taken in its
// order once the queue has room.
func TestLimitMaxQueuedHoldsAdmission(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].MaxQueued = 2
	bob.write(t)
	pausedRoute(t, bob)
	first := alice.sendTo(t, "documents", "first", "a")
	second := alice.sendTo(t, "documents", "second", "b")
	_, _, stderr := bob.handleRound(t)
	if led := bob.ledger(t); led.Jobs[first.ID] == nil || led.Jobs[second.ID] == nil || strings.Contains(stderr, "at its cap") {
		t.Fatalf("at the cap: %d jobs\n%s", len(led.Jobs), stderr)
	}
	third := alice.sendTo(t, "documents", "third", "c")
	_, _, stderr = bob.handleRound(t)
	if bob.ledger(t).Jobs[third.ID] != nil {
		t.Fatal("one over the cap was admitted")
	}
	if n := strings.Count(stderr, "auu: route import is at its cap; 1 ask waits in the inbox\n"); n != 1 {
		t.Fatalf("the round said it %d times:\n%s", n, stderr)
	}
	bob.run("handle", "resume", "import")
	bob.handleRound(t)
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[third.ID]; job == nil || job.State != jobSucceeded || job.Seq != 2 {
		t.Fatalf("the waiting ask, once there was room: %+v", job)
	}
}

// TestLimitMaxQueuedBytesHoldsAdmission: a route takes asks while their
// bytes are within its max_queued_bytes: at the cap both are taken, one
// byte under it the second waits, and an ask after a waiting one waits too
// whatever its size, so none passes another. An ask larger than the cap by
// itself is said to wait until the cap is raised.
func TestLimitMaxQueuedBytesHoldsAdmission(t *testing.T) {
	alice, bob := newHandler(t)
	pausedRoute(t, bob)
	a := alice.sendTo(t, "documents", "a", strings.Repeat("a", 2000))
	b := alice.sendTo(t, "documents", "b", strings.Repeat("b", 4000))
	c := alice.sendTo(t, "documents", "c", "c")
	bob.run("inbox")
	size := func(id string) int64 {
		m, err := storeOf(t, bob.user).Load(store.Inbox, id)
		if err != nil {
			t.Fatal(err)
		}
		return askBytes(m)
	}
	sa, sb, sc := size(a.ID), size(b.ID), size(c.ID)
	if sa <= 0 || sb <= sa || sc <= 0 {
		t.Fatalf("sizes %d %d %d", sa, sb, sc)
	}
	// One byte short of a and b together: a is taken, b waits, and c,
	// which would fit, waits behind it.
	bob.routes["import"].MaxQueuedBytes = sa + sb - 1
	bob.write(t)
	_, _, stderr := bob.handleRound(t)
	led := bob.ledger(t)
	if led.Jobs[a.ID] == nil || led.Jobs[a.ID].Bytes != sa || led.Jobs[b.ID] != nil || led.Jobs[c.ID] != nil {
		t.Fatalf("one short of the cap: a %+v, b %v, c %v", led.Jobs[a.ID], led.Jobs[b.ID] != nil, led.Jobs[c.ID] != nil)
	}
	if !strings.Contains(stderr, "route import is at its cap; 2 asks wait in the inbox\n") {
		t.Fatalf("the round said:\n%s", stderr)
	}
	if out := bob.run("handle", "status"); !strings.Contains(out, "queued:   "+strconv.FormatInt(sa, 10)+" bytes of max_queued_bytes ") {
		t.Fatalf("status said\n%s", out)
	}
	// At the cap: b is taken, and c waits.
	bob.routes["import"].MaxQueuedBytes = sa + sb
	bob.write(t)
	bob.handleRound(t)
	if led := bob.ledger(t); led.Jobs[b.ID] == nil || led.Jobs[c.ID] != nil {
		t.Fatal("at the cap b was not taken, or c was")
	}
	// With the queue empty and the cap at c's size, c is taken; an ask
	// larger than the cap by itself waits, and says so.
	bob.run("handle", "resume", "import")
	bob.handleRound(t)
	big := alice.sendTo(t, "documents", "big", strings.Repeat("d", 6000))
	bob.routes["import"].MaxQueuedBytes = sc
	bob.write(t)
	bob.run("handle", "pause", "import")
	_, _, stderr = bob.handleRound(t)
	want := "route import is at its cap; 1 ask waits in the inbox, the first, " + big.ID[:12] + ", larger than its max_queued_bytes of " +
		strconv.FormatInt(sc, 10) + " by itself, so it waits until the cap is raised"
	if led := bob.ledger(t); led.Jobs[c.ID] == nil || led.Jobs[big.ID] != nil || !strings.Contains(stderr, want) {
		t.Fatalf("an ask over the cap by itself:\n%s", stderr)
	}
}

// TestLimitAskBytesHoldsAtTheMaximum: an ask's size is the relay's when it
// has one, and otherwise its text and its files' claimed sizes, held at the
// type's maximum rather than wrapping; the route's load is held the same
// way, and a load at the maximum leaves room for nothing but an empty ask.
func TestLimitAskBytesHoldsAtTheMaximum(t *testing.T) {
	ask := func(relay int64, text string, sizes ...int64) *store.Stored {
		m := &store.Stored{RelaySize: relay, Inner: &envelope.Inner{}}
		m.Inner.Body.Text = text
		for _, n := range sizes {
			m.Inner.Body.Attachments = append(m.Inner.Body.Attachments, message.Attachment{Size: n})
		}
		return m
	}
	for _, c := range []struct {
		m    *store.Stored
		want int64
	}{
		{ask(70000, "abc", 5), 70000},
		{ask(0, "abc", 5, 7), 15},
		{ask(0, "abc", math.MaxInt64), math.MaxInt64},
		{ask(0, "", math.MaxInt64, math.MaxInt64), math.MaxInt64},
		{ask(0, "abc", math.MaxInt64-3), math.MaxInt64},
		{ask(0, "abc", math.MaxInt64-4), math.MaxInt64 - 1},
		{ask(0, ""), 0},
	} {
		if got := askBytes(c.m); got != c.want {
			t.Errorf("askBytes = %d, want %d", got, c.want)
		}
	}
	r := &handleRun{
		cfg: &handleConfig{Routes: map[string]*handleRoute{"import": {MaxQueued: 10, MaxQueuedBytes: math.MaxInt64}}},
		led: &handleLedger{Jobs: map[string]*handleJob{
			strings.Repeat("a", 32): {Route: "import", State: jobQueued, Bytes: math.MaxInt64},
			strings.Repeat("b", 32): {Route: "import", State: jobRunning, Bytes: math.MaxInt64},
			strings.Repeat("c", 32): {Route: "import", State: jobSucceeded, Bytes: math.MaxInt64},
		}},
	}
	if jobs, bytes := r.queued("import"); jobs != 2 || bytes != math.MaxInt64 {
		t.Fatalf("queued = %d, %d", jobs, bytes)
	}
	if !r.fits("import", 0) || r.fits("import", 1) {
		t.Fatal("a load at the maximum: want room for an empty ask and nothing more")
	}
	r.cfg.Routes["import"].MaxQueuedBytes = 10
	if r.fits("import", 0) {
		t.Fatal("a load over a lowered cap left room")
	}
}

// A log longer than max_log_bytes is cut to it after the run, its first
// line kept, the end a mark naming the cap and what was written, and the
// cut said; a log at the cap is not cut.
func TestALogOverMaxLogBytesIsCutAndSaid(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["import"].MaxLogBytes = 4096
	bob.write(t)
	for _, n := range []int{4096, 4097, 8000} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Setenv(handlerScript, "spew:"+strconv.Itoa(n))
			alice.sendTo(t, "documents", "spew", "a")
			_, _, stderr := bob.handleRound(t)
			if n == 4096 && strings.Contains(stderr, "was cut at max_log_bytes") {
				t.Fatalf("a log at the cap was cut:\n%s", stderr)
			}
			if n > 4096 && !strings.Contains(stderr, "stderr-1.txt was cut at max_log_bytes of 4096; the script wrote "+strconv.Itoa(n)+" bytes") {
				t.Fatalf("the cut was not said:\n%s", stderr)
			}
		})
	}
	// The log itself, kept for review on a failure.
	t.Setenv(handlerScript, "spew:9000;exit:3")
	sent := alice.sendTo(t, "documents", "kept", "a")
	bob.handleRound(t)
	data, err := os.ReadFile(filepath.Join(bob.keptDir("import", sent.ID), "stderr-1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mark := "\n[handle: the log is cut here at max_log_bytes of 4096; the script wrote 9000 bytes]\n"
	if len(data) != 4096 || !strings.HasPrefix(string(data), "the first line\nxxx") || !strings.HasSuffix(string(data), mark) {
		t.Fatalf("the cut log is %d bytes, beginning %q and ending %q", len(data), data[:20], data[len(data)-100:])
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.Reason != "exited 3: the first line" {
		t.Fatalf("the reason is %q", job.Reason)
	}
}

// A succeeded job's directories go once its reply is saved, and not
// before: a reply that could not be sent leaves them, since it is sent
// from them.
func TestASucceededJobsDirectoriesGoAfterTheReplyIsSaved(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "reply:done")
	sent := alice.sendTo(t, "documents", "a question", "a")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	bob.handleRound(t)
	for _, dir := range []string{bob.jobDir("import", sent.ID), bob.keptDir("import", sent.ID)} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("a job whose reply did not go lost %s: %v", dir, err)
		}
	}
	bob.run("peers", "add", alice.exportLine())
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.Reply == "" {
		t.Fatalf("the reply did not go: %+v", job)
	}
	for _, dir := range []string{bob.jobDir("import", sent.ID), bob.keptDir("import", sent.ID)} {
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("%s is left after the reply was saved", dir)
		}
	}
}

// A failed job's directories, and a skipped one's, stay for keep_failed
// from when it ended and go at the sweep after: a second short of it they
// are there, at it they are gone. The ledger's entry stays.
func TestFailedJobsAreKeptForKeepFailed(t *testing.T) {
	freezeClock(t)
	alice, bob := newHandler(t)
	bob.routes["import"].KeepFailed = "1h"
	bob.write(t)
	failed := failInReview(t, alice, bob, "failed", "no such table")
	pausedRoute(t, bob)
	skipped := alice.sendTo(t, "documents", "skipped", "a")
	bob.handleRound(t)
	bob.run("handle", "skip", skipped.ID)
	bob.handleRound(t)
	// The skipped job never ran and has no directories to keep; it is in
	// the ledger with the time it was skipped.
	if job := bob.ledger(t).Jobs[skipped.ID]; job.Ended.IsZero() {
		t.Fatalf("the skipped job has no end: %+v", job)
	}
	dirs := []string{bob.jobDir("import", failed.ID), bob.keptDir("import", failed.ID)}
	moveClock(t, time.Hour-time.Second)
	bob.handleRound(t)
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("a second short of keep_failed %s is gone: %v", dir, err)
		}
	}
	moveClock(t, time.Second)
	bob.handleRound(t)
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("at keep_failed %s is still there", dir)
		}
	}
	if job := bob.ledger(t).Jobs[failed.ID]; job == nil || job.State != jobFailed {
		t.Fatalf("the swept job's entry: %+v", job)
	}
}

// TestLimitAnEndedAtTheExtremes: a failed job's directories go when it
// ended keep_failed ago or more, at every value the grammar names, and not
// before; a job with no end, or one whose reply is still owed, keeps them.
func TestLimitAnEndedAtTheExtremes(t *testing.T) {
	now := handleNow()
	route := &handleRoute{keepFailed: time.Hour}
	for _, e := range testutil.TimeEdges(now) {
		var want bool
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast, testutil.TheEarliest:
			want = true
		case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead, testutil.OnePastYear9999, testutil.TheLatest:
			want = false
		default:
			t.Fatalf("no answer for %q", e.Name)
		}
		job := &handleJob{State: jobFailed, Review: true, Ended: e.At, Reply: strings.Repeat("e", 32)}
		if got := sweepable(job, route, now.Add(time.Hour)); got != want {
			t.Errorf("ended %s (%v): sweepable %v, want %v", e.Name, e.At, got, want)
		}
	}
	if sweepable(&handleJob{State: jobFailed, Review: true, Reply: strings.Repeat("e", 32)}, route, now) {
		t.Error("a job with no end was swept")
	}
	if sweepable(&handleJob{State: jobFailed, Review: true, Ended: testutil.EarliestInstant()}, route, now) {
		t.Error("a job whose reply is owed was swept")
	}
	if sweepable(&handleJob{State: jobFailed, Review: true, Ended: testutil.EarliestInstant(), Reply: strings.Repeat("e", 32)}, nil, now) {
		t.Error("a job whose route is out of the file was swept")
	}
}

// The sweep removes only the directories of the jobs the ledger names: an
// entry under handle/jobs/ or handle/kept/ that is no job's, a route's
// directory with no job, a file, a link, is said once by name and left, as
// is what a link points at.
func TestTheSweepTouchesOnlyWhatTheLedgerNames(t *testing.T) {
	alice, bob := newHandler(t)
	sent := alice.sendTo(t, "documents", "done", "a")
	handle := filepath.Join(bob.home, "handle")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "precious"), []byte("not handle's"), 0o600); err != nil {
		t.Fatal(err)
	}
	stray := []string{
		filepath.Join(handle, "jobs", "exports", strings.Repeat("a", 32)),
		filepath.Join(handle, "jobs", "import", strings.Repeat("b", 32)),
		filepath.Join(handle, "kept", "import", "notes.txt"),
	}
	for _, path := range stray[:2] {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(stray[2]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray[2], []byte("a host's note"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(handle, "kept", "import", strings.Repeat("c", 32))
	linked := os.Symlink(outside, link) == nil
	_, _, stderr := bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobSucceeded {
		t.Fatalf("the job is %+v", job)
	}
	for _, dir := range []string{bob.jobDir("import", sent.ID), bob.keptDir("import", sent.ID)} {
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("the succeeded job's %s was not swept", dir)
		}
	}
	said := []string{filepath.Join(handle, "jobs", "exports"), stray[1], stray[2]}
	if linked {
		said = append(said, link)
	}
	for _, path := range said {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("the stray %s was removed: %v", path, err)
		}
		if n := strings.Count(stderr, "auu: "+path+" is no job's in the ledger, and is left alone\n"); n != 1 {
			t.Errorf("the stray %s was said %d times:\n%s", path, n, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "precious")); err != nil {
		t.Fatalf("what the link points at was touched: %v", err)
	}
}

// Asks left at a route's cap are taken within the round as the jobs before
// them end: nothing else would wake a service for them, since they are
// fetched already (the reader's finding 1).
func TestAsksLeftAtTheCapAreTakenAsTheQueueDrains(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].MaxQueued = 1
	bob.write(t)
	var sent []sentJSON
	for _, subject := range []string{"one", "two", "three"} {
		sent = append(sent, alice.sendTo(t, "documents", subject, "a"))
	}
	_, _, stderr := bob.handleRound(t)
	for _, s := range sent {
		if job := bob.ledger(t).Jobs[s.ID]; job == nil || job.State != jobSucceeded {
			t.Fatalf("%s after one round: %+v\n%s", s.ID[:12], job, stderr)
		}
	}
	if strings.Contains(stderr, "at its cap") {
		t.Fatalf("a round that took every ask said one waits:\n%s", stderr)
	}
}

// The backlog a route's first round runs is taken under its caps: the
// first ask that does not fit, and those after it, stay in the inbox and
// are said, as at any round (the reader's finding 3).
func TestTheBacklogIsTakenUnderTheCaps(t *testing.T) {
	alice, bob := newHandlerCold(t)
	bob.routes["import"].MaxQueued = 1
	bob.write(t)
	t.Setenv(handlerScript, "say:no such table;exit:3")
	var sent []sentJSON
	for _, subject := range []string{"head", "behind", "last"} {
		sent = append(sent, alice.sendTo(t, "documents", subject, "a"))
	}
	_, _, stderr := bob.handleRound(t, "--backlog")
	led := bob.ledger(t)
	// The head fails for review and holds the route; the next is taken
	// once the head has left the queue, and waits behind it; the last
	// waits in the inbox.
	if led.Jobs[sent[0].ID] == nil || led.Jobs[sent[0].ID].State != jobFailed ||
		led.Jobs[sent[1].ID] == nil || led.Jobs[sent[1].ID].State != jobQueued || led.Jobs[sent[2].ID] != nil {
		t.Fatalf("the backlog under a cap of one: %v %v %v\n%s", led.Jobs[sent[0].ID], led.Jobs[sent[1].ID], led.Jobs[sent[2].ID], stderr)
	}
	if !strings.Contains(stderr, "route import is at its cap; 1 ask waits in the inbox") {
		t.Fatalf("the round said:\n%s", stderr)
	}
}

// A directory a script left that its account may read and not write, as
// an unpacked archive may leave one, is removed with its job all the same.
func TestADirectoryTheScriptCannotWriteIsRemovedWithItsJob(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "rodir:archive;echo:done")
	sent := alice.sendTo(t, "documents", "unpack", "a")
	_, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("the round ended %v\n%s", err, stderr)
	}
	if _, err := os.Stat(bob.jobDir("import", sent.ID)); err == nil {
		t.Fatalf("the job's directory is left:\n%s", stderr)
	}
}

// A job's directories that will not go are said once a run and tried
// again at the next sweep, and neither the round nor the next start ends
// for them; once they can go, they go (the reader's finding 2).
func TestADirectoryThatWillNotGoIsSaidAndTheRunGoesOn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a directory's mode does not stop its entries being removed on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root removes under a directory of any mode")
	}
	alice, bob := newHandler(t)
	sent := alice.sendTo(t, "documents", "stuck", "a")
	routeDir := filepath.Dir(bob.jobDir("import", sent.ID))
	beforeCompose = func() error { return os.Chmod(routeDir, 0o555) }
	t.Cleanup(func() { beforeCompose = nil; os.Chmod(routeDir, 0o700) })
	_, err, stderr := bob.handleRound(t)
	beforeCompose = nil
	said := sent.ID[:12] + "'s directories could not all be removed, and are tried again at the next sweep: "
	if err != nil || strings.Count(stderr, said) != 1 {
		t.Fatalf("the round ended %v and said:\n%s", err, stderr)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobSucceeded || job.Reply == "" {
		t.Fatalf("the job is %+v", job)
	}
	_, err, stderr = bob.handleRound(t)
	if err != nil || strings.Count(stderr, said) != 1 {
		t.Fatalf("the next start ended %v and said:\n%s", err, stderr)
	}
	os.Chmod(routeDir, 0o700)
	bob.handleRound(t)
	if _, err := os.Stat(bob.jobDir("import", sent.ID)); err == nil {
		t.Fatal("the directory that could go again is left")
	}
}

// The sweep runs after every round of one run, as the service runs them,
// and at the start of a run, for what a run that stopped left: a failed
// job's directories go at the round after keep_failed within the run, and
// a succeeded job's directory a crash left goes when the next run opens.
func TestTheSweepRunsAfterEveryRoundAndAtTheStart(t *testing.T) {
	freezeClock(t)
	alice, bob := newHandler(t)
	bob.routes["import"].KeepFailed = "1h"
	// Parallel, so that the failed job holds nothing behind it.
	bob.routes["import"].Execution = executionParallel
	bob.write(t)
	t.Setenv(handlerScript, "say:no such table;exit:3")
	failed := alice.sendTo(t, "documents", "failed", "a")
	t.Setenv("AUU_HOME", bob.home)
	r, release, err := openHandleRun("", false, true)
	if err != nil {
		t.Fatal(err)
	}
	round := func() {
		t.Helper()
		var err error
		captureStderr(t, func() { err = r.round(context.Background(), false, true) })
		if err != nil {
			t.Fatal(err)
		}
	}
	round()
	if _, err := os.Stat(bob.jobDir("import", failed.ID)); err != nil {
		t.Fatalf("the failed job's directory is gone at once: %v", err)
	}
	moveClock(t, time.Hour)
	round()
	if _, err := os.Stat(bob.jobDir("import", failed.ID)); err == nil {
		t.Fatal("the round after keep_failed, in the same run, left the failed job's directory")
	}
	release()

	t.Setenv(handlerScript, "echo:done")
	done := alice.sendTo(t, "documents", "done", "a")
	bob.handleRound(t)
	left := filepath.Join(bob.jobDir("import", done.ID), "attempt-1")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	r, release, err = openHandleRun("", false, true)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Stat(bob.jobDir("import", done.ID)); err == nil {
		t.Fatal("the start left what a stopped run left of a succeeded job")
	}
}

// A file at the name of a job the ledger holds is not that job's
// directory, and is said and left like any stray.
func TestAFileAtAJobsNameIsSaidAndLeft(t *testing.T) {
	alice, bob := newHandlerCold(t)
	waiting := alice.sendTo(t, "documents", "waiting", "a")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[waiting.ID]; job == nil || job.State != jobSkipped {
		t.Fatalf("the first round's ask: %+v", job)
	}
	path := bob.jobDir("import", waiting.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, stderr := bob.handleRound(t)
	if !strings.Contains(stderr, "auu: "+path+" is no job's in the ledger, and is left alone\n") {
		t.Fatalf("the round said:\n%s", stderr)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the file was removed: %v", err)
	}
}
