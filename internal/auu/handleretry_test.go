package auu

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A started attempt that fails on a route that is not idempotent may have
// done its work, so it is never run again: a nonzero exit is failed for
// review at once, attempt 1 of 1, and its reply goes; a second round runs
// nothing.
func TestANonIdempotentRouteGoesToReviewOnANonzeroExit(t *testing.T) {
	alice, bob := newHandler(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:3")
	sent := alice.sendTo(t, "documents", "once", "only once")
	bob.handleRound(t)
	moveClock(t, time.Hour)
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || job.Attempt != 1 {
		t.Fatalf("the job is %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 1 || r[0].Text != "handle: failed (exit 3, attempt 1 of 1)" {
		t.Fatalf("the replies are %+v", r)
	}
}

// The same for a timeout.
func TestANonIdempotentRouteGoesToReviewOnATimeout(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Timeout = "2s"
	bob.routes["import"].Retries = 3
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";sleep:30s")
	sent := alice.sendTo(t, "documents", "slow", "too slow")
	bob.handleRound(t)
	moveClock(t, time.Hour)
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || !job.TimedOut || job.Attempt != 1 {
		t.Fatalf("the job is %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
}

// And for an interruption: a run stopped while the script ran writes the
// job interrupted, killed by its own stop; the next round puts it in
// review, since the route is not idempotent, and its reply says so.
func TestANonIdempotentRouteGoesToReviewOnAnInterruption(t *testing.T) {
	alice, bob := newHandler(t)
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv(handlerScript, "append:"+started+";sleep:60s")
	sent := alice.sendTo(t, "documents", "interrupted", "stopped mid-run")
	stopWhenStarted(t, bob, started)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobInterrupted || !job.Killed || !job.Interrupted || job.Ended.IsZero() {
		t.Fatalf("after the stop the job is %+v", job)
	}
	bob.handleRound(t)
	job = bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || job.Reason != "interrupted on a route that is not idempotent, so it is not run again" {
		t.Fatalf("after the next round the job is %+v", job)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 1 || r[0].Text != "handle: failed (interrupted, attempt 1 of 1)" {
		t.Fatalf("the replies are %+v", r)
	}
}

// stopWhenStarted runs one round in this process, as handle run --once
// does, and stops it the way a signal does, by ending its context, once
// the script has written to started.
func stopWhenStarted(t *testing.T, bob *handlerHost, started string) {
	t.Helper()
	t.Setenv("AUU_HOME", bob.home)
	r, release, err := openHandleRun("", false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			if _, err := os.Stat(started); err == nil {
				cancel()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	var runErr error
	captureStderr(t, func() {
		realStdout := os.Stdout
		null, _ := os.Open(os.DevNull)
		os.Stdout = null
		runErr = r.once(ctx, false)
		os.Stdout = realStdout
		null.Close()
	})
	if runErr != nil {
		t.Fatalf("a stopped run ended %v; a stop is not a failure", runErr)
	}
}

// A stop kills the script and everything it started, waits for them, and
// writes the job interrupted with killed true and its end before the run
// ends; the child the script started is gone too (off Windows, where
// whether a process is there is asked by signal zero).
func TestAStopWritesInterruptedWithKilledBeforeExiting(t *testing.T) {
	alice, bob := newHandler(t)
	dir := t.TempDir()
	pidFile, started := filepath.Join(dir, "pid"), filepath.Join(dir, "started")
	t.Setenv(handlerScript, "spawn:"+pidFile+";append:"+started+";sleep:60s")
	sent := alice.sendTo(t, "documents", "stopped", "stop me")
	began := time.Now()
	stopWhenStarted(t, bob, started)
	if took := time.Since(began); took > 30*time.Second {
		t.Fatalf("the stop took %s", took)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobInterrupted || !job.Killed || job.Ended.IsZero() || job.Reason != "the service was stopped while it ran" {
		t.Fatalf("the job is %+v", job)
	}
	if runtime.GOOS == "windows" {
		return
	}
	pid := 0
	fmt.Sscanf(strings.TrimSpace(readFile(t, pidFile)), "%d", &pid)
	deadline := time.Now().Add(5 * time.Second)
	for syscallKill(pid) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("the script's child (pid %d) outlived the stop", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// On an idempotent route a started attempt that fails is run again at
// serve's backoff, up to the route's retries attempts in all, and only the
// last, failed for review, gets a reply, saying which attempt of how many.
func TestAnIdempotentRouteRetriesUpToRetriesThenReviews(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:3")
	sent := alice.sendTo(t, "documents", "retried", "try again")
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || job.Review || job.Attempt != 1 || job.RetryAt.IsZero() {
		t.Fatalf("after one failure the job is %+v", job)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 0 {
		t.Fatalf("a reply went before the job ended: %+v", r)
	}
	// Not before its retry is due.
	bob.handleRound(t)
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times before its retry was due", runs)
	}
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	moveClock(t, retryBackoff(2))
	bob.handleRound(t)
	job = bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || job.Attempt != 3 {
		t.Fatalf("after the retries the job is %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 3 {
		t.Fatalf("the script ran %d times", runs)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 1 || r[0].Text != "handle: failed (exit 3, attempt 3 of 3)" {
		t.Fatalf("the replies are %+v", r)
	}
}

// A failure before launch is retried at serve's backoff: not before the
// first interval, and then not before twice it.
func TestAPreLaunchFailureRetriesWithServesBackoff(t *testing.T) {
	alice, bob := newHandler(t)
	// The clock is held still, so that "a second before" is a second
	// before whatever second the round began in: a run slow enough to
	// cross into the next second between the round and the move would
	// otherwise find the retry due.
	freezeClock(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	bob.run("inbox")
	plantBadDigest(t, bob, sent.ID)
	bob.handleRound(t)
	first := bob.ledger(t).Jobs[sent.ID]
	if first.Failures != 1 || !first.RetryAt.Equal(handleNow().Add(retryBackoff(1))) {
		t.Fatalf("after one failure: %+v; want its retry one interval on", first)
	}
	moveClock(t, retryBackoff(1)-time.Second)
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.Failures != 1 {
		t.Fatalf("a second before its retry the job was tried: %+v", job)
	}
	moveClock(t, time.Second)
	bob.handleRound(t)
	second := bob.ledger(t).Jobs[sent.ID]
	if second.Failures != 2 || !second.RetryAt.Equal(handleNow().Add(retryBackoff(2))) {
		t.Fatalf("after two failures: %+v; want its retry twice the interval on", second)
	}
}

// A run that went away with a job running, killed from outside with the
// ledger at running, leaves the next start a job interrupted, not killed
// by the service: it is put in review even on an idempotent route, since
// nothing says the script is gone; with supervisor_reaps, the host's word
// that it is, it is queued again and runs.
func TestACrashBetweenRunningAndTerminalIsInterruptedThenReviewed(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.write(t)
	t.Setenv(handlerScript, "exit:3")
	sent := alice.sendTo(t, "documents", "crashed", "the run went away")
	bob.handleRound(t)
	plantRunning := func() {
		l := bob.ledger(t)
		job := l.Jobs[sent.ID]
		job.State, job.Review, job.Attempt, job.Started = jobRunning, false, 2, handleNow()
		if err := l.save(); err != nil {
			t.Fatal(err)
		}
	}
	plantRunning()
	_, _, stderr := bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || job.Killed ||
		job.Reason != "interrupted, and nothing says its script is gone: the service did not stop it and supervisor_reaps is not set" {
		t.Fatalf("after the crash the job is %+v\n%s", job, stderr)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 1 || r[0].Text != "handle: failed (interrupted, attempt 2 of 3)" {
		t.Fatalf("the replies are %+v", r)
	}

	// With supervisor_reaps it runs again.
	second := alice.sendTo(t, "documents", "crashed again", "and was reaped")
	t.Setenv(handlerScript, "exit:3")
	bob.handleRound(t)
	bob.reaps = true
	bob.write(t)
	l := bob.ledger(t)
	// The first job, in review, holds the sequential route; it is set aside
	// as an operator's skip would.
	l.Jobs[sent.ID].State, l.Jobs[sent.ID].By = jobSkipped, skippedByOperator
	j := l.Jobs[second.ID]
	j.State, j.Review, j.Attempt, j.Started = jobRunning, false, 1, handleNow()
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(handlerScript, "echo:done")
	bob.handleRound(t)
	if j := bob.ledger(t).Jobs[second.ID]; j.State != jobSucceeded || j.Attempt != 2 {
		t.Fatalf("with supervisor_reaps the job is %+v", j)
	}
}

// Each attempt is given a fresh copy of the asker's files: a script that
// edits its copy and fails gets the original next time.
func TestAScriptThatEditsAnAttachmentAndFailsGetsAFreshCopyNextTime(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.write(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := filepath.Join(t.TempDir(), "seen")
	t.Setenv(handlerScript, "snapshot:AUU_ATTACHMENTS="+seen+";into:AUU_ATTACHMENTS/data.csv=edited;exit:3")
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	bob.handleRound(t)
	if got := readFile(t, filepath.Join(seen, "data.csv")); got != "a,b\n" {
		t.Fatalf("the first attempt was given %q", got)
	}
	os.RemoveAll(seen)
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.Attempt != 2 {
		t.Fatalf("the job is %+v", job)
	}
	if got := readFile(t, filepath.Join(seen, "data.csv")); got != "a,b\n" {
		t.Fatalf("the second attempt was given %q, not a fresh copy", got)
	}
}

// A retry waiting its turn is decided again under the file as it is when
// it is due: a route made not idempotent since the failure does not run
// the job a second time, which is put in review with its reply.
func TestARetryIsDecidedAgainUnderTheFileAsItIsNow(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	// A first line long enough that the reason is cut: what is added on
	// review must still be there whole.
	t.Setenv(handlerScript, "append:"+marker+";say:"+strings.Repeat("w", 600)+";exit:3")
	sent := alice.sendTo(t, "documents", "retried", "try again")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobFailed || job.Review {
		t.Fatalf("after one failure the job is %+v", job)
	}
	bob.routes["import"].Idempotent = false
	bob.write(t)
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || job.Attempt != 1 || !job.Redecided || len(job.Reason) > maxReason ||
		!strings.HasSuffix(job.Reason, "; not run again: the route is no longer idempotent, or its attempts are spent") {
		t.Fatalf("after the file changed the job is %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 1 || r[0].Text != "handle: failed (exit 3, attempt 1 of 1)" {
		t.Fatalf("the replies are %+v", r)
	}
}

// A stop that comes while a job is being prepared starts no attempt: the
// job is left queued, with no attempt counted, and the next run prepares
// and runs it.
func TestAStopWhilePreparingStartsNoAttempt(t *testing.T) {
	alice, bob := newHandler(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker)
	sent := alice.sendTo(t, "documents", "stopped early", "before it starts")
	t.Setenv("AUU_HOME", bob.home)
	r, release, err := openHandleRun("", false, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	beforeOriginalRename = func(string) error { cancel(); return nil }
	captureStderr(t, func() { err = r.once(ctx, false) })
	beforeOriginalRename = nil
	release()
	if err != nil {
		t.Fatalf("the stopped run ended %v", err)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobQueued || job.Attempt != 0 {
		t.Fatalf("after the stop the job is %+v", job)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the script was started")
	}
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobSucceeded || job.Attempt != 1 {
		t.Fatalf("the next run left the job %+v", job)
	}
}

// A job that ran and was interrupted, queued again, and then failed before
// launch until its retries were spent is in review for its failure before
// launch: its reply says it could not be prepared, and nothing of the
// interruption or the earlier attempt.
func TestAFailureBeforeLaunchAfterAnInterruptionSaysWhatEndedIt(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.routes["import"].Retries = 2
	bob.write(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv(handlerScript, "append:"+started+";sleep:60s")
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	stopWhenStarted(t, bob, started)
	// The asker's files will not unpack any more.
	os.RemoveAll(filepath.Join(bob.jobDir("import", sent.ID), "original"))
	plantBadDigest(t, bob, sent.ID)
	bob.handleRound(t)
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || !job.BeforeLaunch || job.Interrupted {
		t.Fatalf("the job is %+v", job)
	}
	r := repliesOn(t, alice, sent.Thread)
	if len(r) != 1 || !strings.HasPrefix(r[0].Text, "handle: failed (could not prepare: the files it sent could not be unpacked: ") ||
		strings.Contains(r[0].Text, "were not kept") || strings.Contains(r[0].Text, "interrupted") {
		t.Fatalf("the replies are %+v", r)
	}
}

// The same whatever state the way back left a job that has run: a retry
// whose files then would not unpack is queued again with its attempt
// counted, and a route made not idempotent after that does not run it a
// second time either, and the reply holds no sentence about a stop.
func TestARetryQueuedAgainIsDecidedAgainToo(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.write(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:"+strings.Repeat("w", 600)+";exit:3")
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	bob.handleRound(t)
	os.RemoveAll(filepath.Join(bob.jobDir("import", sent.ID), "original"))
	plantBadDigest(t, bob, sent.ID)
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobQueued || job.Attempt != 1 || job.Failures != 1 {
		t.Fatalf("after the retry's unpack failed the job is %+v", job)
	}
	bob.routes["import"].Idempotent = false
	bob.write(t)
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	const notAgain = "; not run again: the route is no longer idempotent, or its attempts are spent"
	if job.State != jobFailed || !job.Review || !job.Redecided || len(job.Reason) > maxReason || !strings.HasSuffix(job.Reason, notAgain) {
		t.Fatalf("the job is %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 1 || strings.Contains(r[0].Text, "were not kept") {
		t.Fatalf("the replies are %+v", r)
	}
}

// freezeClock holds handle's clock at the second it is now for the rest of
// the test; moveClock moves it from there.
func freezeClock(t *testing.T) {
	t.Helper()
	was := handleNow
	at := handleNow()
	handleNow = func() time.Time { return at }
	t.Cleanup(func() { handleNow = was })
}
