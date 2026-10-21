package auu

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The long run, in this process, with the watch's pause and the interval
// shortened as serve's long-run tests shorten them (quickWatch), so that a
// test counts polls rather than waiting out real intervals. Anything a test
// sends while it runs goes from another process, since this one's standard
// output belongs to the run.

// longHandle runs bob's handle run, without --once, until ctx ends, and
// gives the error it ended with.
func longHandle(t *testing.T, bob *handlerHost, ctx context.Context) error {
	t.Helper()
	t.Setenv("AUU_HOME", bob.home)
	r, release, err := openHandleRun("", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var runErr error
	captureStderr(t, func() {
		realStdout := os.Stdout
		null, _ := os.Open(os.DevNull)
		os.Stdout = null
		runErr = r.long(ctx, false)
		os.Stdout = realStdout
		null.Close()
	})
	return runErr
}

// countRounds counts the long run's rounds for the rest of the test.
func countRounds(t *testing.T) *atomic.Int64 {
	t.Helper()
	var rounds atomic.Int64
	afterRound = func(int) { rounds.Add(1) }
	t.Cleanup(func() { afterRound = nil })
	return &rounds
}

// sendFromAnotherProcess has a user send a message without touching this
// process's standard output.
func sendFromAnotherProcess(t *testing.T, u *user, args ...string) {
	t.Helper()
	if out, stderr, code := u.inAnotherProcess(append([]string{"send", "--to", "bob"}, args...)...); code != 0 {
		t.Fatalf("send %v: exit %d\n%s%s", args, code, out, stderr)
	}
}

// The long run holds on the relays for mail on its routes' channels and on
// nothing else: an ask on a channel no route takes does not wake it, and an
// ask on a route's channel does, and is run.
func TestTheLongRunWakesForMailOnARoutesChannelOnly(t *testing.T) {
	alice, bob := newHandler(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker)
	rounds := countRounds(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var sentElsewhere, sentToTheRoute bool
	var roundsBefore int64
	quickWatch(t, func(poll int) {
		switch {
		case poll == 3 && !sentElsewhere:
			sentElsewhere = true
			sendFromAnotherProcess(t, alice, "--channel", "images", "--subject", "a picture", "not for the route")
		case poll == 60 && !sentToTheRoute:
			roundsBefore = rounds.Load()
			sentToTheRoute = true
			sendFromAnotherProcess(t, alice, "--channel", "documents", "--subject", "for the route", "run me")
		case sentToTheRoute:
			if data, err := os.ReadFile(marker); err == nil && strings.Count(string(data), "\n") == 1 {
				cancel()
			}
		}
		if poll >= 3000 {
			cancel()
		}
	})
	if err := longHandle(t, bob, ctx); err != nil {
		t.Fatalf("the long run ended %v", err)
	}
	if roundsBefore != 1 {
		t.Fatalf("an ask on a channel no route takes woke the run: %d rounds before the route's ask", roundsBefore)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
}

// A job whose retry falls due ends the hold on a quiet mailbox: the long
// run runs it again with no new mail to wake it.
func TestTheHoldEndsAtRetryAt(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.routes["import"].Retries = 2
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:3")
	sent := alice.sendTo(t, "documents", "retried", "on a quiet mailbox")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	quickWatch(t, func(poll int) {
		if data, err := os.ReadFile(marker); err == nil && strings.Count(string(data), "\n") == 2 {
			cancel()
		}
		if poll >= 3000 {
			cancel()
		}
	})
	if err := longHandle(t, bob, ctx); err != nil {
		t.Fatalf("the long run ended %v", err)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.Attempt != 2 || job.State != jobFailed || !job.Review {
		t.Fatalf("the job is %+v; want its retry run on the quiet mailbox", job)
	}
}

// An operator's request landing in handle/ops/ ends the hold, so that the
// next round, which applies it, comes within a poll and not at the next
// mail; a file that is not a request's shape, as a desktop leaves, wakes
// nothing, and a request still there at the next hold, which nothing in
// this version takes away, does not end that hold too.
func TestAnOperatorRequestWakesTheHold(t *testing.T) {
	_, bob := newHandler(t)
	was := handleOpsPoll
	handleOpsPoll = 10 * time.Millisecond
	t.Cleanup(func() { handleOpsPoll = was })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rounds := countRounds(t)
	ops := filepath.Join(bob.home, "handle", "ops")
	var secondAt int
	quickWatch(t, func(poll int) {
		switch {
		case poll == 5:
			os.MkdirAll(ops, 0o700)
			os.WriteFile(filepath.Join(ops, ".DS_Store"), []byte("a desktop's"), 0o600)
		case poll == 40:
			if n := rounds.Load(); n != 1 {
				t.Errorf("a file of no request's shape woke the hold: %d rounds", n)
			}
			os.WriteFile(filepath.Join(ops, "1-retry-x.json"), []byte("{}"), 0o600)
		case poll > 40 && secondAt == 0 && rounds.Load() >= 2:
			secondAt = poll
		case secondAt > 0 && poll >= secondAt+60:
			cancel()
		}
		if poll >= 5000 {
			cancel()
		}
	})
	if err := longHandle(t, bob, ctx); err != nil {
		t.Fatalf("the long run ended %v", err)
	}
	if secondAt == 0 {
		t.Fatal("the request did not wake the hold")
	}
	if n := rounds.Load(); n != 2 {
		t.Fatalf("the request left in place woke the hold again: %d rounds", n)
	}
}

// The hold is not woken for a job its route would not run: behind a
// sequential route's head in review, a job whose retry is past is not due,
// so nothing is; on a parallel route it is.
func TestTheHoldIsNotWokenForAJobItsHeadHolds(t *testing.T) {
	past := handleNow().Add(-time.Hour)
	r := &handleRun{
		cfg: &handleConfig{Routes: map[string]*handleRoute{"import": {Execution: executionSequential, Retries: 3}}},
		led: &handleLedger{Jobs: map[string]*handleJob{
			strings.Repeat("a", 32): {Route: "import", Seq: 0, State: jobFailed, Review: true},
			strings.Repeat("b", 32): {Route: "import", Seq: 1, State: jobQueued, Failures: 1, RetryAt: past},
		}},
	}
	if due := r.nextDue(); !due.IsZero() {
		t.Fatalf("a job its head holds made the hold due at %v", due)
	}
	r.cfg.Routes["import"].Execution = executionParallel
	if due := r.nextDue(); due.IsZero() {
		t.Fatal("a parallel route's due job did not make the hold due")
	}
}

// One handle run per home: a second, while the first holds the lock, is
// refused at exit 2 by name, before anything is fetched or run.
func TestOneHandleRunPerHome(t *testing.T) {
	_, bob := newHandler(t)
	lock, err := takeHandleLock(filepath.Join(bob.home, "handle"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	_, err = bob.tryRun("handle", "run", "--once")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(e.Error(), "another auu handle run is running in this home") {
		t.Fatalf("a second handle run: %v", err)
	}
}

// Keys that lock under a running service end it at exit 4, with nothing
// counted against the job, its reply kept; the next run, unlocked, sends it
// without running the script again.
func TestHandleRunStopsAtExitFourWhenTheKeysLock(t *testing.T) {
	alice, bob := newHandler(t)
	agentEnv(t)
	bob.encrypt()
	bob.run("unlock", "--send", "--ttl", "0", "--passphrase-file", passphraseFile(t, agentPassphrase))
	dir := t.TempDir()
	started, marker := filepath.Join(dir, "started"), filepath.Join(dir, "runs")
	t.Setenv(handlerScript, "append:"+marker+";append:"+started+";sleep:2s;reply:handled before the lock")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var sent, locked bool
	quickWatch(t, func(poll int) {
		if poll == 3 && !sent {
			sent = true
			sendFromAnotherProcess(t, alice, "--channel", "documents", "--subject", "a question", "please")
		}
		if poll >= 3000 {
			cancel()
		}
	})
	go func() {
		for ctx.Err() == nil {
			if _, err := os.Stat(started); err == nil && !locked {
				locked = true
				bob.inAnotherProcess("lock")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	// The program's main maps a locked identity to exit 4, as for every
	// command.
	if err := longHandle(t, bob, ctx); !isLocked(err) {
		t.Fatalf("the long run whose keys locked ended %v, want the locked error that is exit 4", err)
	}
	var id string
	for jobID := range bob.ledger(t).Jobs {
		id = jobID
	}
	if job := bob.ledger(t).Jobs[id]; job == nil || job.State != jobSucceeded || job.Reply != "" || job.ReplyFailures != 0 {
		t.Fatalf("the job was recorded against: %+v", job)
	}
	bob.run("unlock", "--send", "--ttl", "0", "--passphrase-file", passphraseFile(t, agentPassphrase))
	bob.handleRound(t)
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times, want once: its reply was kept", runs)
	}
	if job := bob.ledger(t).Jobs[id]; job.Reply == "" {
		t.Fatalf("the kept reply did not go after the unlock: %+v", job)
	}
}

// auu handle run without --once is the service, as its own process the way
// a unit runs it: it takes the ask that arrives, runs it and replies, and
// holds; SIGTERM ends it at exit 0. Unix only: Windows delivers no SIGTERM.
func TestHandleRunWithoutOnceIsTheServiceAndAStopEndsItAtZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows delivers no SIGTERM")
	}
	alice, bob := newHandler(t)
	sent := alice.sendTo(t, "documents", "for the service", "please")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "handle", "run")
	cmd.Env = append(os.Environ(), helperEnv+"=1", "AUU_HOME="+bob.home)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if l, err := loadHandleLedger(filepath.Join(bob.home, "handle", handleLedgerFile)); err == nil {
			if job := l.Jobs[sent.ID]; job != nil && job.Reply != "" {
				break
			}
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("the service did not reply to the ask")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the service ended %v at the stop, want exit 0", err)
		}
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("the service did not stop")
	}
}
