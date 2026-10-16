package auu

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A long-running expert retries what failed on a quiet mailbox (G48, R63).
// The hold between rounds had no end but new mail or a stop, so a message
// whose handler failed once, or whose kept reply could not be sent, waited
// for unrelated mail or a restart for the retries its channel promised. Now
// the hold ends when the earliest such message is due, and the next round
// tries it. The tests drive the long run itself, with the interval and the
// watcher's pause shortened, and count the watcher's polls.

// longServe is bob's long run, in this process, under ctx: serve as
// cmdServe starts it, without the flags and the unlock.
func longServe(t *testing.T, bob *expert, ctx context.Context) error {
	t.Helper()
	s, id, _ := bob.opened()
	cfg, err := loadServeConfig(bob.path)
	if err != nil {
		t.Fatal(err)
	}
	r := &serveRun{s: s, id: id, cfg: cfg, led: bob.ledgerOf(t), root: s.ServeDir()}
	var runErr error
	captureStderr(t, func() { runErr = r.long(ctx, false) })
	return runErr
}

// quickWatch shortens the interval and the watcher's pause for the test, and
// calls each with the number of the poll it is, under the hold's context.
// A poll's pause is ten milliseconds, so a test that waits for a number of
// polls waits for that many intervals.
func quickWatch(t *testing.T, each func(poll int)) {
	t.Helper()
	oldSleep, oldInterval := watchSleep, serveInterval
	t.Cleanup(func() { watchSleep, serveInterval = oldSleep, oldInterval })
	serveInterval = 10 * time.Millisecond
	var polls atomic.Int64
	watchSleep = func(ctx context.Context, d time.Duration) {
		each(int(polls.Add(1)))
		pauseUntil(ctx, 10*time.Millisecond)
	}
}

// Codex's TestReviewLongServeRetriesWithoutUnrelatedNewMail, renamed: a
// handler that fails is run again on a quiet mailbox, with no new mail to
// wake the run.
func TestServeRetriesOnAQuietMailbox(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "attempts")
	t.Setenv(handlerScript, "append:"+marker+";exit:1")
	sent := alice.ask(t, "jostle", "retry on quiet mailbox", "question")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	quickWatch(t, func(poll int) {
		if poll >= 3 {
			cancel()
		}
	})
	if err := longServe(t, bob, ctx); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readFile(t, marker), "\n"); n < 2 {
		t.Errorf("the handler ran %d time on a quiet mailbox; the failure was never retried", n)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.Failures < 2 {
		t.Errorf("the ledger holds %+v; want two failures or more", e)
	}
}

// A reply the handler wrote and the relay would not take is sent when the
// relay takes posts again, on the quiet mailbox, without the handler run a
// second time.
func TestServeSendsAKeptReplyOnAQuietMailbox(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:an answer worth keeping")
	sent := alice.ask(t, "jostle", "a question", "the first")

	// A gateway in front of the relay that refuses the first mailbox post,
	// the first round's reply: the fetch and the watch go through, and the
	// relay takes posts again from then on.
	var posts atomic.Int64
	_, _, relays := bob.opened()
	target, err := url.Parse(relays[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && posts.Add(1) == 1 {
			http.Error(w, "fixture: the gateway is down for posts", http.StatusBadGateway)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gateway.Close()
	repointRelay(t, bob.user, gateway.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ledgerPath := filepath.Join(bob.home, "serve", ledgerFile)
	quickWatch(t, func(poll int) {
		if l, err := loadLedger(ledgerPath); err == nil {
			if e := l.Messages[sent.ID]; e != nil && !e.Handled.IsZero() {
				cancel()
			}
		}
		if poll >= 60 {
			cancel()
		}
	})
	if err := longServe(t, bob, ctx); err != nil {
		t.Fatalf("the long run ended %v, the kept reply not sent on the quiet mailbox", err)
	}
	e := bob.ledgerOf(t).Messages[sent.ID]
	if e == nil || e.Handled.IsZero() || e.Failures != 1 {
		t.Fatalf("the ledger holds %+v; want one failure and then the answer", e)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times, want 1: the kept reply is what is sent", runs)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "an answer worth keeping" {
		t.Fatalf("the reply is %q", reply.Text)
	}
}

// The control: a message given up on is no work, and with nothing to retry
// the hold has no end but mail or a stop. Forty polls, many intervals, pass
// on the quiet mailbox, and the handler is not run a second time.
func TestServeHoldsAQuietMailboxWithNothingToRetry(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Retries = 1
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:1")
	sent := alice.ask(t, "jostle", "a question", "the first")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	quickWatch(t, func(poll int) {
		if poll >= 40 {
			cancel()
		}
	})
	if err := longServe(t, bob, ctx); err != nil {
		t.Fatal(err)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times over forty quiet polls, want 1", runs)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || !e.GaveUp || e.Failures != 1 {
		t.Fatalf("the ledger holds %+v; want it given up after one attempt", e)
	}
}

// Under the long run a message that keeps failing spends its retries on the
// quiet mailbox and is given up on, and is not run again after.
func TestServeGivesUpUnderTheLongRun(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Retries = 3
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:the handler could not;exit:3")
	sent := alice.ask(t, "jostle", "a question", "the first")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The polls run on long after the third failure (the backoff is 10ms,
	// 20ms and 40ms), so a fourth run would have had its chance.
	quickWatch(t, func(poll int) {
		if poll >= 60 {
			cancel()
		}
	})
	if err := longServe(t, bob, ctx); err != nil {
		t.Fatal(err)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 3 {
		t.Fatalf("the handler ran %d times, want 3", runs)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || !e.GaveUp || e.Failures != 3 || !e.Handled.IsZero() {
		t.Fatalf("the ledger holds %+v; want it given up after three attempts", e)
	}
}

// A stop is still the end of the long run when a retry bounds the hold: the
// caller's cancellation is not taken for the hold's own deadline.
func TestServeStopEndsABoundedHold(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:1")
	alice.ask(t, "jostle", "a question", "the first")
	oldInterval := serveInterval
	t.Cleanup(func() { serveInterval = oldInterval })
	// An hour's interval: the hold is bounded, and the bound is far off.
	serveInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- longServe(t, bob, ctx) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if data, _ := os.ReadFile(marker); strings.Count(string(data), "\n") >= 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the handler never ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a stop during a bounded hold ended the run with %v; want nil", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a stop did not end a bounded hold")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("the test's own context ran out")
	}
}
