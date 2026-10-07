package auu

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// waitGate sits in front of a real relay and misbehaves on the mailbox list
// the way a relay in trouble does: it hangs without answering, drops the
// connection, answers a status, or answers the listing with its count
// taken out. Everything else passes through, so the users behind it
// are real and so is the thread they wait on.
type waitGate struct {
	inner http.Handler
	mu    sync.Mutex
	mode  string // "", "hang", "drop", "old", or a status to answer
	left  int    // misbehaviours still to perform; negative means for ever
	pass  int    // listings served as they are before the misbehaviour begins
	lists atomic.Int32
	// requests counts everything that reached the gate, listings or not,
	// and seen is each one's method and path, in order.
	requests atomic.Int32
	seen     []string
	// cancelled says a hung request saw its context done before anything
	// was written: the client cut it off, not the transport.
	cancelled atomic.Bool
	// held is the longest a listing that asked for a hold took the real
	// relay to answer, in nanoseconds: the relay's side of the hold.
	held atomic.Int64
	// asked is the query of the last listing that asked for a hold.
	asked atomic.Pointer[string]
	// answered counts listings that asked for a hold and were answered by
	// the relay, as against cut off by the client before an answer; cut
	// says at least one was cut off that way.
	answered atomic.Int32
	cut      atomic.Bool
	// stubsLists counts the listings that asked for stubs, which are the
	// refreshes: a fetch that has nothing to check, or whose relay says
	// its mailbox is empty, must make none.
	stubsLists atomic.Int32
	// dropStubs makes the gate drop the connection on a listing that asks
	// for stubs, and only on those: the fetch's own pages are served, and
	// the refresh that follows them is what meets the failure.
	dropStubs atomic.Bool
	// polls is when each listing the real relay served arrived and was
	// done with, in order, and whether it asked for a hold: the timing of
	// a poll sequence, for a test about what follows what.
	polls []pollTiming
}

// pollTiming is one listing's arrival at the gate and the moment the real
// relay was done with it, answered or cut off.
type pollTiming struct {
	arrived, done time.Time
	held          bool
}

// timings is the poll sequence so far.
func (g *waitGate) timings() []pollTiming {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]pollTiming(nil), g.polls...)
}

// wrote is a ResponseWriter that says whether anything was written.
type wrote struct {
	http.ResponseWriter
	did atomic.Bool
}

func (w *wrote) WriteHeader(code int) { w.did.Store(true); w.ResponseWriter.WriteHeader(code) }
func (w *wrote) Write(p []byte) (int, error) {
	w.did.Store(true)
	return w.ResponseWriter.Write(p)
}

func (g *waitGate) set(mode string, times int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode, g.left = mode, times
}

func (g *waitGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	g.mu.Lock()
	g.seen = append(g.seen, r.Method+" "+r.URL.Path)
	g.mu.Unlock()
	isList := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && !strings.HasSuffix(r.URL.Path, "/channels") &&
		!strings.HasSuffix(r.URL.Path, "/blob")
	if !isList {
		g.inner.ServeHTTP(w, r)
		return
	}
	g.lists.Add(1)
	if strings.Contains(r.URL.RawQuery, "stubs=1") {
		g.stubsLists.Add(1)
	}
	if g.dropStubs.Load() && strings.Contains(r.URL.RawQuery, "stubs=1") {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
		return
	}
	g.mu.Lock()
	mode := g.mode
	if g.pass > 0 {
		// Served as they are before the misbehaviour begins.
		g.pass--
		mode = ""
	} else if g.left == 0 {
		mode = ""
	} else if g.left > 0 {
		g.left--
	}
	g.mu.Unlock()
	switch mode {
	case "":
		query := r.URL.RawQuery
		start := time.Now()
		ww := &wrote{ResponseWriter: w}
		g.inner.ServeHTTP(ww, r)
		held := strings.Contains(query, "wait=")
		g.mu.Lock()
		g.polls = append(g.polls, pollTiming{arrived: start, done: time.Now(), held: held})
		g.mu.Unlock()
		if held {
			g.asked.Store(&query)
			if took := int64(time.Since(start)); took > g.held.Load() {
				g.held.Store(took)
			}
			if ww.did.Load() {
				g.answered.Add(1)
			} else if r.Context().Err() != nil {
				g.cut.Store(true)
			}
		}
	case "hang":
		<-r.Context().Done()
		g.cancelled.Store(true)
	case "drop":
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
	case "old":
		// The real relay's answer with the count taken out, mail and all;
		// the client reads an absent count as zero.
		rec := httptest.NewRecorder()
		g.inner.ServeHTTP(rec, r)
		var answer map[string]json.RawMessage
		if rec.Code == http.StatusOK && json.Unmarshal(rec.Body.Bytes(), &answer) == nil {
			delete(answer, "queued")
			rec.Body.Reset()
			json.NewEncoder(rec.Body).Encode(answer)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	default:
		// A status, and after a space the body to answer it with: a
		// sentence, or a refusal's code and sentence as CODE|SENTENCE.
		code, body, _ := strings.Cut(mode, " ")
		status, err := strconv.Atoi(code)
		if err != nil {
			panic("waitGate: bad mode " + mode)
		}
		if body == "" {
			body = "as the gate says"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		refusalCode, sentence, coded := strings.Cut(body, "|")
		if !coded {
			refusalCode, sentence = "", body
		}
		json.NewEncoder(w).Encode(relayapi.ErrorResponse{Error: sentence, Code: refusalCode})
	}
}

func startGatedRelay(t *testing.T) (string, *waitGate) {
	t.Helper()
	url, gate, _ := startGatedRelayStore(t)
	return url, gate
}

// startGatedRelayStore is startGatedRelay with the relay's store, for a test
// that reads what the relay still holds.
func startGatedRelayStore(t *testing.T) (string, *waitGate, *relay.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	gate := &waitGate{inner: relay.NewServer(st, relay.Config{
		Streams: true,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limits:  relay.DefaultLimits(),
	})}
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)
	return srv.URL, gate, st
}

// since is the requests seen from the n'th on.
func (g *waitGate) since(n int) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen[n:]...)
}

// aboutTheInterval reports whether a pause is the interval less the moment
// the poll before it took: no more than the interval, and not so much less
// that it could be anything else, such as a floor or nothing.
func aboutTheInterval(pause, interval time.Duration) bool {
	return pause <= interval && pause > interval/2
}

// peersWithAThread makes alice and bob on the relay, each in the other's
// peer list, and returns the thread of a message alice has sent bob.
func peersWithAThread(t *testing.T, relayURL string) (alice, bob *user, thread string) {
	t.Helper()
	alice = newUser(t, "alice", relayURL)
	bob = newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "waiting", "--json", "reply when you can")), &sent); err != nil {
		t.Fatal(err)
	}
	return alice, bob, sent.Thread
}

// A relay that accepts the connection and never answers is cut off when the
// wait is over, not when the transport gives up on it: every poll runs under
// the wait's own deadline. The proof is the relay's side of the connection
// seeing the request cancelled, not only that wait returned. The container
// suite's N02 found a ten-second wait answering after the transport's
// handshake timeout, with the transport's exit code.
func TestWaitReturnsAtItsTimeoutWhenTheRelayHangs(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice, _, thread := peersWithAThread(t, relayURL)
	gate.set("hang", -1)

	start := time.Now()
	_, err := alice.tryRun("wait", "--thread", thread, "--timeout", "3s", "--interval", "5s")
	took := time.Since(start)
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("wait against a hung relay: %v, want exit %d", err, exitTimeout)
	}
	if want := "timed out waiting for thread " + thread; err.Error() != want {
		t.Fatalf("error %q, want %q", err, want)
	}
	// Its own deadline, and nothing like the transport's two minutes; the
	// upper bound is loose because it measures the runner, not the claim.
	if took < 3*time.Second || took > 20*time.Second {
		t.Fatalf("wait returned after %s, want its own 3s", took)
	}
	// The relay's side of the cancellation is asynchronous: the handler
	// sets the flag when the server notices the closed connection, which
	// on a loaded machine can be after wait has returned. The claim is
	// that it happens, so it is polled for, not read once; the timing
	// claim is the one above.
	deadline := time.Now().Add(10 * time.Second)
	for !gate.cancelled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the hung request was never cancelled on the relay's side; wait returned some other way")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A poll that fails for a reason waiting may outlast — the connection
// dropped, the relay failing — is said and tried again at the next interval,
// because the point of the command is to wait; the reply that arrives in the
// meantime is delivered.
func TestWaitOutlastsATransportFailure(t *testing.T) {
	var slept []time.Duration
	waitSleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { waitSleep = time.Sleep })

	for _, tc := range []struct{ name, mode, said string }{
		{"the connection dropped", "drop", "contacting relay"},
		{"the relay failing", "500", "relay returned 500: as the gate says"},
		// The one 500 the relay actually produces, which auu turns into
		// a sentence: the sentence must keep the status beneath it, or a
		// wait would end on the very failure it is meant to outlast.
		{"the relay's storage failing", "500 " + relayapi.CodeStorageError + "|" + relayapi.MsgStorageError,
			"the relay could not store or read a message (storage error); whoever runs it needs to look at its log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relayURL, gate := startGatedRelay(t)
			alice, bob, thread := peersWithAThread(t, relayURL)
			var inbox inboxJSON
			if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
				t.Fatal(err)
			}
			bob.run("reply", inbox.Messages[0].ID, "here it is")

			slept = nil
			gate.lists.Store(0)
			gate.set(tc.mode, 2)
			var out string
			var err error
			warning := captureStderr(t, func() {
				out, err = alice.tryRun("wait", "--thread", thread, "--timeout", "1m", "--interval", "5s", "--json")
			})
			if err != nil {
				t.Fatalf("wait gave up on a failure it should have outlasted: %v", err)
			}
			var got waitJSON
			if err := json.Unmarshal([]byte(out), &got); err != nil || !got.Found || got.Message.Subject != "waiting" {
				t.Fatalf("wait --json: %v %s", err, out)
			}
			// At least one poll failed and was tried again after the
			// interval. The exact count is not the wait's to pin: on a
			// dropped connection net/http retries an idempotent GET once
			// on its own, and may spend both drops inside one poll.
			if gate.lists.Load() < 3 || len(slept) == 0 {
				t.Fatalf("%d polls and %v slept; the failure was not outlasted", gate.lists.Load(), slept)
			}
			// The pause is what is left of the interval since the poll
			// began, which for a poll that failed in a moment is the
			// interval less that moment.
			for _, d := range slept {
				if !aboutTheInterval(d, 5*time.Second) {
					t.Fatalf("slept %v between polls, want what is left of the 5s interval", slept)
				}
			}
			if n := strings.Count(warning, "; trying again in 5s\n"); n != len(slept) || !strings.HasPrefix(warning, "warning: ") {
				t.Fatalf("stderr says the poll failed %d times for %d retries:\n%s", n, len(slept), warning)
			}
			if !strings.Contains(warning, tc.said) {
				t.Fatalf("the warning does not carry %q:\n%s", tc.said, warning)
			}
		})
	}
}

// A failure no interval will change ends the wait at once, with the failure
// and the transport's exit code: a relay that answered and refused is a
// person's problem, and ten minutes of polling would only hide it.
func TestWaitStopsForAFailureThatWillNotPass(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice, _, thread := peersWithAThread(t, relayURL)
	waitSleep = func(time.Duration) { t.Fatal("wait slept after a failure that will not pass") }
	t.Cleanup(func() { waitSleep = time.Sleep })
	gate.set("404", -1)

	_, err := alice.tryRun("wait", "--thread", thread, "--timeout", "1m", "--interval", "5s")
	// errors.As, as Main does: the failure is wrapped in the relay's name.
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("wait against a relay that refused: %v, want exit %d", err, exitTransport)
	}
	if !strings.Contains(err.Error(), "relay returned 404") {
		t.Fatalf("error %q does not carry the refusal", err)
	}
	if n := gate.lists.Load(); n != 1 {
		t.Fatalf("%d polls, want the one that was refused", n)
	}
}

// Two fetches from one machine take turns: the second waits for the first
// and finds the mailbox drained, so every message is delivered once and
// counted once. Without the lock both list the same messages, save them
// twice and count them twice. The container suite's N03 found both of two
// fetches delivering all three.
func TestTwoFetchesTakeTurns(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	for i := 0; i < 3; i++ {
		alice.run("send", "--to", "bob", "--subject", "at once", "one of three")
	}

	// Two independent stores on one home, as two processes would have.
	open := func(t *testing.T) (*store.Store, *identity.Identity, *client.Client, *store.Relay) {
		t.Helper()
		s, err := store.Open(bob.home)
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.Identity()
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.DefaultRelay()
		if err != nil {
			t.Fatal(err)
		}
		c, err := dial(s, id, r)
		if err != nil {
			t.Fatal(err)
		}
		return s, id, c, r
	}
	s1, id1, c1, r1 := open(t)
	s2, id2, c2, r2 := open(t)

	// Both start against a lock the test holds, and the test lets go only
	// once both have asked for it and found it held — seen through the
	// pause between asks, which the test supplies — so neither can finish
	// before the other has begun, and both are seen to wait.
	held, err := lockfile.Try(filepath.Join(s1.RelayDir(r1), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	var releaseOnce sync.Once
	fetchLockSleep = func(time.Duration) {
		if asked.Add(1) >= 2 {
			releaseOnce.Do(func() { held.Release() })
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { fetchLockSleep = time.Sleep })
	results := make(chan fetchResult, 2)
	errs := make(chan error, 2)
	var stderr string
	stderr = captureStderr(t, func() {
		for _, f := range []func() (fetchResult, error){
			func() (fetchResult, error) {
				res, _, err := fetch(context.Background(), s1, id1, c1, r1, 0)
				return res, err
			},
			func() (fetchResult, error) {
				res, _, err := fetch(context.Background(), s2, id2, c2, r2, 0)
				return res, err
			},
		} {
			go func() {
				res, err := f()
				results <- res
				errs <- err
			}()
		}
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				t.Errorf("fetch: %v", err)
			}
		}
	})
	var delivered int
	for i := 0; i < 2; i++ {
		delivered += (<-results).Delivered
	}
	if delivered != 3 {
		t.Fatalf("the two fetches delivered %d between them, want 3", delivered)
	}
	if n := strings.Count(stderr, "another auu was fetching from "); n != 2 {
		t.Fatalf("stderr says a fetch waited %d times, want both (they started against a held lock):\n%s", n, stderr)
	}

	// Each message once, whichever fetch brought it.
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, m := range inbox.Messages {
		seen[m.ID]++
	}
	if len(seen) != 3 {
		t.Fatalf("%d distinct messages listed, want 3", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("message %s listed %d times", id, n)
		}
	}
}

// A fetch that cannot get its turn inside the wait says so and stops,
// rather than fetching alongside whoever holds the lock or hanging.
func TestAFetchThatCannotGetItsTurnSaysSo(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(filepath.Join(s.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	fetchLockWait = 250 * time.Millisecond
	t.Cleanup(func() { fetchLockWait = time.Minute })

	_, err = alice.tryRun("inbox")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("inbox against a held lock: %v, want exit %d", err, exitTransport)
	}
	if want := "another auu is fetching from " + r.Name + "; try again in a moment"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not carry %q", err, want)
	}
}

// A wait's poll that meets another fetch's lock is cut off at the wait's
// deadline, as one that meets a relay which never answers is: the lock's
// own minute must not outlast a ten-second wait. The lock is still held
// when the wait returns, so it was the deadline that ended it.
func TestWaitReturnsAtItsTimeoutWhenTheFetchLockIsHeld(t *testing.T) {
	relayURL := startRelay(t)
	alice, _, thread := peersWithAThread(t, relayURL)
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(filepath.Join(s.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	// The lock's own wait is left at its minute: the deadline must win.
	if fetchLockWait != time.Minute {
		t.Fatalf("fetchLockWait is %s; the test needs the shipped minute", fetchLockWait)
	}

	start := time.Now()
	_, err = alice.tryRun("wait", "--thread", thread, "--timeout", "3s", "--interval", "5s")
	took := time.Since(start)
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTimeout {
		t.Fatalf("wait against a held fetch lock: %v, want exit %d", err, exitTimeout)
	}
	if want := "timed out waiting for thread " + thread; err.Error() != want {
		t.Fatalf("error %q, want %q", err, want)
	}
	if took < 3*time.Second || took > 20*time.Second {
		t.Fatalf("wait returned after %s, want its own 3s and not the lock's minute", took)
	}
	if _, err := lockfile.Try(filepath.Join(s.RelayDir(r), fetchLockName)); !errors.Is(err, lockfile.ErrHeld) {
		t.Fatalf("the lock was not still held when wait returned (%v), so the lock's wait ended it, not the deadline", err)
	}
}

// A poll that could not get the fetch lock inside the lock's wait is a
// failure waiting outlasts — another fetch on this machine finishing — so
// the wait says so and polls again, and the reply is delivered.
func TestWaitOutlastsAHeldFetchLock(t *testing.T) {
	relayURL := startRelay(t)
	alice, bob, thread := peersWithAThread(t, relayURL)
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	bob.run("reply", inbox.Messages[0].ID, "here it is")
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(filepath.Join(s.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	// The lock's wait is short and its pause a stub, so the first poll
	// gives up on it at once; the wait's own pause is where the lock is
	// released, so the second poll gets its turn.
	fetchLockWait = 0
	fetchLockSleep = func(time.Duration) {}
	var slept []time.Duration
	waitSleep = func(d time.Duration) {
		slept = append(slept, d)
		held.Release()
	}
	t.Cleanup(func() {
		fetchLockWait, fetchLockSleep, waitSleep = time.Minute, time.Sleep, time.Sleep
	})

	var out string
	warning := captureStderr(t, func() {
		out, err = alice.tryRun("wait", "--thread", thread, "--timeout", "1m", "--interval", "5s", "--json")
	})
	if err != nil {
		t.Fatalf("wait gave up on a held fetch lock: %v", err)
	}
	var got waitJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || !got.Found || got.Message.Subject != "waiting" {
		t.Fatalf("wait --json: %v %s", err, out)
	}
	if len(slept) != 1 || !aboutTheInterval(slept[0], 5*time.Second) {
		t.Fatalf("slept %v, want one interval of 5s between the refused poll and the one that found the reply", slept)
	}
	want := "warning: " + r.Name + ": another auu is fetching from " + r.Name + "; try again in a moment"
	if !strings.HasPrefix(warning, want) || !strings.Contains(warning, "; trying again in 5s\n") {
		t.Fatalf("stderr does not say the poll met the lock and will try again:\n%s", warning)
	}
}

// A peer list with a line that will not parse stops a fetch before anything
// is fetched or quarantined, by the line's number and with the wrapping
// question, at exit 5: the list is what sorts what arrives, and without it
// every sender is a stranger. The container suite's K18 found the inbox
// quarantining everybody and saying nothing about why.
func TestABadPeersLineStopsTheFetchByName(t *testing.T) {
	srv, st, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice, bob, _ := peersWithAThread(t, srv.URL)
	bobFP := bob.exportFingerprint()
	// One more from alice, so there is something to count.
	alice.run("send", "--to", "bob", "--subject", "second", "two")
	if queued, err := st.List(bobFP, 0, 10); err != nil || len(queued) != 2 {
		t.Fatalf("queued %d (%v), want 2", len(queued), err)
	}

	// The first line of bob's peer list, wrapped at a hundred characters.
	peers := filepath.Join(bob.home, "authorized_peers")
	raw, err := os.ReadFile(peers)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(raw))
	if err := os.WriteFile(peers, []byte(line[:100]+"\n"+line[100:]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = bob.tryRun("inbox")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitDamaged {
		t.Fatalf("inbox with a wrapped peers line: %v, want exit %d", err, exitDamaged)
	}
	// The first hundred characters, less the "ccx2." prefix, are the
	// encoded part the parser counts.
	want := peers + " line 1: identity: key line is not the length of a key: 95 encoded bytes, "
	if !strings.HasPrefix(err.Error(), want) || !strings.HasSuffix(err.Error(), " encoded (was the line wrapped?)") {
		t.Fatalf("error %q does not name the line and ask the question", err)
	}

	// Nothing fetched, nothing quarantined: the relay still holds both,
	// and both local boxes are as they were.
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 2 {
		t.Fatalf("the relay holds %d (%v) after the refused fetch, want 2 untouched", len(left), err)
	}
	for _, box := range []string{"inbox", "quarantine"} {
		entries, _ := os.ReadDir(filepath.Join(bob.home, box))
		if len(entries) != 0 {
			t.Fatalf("%s holds %d entries after the refused fetch, want 0", box, len(entries))
		}
	}
	// The line put back, the fetch delivers both, from the sender it knows.
	if err := os.WriteFile(peers, append([]byte(line), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Delivered != 2 || inbox.Fetch.Quarantined != 0 {
		t.Fatalf("after the fix: %+v, want 2 delivered and none quarantined", inbox.Fetch)
	}
}

// A pasted export line with a break in it is refused as such, before any
// length is counted: a mail client or a terminal wrapped what was one line.
func TestAPastedLineWithABreakIsSaidToBe(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	line := bob.exportLine()
	_, err := alice.tryRun("peers", "add", line[:120]+"\n"+line[120:])
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage {
		t.Fatalf("peers add with a break: %v, want exit %d", err, exitUsage)
	}
	if err.Error() != "the line has a break in it; paste it as one line" {
		t.Fatalf("error %q", err)
	}
	if strings.Contains(alice.run("peers", "ls"), "bob") {
		t.Fatal("the broken line was added")
	}
	// A trailing newline is a paste too, and a harmless one.
	alice.run("peers", "add", line+"\n")
	if !strings.Contains(alice.run("peers", "ls"), "bob") {
		t.Fatal("the line with a trailing newline was not added")
	}
}

// A wait asks the relay to hold its listing open for the interval, so a
// reply arrives when it is sent and not at the next poll: bob replies 200ms
// into a 20s interval, and the wait ends well inside a second of that,
// having slept nothing. The relay's side is observed through the gate: the
// listing that asked for the hold took the relay longer to answer than any
// listing answered at once.
func TestWaitEndsWhenTheReplyArrivesDuringTheHold(t *testing.T) {
	var slept []time.Duration
	waitSleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { waitSleep = time.Sleep })
	relayURL, gate := startGatedRelay(t)
	alice, bob, thread := peersWithAThread(t, relayURL)
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	gate.lists.Store(0)

	// The reply, once the relay has been asked to hold alice's listing and
	// a moment after: observed on the gate rather than assumed from the
	// clock, so the reply lands inside the hold and not before it.
	replied := make(chan time.Time, 1)
	joined(t, func() {
		awaitListing(gate)
		time.Sleep(200 * time.Millisecond)
		replied <- time.Now()
		bob.elsewhere("reply", inbox.Messages[0].ID, "here it is")
	})
	start := time.Now()
	out := alice.run("wait", "--thread", thread, "--timeout", "1m", "--interval", "20s", "--json")
	ended := time.Now()
	var got waitJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || !got.Found || got.Message.Subject != "waiting" {
		t.Fatalf("wait --json: %v %s", err, out)
	}
	// Well inside the 20s interval, and inside a second of the reply on
	// a quiet machine; the bound allows a loaded one.
	at := <-replied
	if ended.Sub(at) > 10*time.Second || ended.Sub(start) >= 20*time.Second {
		t.Fatalf("the wait ended %s after the reply, %s after it began; the hold did not end it", ended.Sub(at), ended.Sub(start))
	}
	if len(slept) != 0 {
		t.Fatalf("slept %v; a reply during the hold needs no pause", slept)
	}
	if q := gate.asked.Load(); q == nil || !strings.HasSuffix(*q, "&wait=20s") {
		t.Fatalf("no listing asked for the hold")
	}
	if held := time.Duration(gate.held.Load()); held < 150*time.Millisecond {
		t.Fatalf("the relay answered the held listing in %s; it was not held", held)
	}
}

// The pause after an empty poll is what is left of the interval since the
// poll began. A relay that held the listing for the whole interval and
// answered empty leaves nothing, so the next poll goes at once, with no
// pause at all; the plain sleep of the interval would have made a hold
// cost a second interval on top of it. This test lets a hold run its
// course, so it takes the seven seconds it asks for, with real pauses.
//
// What it asserts is the sequence: the first listing held for the interval,
// the second arrived as soon as the first was answered, no pause was longer
// than the margin, no hold ran past the deadline, and the wait ended at its
// own seven seconds. How many polls that comes to is the clock's: two, or
// three when the last pause ended a moment before the deadline and one more
// poll, asking for no hold, got out. CI's ubuntu runner saw the third on a
// repeat where every other runner saw two.
func TestAHoldThatRanTheIntervalIsFollowedByThePollAtOnce(t *testing.T) {
	var slept []time.Duration
	waitSleep = func(d time.Duration) { slept = append(slept, d); time.Sleep(d) }
	t.Cleanup(func() { waitSleep = time.Sleep })
	relayURL, gate := startGatedRelay(t)
	alice, _, thread := peersWithAThread(t, relayURL)
	gate.lists.Store(0)

	start := time.Now()
	_, err := alice.tryRun("wait", "--thread", thread, "--timeout", "7s", "--interval", "5s")
	took := time.Since(start)
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("wait with nothing arriving: %v, want exit %d", err, exitTimeout)
	}
	// The first poll held for the 5s interval and left nothing to pause
	// for, so the second went at once: it held for what was left less the
	// margin, and only that margin was slept. A plain sleep of the
	// interval would show as a 5s pause here, and as a 5s gap below.
	for _, d := range slept {
		if d > holdMargin {
			t.Fatalf("slept %v after a hold that ran the whole interval", slept)
		}
	}
	polls := gate.timings()
	if n := len(polls); n != 2 && n != 3 {
		t.Fatalf("%d polls reached the relay in 7s with a 5s interval, want 2 or 3: the interval's hold, the remainder's, and at most one the clock let out", n)
	}
	if held := polls[0].done.Sub(polls[0].arrived); !polls[0].held || held < 5*time.Second || held > 6*time.Second {
		t.Fatalf("the relay held the first listing for %s, want the 5s interval", held)
	}
	if gap := polls[1].arrived.Sub(polls[0].done); gap > pollAtOnce {
		t.Fatalf("the second poll arrived %s after the first was answered, want at once", gap)
	}
	if gate.cut.Load() {
		t.Fatal("a hold ran past the deadline and was cut off by the client")
	}
	if took < 7*time.Second || took > 20*time.Second {
		t.Fatalf("the wait took %s, want its own 7s", took)
	}
}

// pollAtOnce is how long after the last answer a poll that goes at once may
// arrive at the relay: a dial and a look at the inbox on a slow machine,
// and nothing like an interval.
const pollAtOnce = 2 * time.Second

// The hold is bounded by what is left of the wait, less the round trip, so
// the last poll's hold ends inside the wait and the relay answers it, rather
// than seeing a request cut off by the deadline and logging an answer nobody
// read. A 2s wait with a 20s interval asks for a hold of a second or less,
// gets an answer, sleeps what is left, and exits 3 at about 2s with the
// empty shape. The pauses here are real, and recorded: a pause that did not
// pass would have the wait poll on a real clock that had not moved.
func TestTheLastHoldEndsWithTheWait(t *testing.T) {
	var slept []time.Duration
	waitSleep = func(d time.Duration) { slept = append(slept, d); time.Sleep(d) }
	t.Cleanup(func() { waitSleep = time.Sleep })
	relayURL, gate := startGatedRelay(t)
	alice, _, thread := peersWithAThread(t, relayURL)

	start := time.Now()
	out, err := alice.tryRun("wait", "--thread", thread, "--timeout", "2s", "--interval", "20s", "--json")
	took := time.Since(start)
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("wait with nothing arriving: %v, want exit %d", err, exitTimeout)
	}
	var got waitJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Found || got.Message != nil {
		t.Fatalf("the shape at the timeout: %v %s", err, out)
	}
	if took < 2*time.Second || took > 15*time.Second {
		t.Fatalf("the wait took %s, want its own 2s", took)
	}
	q := gate.asked.Load()
	if q == nil {
		t.Fatal("the listing did not ask for a hold")
	}
	_, raw, _ := strings.Cut(*q, "wait=")
	if hold, err := time.ParseDuration(raw); err != nil || hold <= 0 || hold > 2*time.Second-holdMargin {
		t.Fatalf("the listing asked for wait=%s, want no more than the 2s left of the wait less the margin", raw)
	}
	// Answered by the relay at the end of the hold: not cut off.
	if gate.answered.Load() != 1 {
		t.Fatalf("the relay answered %d held listings, want the one, which the deadline must not have cut", gate.answered.Load())
	}
	// What was left after the answer was slept, no more than the margin,
	// and the poll after it, if the clock let one out, asked for no hold,
	// since nothing was left.
	if len(slept) != 1 || slept[0] > holdMargin {
		t.Fatalf("slept %v after the last hold, want once and no more than the margin", slept)
	}
}
