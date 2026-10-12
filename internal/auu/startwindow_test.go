package auu

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// waitFront is a real relay behind a proxy that answers the first fail
// upload attempts 500, then the next refuse 429 with the Retry-After
// given, each before its body, and records the opens, the attempts and
// the aborts it saw.
type waitFront struct {
	mu     sync.Mutex
	fail   int
	refuse int
	after  string
	// refuseOpen, when set, answers every open after the first 403.
	refuseOpen bool
	opens      int
	attempts   []string
	aborts     []string
}

func (f *waitFront) seen() (opens int, attempts, aborts []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens, append([]string(nil), f.attempts...), append([]string(nil), f.aborts...)
}

func frontWaits(t *testing.T, refuse int, after string) (*waitFront, *relay.Store, *user, *user) {
	t.Helper()
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	backend, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	f := &waitFront{refuse: refuse, after: after}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upload := strings.TrimPrefix(r.URL.Path, "/v1/uploads/")
		f.mu.Lock()
		switch {
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && strings.HasSuffix(r.URL.Path, "/streams"):
			f.opens++
			if f.refuseOpen && f.opens > 1 {
				f.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"sender is not allowed to post to this mailbox"}`))
				return
			}
		case r.Method == "DELETE" && upload != r.URL.Path:
			f.aborts = append(f.aborts, upload)
		case r.Method == "PUT" && upload != r.URL.Path:
			f.attempts = append(f.attempts, upload)
			if f.fail > 0 {
				f.fail--
				f.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"storage error"}`))
				return
			}
			if f.refuse > 0 {
				f.refuse--
				f.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", f.after)
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limited: requests"}`))
				return
			}
		}
		f.mu.Unlock()
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	us := peersOn(t, srv.URL, "alice", "bob")
	return f, st, us[0], us[1]
}

// shortStartWindow sets the client's start window for the test and puts
// it back after.
func shortStartWindow(t *testing.T, d time.Duration) {
	t.Helper()
	was := startWindow
	startWindow = d
	t.Cleanup(func() { startWindow = was })
}

const startWindowWarning = "warning: the relay asked for a wait of 2s before the first attempt, " +
	"longer than the 2s an opened upload waits; it is opened again after the wait\n"

// An upload nobody has started an attempt on is the relay's for its start
// window from the open, so a wait asked for before the first attempt that
// outlasts what is left of the window, less two seconds, loses the open (R3):
// the client says so once, aborts the upload it opened, waits, and opens
// again, and the send completes on the second upload. The start window is
// two seconds here and the relay asks for two before the first attempt.
func TestAWaitPastTheStartWindowReopensTheUploadOnce(t *testing.T) {
	shortStartWindow(t, 2*time.Second)
	f, st, alice, bob := frontWaits(t, 1, "2")

	var out string
	var err error
	stderr := captureStderr(t, func() {
		out, err = alice.tryRun("send", "--to", "bob", "--stream", "--subject", "after the wait", "here it is")
	})
	if err != nil {
		t.Fatalf("the send after a lost start window: %v\n%s\n%s", err, out, stderr)
	}
	if n := strings.Count(stderr, startWindowWarning); n != 1 {
		t.Fatalf("standard error said the warning %d times, want once:\n%q\nwant:\n%q", n, stderr, startWindowWarning)
	}
	opens, attempts, aborts := f.seen()
	if opens != 2 {
		t.Fatalf("the relay saw %d opens, want 2: the first and the one after the wait", opens)
	}
	if len(attempts) != 2 || attempts[0] == attempts[1] {
		t.Fatalf("the attempts were on %v; want one on the first upload and one on the second", attempts)
	}
	if len(aborts) != 1 || aborts[0] != attempts[0] {
		t.Fatalf("the aborts were %v; want the first upload, %s, let go", aborts, attempts[0])
	}
	if _, err := st.Upload(attempts[0]); err == nil {
		t.Fatalf("the relay still holds the first upload %s after the client let it go", attempts[0])
	}

	var waiting []outboxJSON
	if err := json.Unmarshal([]byte(alice.run("outbox", "--json")), &waiting); err != nil || len(waiting) != 0 {
		t.Fatalf("the outbox after the send: %+v, %v; want it empty", waiting, err)
	}
	inbox := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(inbox), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, inbox)
	}
	found := 0
	for _, m := range got.Messages {
		if m.Subject == "after the wait" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("the message arrived %d times, want once: %+v", found, got.Messages)
	}

	// The reopen after a lost start window is an open like any other and
	// may be refused; the record keeps the let-go id until a new open
	// takes its place, so a fresh send keeps its sealed copy, which an
	// empty id would have the caller drop as a message the relay never
	// took. The proxy refuses the reopen 403, which the client does not
	// retry; a refusal it retries, such as the opens cap's 429, ends the
	// same way after the client's own waits.
	t.Run("a reopen refused keeps the copy in the outbox", func(t *testing.T) {
		f, _, alice, _ := frontWaits(t, 1, "2")
		f.mu.Lock()
		f.refuseOpen = true
		f.mu.Unlock()
		var out string
		var err error
		stderr := captureStderr(t, func() {
			out, err = alice.tryRun("send", "--to", "bob", "--stream", "--subject", "refused again", "here it is")
		})
		if err == nil || !strings.Contains(err.Error(), "(403)") {
			t.Fatalf("a send whose reopen was refused: %v\n%s\n%s; want the refusal", err, out, stderr)
		}
		if n := strings.Count(stderr, startWindowWarning); n != 1 {
			t.Fatalf("standard error said the warning %d times, want once:\n%q", n, stderr)
		}
		_, attempts, aborts := f.seen()
		if len(attempts) != 1 || len(aborts) != 1 || aborts[0] != attempts[0] {
			t.Fatalf("attempts %v, aborts %v; want one attempt on the first upload and it let go", attempts, aborts)
		}
		var waiting []outboxJSON
		if err := json.Unmarshal([]byte(alice.run("outbox", "--json")), &waiting); err != nil || len(waiting) != 1 {
			t.Fatalf("the outbox after the refused reopen: %+v, %v; want the one copy", waiting, err)
		}
		if p := onlyPending(t, alice); p.Upload != attempts[0] {
			t.Fatalf("the outbox record names upload %q, want the let-go %s", p.Upload, attempts[0])
		}
	})

	t.Run("a second loss in the turn ends it with the copy in the outbox", func(t *testing.T) {
		f, st, alice, _ := frontWaits(t, 2, "2")
		var out string
		var err error
		stderr := captureStderr(t, func() {
			out, err = alice.tryRun("send", "--to", "bob", "--stream", "--subject", "lost twice", "here it is")
		})
		if err == nil {
			t.Fatalf("a send whose start window was lost twice succeeded:\n%s\n%s", out, stderr)
		}
		if n := strings.Count(stderr, startWindowWarning); n != 1 {
			t.Fatalf("standard error said the warning %d times, want once:\n%q", n, stderr)
		}
		opens, attempts, aborts := f.seen()
		if opens != 2 || len(attempts) != 2 || attempts[0] == attempts[1] {
			t.Fatalf("the relay saw %d opens and attempts %v; want 2 opens and one attempt on each", opens, attempts)
		}
		// Both uploads are let go: the second is lost as the first was.
		// The record keeps the second's id, which keeps the sealed copy,
		// and --resume meets it gone and opens afresh.
		if len(aborts) != 2 || aborts[0] != attempts[0] || aborts[1] != attempts[1] {
			t.Fatalf("the aborts were %v; want both uploads, %v, let go", aborts, attempts)
		}
		for _, id := range attempts {
			if _, err := st.Upload(id); err == nil {
				t.Fatalf("the relay still holds upload %s after the client let it go", id)
			}
		}
		var waiting []outboxJSON
		if err := json.Unmarshal([]byte(alice.run("outbox", "--json")), &waiting); err != nil || len(waiting) != 1 {
			t.Fatalf("the outbox after the second loss: %+v, %v; want the one copy", waiting, err)
		}
		if p := onlyPending(t, alice); p.Upload != attempts[1] {
			t.Fatalf("the outbox record names upload %q, want the second, %s", p.Upload, attempts[1])
		}
		if out, err := alice.tryRun("send", "--resume"); err != nil {
			t.Fatalf("send --resume after the second loss: %v\n%s", err, out)
		}
		if opens, _, _ := f.seen(); opens != 3 {
			t.Fatalf("the relay saw %d opens after --resume, want a third", opens)
		}
		if out := alice.run("outbox", "--json"); strings.TrimSpace(out) != "[]" {
			t.Fatalf("the outbox after --resume: %s; want it empty", out)
		}
	})

	// An attempt that fails for something other than a wait has started:
	// the upload is no longer unfed, and a wait asked for after it is
	// waited out on the same upload however long it is, with no warning
	// and one open. The 500 never reaches the relay, whose own start
	// window is ten seconds and outlasts the test.
	t.Run("a wait after an attempt that was not a wait keeps the upload", func(t *testing.T) {
		shortStartWindow(t, 3*time.Second)
		f, _, alice, _ := frontWaits(t, 1, "2")
		f.mu.Lock()
		f.fail = 1
		f.mu.Unlock()
		var out string
		var err error
		stderr := captureStderr(t, func() {
			out, err = alice.tryRun("send", "--to", "bob", "--stream", "--subject", "fed once", "here it is")
		})
		if err != nil {
			t.Fatalf("the send after a failed attempt and a wait: %v\n%s\n%s", err, out, stderr)
		}
		if strings.Contains(stderr, "opened again after the wait") {
			t.Fatalf("a wait after a failed attempt was said as a lost open:\n%s", stderr)
		}
		opens, attempts, aborts := f.seen()
		if opens != 1 || len(attempts) != 3 || attempts[0] != attempts[2] || len(aborts) != 0 {
			t.Fatalf("the relay saw %d opens, attempts %v and aborts %v; want one open and three attempts on it",
				opens, attempts, aborts)
		}
	})

	// A wait inside what is left of the start window, the relay's own
	// here, is waited out on the upload already open: no warning, one
	// open, and the second attempt on the same upload completes the send.
	t.Run("a wait inside the window keeps the upload", func(t *testing.T) {
		shortStartWindow(t, relayapi.StartWindow)
		testAWaitInsideTheStartWindow(t)
	})

	// The margin is two seconds, one either side, on the client's own
	// window and whatever the relay holds: of a four-second window a
	// moment after the open, a little under two is left, so a wait of
	// two is over it and loses the open, and a wait of one is under it
	// and keeps the upload. A margin of none or one keeps the first; a
	// margin of three loses the second.
	t.Run("a wait of two against four seconds loses the open", func(t *testing.T) {
		shortStartWindow(t, 4*time.Second)
		f, _, alice, _ := frontWaits(t, 1, "2")
		var out string
		var err error
		stderr := captureStderr(t, func() {
			out, err = alice.tryRun("send", "--to", "bob", "--stream", "--subject", "two of four", "here it is")
		})
		if err != nil {
			t.Fatalf("the send: %v\n%s\n%s", err, out, stderr)
		}
		want := "warning: the relay asked for a wait of 2s before the first attempt, " +
			"longer than the 4s an opened upload waits; it is opened again after the wait\n"
		if n := strings.Count(stderr, want); n != 1 {
			t.Fatalf("standard error said the warning %d times, want once:\n%q", n, stderr)
		}
		if opens, _, aborts := f.seen(); opens != 2 || len(aborts) != 1 {
			t.Fatalf("the relay saw %d opens and aborts %v; want two opens and the first let go", opens, aborts)
		}
	})
	t.Run("a wait of one against four seconds keeps the upload", func(t *testing.T) {
		shortStartWindow(t, 4*time.Second)
		testAWaitInsideTheStartWindow(t)
	})
}

func testAWaitInsideTheStartWindow(t *testing.T) {
	f, _, alice, _ := frontWaits(t, 1, "1")
	var out string
	var err error
	stderr := captureStderr(t, func() {
		out, err = alice.tryRun("send", "--to", "bob", "--stream", "--subject", "a short wait", "here it is")
	})
	if err != nil {
		t.Fatalf("the send after a short wait: %v\n%s\n%s", err, out, stderr)
	}
	if strings.Contains(stderr, "opened again after the wait") {
		t.Fatalf("a wait inside the start window was said as a lost open:\n%s", stderr)
	}
	opens, attempts, aborts := f.seen()
	if opens != 1 || len(attempts) != 2 || attempts[0] != attempts[1] || len(aborts) != 0 {
		t.Fatalf("the relay saw %d opens, attempts %v and aborts %v; want one open and two attempts on it", opens, attempts, aborts)
	}
}
