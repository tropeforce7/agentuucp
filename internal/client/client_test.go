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

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
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
