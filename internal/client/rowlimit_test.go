package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// rowCountRefusal is the sentence a page of more rows than were asked for
// is refused with (G15).
func rowCountRefusal(asked, listed int) string {
	return fmt.Sprintf("the count of its messages is not at most %d, the limit asked for (%d listed)", asked, listed)
}

// stubPage is a listing page of n stub rows after id 0: no envelope on any
// row, ids rising from 1, the span the rows'.
func stubPage(n int) relayapi.ListResponse {
	first, last := int64(1), int64(n)
	page := relayapi.ListResponse{Queued: last, First: &first, Last: &last,
		Allow: relayapi.AllowNone, Card: relayapi.CardNone, Directory: relayapi.DirectoryNone}
	for i := 1; i <= n; i++ {
		page.Messages = append(page.Messages, relayapi.StoredMessage{ID: int64(i),
			Received: time.Now().UTC(), Size: 10, Kind: relayapi.KindStream, Channel: "default"})
	}
	return page
}

// G15 on the stubs listing, the one classifyPast asks: a stubs page is held
// to the rows asked for as a full page is, at limit 1 and at MaxListLimit,
// exactly the limit taken and one over refused naming the count, with no
// row taken. Every ask carried stubs, so the refusal is the stubs path's.
func TestAStubsListingCannotExceedTheRequestedRowLimit(t *testing.T) {
	for _, limit := range []int{1, relayapi.MaxListLimit} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("limit %d, %d over", limit, extra), func(t *testing.T) {
				rec := &recorder{replies: []reply{{status: http.StatusOK, body: stubPage(limit + extra)}}}
				c, _ := newTestClient(t, rec)
				got, err := c.ListWait(t.Context(), ListRequest{After: 0, Limit: limit, Stubs: true})
				rec.mu.Lock()
				asked := slices.Clone(rec.requests)
				rec.mu.Unlock()
				if len(asked) != 1 || !strings.Contains(asked[0], "&stubs=1") ||
					!strings.Contains(asked[0], "&limit="+strconv.Itoa(limit)+"&") {
					t.Fatalf("asks %q; want one, at limit %d with stubs", asked, limit)
				}
				if extra == 0 {
					if err != nil || len(got.Messages) != limit {
						t.Fatalf("a stubs page of exactly %d: %d rows, %v; want every row taken", limit, len(got.Messages), err)
					}
					return
				}
				if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), rowCountRefusal(limit, limit+extra)) {
					t.Fatalf("a stubs page of %d at limit %d: %v; want the malformed answer naming %q",
						limit+extra, limit, err, rowCountRefusal(limit, limit+extra))
				}
				if len(got.Messages) != 0 || got.Last != 0 || got.Queued != 0 {
					t.Fatalf("a refused stubs page left %d rows, last %d, queued %d; want nothing taken",
						len(got.Messages), got.Last, got.Queued)
				}
			})
		}
	}
}

// overflowThenRows is a relay before this release, as halvingRelay is,
// whose page asked for at more than fits rows is over MaxListingHold, and
// whose page at fits rows or fewer is rows(limit) stub rows from 1: a relay
// that halving brings under the hold and that then lists more than the
// halved ask. Every limit asked is recorded.
func overflowThenRows(t *testing.T, fits int, rows func(limit int) int) (*httptest.Server, func() []int) {
	t.Helper()
	var mu sync.Mutex
	var limits []int
	spaces := bytes.Repeat([]byte(" "), 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			json.NewEncoder(w).Encode(relayapi.HealthResponse{OK: true, MaxBytes: relayapi.MaxBytesCeiling,
				KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel})
			return
		}
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			t.Errorf("limit %q: %v", r.URL.Query().Get("limit"), err)
		}
		mu.Lock()
		limits = append(limits, limit)
		mu.Unlock()
		if limit > fits {
			io.WriteString(w, holdHead)
			for left := int64(relayapi.MaxListingHold); left > 0; left -= int64(len(spaces)) {
				if _, err := w.Write(spaces[:min(left, int64(len(spaces)))]); err != nil {
					return
				}
			}
			io.WriteString(w, "}")
			return
		}
		json.NewEncoder(w).Encode(stubPage(rows(limit)))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(limits)
	}
}

// G15 after the halving: the rows a page is held to are the limit the
// halving left, not the one the caller gave. Asked at 200, a page over the
// hold is asked again at 100; a page of 101 or 199 rows there, under the
// 200 first asked and over the 100 last asked, is refused naming 100, and
// a page of exactly 100 is taken.
func TestAHalvedListingIsHeldToTheHalvedLimit(t *testing.T) {
	for _, tc := range []struct {
		rows  int
		taken bool
	}{
		{relayapi.MaxListLimit / 2, true},
		{relayapi.MaxListLimit/2 + 1, false},
		{relayapi.MaxListLimit - 1, false},
	} {
		t.Run(fmt.Sprintf("%d rows at the halved 100", tc.rows), func(t *testing.T) {
			srv, asks := overflowThenRows(t, relayapi.MaxListLimit/2, func(int) int { return tc.rows })
			c, err := New(srv.URL, testIdentity(t, "tester"), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.ListWait(t.Context(), ListRequest{After: 0, Limit: relayapi.MaxListLimit, Stubs: true})
			if limits := asks(); !slices.Equal(limits, []int{relayapi.MaxListLimit, relayapi.MaxListLimit / 2}) {
				t.Fatalf("limits asked %v; want 200 then the halved 100", limits)
			}
			if tc.taken {
				if err != nil || len(got.Messages) != tc.rows {
					t.Fatalf("a page of exactly the halved limit: %d rows, %v; want all %d taken", len(got.Messages), err, tc.rows)
				}
				return
			}
			want := rowCountRefusal(relayapi.MaxListLimit/2, tc.rows)
			if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
				t.Fatalf("a page of %d after the halving to 100: %v; want the malformed answer naming %q", tc.rows, err, want)
			}
			if len(got.Messages) != 0 {
				t.Fatalf("a refused page left %d rows; want none taken", len(got.Messages))
			}
		})
	}
}

// limitCountBody counts what is read from it and whether it was closed.
type limitCountBody struct {
	r      io.Reader
	read   int
	closed bool
}

func (b *limitCountBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read += n
	return n, err
}

func (b *limitCountBody) Close() error { b.closed = true; return nil }

type limitRoundTrip func(*http.Request) (*http.Response, error)

func (f limitRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestLimitABlobRetrysRefusalIsHeldToTheHold: the cap on Blob's drain of a
// retryable refusal's body (G16), io.LimitReader(resp.Body,
// streamAnswerHold + 1). A 503 with Retry-After and a body of exactly the
// hold is drained whole, waited out and asked again, and the 206 after it
// taken; one byte over, declared or not, is refused as a malformed answer
// naming the hold, nothing asked again and the body closed: undeclared,
// with at most the hold plus one read however long the body runs, and
// declared, before a byte of it is read.
func TestLimitABlobRetrysRefusalIsHeldToTheHold(t *testing.T) {
	want := fmt.Sprintf("under %d bytes, the most this route holds", streamAnswerHold)
	for _, tc := range []struct {
		name     string
		size     int
		declared int64
		taken    bool
		maxRead  int
	}{
		{"at the hold, declared", streamAnswerHold, streamAnswerHold, true, streamAnswerHold},
		{"at the hold, undeclared", streamAnswerHold, -1, true, streamAnswerHold},
		{"one over, undeclared", streamAnswerHold + 1, -1, false, streamAnswerHold + 1},
		{"sixteen holds, undeclared", 16 * streamAnswerHold, -1, false, streamAnswerHold + 1},
		{"one over, declared", streamAnswerHold + 1, streamAnswerHold + 1, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, id := rangeClient(t, "http://relay.invalid")
			var slept []time.Duration
			c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
			body := &limitCountBody{r: bytes.NewReader(bytes.Repeat([]byte("x"), tc.size))}
			calls := 0
			c.stream.Transport = limitRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				h := make(http.Header)
				if calls == 1 {
					h.Set("Retry-After", "1")
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: h,
						Body: body, ContentLength: tc.declared, Request: r}, nil
				}
				h.Set("Content-Range", "bytes 0-0/1")
				return &http.Response{StatusCode: http.StatusPartialContent, Header: h,
					Body: io.NopCloser(strings.NewReader("z")), ContentLength: 1, Request: r}, nil
			})
			got, _, err := c.Blob(t.Context(), id.Fingerprint(), 1, 0, 0)
			if got != nil {
				defer got.Close()
			}
			if !body.closed {
				t.Fatalf("the refusal's body was not closed")
			}
			if tc.taken {
				if err != nil || got == nil || calls != 2 || len(slept) != 1 || slept[0] != time.Second {
					t.Fatalf("a refusal of %d bytes: calls %d, slept %v, %v; want it waited out a second and asked again", tc.size, calls, slept, err)
				}
				if b, _ := io.ReadAll(got); string(b) != "z" {
					t.Fatalf("the 206 after the retry read %q; want z", b)
				}
				if body.read != tc.size {
					t.Fatalf("the refusal drained %d of %d bytes; want all of it, for the connection's reuse", body.read, tc.size)
				}
				return
			}
			if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
				t.Fatalf("a refusal of %d bytes (declared %d): %v; want the malformed answer naming %q", tc.size, tc.declared, err, want)
			}
			if got != nil || calls != 1 || len(slept) != 0 {
				t.Fatalf("a refusal over the hold: calls %d, slept %v, body %v; want nothing waited or asked again", calls, slept, got != nil)
			}
			if body.read > tc.maxRead {
				t.Fatalf("a refusal of %d bytes (declared %d) read %d; want at most %d", tc.size, tc.declared, body.read, tc.maxRead)
			}
		})
	}
}

// The limit a page is held to is the one the relay applies: a caller that
// asks for none is asked the default, relayapi.DefaultListLimit, and one
// that asks for more than MaxListLimit has it clamped, as the relay clamps
// it. An honest page of either is taken, and one row over is refused.
func TestARowLimitIsTheOneTheRelayApplies(t *testing.T) {
	for _, tc := range []struct {
		asked, applies int
	}{
		{0, relayapi.DefaultListLimit},
		{-1, relayapi.DefaultListLimit},
		{relayapi.MaxListLimit * 5, relayapi.MaxListLimit},
	} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("asked %d, %d over", tc.asked, extra), func(t *testing.T) {
				rec := &recorder{replies: []reply{{status: http.StatusOK, body: stubPage(tc.applies + extra)}}}
				c, _ := newTestClient(t, rec)
				got, err := c.ListWait(t.Context(), ListRequest{After: 0, Limit: tc.asked, Stubs: true})
				if extra == 0 {
					if err != nil || len(got.Messages) != tc.applies {
						t.Fatalf("an honest page of %d: rows=%d err=%v", tc.applies, len(got.Messages), err)
					}
					return
				}
				if !errors.Is(err, ErrMalformedAnswer) || len(got.Messages) != 0 {
					t.Fatalf("a page of %d asked %d: rows=%d err=%v; want malformed with no rows", tc.applies+1, tc.asked, len(got.Messages), err)
				}
			})
		}
	}
}
