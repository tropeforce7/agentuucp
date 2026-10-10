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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The third adversarial trace, at v0.17.0: a listing hold the relay
// chose. The client sized the hold it reads a listing page under to twice
// the max_bytes the relay's health answer gave, which checkHealth admits
// up to MaxBytesCeiling, a gigabyte; a relay that said a gigabyte could
// have a page of two read whole into memory. The hold is now never above
// relayapi.MaxListingHold, whatever the relay says. The trace's test is
// here as the regression test, renamed for what it proves.

// holdHead is a listing page's fields, its object left open: the rest of
// a page here is white space and the closing brace, which a strict decode
// takes.
const holdHead = `{"messages":[],"queued":0,"first":0,"last":0,"allow":"none","card":"none","directory":"none"`

// holdRelay is a relay whose health answer says the max_bytes held in
// maxBytes and whose every listing is holdHead, pad spaces and the closing
// brace, written from spaces in pieces so that the server's own
// allocations are a few buffers whatever the page's size. healths and
// listings count the two routes.
func holdRelay(t *testing.T, maxBytes, pad *atomic.Int64, spaces []byte) (srv *httptest.Server, healths, listings *atomic.Int64) {
	t.Helper()
	healths, listings = new(atomic.Int64), new(atomic.Int64)
	closing := []byte("}")
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			healths.Add(1)
			json.NewEncoder(w).Encode(relayapi.HealthResponse{OK: true, MaxBytes: maxBytes.Load(), KnockMaxBytes: relayapi.DefaultMaxBytes,
				Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel})
			return
		}
		listings.Add(1)
		io.WriteString(w, holdHead)
		for left := pad.Load(); left > 0; {
			n := min(left, int64(len(spaces)))
			if _, err := w.Write(spaces[:n]); err != nil {
				return // the client stopped reading: refused over its hold
			}
			left -= n
		}
		w.Write(closing)
	}))
	t.Cleanup(srv.Close)
	return srv, healths, listings
}

// holdPad is the padding that makes a page of exactly n bytes.
func holdPad(n int64) int64 { return n - int64(len(holdHead)) - 1 }

// The trace's scenario, scaled to the bound that moved: a relay says
// max_bytes is a gigabyte on its health answer and answers a listing with
// a page of white space over MaxListingHold, twice it here (the trace's
// was 48 MiB under a hold of 2 GiB). The client holds the page to
// MaxListingHold, not to the 2 GiB the relay's word would size, refuses
// it as a malformed answer naming that hold, and allocates under three
// times the hold doing so (io.ReadAll over the LimitReader costs about
// 2.1 times what it reads); read whole, the page would cost more than
// that. A subtest holds MaxListingHold's arithmetic, and that the inline
// mail this client sends fits a page.
func TestTheListingHoldIsBoundedWhateverTheRelaySays(t *testing.T) {
	t.Run("arithmetic", func(t *testing.T) {
		page := int64(relayapi.MaxPageBytes)
		if page != 64<<20 {
			t.Fatalf("MaxPageBytes = %d; want 64 MiB", page)
		}
		hold := int64(relayapi.MaxListingHold)
		if hold != 2*page+relayapi.FramingAllowance {
			t.Fatalf("MaxListingHold = %d; want 2*MaxPageBytes + %d", hold, relayapi.FramingAllowance)
		}
		if hold != 134283264 {
			t.Fatalf("MaxListingHold = %d; want 134283264, the figure its comment gives", hold)
		}
		// A page carries its envelopes as the JSON they were posted as,
		// so the largest envelope this client sends inline fits a page.
		if relayapi.DefaultMaxBytes > page {
			t.Fatalf("the inline cap %d is over MaxPageBytes, %d", relayapi.DefaultMaxBytes, page)
		}
	})

	var maxBytes, pad atomic.Int64
	maxBytes.Store(relayapi.MaxBytesCeiling)
	pad.Store(2 * relayapi.MaxListingHold)
	spaces := bytes.Repeat([]byte(" "), 1<<20)
	srv, _, _ := holdRelay(t, &maxBytes, &pad, spaces)
	c, err := New(srv.URL, testIdentity(t, "tester"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	hold, _, err := c.listingCap(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.List(t.Context(), 0, 1)
	runtime.ReadMemStats(&after)
	grown := after.TotalAlloc - before.TotalAlloc
	t.Logf("hold %d bytes; TotalAlloc grew by %d MiB; List err = %v", hold, grown>>20, err)
	if hold != relayapi.MaxListingHold {
		t.Errorf("a relay saying max_bytes %d sized the hold to %d; want MaxListingHold, %d", relayapi.MaxBytesCeiling, hold, relayapi.MaxListingHold)
	}
	want := fmt.Sprintf("under %d bytes, the most this route holds", relayapi.MaxListingHold)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
		t.Errorf("a page of %d bytes from a relay saying a gigabyte: %v; want the malformed answer naming %q", pad.Load(), err, want)
	}
	// Under the race detector the same read measures about twice as much,
	// 4.2 times the hold against 2.1 (measured on Go 1.27), so the bound is
	// doubled there: still well under what reading the page whole costs,
	// which is over 19 times the hold without the detector.
	bound := uint64(3 * relayapi.MaxListingHold)
	if raceEnabled {
		bound *= 2
	}
	if grown >= bound {
		t.Errorf("refusing the page allocated %d bytes; want under %d (3 x the hold, doubled under the race detector: %v)", grown, bound, raceEnabled)
	}
}

// TestLimitListingHold: holdFor is twice max_bytes plus the framing
// allowance up to MaxListingHold, which 64 MiB reaches exactly and every
// figure above it, to the ceiling, is held at. Through List against a
// relay saying a gigabyte, a page of exactly the hold is taken and one of
// a byte more is refused naming it.
func TestLimitListingHold(t *testing.T) {
	for _, tc := range []struct {
		maxBytes, want int64
	}{
		{1, 2 + relayapi.FramingAllowance},
		{relayapi.DefaultMaxBytes, 2*relayapi.DefaultMaxBytes + relayapi.FramingAllowance},
		{64<<20 - 1, relayapi.MaxListingHold - 2},
		{64 << 20, relayapi.MaxListingHold},
		{64<<20 + 1, relayapi.MaxListingHold},
		{relayapi.MaxBytesCeiling, relayapi.MaxListingHold},
	} {
		if got := holdFor(tc.maxBytes); got != tc.want {
			t.Errorf("holdFor(%d) = %d; want %d", tc.maxBytes, got, tc.want)
		}
	}

	var maxBytes, pad atomic.Int64
	maxBytes.Store(relayapi.MaxBytesCeiling)
	spaces := bytes.Repeat([]byte(" "), 1<<20)
	srv, _, _ := holdRelay(t, &maxBytes, &pad, spaces)
	c, err := New(srv.URL, testIdentity(t, "tester"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pad.Store(holdPad(relayapi.MaxListingHold))
	if _, err := c.List(context.Background(), 0, 1); err != nil {
		t.Fatalf("a page of exactly the hold, %d bytes: %v; want it taken", relayapi.MaxListingHold, err)
	}
	pad.Store(holdPad(relayapi.MaxListingHold + 1))
	_, err = c.List(context.Background(), 0, 1)
	want := fmt.Sprintf("under %d bytes, the most this route holds", relayapi.MaxListingHold)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
		t.Fatalf("a page one byte over the hold: %v; want the malformed answer naming %q", err, want)
	}
}

// TestAMaxBytesRiseAboveTheBoundDoesNotWidenTheHold: a page refused for
// its size asks health once more and lists again only when the hold grew.
// A relay whose max_bytes rises from 64 MiB to a gigabyte leaves the hold
// at MaxListingHold, so grew is false and the page is not asked for
// again; one that rises from 16 MiB to 32 MiB widens it, and the page is
// asked for again and taken.
func TestAMaxBytesRiseAboveTheBoundDoesNotWidenTheHold(t *testing.T) {
	spaces := bytes.Repeat([]byte(" "), 1<<20)

	t.Run("64 MiB to a gigabyte", func(t *testing.T) {
		var maxBytes, pad atomic.Int64
		maxBytes.Store(64 << 20)
		srv, healths, listings := holdRelay(t, &maxBytes, &pad, spaces)
		c, err := New(srv.URL, testIdentity(t, "tester"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if hold, _, err := c.listingCap(t.Context(), false); err != nil || hold != relayapi.MaxListingHold {
			t.Fatalf("listingCap at 64 MiB: %d, %v; want %d", hold, err, relayapi.MaxListingHold)
		}
		maxBytes.Store(relayapi.MaxBytesCeiling)
		pad.Store(holdPad(relayapi.MaxListingHold + 1))
		_, err = c.List(t.Context(), 0, 1)
		if !errors.Is(err, ErrMalformedAnswer) {
			t.Fatalf("a page over the hold: %v; want the malformed answer", err)
		}
		if healths.Load() != 2 || listings.Load() != 1 {
			t.Fatalf("healths %d, listings %d; want 2 (asked once more) and 1 (the hold did not grow, the page not asked for again)", healths.Load(), listings.Load())
		}
		if hold, grew, err := c.listingCap(t.Context(), true); err != nil || grew || hold != relayapi.MaxListingHold {
			t.Fatalf("listingCap again at a gigabyte: %d, grew %v, %v; want %d, not grown", hold, grew, err, relayapi.MaxListingHold)
		}
	})

	t.Run("16 MiB to 32 MiB", func(t *testing.T) {
		var maxBytes, pad atomic.Int64
		maxBytes.Store(16 << 20)
		srv, healths, listings := holdRelay(t, &maxBytes, &pad, spaces)
		c, err := New(srv.URL, testIdentity(t, "tester"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if hold, _, err := c.listingCap(t.Context(), false); err != nil || hold != holdFor(16<<20) {
			t.Fatalf("listingCap at 16 MiB: %d, %v; want %d", hold, err, holdFor(16<<20))
		}
		maxBytes.Store(32 << 20)
		pad.Store(holdPad(holdFor(16<<20) + 1))
		if _, err := c.List(t.Context(), 0, 1); err != nil {
			t.Fatalf("a page over the old hold after max_bytes rose: %v; want it taken under the new", err)
		}
		if healths.Load() != 2 || listings.Load() != 2 {
			t.Fatalf("healths %d, listings %d; want 2 and 2 (the refused page and the retry)", healths.Load(), listings.Load())
		}
		if hold, _, err := c.listingCap(t.Context(), false); err != nil || hold != holdFor(32<<20) {
			t.Fatalf("listingCap after the rise: %d, %v; want %d", hold, err, holdFor(32<<20))
		}
	})
}

// listAsk is one listing request as a stand-in relay saw it.
type listAsk struct {
	limit int
	after string
	stubs string
	wait  string
	peers string
}

// halvingRelay is a relay before this release, which fills a page to its
// whole max_bytes: its health answer says maxBytes, and a listing asked
// for more than fits rows is a page of white space over MaxListingHold,
// while one asked for fits rows or fewer is that many stub rows after the
// after asked for. fits of zero makes every page over the hold. Every
// listing request is recorded.
func halvingRelay(t *testing.T, maxBytes int64, fits int) (srv *httptest.Server, healths *atomic.Int64, asks func() []listAsk) {
	t.Helper()
	healths = new(atomic.Int64)
	var mu sync.Mutex
	var seen []listAsk
	spaces := bytes.Repeat([]byte(" "), 1<<20)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			healths.Add(1)
			json.NewEncoder(w).Encode(relayapi.HealthResponse{OK: true, MaxBytes: maxBytes, KnockMaxBytes: relayapi.DefaultMaxBytes,
				Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel})
			return
		}
		q := r.URL.Query()
		limit, err := strconv.Atoi(q.Get("limit"))
		if err != nil {
			t.Errorf("limit %q: %v", q.Get("limit"), err)
		}
		mu.Lock()
		seen = append(seen, listAsk{limit: limit, after: q.Get("after"), stubs: q.Get("stubs"), wait: q.Get("wait"), peers: q.Get("peers")})
		mu.Unlock()
		if fits == 0 || limit > fits {
			io.WriteString(w, holdHead)
			for left := int64(relayapi.MaxListingHold); left > 0; left -= int64(len(spaces)) {
				if _, err := w.Write(spaces[:min(left, int64(len(spaces)))]); err != nil {
					return
				}
			}
			io.WriteString(w, "}")
			return
		}
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		rows := make([]map[string]any, 0, limit)
		for i := range int64(limit) {
			rows = append(rows, map[string]any{"id": after + 1 + i, "received": "2026-09-20T00:00:00Z",
				"kind": "envelope", "size": 10, "channel": "default"})
		}
		json.NewEncoder(w).Encode(map[string]any{"messages": rows, "queued": limit, "first": after + 1,
			"last": after + int64(limit), "allow": "none", "card": "none", "directory": "none"})
	}))
	t.Cleanup(srv.Close)
	return srv, healths, func() []listAsk {
		mu.Lock()
		defer mu.Unlock()
		return append([]listAsk(nil), seen...)
	}
}

// R9: a relay before this release fills a page to its whole max_bytes,
// which may be a gigabyte, so a page from it can be over MaxListingHold
// where a page of fewer rows is not. A page over a hold already at
// MaxListingHold is asked for again with the limit halved, the same after
// and the same stubs on every ask, down to the first that fits, and its
// rows come back. A single row over the hold is refused naming the hold
// once the limit reached 1, after exactly seven asks more than the first
// from 200, and from 128, whose halving passes 2; a limit above
// MaxListLimit halves from MaxListLimit, and no limit starts at the
// default. Every ask keeps the wait and the peers too. A hold below
// MaxListingHold does not halve: the page is over what the relay itself
// says it builds, and the refusal stands after the re-ask of health.
func TestAPageOverTheHoldIsAskedForWithFewerRows(t *testing.T) {
	want := fmt.Sprintf("under %d bytes, the most this route holds", relayapi.MaxListingHold)

	t.Run("halved to the first that fits", func(t *testing.T) {
		srv, healths, asks := halvingRelay(t, relayapi.MaxBytesCeiling, 25)
		c, err := New(srv.URL, testIdentity(t, "tester"), nil)
		if err != nil {
			t.Fatal(err)
		}
		l, err := c.ListWait(t.Context(), ListRequest{After: 10, Limit: 200, Stubs: true})
		if err != nil {
			t.Fatalf("ListWait: %v; want the page of 25 rows taken", err)
		}
		got := asks()
		var limits []int
		for _, a := range got {
			limits = append(limits, a.limit)
			if a.after != "10" || a.stubs != "1" {
				t.Errorf("an ask with after %q and stubs %q; want 10 and 1 on every ask", a.after, a.stubs)
			}
		}
		if !slices.Equal(limits, []int{200, 100, 50, 25}) {
			t.Fatalf("limits asked %v; want 200, 100, 50, 25", limits)
		}
		if len(l.Messages) != 25 || l.Messages[0].ID != 11 || l.Messages[24].ID != 35 {
			t.Fatalf("%d rows back; want 25, ids 11 to 35", len(l.Messages))
		}
		if healths.Load() != 2 {
			t.Fatalf("healths %d; want 2, the first and the re-ask", healths.Load())
		}
	})

	// From 200 the halving passes 3 and reaches 1 from it; from 128 it
	// passes 2, which is the ask a stop short of 1 would leave out.
	for _, tc := range []struct {
		from   int
		limits []int
	}{
		{200, []int{200, 100, 50, 25, 12, 6, 3, 1}},
		{128, []int{128, 64, 32, 16, 8, 4, 2, 1}},
	} {
		t.Run(fmt.Sprintf("a lone row over the hold from %d", tc.from), func(t *testing.T) {
			srv, healths, asks := halvingRelay(t, relayapi.MaxBytesCeiling, 0)
			c, err := New(srv.URL, testIdentity(t, "tester"), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.ListWait(t.Context(), ListRequest{After: 10, Limit: tc.from})
			if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
				t.Fatalf("every page over the hold: %v; want the malformed answer naming %q", err, want)
			}
			var limits []int
			for _, a := range asks() {
				limits = append(limits, a.limit)
				if a.after != "10" || a.stubs != "" {
					t.Errorf("an ask with after %q and stubs %q; want 10 and none on every ask", a.after, a.stubs)
				}
			}
			if !slices.Equal(limits, tc.limits) {
				t.Fatalf("limits asked %v; want %v, the first and seven more down to 1", limits, tc.limits)
			}
			if healths.Load() != 2 {
				t.Fatalf("healths %d; want 2", healths.Load())
			}
		})
	}

	// A limit above MaxListLimit is asked for as given and halves from
	// MaxListLimit; no limit is the default, 50.
	for _, tc := range []struct {
		from   int
		limits []int
	}{
		{1000, []int{1000, 100, 50, 25, 12, 6, 3, 1}},
		{0, []int{relayapi.DefaultListLimit, 25, 12, 6, 3, 1}},
	} {
		t.Run(fmt.Sprintf("halving from a limit of %d", tc.from), func(t *testing.T) {
			srv, _, asks := halvingRelay(t, relayapi.MaxBytesCeiling, 0)
			c, err := New(srv.URL, testIdentity(t, "tester"), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.ListWait(t.Context(), ListRequest{After: 10, Limit: tc.from})
			if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
				t.Fatalf("every page over the hold: %v; want the malformed answer naming %q", err, want)
			}
			var limits []int
			for _, a := range asks() {
				limits = append(limits, a.limit)
			}
			if !slices.Equal(limits, tc.limits) {
				t.Fatalf("limits asked %v; want %v", limits, tc.limits)
			}
		})
	}

	t.Run("every ask keeps the wait and the peers", func(t *testing.T) {
		srv, _, asks := halvingRelay(t, relayapi.MaxBytesCeiling, 25)
		c, err := New(srv.URL, testIdentity(t, "tester"), nil)
		if err != nil {
			t.Fatal(err)
		}
		peer := testIdentity(t, "bob").Fingerprint()
		issued := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
		_, err = c.ListWait(t.Context(), ListRequest{After: 10, Limit: 200, Stubs: true, Wait: 2 * time.Second,
			Peers: map[string]time.Time{peer: issued}})
		if err != nil {
			t.Fatalf("ListWait: %v; want the page of 25 rows taken", err)
		}
		got := asks()
		if len(got) != 4 {
			t.Fatalf("%d asks; want 4, 200 halved to 25", len(got))
		}
		wantPeers := peer + ":" + strconv.FormatInt(issued.UnixNano(), 10)
		if got[0].wait != "2s" || got[0].peers != wantPeers {
			t.Fatalf("the first ask's wait %q and peers %q; want 2s and %q", got[0].wait, got[0].peers, wantPeers)
		}
		for _, a := range got[1:] {
			if a.wait != got[0].wait || a.peers != got[0].peers || a.after != "10" || a.stubs != "1" {
				t.Errorf("the ask at %d: wait %q, peers %q, after %q, stubs %q; want the first ask's %q, %q, 10 and 1",
					a.limit, a.wait, a.peers, a.after, a.stubs, got[0].wait, got[0].peers)
			}
		}
	})

	t.Run("a hold below MaxListingHold does not halve", func(t *testing.T) {
		srv, healths, asks := halvingRelay(t, relayapi.DefaultMaxBytes, 0)
		c, err := New(srv.URL, testIdentity(t, "tester"), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.ListWait(t.Context(), ListRequest{After: 10, Limit: 200})
		small := fmt.Sprintf("under %d bytes, the most this route holds", holdFor(relayapi.DefaultMaxBytes))
		if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), small) {
			t.Fatalf("a page over a 16 MiB relay's hold: %v; want the malformed answer naming %q", err, small)
		}
		if got := asks(); len(got) != 1 || got[0].limit != 200 {
			t.Fatalf("asks %v; want the one at 200, the refusal standing", got)
		}
		if healths.Load() != 2 {
			t.Fatalf("healths %d; want 2, the first and the re-ask that found no growth", healths.Load())
		}
	})
}
