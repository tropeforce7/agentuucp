package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// G4: a page of exactly the listing hold is taken at a cost bounded by the
// hold (R13, as ruled again in R13a). The second adversarial pass measured
// 10.1 times the hold allocated and 8.0 times live: io.ReadAll's doublings,
// then a json.Decoder for the key walk and another for the decode, each
// growing its own copy of the page. The review's test,
// TestAdv2_APageAtTheHoldIsTakenAtManyTimesTheHold, lands here renamed,
// its relay and measure unchanged.
//
// R13a sets two bounds. A page that declares its length is read into a
// buffer of that length and costs the page once, 1.00 times the hold
// measured, held under 1.25 times allocated and live so that a return to
// growing the buffer fails. A chunked page keeps the review's own
// assertion, under three times allocated, and is held under 2.25 times
// live (2.10 measured): it is the one cost a relay can impose by
// withholding its length, and the hold bounds it.

// pageCostHead is a listing page's fields, its object left open.
const pageCostHead = `{"messages":[],"queued":0,"first":0,"last":0,"allow":"none","card":"none","directory":"none"`

// pageCostRelay answers health with max_bytes of a gigabyte and every
// listing with a page of exactly size bytes: white space before the object
// (lead) or before its closing brace. With declared it sends the page's
// Content-Length; without, net/http sends it chunked, which is the review's
// case and the one the Content-Length sizing does nothing for (R14).
func pageCostRelay(t *testing.T, size int64, lead, declared bool, asks *atomic.Int64) *httptest.Server {
	t.Helper()
	spaces := bytes.Repeat([]byte(" "), 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			io.WriteString(w, `{"ok":true,"max_bytes":1073741824,"knock_max_bytes":1,"registration":"open","wire_level":1}`)
			return
		}
		asks.Add(1)
		if declared {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		}
		pad := size - int64(len(pageCostHead)) - 1
		write := func() {
			for left := pad; left > 0; {
				n := min(left, int64(len(spaces)))
				if _, err := w.Write(spaces[:n]); err != nil {
					return
				}
				left -= n
			}
		}
		if lead {
			write()
			io.WriteString(w, pageCostHead+"}")
			return
		}
		io.WriteString(w, pageCostHead)
		write()
		io.WriteString(w, "}")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// pageCostMeasure runs f while sampling the live heap every millisecond,
// and returns TotalAlloc's growth and the highest HeapAlloc seen above the
// start. TotalAlloc sees every byte allocated and dropped; HeapAlloc sees
// what is held at once, which is what a page costs the machine.
func pageCostMeasure(f func()) (total, peak uint64) {
	return measurePageCost(f, false)
}

// pageCostMeasureCollected is pageCostMeasure with a collection forced
// before each sample, so that HeapAlloc is what is reachable then and not
// garbage a collector slowed by other work has not reached: under a whole
// suite's load the plain sample read a page of envelopes a tenth of a page
// higher. TotalAlloc is unchanged by it.
func pageCostMeasureCollected(f func()) (total, peak uint64) {
	return measurePageCost(f, true)
}

func measurePageCost(f func(), collect bool) (total, peak uint64) {
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var max atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			if collect {
				runtime.GC()
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > max.Load() {
				max.Store(ms.HeapAlloc)
			}
		}
	}()
	f()
	close(stop)
	<-done
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > max.Load() {
		max.Store(after.HeapAlloc)
	}
	p := uint64(0)
	if m := max.Load(); m > before.HeapAlloc {
		p = m - before.HeapAlloc
	}
	return after.TotalAlloc - before.TotalAlloc, p
}

// The review's case, a chunked page of exactly MaxListingHold with its
// padding before the object and before its closing brace, taken under three
// times the hold allocated and 2.25 times live; and the same page with its
// Content-Length declared, taken under 1.25 times the hold both ways (R13a).
func TestAPageAtTheHoldIsTakenUnderThreeTimesTheHold(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation is measured without the race detector")
	}
	if relayapi.MaxListingHold != 2*(64<<20)+(1<<16) {
		t.Fatalf("MaxListingHold = %d; the review measured 2*64 MiB + 64 KiB", relayapi.MaxListingHold)
	}
	for _, tc := range []struct {
		lead, declared bool
	}{
		{true, false},
		{false, false},
		{true, true},
		{false, true},
	} {
		t.Run(fmt.Sprintf("leading=%v,declared=%v", tc.lead, tc.declared), func(t *testing.T) {
			var asks atomic.Int64
			srv := pageCostRelay(t, relayapi.MaxListingHold, tc.lead, tc.declared, &asks)
			c, err := New(srv.URL, testIdentity(t, "tester"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := c.listingCap(t.Context(), false); err != nil {
				t.Fatal(err)
			}
			var listErr error
			total, peak := pageCostMeasure(func() { _, listErr = c.List(t.Context(), 0, relayapi.MaxListLimit) })
			hold := uint64(relayapi.MaxListingHold)
			t.Logf("page of %d bytes (the hold): List err=%v; asks=%d; TotalAlloc +%d MiB (%.2fx the hold); peak live heap +%d MiB (%.2fx)",
				hold, listErr, asks.Load(), total>>20, float64(total)/float64(hold), peak>>20, float64(peak)/float64(hold))
			if listErr != nil {
				t.Fatalf("a page of exactly the hold was refused: %v", listErr)
			}
			if asks.Load() != 1 {
				t.Errorf("the page was asked for %d times; want once", asks.Load())
			}
			// The bounds in hundredths of the hold, R13a's figures.
			totalCap, peakCap := uint64(300), uint64(225)
			if tc.declared {
				totalCap, peakCap = 125, 125
			}
			if total*100 >= totalCap*hold {
				t.Errorf("a relay saying max_bytes 1 GiB had a page of %d bytes (declared %v) taken at a cost of %d MiB allocated, %.2f times the hold; want under %.2f times",
					hold, tc.declared, total>>20, float64(total)/float64(hold), float64(totalCap)/100)
			}
			if peak*100 >= peakCap*hold {
				t.Errorf("a page of %d bytes (declared %v) held %d MiB live at its peak, %.2f times the hold; want under %.2f times",
					hold, tc.declared, peak>>20, float64(peak)/float64(hold), float64(peakCap)/100)
			}
		})
	}
}

// countingBody is an answer body that counts the Read calls made of it.
type countingBody struct {
	r     io.Reader
	reads int
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads++
	return b.r.Read(p)
}

// readCapped against a body of each length about a hold, declared and not.
// A declared length at or under the hold is read into a buffer of exactly
// that length; one over is refused with errDeclaredOver before a Read is
// made of the body; an undeclared one is read to the hold and a byte, and
// left to its caller to refuse over it. A declared length the body falls
// short of is the reader's own unexpected end.
func TestReadCappedReadsADeclaredLengthIntoItsOwnSize(t *testing.T) {
	const hold = 4096
	body := func(n int) *countingBody {
		return &countingBody{r: bytes.NewReader(bytes.Repeat([]byte("x"), n))}
	}
	for _, n := range []int{0, 1, hold - 1, hold} {
		b := body(n)
		got, err := readCapped(b, int64(n), hold)
		if err != nil || len(got) != n {
			t.Errorf("declared %d under a hold of %d: %d bytes, %v; want all of it", n, hold, len(got), err)
		}
		if cap(got) != n {
			t.Errorf("declared %d: a buffer of capacity %d; want exactly the declared length", n, cap(got))
		}
	}
	for _, declared := range []int64{hold + 1, 1 << 40, 1<<63 - 1} {
		b := body(hold + 1)
		got, err := readCapped(b, declared, hold)
		if !errors.Is(err, errDeclaredOver) || got != nil {
			t.Errorf("declared %d over a hold of %d: %d bytes, %v; want errDeclaredOver and nothing", declared, hold, len(got), err)
		}
		if b.reads != 0 {
			t.Errorf("declared %d over a hold of %d: the body was read %d times; want none", declared, hold, b.reads)
		}
	}
	for _, n := range []int{hold, hold + 1, 2 * hold} {
		got, err := readCapped(body(n), -1, hold)
		if err != nil {
			t.Errorf("undeclared, %d bytes: %v", n, err)
		}
		if want := min(n, hold+1); len(got) != want {
			t.Errorf("undeclared, %d bytes sent: read %d; want %d, the hold and a byte at most", n, len(got), want)
		}
	}
	if got, err := readCapped(body(10), 20, hold); !errors.Is(err, io.ErrUnexpectedEOF) || got != nil {
		t.Errorf("declared 20 with 10 sent: %d bytes, %v; want io.ErrUnexpectedEOF", len(got), err)
	}
}

// Through attempt: an answer whose Content-Length is over the route's hold
// is refused as an answer over the hold, by name, without waiting for a
// body the relay never sends, and a Content-Length of exactly the hold is
// taken.
func TestADeclaredLengthOverTheHoldIsRefusedBeforeTheBody(t *testing.T) {
	release := make(chan struct{})
	var declare atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			fmt.Fprintf(w, `{"ok":true,"max_bytes":%d,"knock_max_bytes":1,"registration":"open","wire_level":1}`, relayapi.DefaultMaxBytes)
			return
		}
		n := declare.Load()
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		if n > holdFor(relayapi.DefaultMaxBytes) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select { // the body never comes
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, pageCostHead)
		io.WriteString(w, strings.Repeat(" ", int(n)-len(pageCostHead)-1))
		io.WriteString(w, "}")
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c, err := New(srv.URL, testIdentity(t, "tester"), nil)
	if err != nil {
		t.Fatal(err)
	}
	hold := holdFor(relayapi.DefaultMaxBytes)
	declare.Store(hold)
	if _, err := c.List(t.Context(), 0, 1); err != nil {
		t.Fatalf("a declared page of exactly the hold, %d bytes: %v; want it taken", hold, err)
	}
	declare.Store(hold + 1)
	// A client that waited for the body would wait for ever; the deadline
	// turns that into a failure with a sentence rather than a hung run.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	start := time.Now()
	_, err = c.List(ctx, 0, 1)
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the refusal took %v; it waited for a body the relay never sent", d)
	}
	want := fmt.Sprintf("under %d bytes, the most this route holds", hold)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
		t.Fatalf("a Content-Length one over the hold: %v; want the malformed answer naming %q", err, want)
	}
}
