package relay

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A fault in a courier worker's turn is a failed turn, not the end of the
// relay (S59): the worker's goroutine is outside every HTTP handler, so a
// panic there ended the process. Now the fault is said once, with its
// stack, the neighbour is left alone for a failed attempt's backoff, and
// the worker's next turn dials it again.
func TestAWorkerTurnThatFaultsIsAFailedTurn(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	w := newWorkers(h.store, h.server.courier, h.server.cfg.CourierLimits, h.server.log, h.clock.Now)
	if w == nil {
		t.Fatal("this relay dials nobody")
	}
	dials := 0
	w.dial = func(r *store.Relay) (*client.Client, error) {
		dials++
		if dials == 1 {
			panic("a fault planted in the first dial")
		}
		return nil, errors.New("connection refused")
	}
	var waits []time.Duration
	w.sleep = func(_ context.Context, d time.Duration, _ <-chan struct{}) {
		waits = append(waits, d)
		// Past the backoff, so the next turn dials rather than waits.
		h.clock.advance(d + time.Second)
		if len(waits) == 2 {
			w.stop()
		}
	}
	user := h.user(t, "alice")
	h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	w.start()
	w.done.Wait()

	if dials != 2 {
		t.Fatalf("the worker dialled %d times; want the faulted turn and the one after it", dials)
	}
	if len(waits) == 0 || waits[0] < 45*time.Second {
		t.Fatalf("the turn after the fault waited %v; want a failed attempt's backoff", waits)
	}
	logs := h.logs.String()
	if n := strings.Count(logs, "a turn for a neighbour ended with a fault"); n != 1 || !strings.Contains(logs, "a fault planted in the first dial") ||
		!strings.Contains(logs, "goroutine ") {
		t.Fatalf("the fault was said %d times, want once with its stack:\n%s", n, logs)
	}
}

// A fault in the middle of a scan leaves the store's one connection free:
// its rows are closed by a defer as well as by hand, so a fault that a
// recover turns into a failed turn does not hold the connection every other
// call on the relay waits for (S59). The purge's per-row callback is where a
// fault can come mid-scan.
func TestAFaultMidScanLeavesTheStoreAnswering(t *testing.T) {
	limits := DefaultCourierLimits()
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	handed := h.queue(user, sealedFor(h.fpOf(t, "bob"), "handed"), "bar")
	if err := h.store.Handed(handed, 5, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the planted fault never ran; the test proves nothing")
			}
		}()
		// The purge asks the window once before its query, then for each
		// handed row inside the scan: the second call is mid-scan.
		calls := 0
		h.store.PurgeOutbound(h.clock.Now().Add(365*24*time.Hour), finalRowRetention,
			func(int) time.Duration {
				if calls++; calls == 2 {
					panic("a fault planted mid-scan")
				}
				return time.Hour
			})
	}()
	answered := make(chan error, 1)
	go func() {
		_, err := h.store.Carried("0000")
		answered <- err
	}()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("the store after a fault mid-scan: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the store did not answer after a fault mid-scan: its one connection is held")
	}
}

// A fault in every turn doubles the neighbour's wait, a wake while it is
// left alone notwithstanding: a turn that only finds the neighbour still
// waiting does not count the run of faults back to none, or a busy
// neighbour's would never pass a failed attempt's first backoff.
func TestAWorkerThatFaultsEveryTurnBacksOffDoubling(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	w := newWorkers(h.store, h.server.courier, h.server.cfg.CourierLimits, h.server.log, h.clock.Now)
	if w == nil {
		t.Fatal("this relay dials nobody")
	}
	w.rnd = func() float64 { return 0 }
	dials := 0
	w.dial = func(r *store.Relay) (*client.Client, error) {
		dials++
		panic("a fault planted in every dial")
	}
	var waits []time.Duration
	w.sleep = func(_ context.Context, d time.Duration, _ <-chan struct{}) {
		waits = append(waits, d)
		switch len(waits) {
		case 1:
			// A wake: the next turn comes while the neighbour is left alone.
		case 2:
			h.clock.advance(d + time.Second)
		default:
			w.stop()
		}
	}
	user := h.user(t, "alice")
	h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	w.start()
	w.done.Wait()

	if dials != 2 || len(waits) != 3 {
		t.Fatalf("%d dials and waits %v; want a fault, a turn that waited, and a fault", dials, waits)
	}
	if waits[0] != backoffFor(1, w.rnd) || waits[2] != backoffFor(2, w.rnd) || waits[2] <= waits[0] {
		t.Fatalf("the waits after two faults were %v and %v; want %v doubling to %v",
			waits[0], waits[2], backoffFor(1, w.rnd), backoffFor(2, w.rnd))
	}
}
