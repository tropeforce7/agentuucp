package lockfile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestOneHolderAtATime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Try(path); !errors.Is(err, ErrHeld) {
		t.Fatalf("a second Try gave %v, want ErrHeld", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := Try(path)
	if err != nil {
		t.Fatalf("after Release, Try gave %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	// Releasing twice, or nothing, is nothing.
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	var none *Lock
	if err := none.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestTakeWaitsAndGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	// Free: taken at once, nobody waited for, nobody slept.
	slept := 0
	count := func(time.Duration) { slept++ }
	l, waited, err := Take(context.Background(), path, time.Second, count)
	if err != nil || waited || slept != 0 {
		t.Fatalf("Take on a free lock: %v, waited %v, slept %d", err, waited, slept)
	}
	// Held for longer than the wait: asked, slept, asked again, and ErrHeld
	// once the wait is over. The sleep is a stub, so the wait is the
	// deadline alone; a short one keeps the asking bounded.
	slept = 0
	if _, waited, err := Take(context.Background(), path, 20*time.Millisecond, count); !errors.Is(err, ErrHeld) || !waited || slept == 0 {
		t.Fatalf("Take on a held lock: %v, waited %v, slept %d; want ErrHeld after asking", err, waited, slept)
	}
	// Held, then released the moment the taker is seen to be waiting: taken,
	// and it waited. The release happens inside the taker's own sleep, so
	// there is no race to lose.
	released := false
	release := func(time.Duration) {
		if !released {
			released = true
			if err := l.Release(); err != nil {
				t.Error(err)
			}
		}
	}
	got, waited, err := Take(context.Background(), path, 10*time.Second, release)
	if err != nil || !waited || !released {
		t.Fatalf("Take after a release: %v, waited %v, released %v", err, waited, released)
	}
	got.Release()
}

// A context done while the taker waits ends the waiting with the context's
// error, not ErrHeld: whoever is waiting inside a poll is cut off with the
// poll, and the caller can tell the two apart.
func TestTakeStopsWhenTheContextIsDone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	held, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	ctx, cancel := context.WithCancel(context.Background())
	asked := 0
	cancelInPause := func(time.Duration) {
		asked++
		cancel()
	}
	got, waited, err := Take(ctx, path, time.Minute, cancelInPause)
	if got != nil || !waited || asked != 1 {
		t.Fatalf("Take under a cancelled context: lock %v, waited %v, asked %d", got, waited, asked)
	}
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrHeld) {
		t.Fatalf("Take under a cancelled context gave %v, want the context's error and not ErrHeld", err)
	}
	// A context already done still asks once: a free lock is taken.
	held.Release()
	done, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	got, waited, err = Take(done, path, time.Minute, nil)
	if err != nil || waited || got == nil {
		t.Fatalf("Take of a free lock under a done context: %v, waited %v", err, waited)
	}
	got.Release()
}
