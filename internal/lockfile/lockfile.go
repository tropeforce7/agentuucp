// Package lockfile is one lock per file, held by one process at a time and
// released by the kernel when the process exits however it exits, so a
// crash leaves nothing stale. On Unix it is flock; on Windows it is a file
// opened with no sharing allowed, which has flock's shape. The agent holds
// one for its lifetime, and a fetch holds one for its length.
package lockfile

import (
	"context"
	"errors"
	"time"
)

// ErrHeld is a lock another process holds.
var ErrHeld = errors.New("held by another process")

// pollInterval is how often a waiting Take asks again. The kernel offers no
// bounded wait on either platform, so waiting is asking.
const pollInterval = 100 * time.Millisecond

// Take takes the lock at path, waiting up to wait for whoever holds it, and
// reports ErrHeld when the wait is over. A zero wait asks once. It stops
// asking when ctx is done and returns ctx.Err(), checked after each pause,
// so that whatever is waiting inside a poll is cut off with the poll.
// waited says whether anybody was waited for at all. sleep is the pause
// between asks, time.Sleep when nil; a test passes its own, which is how
// it knows the taker has asked and found the lock held.
func Take(ctx context.Context, path string, wait time.Duration, sleep func(time.Duration)) (l *Lock, waited bool, err error) {
	if sleep == nil {
		sleep = time.Sleep
	}
	deadline := time.Now().Add(wait)
	for {
		l, err := Try(path)
		if !errors.Is(err, ErrHeld) || !time.Now().Before(deadline) {
			return l, waited, err
		}
		waited = true
		sleep(pollInterval)
		if err := ctx.Err(); err != nil {
			return nil, waited, err
		}
	}
}
