package relay

import (
	"log/slog"
	"sync"
	"time"
)

// A storage fault — a write, read, rename or mkdir under the message
// directory that failed — is answered to the client as a 500 that says
// nothing, since nothing the client can do would help. This is where the
// relay says why: one WARN line with the path and the error, so the operator
// has a line to find. It is limited to one a minute per path, so a broken
// disk under a busy relay does not fill the log with the same line.

const (
	// faultInterval is how long one path's fault line covers.
	faultInterval = time.Minute
	// faultEntries caps the map of paths recently logged. Paths derive from
	// validated fingerprints and upload ids, so the map is bounded by the
	// relay's own contents anyway; the cap is the guarantee.
	faultEntries = 1024
)

// faultLog remembers when each path was last logged.
type faultLog struct {
	log *slog.Logger
	now func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

func newFaultLog(log *slog.Logger, now func() time.Time) *faultLog {
	if now == nil {
		now = time.Now
	}
	return &faultLog{log: log, now: now, last: map[string]time.Time{}}
}

// note logs a fault at path unless one was logged for it inside the last
// minute. On every line written, entries older than a minute are dropped,
// and past the cap the oldest goes.
func (f *faultLog) note(path string, err error) {
	if f == nil || f.log == nil {
		return
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.last[path]; ok && now.Sub(t) < faultInterval {
		return
	}
	for p, t := range f.last {
		if now.Sub(t) >= faultInterval {
			delete(f.last, p)
		}
	}
	if len(f.last) >= faultEntries {
		oldest, when := "", now
		for p, t := range f.last {
			if !t.After(when) {
				oldest, when = p, t
			}
		}
		delete(f.last, oldest)
	}
	f.last[path] = now
	f.log.Warn("storage fault", "path", path, "err", err)
}

// size reports how many paths are remembered, for the test of the cap.
func (f *faultLog) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.last)
}
