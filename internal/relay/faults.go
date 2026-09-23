package relay

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// A storage fault — a write, read, rename or mkdir under the message
// directory that failed — is answered to the client as a 500 that says
// nothing, since nothing the client can do would help. This is where the
// relay says why: one WARN line with the path and the error, so the operator
// has a line to find. It is limited to one a minute per path, so a broken
// disk under a busy relay does not fill the log with the same line. An
// allow list that no longer verifies is said the same way, one line a
// minute per mailbox, for the same reason: a sender retrying in a loop
// against a broken list is the same shape as a broken disk. A card that no
// longer verifies likewise, at a knock, and a channel directory that does
// not verify, at a post to a named channel — each naming the mailbox alone
// and never the sender, under both access log modes as the allow list's
// line is: the line is about a row on this relay, not about who talks to
// whom.

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
// minute.
func (f *faultLog) note(path string, err error) {
	if f.due(path) {
		f.log.Warn("storage fault", "path", path, "err", err)
	}
}

// noteAllowlist logs that a mailbox's allow list does not verify, unless
// that was logged for the mailbox inside the last minute. The key is
// prefixed so that a mailbox's line and a path's line are limited apart.
func (f *faultLog) noteAllowlist(fp string) {
	if f.due("allowlist:" + fp) {
		f.log.Warn(fmt.Sprintf("allow list for %s does not verify; refusing every post to it until the owner pushes again", fp))
	}
}

// noteCard logs that a mailbox's card does not verify, so knocks to it
// are refused, unless that was logged for the mailbox inside the last
// minute; keyed apart from the allow list's line and a path's.
func (f *faultLog) noteCard(fp string) {
	if f.due("card:" + fp) {
		f.log.Warn(fmt.Sprintf("card for %s does not verify; refusing knocks to it until the owner pushes again", fp))
	}
}

// noteDirectory logs that a mailbox's channel directory does not verify,
// so every named channel is refused, unless that was logged for the
// mailbox inside the last minute; keyed apart from the allow list's line,
// the card's and a path's.
func (f *faultLog) noteDirectory(fp string) {
	if f.due("directory:" + fp) {
		f.log.Warn(fmt.Sprintf("channel directory for %s does not verify; refusing every named channel to it until the owner pushes again", fp))
	}
}

// due reports whether a line for key is to be written now, and records it
// when so. On every line written, entries older than a minute are dropped,
// and past the cap the oldest goes.
func (f *faultLog) due(key string) bool {
	if f == nil || f.log == nil {
		return false
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.last[key]; ok && now.Sub(t) < faultInterval {
		return false
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
	f.last[key] = now
	return true
}

// size reports how many paths are remembered, for the test of the cap.
func (f *faultLog) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.last)
}
