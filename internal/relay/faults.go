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

// noteCarriedAgain says that a neighbour has handed this relay an envelope
// it already holds.
//
// A retry after a lost answer is one, and so is a loop: a neighbour that
// sends the same envelope back from another direction is the thing an
// operator wants to know about, and the two cannot be told apart from here.
// It is keyed by this relay's own name for that neighbour — never by
// anything a sender chose, which would be a limit keyed on a string the
// sender picked — so a burst from one neighbour is one line a minute and two
// neighbours are two, and it names no mailbox and no fingerprint.
func (f *faultLog) noteCarriedAgain(neighbour string) {
	if f == nil || f.log == nil {
		return
	}
	key := "carried:" + neighbour
	if !f.due(key) {
		return
	}
	f.log.Warn("a neighbour handed over an envelope this relay already carried; "+
		"a retry whose answer was lost, or a loop, and either way it goes no further",
		"neighbour", neighbour)
}

// noteDirectory logs that a mailbox's channel directory does not verify,
// so every post to the mailbox is refused, default included, unless that
// was logged for the mailbox inside the last minute; keyed apart from the
// allow list's line, the card's and a path's. It says the same thing the
// allow list's line says because it now means the same thing: the
// mailbox is closed until its owner pushes again.
func (f *faultLog) noteDirectory(fp string) {
	if f.due("directory:" + fp) {
		f.log.Warn(fmt.Sprintf("channel directory for %s does not verify; refusing every post to it until the owner pushes again", fp))
	}
}

// noteUndialable says a courier this relay accepts from is one it cannot dial,
// so news for it stops here. It is the one-way peering the start already says
// out loud, met at the moment it costs something.
func (f *faultLog) noteUndialable(name string) {
	if f.due("undialable:" + name) {
		f.log.Warn("courier: an undeliverable cannot be passed back to a neighbour this relay "+
			"accepts from but cannot dial; the peering is one-way", "neighbour", name)
	}
}

// noteReportNotQueued says an undeliverable could not be written down. The row
// it was about is already failed, which is what its own poster needs.
//
// Nobody further back is told, and nothing will tell them later: the row that
// would have to notice is a handed one, and a handed row is never given up on.
// So this line is the only trace, and it says that rather than promising a
// timeout that does not exist. The error here is this relay's own — a full
// disk, a queue at its bound — and so is bounded by this tree's own words.
func (f *faultLog) noteReportNotQueued(name string, err error) {
	if f.due("report:" + name) {
		f.log.Error("courier: an undeliverable for a neighbour could not be queued; "+
			"nobody further back will be told of it", "neighbour", name, "err", err)
	}
}

// noteReportRefused says a neighbour would not take an undeliverable this
// relay was passing back. The chain ends here: a report is never generated
// for a report, so there is nothing further to try and nothing to tell.
//
// It takes the sentence and not the error, for the reason noteRefusal exists.
// An *HTTPError prints the neighbour's whole message, which is bounded by what
// a client will read from a relay — sixteen megabytes twice over, which
// escaping can quadruple — and by nothing smaller. A line a minute of that,
// per peer, is a neighbour choosing how large this relay's log grows, which is
// the choice said takes away and which passing the error here took back.
func (f *faultLog) noteReportRefused(name, said string) {
	if f.due("reportrefused:" + name) {
		f.log.Warn("courier: a neighbour would not take an undeliverable; the chain ends here, "+
			"and nothing further is tried or told",
			"neighbour", name, "said", said)
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
