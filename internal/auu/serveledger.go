package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The ledger is serve's record of what it has answered.
//
// It is the only thing that says a message is pending, and deliberately so.
// The watch's baseline is "now", so anything that arrived while serve was
// down would be lost if the watch were the source; and "unread" is a mark
// the owner can clear by reading their own expert's mail, which must not
// silently kill an answer. A message with an entry here is settled, however
// it was settled; a message without one is work.
//
// It is also where a thread's turns are counted, which is why each entry
// carries the thread and the channel: counting a walk of the spool instead
// would go wrong the moment somebody removed a message.

// ledgerFile is the ledger's name under the serve directory.
const ledgerFile = "ledger.json"

const ledgerV = 1

// ledger is the file.
type ledger struct {
	V        int                     `json:"v"`
	Messages map[string]*ledgerEntry `json:"messages"`

	path string
	// existed says the file was there when this run started, which is what
	// the first-start rule turns on.
	existed bool
}

// ledgerEntry is one message's outcome.
type ledgerEntry struct {
	Thread  string `json:"thread"`
	Channel string `json:"channel"`
	// Handled is when it was settled, zero while it is only failing.
	Handled time.Time `json:"handled"`
	// Tried is the last attempt, whether it ended in an answer or a
	// failure. It is what the sweep ages a thread by and what 'serve ls'
	// shows as a thread's last activity: a message that has only ever
	// failed, or that gave up, has no Handled to be aged by, and its state
	// is exactly what the next attempt needs. Every attempt writes it, so
	// an entry that counts an attempt and has no time for it is from
	// before there were timestamps, and loadLedger refuses it.
	Tried time.Time `json:"tried"`
	// Reply is the id of what serve sent back, empty when the handler had
	// nothing to say or when nothing has been sent yet.
	Reply    string `json:"reply"`
	Failures int    `json:"failures"`
	// GaveUp says the retries ran out; Skipped, that it was in the inbox
	// before serve ever ran here.
	GaveUp  bool `json:"gave_up,omitempty"`
	Skipped bool `json:"skipped,omitempty"`
	// Newer is why a message is pending and not answered: a stream that
	// waits on the relay for a newer auu (D42), by the section it needs.
	// It is never settled, skipped or counted as a turn for it; a round
	// after the upgrade finds the message delivered and answers it, and
	// the reason goes when it does.
	Newer string `json:"newer,omitempty"`
	// From is the fingerprint of the message's sender, written when the
	// entry is made. A thread belongs to the sender of its earliest entry
	// by arrival that is not skipped and has one (opener), and serve
	// answers nobody else on it. While nothing on the thread has been
	// tried or answered, a message that arrived before the recorded
	// opener's is answered, and its sender becomes the opener. An entry
	// from a v0.17.0 ledger has none. It is given one from its message in
	// the inbox at the run's start (fillSenders), or when it is next
	// written. So a thread carried over takes its opener from the earliest
	// of its messages still in the inbox. A thread whose opener's messages
	// the owner has removed may take another sender's.
	From string `json:"from,omitempty"`
	// Arrived and RelayID are when the message arrived on this machine, the
	// record's Arrived, and the relay's counter for it, written with From
	// and never rewritten. They are the order a thread's opener is read in,
	// which is the order pending takes messages in. An entry an earlier
	// release wrote holds the relay's received under the same key, a clock
	// within the skew of this one; it is not rewritten. Tried is not
	// that order: it is rewritten at every attempt, and a stream held for
	// a newer auu has none.
	Arrived time.Time `json:"arrived,omitempty"`
	RelayID int64     `json:"relay_id,omitempty"`
}

// last is when this message was last touched at all.
func (e *ledgerEntry) last() time.Time {
	if e.Handled.After(e.Tried) {
		return e.Handled
	}
	return e.Tried
}

// settled says an entry is not work any more: answered, given up on, or
// skipped as old mail. An entry that has only failed is still pending.
func (e *ledgerEntry) settled() bool {
	return !e.Handled.IsZero() || e.GaveUp || e.Skipped
}

// loadLedger reads the ledger, or gives an empty one that knows it is new.
// A file that is there and will not read is refused rather than replaced:
// the alternative is answering a year of mail for a second time.
func loadLedger(path string) (*ledger, error) {
	l := &ledger{V: ledgerV, Messages: map[string]*ledgerEntry{}, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	l.existed = true
	if err := json.Unmarshal(data, l); err != nil {
		return nil, fmt.Errorf("%s will not read (%v); it is the record of what has been answered, "+
			"so fix it or move it aside knowing that everything in the inbox becomes new mail", path, err)
	}
	if l.V != ledgerV {
		return nil, fmt.Errorf("%s is version %d; this %s writes version %d", path, l.V, prog, ledgerV)
	}
	if l.Messages == nil {
		l.Messages = map[string]*ledgerEntry{}
	}
	for id, e := range l.Messages {
		if e == nil {
			return nil, fmt.Errorf("%s has no entry under %q; it is the record of what has been answered, "+
				"so fix it or move it aside knowing that everything in the inbox becomes new mail", path, id)
		}
		if e.Failures < 0 {
			return nil, fmt.Errorf("%s counts %d failures for %s, which is not a count; it is the record of what "+
				"has been answered, so fix it or move it aside knowing that everything in the inbox becomes new mail",
				path, e.Failures, id)
		}
		// A sender is a fingerprint or nothing: it is compared with the
		// sender of every later message on the thread, and its first
		// sixteen characters are what the console says.
		if e.From != "" {
			if !identity.ValidFingerprint(e.From) {
				return nil, fmt.Errorf("%s names %q as the sender of %s, which is not a fingerprint; it is the "+
					"record of what has been answered, so fix it or move it aside knowing that everything in the "+
					"inbox becomes new mail", path, e.From, id)
			}
		}
		// A relay's counter is never below zero; it orders a thread's
		// opener, and a negative one would sort ahead of every real one.
		if e.RelayID < 0 {
			return nil, fmt.Errorf("%s has relay id %d for %s, which is not a relay's counter; it is the record of "+
				"what has been answered, so fix it or move it aside knowing that everything in the inbox becomes "+
				"new mail", path, e.RelayID, id)
		}
		// An attempt has a time. An entry that counts one and has none
		// was written before there were timestamps, and nothing on this
		// machine is from before.
		if (e.Failures > 0 || e.GaveUp) && e.Tried.IsZero() {
			return nil, fmt.Errorf("%s has an attempt with no time for %s, which is how a ledger from before v0.11.0 "+
				"was written; it is the record of what has been answered, so fix it or move it aside knowing that "+
				"everything in the inbox becomes new mail", path, id)
		}
	}
	l.path = path
	return l, nil
}

// save writes the ledger through a temporary file in the same directory, so
// that a crash between two messages leaves the last complete record rather
// than half of one.
//
// A ledger that has been written exists, which is what the first-start rule
// turns on. Saying so here rather than only at load is what makes the rule
// a rule about the first round of the service and not about every round of
// it: the long run loads the ledger once and keeps it.
func (l *ledger) save() error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(l.path), filepath.Base(l.path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, l.path); err != nil {
		return err
	}
	l.existed = true
	return nil
}

// entry is a message's record, made if it has none.
func (l *ledger) entry(id, thread, channel string) *ledgerEntry {
	e, ok := l.Messages[id]
	if !ok {
		e = &ledgerEntry{Thread: thread, Channel: channel}
		l.Messages[id] = e
	}
	return e
}

// repliedWith finds the message serve answered with the given reply, which
// is what makes a reply to that reply a follow-up rather than a stranger's
// message on a thread of its own. Nothing is what a message serve never
// sent gets.
func (l *ledger) repliedWith(id string) *ledgerEntry {
	if id == "" {
		return nil
	}
	for _, e := range l.Messages {
		if e.Reply == id {
			return e
		}
	}
	return nil
}

// answered is how many messages on a thread serve has answered, which is
// what max_turns counts and what AUU_TURN is one more than. A message that
// has only failed is not a turn: it is the same turn, tried again.
func (l *ledger) answered(thread string) int {
	n := 0
	for _, e := range l.Messages {
		if e.Thread == thread && !e.Handled.IsZero() && !e.Skipped {
			n++
		}
	}
	return n
}

// opener is the fingerprint of the peer whose thread this is: the sender of
// the thread's earliest entry by arrival, among the entries that are not
// skipped and that name a sender. Arrival is when the message arrived on
// this machine, the record's Arrived, then the relay's counter, then the
// message id: pending's order, store.ArrivalOrder, without the two ties
// it breaks after the counter, which an entry does not keep. It is never
// rewritten, so two runs agree. Nothing is what a thread serve
// has not seen gets. A thread from a v0.17.0 ledger has its senders from
// its messages still in the inbox (fillSenders). One whose messages are
// all gone gets nothing until the first message serve takes up on it after
// the upgrade is written.
func (l *ledger) opener(thread string) string {
	_, e := l.openerEntry(thread)
	if e == nil {
		return ""
	}
	return e.From
}

// openerEntry is the entry opener reads the opener from, and its message
// id, or nil.
func (l *ledger) openerEntry(thread string) (string, *ledgerEntry) {
	var bestID string
	var best *ledgerEntry
	for id, e := range l.Messages {
		if e.Thread != thread || e.Skipped || e.From == "" {
			continue
		}
		if best == nil || arrivedBefore(e.Arrived, e.RelayID, id, best.Arrived, best.RelayID, bestID) {
			bestID, best = id, e
		}
	}
	return bestID, best
}

// arrivedBefore is the order of arrival: when the message arrived on this
// machine, the record's Arrived, then the relay's counter, then the
// message id, so that two runs agree. It is pending's order as far as an
// entry keeps it; an entry an earlier release wrote holds the relay's
// received in place of the arrival.
func arrivedBefore(at time.Time, relayID int64, id string, than time.Time, thanRelayID int64, thanID string) bool {
	switch {
	case !at.Equal(than):
		return at.Before(than)
	case relayID != thanRelayID:
		return relayID < thanRelayID
	default:
		return id < thanID
	}
}

// tried says something on a thread has been tried or answered: a
// conversation is in it, and no later message's stamp moves its opener.
func (l *ledger) tried(thread string) bool {
	for _, e := range l.Messages {
		if e.Thread == thread && !e.Skipped && (!e.Tried.IsZero() || !e.Handled.IsZero()) {
			return true
		}
	}
	return false
}

// touched says serve has seen this thread before, which is what moves a
// read-only channel's worktree to the current HEAD at a new thread's first
// message and leaves it alone after that.
func (l *ledger) touched(thread string) bool {
	for _, e := range l.Messages {
		if e.Thread == thread && !e.Skipped {
			return true
		}
	}
	return false
}
