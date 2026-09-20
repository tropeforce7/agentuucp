package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
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
