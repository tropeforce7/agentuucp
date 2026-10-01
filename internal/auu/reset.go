package auu

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A cursor past everything a relay holds. The relay's listing says the
// lowest and highest ids it holds for the mailbox; a cursor above the
// highest is past all of it, which happens on an ordinary day, when the
// newest mail kept on the relay is removed, and after a relay's numbering
// began again, when its database was deleted. The two are told apart by
// what the relay holds, not by guessing: every row is matched against what
// this machine already has of that relay, by the relay's id, the time the
// relay received it and the size it lists it at. When every row is mail
// this machine has, the cursor is set to the relay's last id and nothing
// is said or downloaded. When any is not, the cursor is set before the
// relay's first id and the mailbox is fetched again in the same run, each
// message this machine already holds met rather than saved, and the
// sentence says what happened.

// relayCopy is what a relay's listing says of one message: its id there,
// when the relay received it, and the size the relay lists it at.
type relayCopy struct {
	ID       int64
	Received time.Time
	Size     int64
}

// copyOf is a listed row's relayCopy.
func copyOf(m client.Message) relayCopy {
	return relayCopy{ID: m.ID, Received: m.Received, Size: m.Size}
}

// same reports whether two copies are one: all three agree. A record from
// before its size was kept has zero there and matches nothing.
func (a relayCopy) same(b relayCopy) bool {
	return a.ID == b.ID && a.Size == b.Size && a.Size > 0 && a.Received.Equal(b.Received)
}

// heldRecord is one record this machine holds of one relay's mail.
type heldRecord struct {
	box    store.Box
	id     string
	listed relayCopy
	// stillOn is what the record says: the relay holds it, or its
	// payload.
	stillOn bool
}

// heldOf is every record of one relay in the inbox and the quarantine, and
// its left-behind entries.
func heldOf(s *store.Store, relayName string) ([]heldRecord, []store.LeftEntry, error) {
	var out []heldRecord
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		msgs, err := s.List(box)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range msgs {
			if m.Relay != relayName {
				continue
			}
			out = append(out, heldRecord{box: box, id: m.Inner.ID,
				listed:  relayCopy{ID: m.RelayID, Received: m.Received, Size: m.RelaySize},
				stillOn: m.StillOnRelay()})
		}
	}
	left, err := s.LeftBehind(relayName)
	if err != nil {
		return nil, nil, err
	}
	return out, left, nil
}

// pastAll is the classification both a fetch and a watch make of a cursor
// past everything the relay holds: the relay's rows, listed without their
// envelopes from the start, each matched to a record or a left-behind
// entry of this machine's for that relay, or not. A fetch acts on it; a
// watch only says what is new.
type pastAll struct {
	// matched is each matched row's record, by the row's id; a row matched
	// to a left-behind entry is in left.
	matched map[int64]heldRecord
	left    map[int64]store.LeftEntry
	// fresh is the rows nothing here matches: mail this machine does not
	// have, or cannot tell it has without opening it.
	fresh []client.Message
	// records and entries are what was matched against, for the pass
	// that marks what the relay no longer holds.
	records []heldRecord
	entries []store.LeftEntry
}

// classifyPast lists the relay's mailbox as stubs from the start and
// matches each row. It costs one stubs listing a page of
// relayapi.MaxListLimit rows, and downloads no envelope; a mailbox the
// relay says is empty, last zero, costs no listing, since there is no row
// to match.
func classifyPast(ctx context.Context, s *store.Store, c *client.Client, r *store.Relay, last int64) (*pastAll, error) {
	records, entries, err := heldOf(s, r.Name)
	if err != nil {
		return nil, err
	}
	p := &pastAll{matched: map[int64]heldRecord{}, left: map[int64]store.LeftEntry{},
		records: records, entries: entries}
	if last == 0 {
		return p, nil
	}
	for after := int64(0); ; {
		page, err := c.ListWait(ctx, client.ListRequest{After: after, Limit: relayapi.MaxListLimit, Stubs: true})
		if err != nil {
			return nil, err
		}
		if len(page.Messages) == 0 {
			return p, nil
		}
		for _, m := range page.Messages {
			after = m.ID
			listed := copyOf(m)
			if rec, ok := matchRecord(records, listed); ok {
				p.matched[m.ID] = rec
				continue
			}
			if e, ok := matchLeft(entries, listed); ok {
				p.left[m.ID] = e
				continue
			}
			p.fresh = append(p.fresh, m)
		}
		// The page that reaches the relay's last id is the last page: one
		// more would be empty, and cost a request to say so.
		if after >= last {
			return p, nil
		}
	}
}

func matchRecord(records []heldRecord, listed relayCopy) (heldRecord, bool) {
	for _, rec := range records {
		if rec.listed.same(listed) {
			return rec, true
		}
	}
	return heldRecord{}, false
}

func matchLeft(entries []store.LeftEntry, listed relayCopy) (store.LeftEntry, bool) {
	for _, e := range entries {
		if (relayCopy{ID: e.RelayID, Received: e.Received, Size: e.Size}).same(listed) {
			return e, true
		}
	}
	return store.LeftEntry{}, false
}

// settleMatched is the reset when every row was matched: a matched record
// that says it was let go from the relay is acknowledged again, so the
// person's earlier choice stands; then what the relay no longer holds is
// marked so. Nothing is downloaded.
func settleMatched(ctx context.Context, s *store.Store, c *client.Client, relayName string, p *pastAll) (map[string]bool, error) {
	met := map[string]bool{}
	for relayID, rec := range p.matched {
		met[rec.id] = true
		if !rec.stillOn {
			if err := c.Ack(ctx, relayID); err != nil {
				return nil, transportErr(err)
			}
		}
	}
	keep := map[string]bool{}
	for _, e := range p.left {
		keep[e.ID] = true
	}
	return met, keepLeft(s, relayName, p.records, p.entries, met, keep, nil)
}

// meeter is what a fetch knows of the mail it already holds from one relay,
// which it meets rather than saves (ruling 53): a fetch is the same whether
// a message is listed to it once or again, after a lost acknowledgement, a
// cursor set back by hand, or a reset cut off part-way and run again.
type meeter struct {
	relay *store.Relay
	// entries is the relay's left-behind file as the fetch began, and
	// moved each one met under a new relay id.
	entries []store.LeftEntry
	moved   map[string]store.LeftEntry
	// met is every message met since the last reset began, by its own
	// id, and fresh counts what was handled that this machine did not
	// have: delivered, quarantined or kept as damaged.
	met   map[string]bool
	fresh int
}

func newMeeter(s *store.Store, r *store.Relay) (*meeter, error) {
	entries, err := s.LeftBehind(r.Name)
	if err != nil {
		return nil, err
	}
	return &meeter{relay: r, entries: entries, moved: map[string]store.LeftEntry{}, met: map[string]bool{}}, nil
}

// meet reports whether a message the fetch opened is one this machine
// already holds from this relay. One in the inbox or the quarantine keeps
// its record as it is, but for what the record says of the relay's copy —
// its id there, the time the relay received it, the size it lists it at —
// which is the one thing about it the relay changed; and a record that
// says it was let go from the relay is acknowledged again. One removed here
// alone and left on the relay is remembered under its new relay id. Neither
// is counted as delivered.
//
// A record of the same id held through another relay is not met: the fetch
// saves over it as it always has, so that what arrives here is not left
// queued on this relay, unacknowledged and behind the cursor, for every
// later fetch to call skipped mail.
func (mt *meeter) meet(ctx context.Context, s *store.Store, c *client.Client, m client.Message, innerID string) (bool, error) {
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		rec, err := s.Holding(box, innerID)
		if err != nil {
			// A record of this id that will not read is not met: the
			// message is saved over it, as it always was, which puts a
			// good copy where the broken one was rather than refusing
			// every fetch of the mailbox until a person removes it.
			continue
		}
		if rec == nil {
			continue
		}
		if rec.Relay != mt.relay.Name {
			return false, nil
		}
		mt.met[innerID] = true
		letGo := !rec.OnRelay && !rec.PayloadOnRelay
		rec.RelayID, rec.Received, rec.RelaySize = m.ID, m.Received, m.Size
		rec.PayloadGone = false
		if err := s.Save(box, rec); err != nil {
			return false, err
		}
		if letGo {
			if err := c.Ack(ctx, m.ID); err != nil {
				return false, transportErr(err)
			}
		}
		return true, nil
	}
	for _, e := range mt.entries {
		if e.ID == innerID {
			mt.met[innerID] = true
			mt.moved[innerID] = store.LeftEntry{RelayID: m.ID, ID: innerID, Received: m.Received, Size: m.Size}
			return true, nil
		}
	}
	return false, nil
}

// settle writes the left-behind entries met under a new relay id, when no
// reset is finishing to write them with the rest.
func (mt *meeter) settle(s *store.Store) error {
	if len(mt.moved) == 0 {
		return nil
	}
	out := make([]store.LeftEntry, 0, len(mt.entries))
	for _, e := range mt.entries {
		if to, ok := mt.moved[e.ID]; ok {
			e = to
		}
		out = append(out, e)
	}
	mt.entries, mt.moved = out, map[string]store.LeftEntry{}
	return s.SetLeftBehind(mt.relay.Name, out)
}

// resetRun is a fetch that set its cursor before the relay's first id,
// because the cursor was past everything the relay holds and the relay
// holds mail this machine cannot tell it has. What it does not meet is no
// longer on the relay.
type resetRun struct {
	relay   *store.Relay
	was     int64
	first   int64
	last    int64
	records []heldRecord
	entries []store.LeftEntry
	meet    *meeter
}

// startReset sets up the re-fetch, counting from here what is met and what
// is new.
func startReset(r *store.Relay, was int64, page client.Listing, p *pastAll, mt *meeter) *resetRun {
	mt.met, mt.fresh = map[string]bool{}, 0
	return &resetRun{relay: r, was: was, first: page.First, last: page.Last,
		records: p.records, entries: p.entries, meet: mt}
}

// finish is the end of the re-fetch: what it did not meet is no longer on
// the relay, and the sentence is said when it found mail this machine did
// not have.
func (rs *resetRun) finish(s *store.Store) error {
	keep := map[string]bool{}
	for id := range rs.meet.moved {
		keep[id] = true
	}
	if err := keepLeft(s, rs.relay.Name, rs.records, rs.entries, rs.meet.met, keep, rs.meet.moved); err != nil {
		return err
	}
	rs.meet.moved = map[string]store.LeftEntry{}
	if rs.meet.fresh > 0 {
		fmt.Fprintf(os.Stderr, "%s: this machine's cursor was %d and the relay's mail is numbered %d to %d, "+
			"so the cursor was reset and mail is fetched from the beginning; nothing is delivered twice here\n",
			rs.relay.Name, rs.was, rs.first, rs.last)
	}
	return nil
}

// keepLeft marks every record of the relay the reset did not meet as no
// longer on it — the message, or a quarantined stream's payload, which is
// gone — so that nothing asks the relay for anything under a relay id that
// may now name other mail; and keeps the left-behind entries that were
// met, under the relay id they were met under where it moved.
func keepLeft(s *store.Store, relayName string, records []heldRecord, entries []store.LeftEntry,
	met, keepEntry map[string]bool, moved map[string]store.LeftEntry) error {
	for _, rec := range records {
		if met[rec.id] || !rec.stillOn {
			continue
		}
		m, err := s.Load(rec.box, rec.id)
		if err != nil {
			return err
		}
		m.OnRelay = false
		if m.PayloadOnRelay {
			m.PayloadGone = true
		}
		if err := s.Save(rec.box, m); err != nil {
			return err
		}
	}
	var left []store.LeftEntry
	for _, e := range entries {
		if !keepEntry[e.ID] {
			continue
		}
		if to, ok := moved[e.ID]; ok {
			e = to
		}
		left = append(left, e)
	}
	if len(left) == len(entries) && len(moved) == 0 {
		return nil
	}
	return s.SetLeftBehind(relayName, left)
}
