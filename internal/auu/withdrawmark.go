package auu

import (
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// markWithdrawn is the mark a withdrawal note makes, run where a message is
// filed into the inbox or the quarantine, with the record about to be
// saved, and before it is saved (R146 P10): a crash between the two leaves
// the original marked and the note to be fetched again, which marks
// nothing new, rather than a note filed and seen again as a duplicate with
// its original never marked.
//
// It acts only on a section that passes withdraw.CheckSections, on a record
// that is not a stream, naming a message this machine holds in the inbox or
// the quarantine whose verified sender is the note's (R150): a message id is
// no secret, and a note from anybody else would otherwise mark another
// person's message withdrawn. A note from another sender marks nothing and
// is said once, naming the note and never its reason. A note for an id this
// machine does not hold marks nothing and is filed as any note, which is
// also what a message this home sent and did not receive is: the sent box
// is not looked in.
//
// The mark is idempotent: a message already marked keeps the mark it has,
// so a second note for it, or the same note fetched again, changes nothing.
// It changes nothing else about the message: its text, its attachments, read,
// on_relay and an acknowledgement owed are as they were.
//
// A record that will not read is said once and marked not; the note is
// filed all the same, since a fault a message chose is that message's, never
// the fetch's.
func markWithdrawn(s *store.Store, note *store.Stored) error {
	if note == nil || note.Inner == nil || note.Streamed {
		return nil
	}
	w, err := withdraw.CheckSections(note.Inner.Sections, note.Inner.Body)
	if err != nil || w == nil {
		return nil
	}
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		m, err := s.Holding(box, w.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: a withdrawal note names a message whose record will not read; nothing was marked: %v\n",
				note.Inner.ID[:12], err)
			return nil
		}
		if m == nil {
			continue
		}
		if m.Inner.From != note.Inner.From {
			fmt.Fprintf(os.Stderr, "%s: a withdrawal note names a message it was not signed by the sender of; nothing was marked\n",
				note.Inner.ID[:12])
			return nil
		}
		if !m.Withdrawn.IsZero() {
			return nil
		}
		m.Withdrawn = time.Now().UTC().Truncate(time.Second)
		m.WithdrawnBy = note.Inner.ID
		m.WithdrawnReason = w.Reason
		if err := s.Save(box, m); err != nil {
			return fmt.Errorf("marking the message a withdrawal note names: %w", err)
		}
		return nil
	}
	return nil
}

// remarkHeld runs the mark again for a note this machine already holds,
// met again by a fetch. The mark is idempotent, so it changes nothing when
// the original is marked; it puts back a mark that a writer racing the
// first, such as a read marking the original read, saved over, since
// nothing else would ever mark it again.
func remarkHeld(s *store.Store, id string) error {
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		held, err := s.Holding(box, id)
		if err != nil || held == nil {
			continue
		}
		return markWithdrawn(s, held)
	}
	return nil
}
