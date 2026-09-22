package relay

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A mailbox's allow list. The signed document is kept as it came so it can
// be verified again every time it is enforced and served back to the owner
// verbatim. Nothing is unpacked into rows: a row that could be edited into
// admitting a stranger is what this replaces.

// ErrAllowlistOlder means the list offered was issued no later than the one
// the relay holds. Two machines of one identity cannot push each other
// backwards in silence: the loser is told, and decides. The error returned
// is an *AllowlistOlderError, which says when the stored one was issued.
var ErrAllowlistOlder = errors.New("relay: a newer allow list is already there")

// AllowlistOlderError is ErrAllowlistOlder with the stored issue time, for
// the refusal to name it.
type AllowlistOlderError struct{ Issued time.Time }

func (e *AllowlistOlderError) Error() string {
	return fmt.Sprintf("%v (issued %s)", ErrAllowlistOlder, e.Issued.UTC().Format(time.RFC3339))
}

func (e *AllowlistOlderError) Unwrap() error { return ErrAllowlistOlder }

// SetAllowlist replaces a mailbox's allow list with one already verified by
// the caller against the mailbox's key, in one transaction, so a concurrent
// push from another machine sees one state or the other.
//
// A list issued before the stored one, or at the same instant with
// different bytes, is ErrAllowlistOlder. The same bytes at the same instant
// are the list the relay already holds, and pushing them again is not an
// error: a machine catching a relay up after an outage must be able to push
// what it has without first asking what the relay has. The rule holds
// only between two lists that verify: a row that does not — its
// signature blanked, a bit of it flipped, its document edited, by
// somebody with the database open — is replaced whatever its issued
// says, since a row that does not verify says nothing about when the
// owner issued it, and an editor who also moved its issued forward must
// not lock the owner out of the one repair. The stored row is verified
// here, inside the transaction, against the mailbox's bundle, and the
// time it is held to is the one inside the verified document, never the
// issued column, which the signature does not cover and which is written
// for the administrator's eye alone: a column set a century ahead under
// a row that still verifies would otherwise answer every push 409 with
// no broken state to name the repair. The first cut verified nothing
// here, read a blank signature alone as no bar and held the column, so
// a flipped signature issued ahead, and a column alone moved ahead,
// each answered the owner's repair 409. It reports whether anything was
// written; the repeated push is the one success that writes nothing.
func (s *Store) SetAllowlist(fp string, d *allowlist.Document, doc, sig []byte) (stored bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var bundle, storedDoc, storedSig []byte
	err = tx.QueryRow(`SELECT m.bundle, a.doc, a.sig FROM mailboxes m
		LEFT JOIN allowlists a ON a.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &storedDoc, &storedSig)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNoMailbox
	}
	if err != nil {
		return false, err
	}
	// A mailbox with no row joins nil bytes, which allowDecision reads as
	// broken: no rule, and the first push is taken.
	if state, stored := allowDecision(bundle, storedDoc, storedSig); state == relayapi.AllowSigned {
		held := stored.Issued
		if !d.Issued.After(held) {
			if d.Issued.Equal(held) && bytes.Equal(doc, storedDoc) {
				return false, nil
			}
			return false, &AllowlistOlderError{Issued: held}
		}
	}
	// Nanoseconds kept: the comparison above is between what the owner's
	// machines wrote, and a push made within the second of the last one
	// must still be seen to come after it.
	if _, err := tx.Exec(`INSERT INTO allowlists (fp, doc, sig, issued, count) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (fp) DO UPDATE SET doc = excluded.doc, sig = excluded.sig,
			issued = excluded.issued, count = excluded.count`,
		fp, doc, sig, d.Issued.UTC().Format(time.RFC3339Nano), len(d.Senders)); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// Allowlist returns the document and signature as they were pushed, with
// the state the relay reads them as, and found false for a mailbox that has
// never pushed one. The state is the relay's reading; the owner verifies
// the pair with their own key.
func (s *Store) Allowlist(fp string) (doc, sig []byte, state string, found bool, err error) {
	var bundle []byte
	var has int
	err = s.db.QueryRow(`SELECT m.bundle, a.doc, a.sig, a.fp IS NOT NULL FROM mailboxes m
		LEFT JOIN allowlists a ON a.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &doc, &sig, &has)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, "", false, ErrNoMailbox
	}
	if err != nil {
		return nil, nil, "", false, err
	}
	if has == 0 {
		return nil, nil, relayapi.AllowNone, false, nil
	}
	state, _ = allowDecision(bundle, doc, sig)
	return doc, sig, state, true, nil
}

// AllowState is the state alone, for the owner's listing.
func (s *Store) AllowState(fp string) (string, error) {
	_, _, state, _, err := s.Allowlist(fp)
	return state, err
}

// MayPost reports whether sender is allowed to post to fp, reading the
// list and verifying it every time: there is no cache, since a cache would
// hide an edit made while the relay runs until it restarted, which is the
// edit this exists to catch. A mailbox with no list, or with a list that
// names nobody, accepts mail from any registered sender; a list that no
// longer verifies refuses every sender, and is said in the log once a
// minute. Whether the mailbox exists is the caller's to have settled first;
// one that does not refuses.
func (s *Store) MayPost(fp, sender string) (bool, error) {
	// An allow list is about other people. The owner writing to their own
	// mailbox — a note to themselves, from any machine holding their key —
	// is always allowed, and never needs to be listed.
	if sender == fp {
		return true, nil
	}
	var bundle, doc, sig []byte
	var has int
	err := s.db.QueryRow(`SELECT m.bundle, a.doc, a.sig, a.fp IS NOT NULL FROM mailboxes m
		LEFT JOIN allowlists a ON a.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &doc, &sig, &has)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if has == 0 {
		return true, nil
	}
	state, d := allowDecision(bundle, doc, sig)
	if state == relayapi.AllowBroken {
		s.faults.noteAllowlist(fp)
		return false, nil
	}
	return d.Admits(sender), nil
}

// allowDecision reads a stored list as the relay enforces it: verified
// against the mailbox's registered key, and broken otherwise, with no
// document, so the caller refuses everyone. A row with no signature is
// broken before anything is parsed: nothing writes one, so it is a signed
// row somebody blanked the signature of, and there is no compatibility
// state for authentication data — anything malformed fails closed until
// the owner pushes again.
func allowDecision(bundle, doc, sig []byte) (state string, d *allowlist.Document) {
	if len(sig) == 0 {
		return relayapi.AllowBroken, nil
	}
	pub, err := identity.ParseBundle(bundle)
	if err != nil {
		return relayapi.AllowBroken, nil
	}
	if d, err = allowlist.Verify(pub, doc, sig); err != nil {
		return relayapi.AllowBroken, nil
	}
	return relayapi.AllowSigned, d
}
