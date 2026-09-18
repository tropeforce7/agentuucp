package relay

import (
	"bytes"
	"database/sql"
	"encoding/json"
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
// what it has without first asking what the relay has. An unsigned row —
// one the migration converted, with no signature, which the relay reads
// as broken — is replaced whatever its issue time, since that time is the
// relay's clock and orders nothing the owner did. It reports whether
// anything was written; the repeated push is the one success that writes
// nothing.
func (s *Store) SetAllowlist(fp string, d *allowlist.Document, doc, sig []byte) (stored bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRow(`SELECT 1 FROM mailboxes WHERE fp = ?`, fp).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNoMailbox
	}
	if err != nil {
		return false, err
	}

	var storedDoc, storedSig []byte
	var storedIssued string
	err = tx.QueryRow(`SELECT doc, sig, issued FROM allowlists WHERE fp = ?`, fp).Scan(&storedDoc, &storedSig, &storedIssued)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil && len(storedSig) > 0 {
		held, err := time.Parse(time.RFC3339Nano, storedIssued)
		if err != nil {
			return false, fmt.Errorf("relay: allow list for %s has issued %q: %w", fp, storedIssued, err)
		}
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
// broken before anything is parsed — the rows the migration from before
// signed lists wrote, and a signed row somebody blanked the signature of,
// read the same: there is no compatibility state for authentication data,
// and anything malformed fails closed until the owner pushes again.
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

// convertAllowlists is the Go half of migrating 6 to 7. It creates the
// allowlists table from its constant, since the transaction that would
// has not run yet, and writes one row per mailbox that has rows in the old
// table: a document naming its senders, sorted, without the owner, who is
// always admitted and may not be listed; no signature, since nobody signed
// it, which the relay reads as broken until the owner pushes — a mailbox
// that was restricted refuses every sender after the upgrade rather than
// admitting anyone on the strength of a row the relay cannot verify; and
// the migration's own time as issued. It can be interrupted and repeated:
// the old table is still there until the transaction drops it, and a row
// already written is written again the same, but for the time.
func convertAllowlists(s *Store) error {
	if _, err := s.db.Exec(allowlistsTable); err != nil {
		return fmt.Errorf("relay: creating allowlists: %w", err)
	}
	rows, err := s.db.Query(`SELECT fp, sender_fp FROM allowlist ORDER BY fp, sender_fp`)
	if err != nil {
		return fmt.Errorf("relay: reading the allow lists: %w", err)
	}
	defer rows.Close()
	// The query is drained before any writing: one connection, and a write
	// while a read is open would deadlock.
	senders := map[string][]string{}
	var order []string
	for rows.Next() {
		var fp, sender string
		if err := rows.Scan(&fp, &sender); err != nil {
			return err
		}
		if _, seen := senders[fp]; !seen {
			order = append(order, fp)
		}
		if sender != fp {
			senders[fp] = append(senders[fp], sender)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, fp := range order {
		d := &allowlist.Document{V: allowlist.Version, Owner: fp, Issued: now, Senders: senders[fp]}
		if d.Senders == nil {
			d.Senders = []string{}
		}
		if err := d.Validate(); err != nil {
			return fmt.Errorf("relay: the allow list for %s cannot be converted: %v", fp, err)
		}
		doc, err := json.Marshal(d)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT INTO allowlists (fp, doc, sig, issued, count) VALUES (?, ?, X'', ?, ?)
			ON CONFLICT (fp) DO UPDATE SET doc = excluded.doc, sig = excluded.sig,
				issued = excluded.issued, count = excluded.count`,
			fp, doc, now.Format(time.RFC3339Nano), len(d.Senders)); err != nil {
			return fmt.Errorf("relay: converting the allow list for %s: %w", fp, err)
		}
	}
	return nil
}
