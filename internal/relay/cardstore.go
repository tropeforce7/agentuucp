package relay

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A mailbox's card. The signed document is kept as it came so it can be
// verified again every time a knock is let past the allow list, and served
// back verbatim to the owner and to the listing. The two words beside it
// are the relay's parse at the push, for the listing's query and the
// administrator's line; nothing that decides trust reads them.

// ErrCardOlder means the card offered was issued no later than the one the
// relay holds. Two machines of one identity cannot push each other
// backwards in silence: the loser is told, and decides. The error returned
// is a *CardOlderError, which says when the stored one was issued.
var ErrCardOlder = errors.New("relay: a newer card is already there")

// CardOlderError is ErrCardOlder with the stored issue time, for the
// refusal to name it.
type CardOlderError struct{ Issued time.Time }

func (e *CardOlderError) Error() string {
	return fmt.Sprintf("%v (issued %s)", ErrCardOlder, e.Issued.UTC().Format(time.RFC3339))
}

func (e *CardOlderError) Unwrap() error { return ErrCardOlder }

// SetCard replaces a mailbox's card with one already verified by the
// caller against the mailbox's key, in one transaction, so a concurrent
// push from another machine sees one state or the other.
//
// A card issued before the stored one, or at the same instant with
// different bytes, is ErrCardOlder. The same bytes at the same instant are
// the card the relay already holds, and pushing them again is not an
// error. The rule holds only between two cards that verify: a row that
// does not — its signature blanked, a bit of it flipped, its document
// edited, by somebody with the database open — is replaced whatever its
// issued says, since a row that does not verify says nothing about when
// the owner issued it, and an editor who also moved its issued forward
// must not lock the owner out of the one repair. The stored row is
// verified here, inside the transaction, against the mailbox's bundle,
// and the time it is held to is the one inside the verified document,
// never the issued column, which the signature does not cover and is
// written for the administrator's eye alone. It reports whether anything
// was written; the repeated push is the one success that writes nothing.
func (s *Store) SetCard(fp string, d *card.Document, doc, sig []byte) (stored bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var bundle, storedDoc, storedSig []byte
	err = tx.QueryRow(`SELECT m.bundle, c.doc, c.sig FROM mailboxes m
		LEFT JOIN cards c ON c.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &storedDoc, &storedSig)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNoMailbox
	}
	if err != nil {
		return false, err
	}
	// A mailbox with no row joins nil bytes, which cardDecision reads as
	// broken: no rule, and the first push is taken.
	if state, stored := cardDecision(bundle, storedDoc, storedSig); state == relayapi.CardSigned {
		held := stored.Issued
		if !d.Issued.After(held) {
			if d.Issued.Equal(held) && bytes.Equal(doc, storedDoc) {
				return false, nil
			}
			return false, &CardOlderError{Issued: held}
		}
	}
	// Nanoseconds kept, as the allow list's are: a push made within the
	// second of the last one must still be seen to come after it.
	if _, err := tx.Exec(`INSERT INTO cards (fp, doc, sig, issued, listed, knocks) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (fp) DO UPDATE SET doc = excluded.doc, sig = excluded.sig,
			issued = excluded.issued, listed = excluded.listed, knocks = excluded.knocks`,
		fp, doc, sig, d.Issued.UTC().Format(time.RFC3339Nano), boolInt(d.Listed), boolInt(d.Knocks)); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Card returns the document and signature as they were pushed, with the
// state the relay reads them as, and found false for a mailbox that has
// never pushed one. The state is the relay's reading; the owner verifies
// the pair with their own key.
func (s *Store) Card(fp string) (doc, sig []byte, state string, found bool, err error) {
	var bundle []byte
	var has int
	err = s.db.QueryRow(`SELECT m.bundle, c.doc, c.sig, c.fp IS NOT NULL FROM mailboxes m
		LEFT JOIN cards c ON c.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &doc, &sig, &has)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, "", false, ErrNoMailbox
	}
	if err != nil {
		return nil, nil, "", false, err
	}
	if has == 0 {
		return nil, nil, relayapi.CardNone, false, nil
	}
	state, _ = cardDecision(bundle, doc, sig)
	return doc, sig, state, true, nil
}

// CardState is the state alone, for the owner's listing.
func (s *Store) CardState(fp string) (string, error) {
	_, _, state, _, err := s.Card(fp)
	return state, err
}

// TakesKnocks reports whether a mailbox's card says knocks, reading the
// card and verifying it every time, as MayPost reads the allow list: there
// is no cache, and the knocks column is never read, since a cache would
// hide an edit made while the relay runs and the column is the relay's
// own parse, which an editor can set. A mailbox with no card takes none;
// one whose card no longer verifies takes none and is said in the log
// once a minute. Whether the mailbox exists is the caller's to have
// settled first; one that does not takes none.
func (s *Store) TakesKnocks(fp string) (bool, error) {
	var bundle, doc, sig []byte
	var has int
	err := s.db.QueryRow(`SELECT m.bundle, c.doc, c.sig, c.fp IS NOT NULL FROM mailboxes m
		LEFT JOIN cards c ON c.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &doc, &sig, &has)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if has == 0 {
		return false, nil
	}
	state, d := cardDecision(bundle, doc, sig)
	if state == relayapi.CardBroken {
		s.faults.noteCard(fp)
		return false, nil
	}
	return d.Knocks, nil
}

// cardDecision reads a stored card as the relay enforces it: verified
// against the mailbox's registered key, and broken otherwise, with no
// document, so the caller takes no knock and lists nothing. A row with no
// signature is broken before anything is parsed: nothing writes one, so it
// is a signed row somebody blanked the signature of, and there is no
// compatibility state for authentication data — anything malformed fails
// closed until the owner pushes again.
func cardDecision(bundle, doc, sig []byte) (state string, d *card.Document) {
	if len(sig) == 0 {
		return relayapi.CardBroken, nil
	}
	pub, err := identity.ParseBundle(bundle)
	if err != nil {
		return relayapi.CardBroken, nil
	}
	if d, err = card.Verify(pub, doc, sig); err != nil {
		return relayapi.CardBroken, nil
	}
	return relayapi.CardSigned, d
}

// ListedCards is a page of the cards whose documents said listed, with
// the bundle each was verified against at its push, in fingerprint order
// from after exclusive, at most limit entries, and how many such cards the
// relay holds in all. A blocked owner is left out of both. The relay
// verifies nothing here: it serves stored bytes, and the reader verifies
// every entry with the bundle beside it, because the reader is the party
// that must not trust the relay, and a verification here would only
// remove what the reader removes anyway. The listed column is the relay's
// parse at the push and decides only which rows are served; a row whose
// column was edited to say listed serves a document that says otherwise,
// which the reader drops.
func (s *Store) ListedCards(after string, limit int) (entries []relayapi.ListedEntry, total int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	// The count and the page in one transaction, so that they agree.
	if err := tx.QueryRow(`SELECT COUNT(*) FROM cards c WHERE c.listed = 1
		AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.fp = c.fp)`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT m.bundle, c.doc, c.sig FROM cards c JOIN mailboxes m ON m.fp = c.fp
		WHERE c.listed = 1 AND c.fp > ? AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.fp = c.fp)
		ORDER BY c.fp LIMIT ?`, after, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	entries = []relayapi.ListedEntry{}
	for rows.Next() {
		var e relayapi.ListedEntry
		if err := rows.Scan(&e.Bundle, &e.Document, &e.Signature); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return entries, total, tx.Commit()
}
