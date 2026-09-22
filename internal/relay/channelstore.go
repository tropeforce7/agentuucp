package relay

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
)

// A mailbox's channel directory. The signed document is kept as it came so
// it can be served back verbatim, and its channels are unpacked into rows
// so a post can be checked against one name and its period.

// ErrDirectoryOlder means the directory offered was issued no later than the
// one the relay holds. Two machines of one identity cannot push each other
// backwards in silence: the loser is told, and decides. The error returned
// is a *DirectoryOlderError, which says when the stored one was issued.
var ErrDirectoryOlder = errors.New("relay: a newer directory is already there")

// DirectoryOlderError is ErrDirectoryOlder with the stored issue time, for
// the refusal to name it.
type DirectoryOlderError struct{ Issued time.Time }

func (e *DirectoryOlderError) Error() string {
	return fmt.Sprintf("%v (issued %s)", ErrDirectoryOlder, e.Issued.UTC().Format(time.RFC3339))
}

func (e *DirectoryOlderError) Unwrap() error { return ErrDirectoryOlder }

// SetDirectory replaces a mailbox's directory with one already verified by
// the caller against the mailbox's key, in one transaction: the stored
// issue time is read and compared, the channel rows are deleted and
// re-inserted, and the document row is written, so a concurrent push from
// another machine sees one state or the other. Messages are never touched;
// mail queued under a channel the new directory leaves out stays queued
// under that name.
//
// A directory issued before the stored one, or at the same instant with
// different bytes, is ErrDirectoryOlder. The same bytes at the same instant
// are the directory the relay already holds, and pushing them again is not
// an error: a machine catching a relay up after an outage must be able to
// push what it has without first asking what the relay has. The rule
// holds only between two directories that verify: a stored row that does
// not — its signature blanked, a bit of it flipped, its document edited,
// by somebody with the database open — is replaced whatever its issued
// says, since a row that does not verify says nothing about when the
// owner issued it, and an editor who also moved its issued forward must
// not lock the owner out of pushing. The stored row is verified here,
// inside the transaction, against the mailbox's bundle, and the time the
// push is held to is the one inside the verified document, never the
// issued column, which the signature does not cover; the first cut
// verified nothing here and held the column, as the allow list's and the
// card's pushes did before them. It reports whether anything was written;
// the repeated push is the one success that writes nothing, so a caller
// can tell a change from a repeat.
func (s *Store) SetDirectory(fp string, d *channels.Directory, doc, sig []byte) (stored bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var bundle, storedDoc, storedSig []byte
	err = tx.QueryRow(`SELECT m.bundle, r.doc, r.sig FROM mailboxes m
		LEFT JOIN directories r ON r.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &storedDoc, &storedSig)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNoMailbox
	}
	if err != nil {
		return false, err
	}
	// A mailbox with no row joins nil bytes, which directoryDecision
	// reads as not verifying: no rule, and the first push is taken.
	if stored, ok := directoryDecision(bundle, storedDoc, storedSig); ok {
		held := stored.Issued
		if !d.Issued.After(held) {
			if d.Issued.Equal(held) && bytes.Equal(doc, storedDoc) {
				return false, nil
			}
			return false, &DirectoryOlderError{Issued: held}
		}
	}

	if _, err := tx.Exec(`DELETE FROM channels WHERE fp = ?`, fp); err != nil {
		return false, err
	}
	stmt, err := tx.Prepare(`INSERT INTO channels (fp, name, description, not_before, not_after, position)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return false, err
	}
	defer stmt.Close()
	for i, ch := range d.Channels {
		if _, err := stmt.Exec(fp, ch.Name, ch.Description, boundText(ch.NotBefore), boundText(ch.NotAfter), i); err != nil {
			return false, err
		}
	}
	// Nanoseconds kept: the comparison above is between what the owner's
	// machines wrote, and a push made within the second of the last one
	// must still be seen to come after it.
	if _, err := tx.Exec(`INSERT INTO directories (fp, doc, sig, issued) VALUES (?, ?, ?, ?)
		ON CONFLICT (fp) DO UPDATE SET doc = excluded.doc, sig = excluded.sig, issued = excluded.issued`,
		fp, doc, sig, d.Issued.UTC().Format(time.RFC3339Nano)); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// directoryDecision reads a stored directory as the push is held to it:
// verified against the mailbox's registered key, and nothing otherwise. A
// row with no signature is nothing before anything is parsed: nothing
// writes one, so it is a signed row somebody blanked the signature of.
// It is the allow list's allowDecision and the card's cardDecision for
// the document that has no state word of its own: a directory that does
// not verify is not served as broken, since the reader verifies it with
// the key they hold for the owner and refuses it there, and a post is
// routed by the channel rows the push unpacked, which this does not read.
func directoryDecision(bundle, doc, sig []byte) (*channels.Directory, bool) {
	if len(sig) == 0 {
		return nil, false
	}
	pub, err := identity.ParseBundle(bundle)
	if err != nil {
		return nil, false
	}
	d, err := channels.Verify(pub, doc, sig)
	if err != nil {
		return nil, false
	}
	return d, true
}

// Directory returns the signed document and its signature as they were
// pushed, and found false for a mailbox that has never pushed one, which
// has the one channel, default.
func (s *Store) Directory(fp string) (doc, sig []byte, found bool, err error) {
	err = s.db.QueryRow(`SELECT doc, sig FROM directories WHERE fp = ?`, fp).Scan(&doc, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	return doc, sig, true, nil
}

// DirectoryIssued is when the directory a mailbox holds was issued, and
// found false for a mailbox that has never pushed one.
func (s *Store) DirectoryIssued(fp string) (issued time.Time, found bool, err error) {
	var raw string
	err = s.db.QueryRow(`SELECT issued FROM directories WHERE fp = ?`, fp).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	issued, err = time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("relay: directory for %s has issued %q: %w", fp, raw, err)
	}
	return issued, true, nil
}

// ChannelState says whether a mailbox has a channel of that name, and what
// its period is. A mailbox with no directory has default and nothing else.
// Whether the mailbox exists is the caller's to have settled first.
func (s *Store) ChannelState(fp, name string) (exists bool, ch channels.Channel, err error) {
	var one int
	err = s.db.QueryRow(`SELECT 1 FROM directories WHERE fp = ?`, fp).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		if name == channels.Default {
			return true, channels.Channel{Name: channels.Default}, nil
		}
		return false, ch, nil
	}
	if err != nil {
		return false, ch, err
	}
	var notBefore, notAfter sql.NullString
	err = s.db.QueryRow(`SELECT name, description, not_before, not_after FROM channels WHERE fp = ? AND name = ?`,
		fp, name).Scan(&ch.Name, &ch.Description, &notBefore, &notAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return false, channels.Channel{}, nil
	}
	if err != nil {
		return false, ch, err
	}
	if ch.NotBefore, err = boundTime(notBefore); err != nil {
		return false, ch, fmt.Errorf("relay: channel %q of %s: not_before: %w", name, fp, err)
	}
	if ch.NotAfter, err = boundTime(notAfter); err != nil {
		return false, ch, fmt.Errorf("relay: channel %q of %s: not_after: %w", name, fp, err)
	}
	return true, ch, nil
}

// ChannelCounts is how many messages are queued under each name a mailbox
// holds mail for. A name with nothing queued is absent; a name the directory
// no longer lists is present while mail is still queued under it.
func (s *Store) ChannelCounts(fp string) (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT channel, COUNT(*) FROM messages WHERE to_fp = ? GROUP BY channel`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int64)
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		counts[name] = n
	}
	return counts, rows.Err()
}

// boundText renders a period bound for its column, NULL for none.
func boundText(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// boundTime reads a bound back, nil for NULL.
func boundTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
