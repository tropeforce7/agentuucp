package relay

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A mailbox's channel directory. The signed document is kept as it came,
// served back verbatim to a sender the owner admits, and verified afresh
// wherever the relay acts on it — at every post and every stream open,
// where the channel and its period come out of the verified document.
// Its channels are also unpacked into rows at the push, and those rows
// are now the administrator's count and the watch's issue time alone:
// nothing routes by them, so a row somebody inserts or edits with the
// database open changes what an operator is shown and not what the relay
// does.

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

// directoryDecision reads a stored directory as the relay acts on it:
// verified against the mailbox's registered key, and nothing otherwise. A
// row with no signature is nothing before anything is parsed: nothing
// writes one, so it is a signed row somebody blanked the signature of.
// It is the allow list's allowDecision and the card's cardDecision, and
// like them it is the decision itself: a post's channel and its period
// come out of the document this returns, the push is held to the time
// inside it, and the owner's listing says signed, none or broken by it.
// The channel rows are not read here or anywhere that routes.
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
//
// This reads the issued column, which the signature does not cover, and
// that is safe because nothing decides anything by it: its one caller is
// the watch, whose answer tells a peer that a directory it watches may
// have changed, and that peer then fetches the directory and verifies it
// with the key they hold. A column an intruder moved forward wakes a
// watcher once for a fetch that then fails to verify, which is a thing
// the watcher should find out. Nothing that admits, routes or refuses
// reads it: a push is held to the time inside the verified document, and
// a post is routed by the verified document.
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
//
// The answer comes from the directory the owner signed, verified here and
// now against the mailbox's registered key, exactly as MayPost verifies
// the allow list: policy the relay enforces for a user is verified where
// it is enforced, not where it was stored. The channels rows are the
// relay's parse at the push and are not read here, so a row inserted or
// edited by somebody with the database open routes nothing.
//
// It costs one signature verification and one strict decode of at most 64
// channels per post and per stream open, on top of the allow list's one.
//
// A directory that does not verify closes the mailbox: every name is
// refused, default and the owner's own post included, and the fault is
// noted so the operator has a line. It fails closed because that is what
// malformed authentication data does here — there is no state that says
// "not yet" — and because the alternative opens something the owner did
// not sign: an owner whose verified directory removed default, or gave
// it a period that has ended, would have default back the moment a
// stored byte changed. A broken allow list already refuses every sender
// to a mailbox until its owner pushes, so one flipped bit already closes
// a mailbox; this is that rule and not a new one. The owner is told at
// their next fetch, by the word on their listing and the sentence auu
// inbox prints, and their push is the whole repair.
//
// The sender is told what a sender is always told about a name: that
// there is no such channel. The state of somebody else's directory is
// not a sender's to learn.
func (s *Store) ChannelState(fp, name string) (exists bool, ch channels.Channel, err error) {
	var bundle, doc, sig []byte
	var has int
	err = s.db.QueryRow(`SELECT m.bundle, d.doc, d.sig, d.fp IS NOT NULL FROM mailboxes m
		LEFT JOIN directories d ON d.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &doc, &sig, &has)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ch, nil
	}
	if err != nil {
		return false, ch, err
	}
	if has == 0 {
		return defaultOnly(name)
	}
	d, ok := directoryDecision(bundle, doc, sig)
	if !ok {
		s.faults.noteDirectory(fp)
		return false, channels.Channel{}, nil
	}
	for _, one := range d.Channels {
		if one.Name == name {
			return true, one, nil
		}
	}
	return false, channels.Channel{}, nil
}

// defaultOnly is what a mailbox has when it has published no directory at
// all: the one channel, default, and no other name. A mailbox whose
// directory does not verify is not this — it is closed — since a
// directory that has gone wrong must not open a name the owner's own
// document had removed.
func defaultOnly(name string) (bool, channels.Channel, error) {
	if name == channels.Default {
		return true, channels.Channel{Name: channels.Default}, nil
	}
	return false, channels.Channel{}, nil
}

// DirectoryState is the state of a mailbox's channel directory as the
// relay reads it, for the owner's own listing: signed, none, or broken.
// The owner would otherwise learn that their directory no longer verifies
// only from their senders' silence, as they would for the allow list and
// the card.
func (s *Store) DirectoryState(fp string) (string, error) {
	var bundle, doc, sig []byte
	var has int
	err := s.db.QueryRow(`SELECT m.bundle, d.doc, d.sig, d.fp IS NOT NULL FROM mailboxes m
		LEFT JOIN directories d ON d.fp = m.fp WHERE m.fp = ?`, fp).Scan(&bundle, &doc, &sig, &has)
	if errors.Is(err, sql.ErrNoRows) {
		return relayapi.DirectoryNone, nil
	}
	if err != nil {
		return "", err
	}
	if has == 0 {
		return relayapi.DirectoryNone, nil
	}
	return directoryWord(bundle, doc, sig), nil
}

// directoryWord is the state of a directory row whose bytes the caller has
// already read, in the two words a row that exists can be. DirectoryState
// reads its own row for one mailbox; the administrator's record reads every
// mailbox in one query and arrives here with the bytes in hand. Both say
// the same word about the same row because both ask directoryDecision,
// which is the one place a stored directory is judged.
func directoryWord(bundle, doc, sig []byte) string {
	if _, ok := directoryDecision(bundle, doc, sig); !ok {
		return relayapi.DirectoryBroken
	}
	return relayapi.DirectorySigned
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
