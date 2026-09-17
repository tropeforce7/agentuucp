package relay

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TokenRecord is a registered enrolment token as the relay holds it.
//
// There is no field for who redeemed it. The relay records that once, in the
// operator's audit log, and never in a form it keeps: a permanent table of who
// invited whom is a social graph of a different kind, and the store can do
// without it.
type TokenRecord struct {
	token.Claims
	UsesLeft     int
	Revoked      bool
	Created      time.Time
	LastRedeemed time.Time
}

// State is live, spent, revoked or expired, in that order of precedence.
func (t TokenRecord) State(now time.Time) string {
	switch {
	case t.Revoked:
		return relayapi.TokenRevoked
	case now.Unix() > t.NotAfter:
		return relayapi.TokenExpired
	case t.UsesLeft <= 0:
		return relayapi.TokenSpent
	default:
		return relayapi.TokenLive
	}
}

// Wire turns a record into the shape an administrator's client sees.
func (t TokenRecord) Wire(now time.Time) relayapi.TokenRecord {
	return relayapi.TokenRecord{
		ID:           t.ID,
		Issuer:       t.Issuer,
		Relay:        t.Relay,
		Use:          t.Use,
		Subject:      t.Subject,
		Note:         t.Note,
		NotBefore:    t.NotBeforeTime(),
		NotAfter:     t.NotAfterTime(),
		Uses:         t.Uses,
		UsesLeft:     t.UsesLeft,
		Revoked:      t.Revoked,
		Created:      t.Created,
		LastRedeemed: t.LastRedeemed,
		State:        t.State(now),
	}
}

// AddToken registers a token so that it can be redeemed. A token that verifies
// but was never registered is refused at enrolment: the relay knowing every
// live token is what makes revocation and single use possible at all.
func (s *Store) AddToken(c token.Claims, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO tokens (id, issuer, use, relay, subject, note,
			not_before, not_after, uses, uses_left, revoked, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		c.ID, c.Issuer, c.Use, c.Relay, c.Subject, c.Note,
		c.NotBefore, c.NotAfter, c.Uses, c.Uses, now.UTC().Format(time.RFC3339))
	if err == nil {
		return nil
	}
	var one int
	if qErr := s.db.QueryRow(`SELECT 1 FROM tokens WHERE id = ?`, c.ID).Scan(&one); qErr == nil {
		return ErrDuplicateToken
	}
	return fmt.Errorf("relay: registering token: %w", err)
}

// Token returns one registered token.
func (s *Store) Token(id string) (*TokenRecord, error) {
	rows, err := s.db.Query(tokenSelect+` WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanTokens(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrTokenUnknown
	}
	return &out[0], nil
}

const tokenSelect = `SELECT id, issuer, use, relay, subject, note,
	not_before, not_after, uses, uses_left, revoked, created, last_redeemed FROM tokens`

// Tokens lists registered tokens, newest first. Unless all is set, only the
// ones an administrator can still do something about are returned.
func (s *Store) Tokens(all bool, now time.Time) ([]TokenRecord, error) {
	query := tokenSelect
	args := []any{}
	if !all {
		query += ` WHERE revoked = 0 AND uses_left > 0 AND not_after >= ?`
		args = append(args, now.Unix())
	}
	query += ` ORDER BY created DESC, id`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTokens(rows)
}

func scanTokens(rows *sql.Rows) ([]TokenRecord, error) {
	var out []TokenRecord
	for rows.Next() {
		var t TokenRecord
		var revoked int
		var created string
		var lastRedeemed sql.NullString
		if err := rows.Scan(&t.ID, &t.Issuer, &t.Use, &t.Relay, &t.Subject, &t.Note,
			&t.NotBefore, &t.NotAfter, &t.Uses, &t.UsesLeft, &revoked, &created, &lastRedeemed); err != nil {
			return nil, err
		}
		t.Revoked = revoked != 0
		t.Created, _ = time.Parse(time.RFC3339, created)
		if lastRedeemed.Valid {
			t.LastRedeemed, _ = time.Parse(time.RFC3339, lastRedeemed.String)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken withdraws a token. It is idempotent, and reports whether a token
// with that id exists at all.
func (s *Store) RevokeToken(id string) (bool, error) {
	res, err := s.db.Exec(`UPDATE tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// PurgeTokens drops tokens long past their expiry. Nothing an administrator
// could still act on is removed.
func (s *Store) PurgeTokens(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE not_after < ?`, before.Unix())
	return err
}

// Block is an identity an administrator has barred from the relay.
type Block struct {
	FP      string
	Reason  string
	Created time.Time
	ByFP    string
}

// SetBlock bars an identity, or updates the reason on an existing block. The
// fingerprint need not have a mailbox: blocking in advance is allowed.
func (s *Store) SetBlock(fp, reason, byFP string, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO blocks (fp, reason, created, by_fp) VALUES (?, ?, ?, ?)
		ON CONFLICT(fp) DO UPDATE SET reason = excluded.reason, by_fp = excluded.by_fp`,
		fp, reason, now.UTC().Format(time.RFC3339), byFP)
	return err
}

// RemoveBlock lifts a block, reporting whether there was one.
func (s *Store) RemoveBlock(fp string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM blocks WHERE fp = ?`, fp)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Blocks lists every block.
func (s *Store) Blocks() ([]Block, error) {
	rows, err := s.db.Query(`SELECT fp, reason, created, by_fp FROM blocks ORDER BY created DESC, fp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Block
	for rows.Next() {
		var b Block
		var created string
		if err := rows.Scan(&b.FP, &b.Reason, &created, &b.ByFP); err != nil {
			return nil, err
		}
		b.Created, _ = time.Parse(time.RFC3339, created)
		out = append(out, b)
	}
	return out, rows.Err()
}

// The allow list's count, document, signature and the bundle come along so
// that the record can say what state the list is in, which needs the
// signature verified: a count is a number and decides nothing.
const mailboxSelect = `
	SELECT m.fp, m.name, m.created, m.queued_messages, m.queued_bytes,
		COALESCE(a.count, 0), a.doc, a.sig, a.fp IS NOT NULL, m.bundle,
		(SELECT COUNT(*) FROM channels c WHERE c.fp = m.fp),
		EXISTS (SELECT 1 FROM blocks b WHERE b.fp = m.fp)
	FROM mailboxes m LEFT JOIN allowlists a ON a.fp = m.fp`

// Mailboxes returns a page of mailboxes ordered by fingerprint, starting after
// the one given. Keyset paging, so a page is stable while mailboxes come and
// go underneath it.
func (s *Store) Mailboxes(after string, limit int) ([]relayapi.MailboxRecord, error) {
	rows, err := s.db.Query(mailboxSelect+` WHERE m.fp > ? ORDER BY m.fp LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMailboxes(rows)
}

// MailboxRecord returns one mailbox as an administrator sees it.
func (s *Store) MailboxRecord(fp string) (*relayapi.MailboxRecord, error) {
	rows, err := s.db.Query(mailboxSelect+` WHERE m.fp = ?`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanMailboxes(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNoMailbox
	}
	return &out[0], nil
}

func scanMailboxes(rows *sql.Rows) ([]relayapi.MailboxRecord, error) {
	var out []relayapi.MailboxRecord
	for rows.Next() {
		var m relayapi.MailboxRecord
		var created string
		var blocked, hasList int
		var doc, sig, bundle []byte
		if err := rows.Scan(&m.FP, &m.Name, &created, &m.QueuedMessages, &m.QueuedBytes,
			&m.AllowlistSize, &doc, &sig, &hasList, &bundle, &m.Channels, &blocked); err != nil {
			return nil, err
		}
		m.Created, _ = time.Parse(time.RFC3339, created)
		m.Blocked = blocked != 0
		if hasList != 0 {
			m.Allow, _ = allowDecision(bundle, doc, sig)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Deregister removes a mailbox and everything queued for it. The foreign keys
// cascade to the messages and the allow list; the counters are the relay's own
// bookkeeping and come down in the same transaction.
func (s *Store) Deregister(fp string) (bool, error) {
	return s.dropMessages(fp, true)
}

// PurgeMailbox drops everything queued for a mailbox and leaves the mailbox.
func (s *Store) PurgeMailbox(fp string) (bool, error) {
	return s.dropMessages(fp, false)
}

// dropMessages backs both. The ids are collected inside the transaction and
// the files removed after it commits: the rows are the record, and a file left
// behind by a failed unlink is an orphan the sweep takes.
func (s *Store) dropMessages(fp string, removeMailbox bool) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var messages, bytes int64
	err = tx.QueryRow(`SELECT queued_messages, queued_bytes FROM mailboxes WHERE fp = ?`, fp).
		Scan(&messages, &bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	var ids []int64
	if !removeMailbox {
		rows, err := tx.Query(`SELECT id FROM messages WHERE to_fp = ?`, fp)
		if err != nil {
			return false, err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return false, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, err
		}
	}

	if removeMailbox {
		// ON DELETE CASCADE takes the messages and the allow list with it.
		if _, err := tx.Exec(`DELETE FROM mailboxes WHERE fp = ?`, fp); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM messages WHERE to_fp = ?`, fp); err != nil {
			return false, err
		}
		if _, err := tx.Exec(
			`UPDATE mailboxes SET queued_messages = 0, queued_bytes = 0 WHERE fp = ?`, fp); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(
		`UPDATE relay_stats SET queued_messages = queued_messages - ?, queued_bytes = queued_bytes - ? WHERE id = 1`,
		messages, bytes); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}

	if removeMailbox {
		return true, s.removeMailboxFiles(fp)
	}
	for _, id := range ids {
		if err := s.removeMessage(fp, id); err != nil {
			return true, err
		}
	}
	return true, nil
}

// Counts is what the status endpoint reports about the size of things.
type Counts struct {
	Mailboxes  int64
	LiveTokens int64
	Blocks     int64
	LiveCerts  int64
}

// Counts totals the three tables an administrator asks about.
func (s *Store) Counts(now time.Time) (Counts, error) {
	var c Counts
	err := s.db.QueryRow(`
		SELECT (SELECT COUNT(*) FROM mailboxes),
		       (SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND uses_left > 0 AND not_after >= ?),
		       (SELECT COUNT(*) FROM blocks),
		       (SELECT COUNT(*) FROM certs WHERE revoked = 0 AND not_after >= ?)`,
		now.Unix(), now.Unix()).
		Scan(&c.Mailboxes, &c.LiveTokens, &c.Blocks, &c.LiveCerts)
	return c, err
}
