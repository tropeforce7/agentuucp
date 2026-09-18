package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Uploads in progress. A stream arrives in pieces, so the relay holds a
// partial file and a row saying how much of it has landed, until the sender
// says it is done.
//
// The row carries from_fp, which is the one place the relay records who sent
// anything: it must know who may append to a half-finished upload. It is
// deleted on completion or abandonment, and the message the upload becomes
// carries no sender at all.

// Upload failures.
var (
	ErrNoUpload     = errors.New("relay: no such upload")
	ErrUploadOffset = errors.New("relay: upload offset does not match")
	ErrStreamTooBig = errors.New("relay: stream is larger than this relay accepts")
)

const uploadsName = "uploads"

// Upload is an upload in progress. Channel is the name the stream was
// opened for, checked at open and copied to the message at completion.
type Upload struct {
	ID       string
	To       string
	From     string
	Channel  string
	Size     int64
	Received int64
	Created  time.Time
	Expires  time.Time
}

func (s *Store) uploadDir() string { return filepath.Join(s.dir, uploadsName) }

func (s *Store) uploadPath(id string) string { return filepath.Join(s.uploadDir(), id) }

// NewUploadID is 16 random bytes as hex, like a token id.
func NewUploadID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidUploadID reports whether s could have come from NewUploadID. Checked
// before the value goes anywhere near a path.
func ValidUploadID(s string) bool { return len(s) == 32 && isLowerHex(s) }

// OpenUpload reserves room for a stream and creates its file.
//
// The quotas count what other open uploads have reserved as though it were
// already queued, so two concurrent streams cannot each be told there is room
// for the last gigabyte.
func (s *Store) OpenUpload(id, toFP, fromFP, channel string, size int64, now, expires time.Time,
	q Quotas, maxStream int64) error {

	if size <= 0 {
		return fmt.Errorf("%w: size must be positive", ErrForm)
	}
	if maxStream > 0 && size > maxStream {
		return ErrStreamTooBig
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var queuedMessages, queuedBytes int64
	err = tx.QueryRow(`SELECT queued_messages, queued_bytes FROM mailboxes WHERE fp = ?`, toFP).
		Scan(&queuedMessages, &queuedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoMailbox
	}
	if err != nil {
		return err
	}

	var reservedCount, reservedBytes int64
	if err := tx.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM uploads WHERE to_fp = ?`, toFP).
		Scan(&reservedCount, &reservedBytes); err != nil {
		return err
	}
	if q.MailboxMaxMessages > 0 && queuedMessages+reservedCount >= q.MailboxMaxMessages {
		return ErrMailboxFull
	}
	if q.MailboxMaxBytes > 0 && queuedBytes+reservedBytes+size > q.MailboxMaxBytes {
		return ErrMailboxFull
	}
	if q.RelayMaxBytes > 0 {
		var relayBytes, relayReserved int64
		if err := tx.QueryRow(`SELECT queued_bytes FROM relay_stats WHERE id = 1`).Scan(&relayBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM uploads`).Scan(&relayReserved); err != nil {
			return err
		}
		if relayBytes+relayReserved+size > q.RelayMaxBytes {
			return ErrRelayFull
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO uploads (id, to_fp, from_fp, size, received, created, expires, channel)
		 VALUES (?, ?, ?, ?, 0, ?, ?, ?)`,
		id, toFP, fromFP, size, now.UTC().Format(time.RFC3339), expires.Unix(), channel); err != nil {
		return err
	}

	f, err := os.OpenFile(s.uploadPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return s.fault(s.uploadPath(id), err)
	}
	if err := f.Close(); err != nil {
		os.Remove(s.uploadPath(id))
		return s.fault(s.uploadPath(id), err)
	}
	if err := tx.Commit(); err != nil {
		os.Remove(s.uploadPath(id))
		return err
	}
	return nil
}

// Upload returns one upload in progress.
func (s *Store) Upload(id string) (*Upload, error) {
	var u Upload
	var created string
	var expires int64
	err := s.db.QueryRow(
		`SELECT id, to_fp, from_fp, channel, size, received, created, expires FROM uploads WHERE id = ?`, id).
		Scan(&u.ID, &u.To, &u.From, &u.Channel, &u.Size, &u.Received, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoUpload
	}
	if err != nil {
		return nil, err
	}
	u.Created, _ = time.Parse(time.RFC3339, created)
	u.Expires = time.Unix(expires, 0)
	return &u, nil
}

// AppendUpload copies at most the remaining bytes from r onto the end of an
// upload, and records how far it now reaches.
//
// The copy streams: nothing larger than the buffer is held, whatever the
// sender sends. offset must match what the relay already has, so a client that
// lost a connection asks with HEAD and resumes from the truth.
//
// One append at a time per upload, and none while a completion or an abort
// is under way: the upload's lock is held from the offset check through the
// file write and the row's update. Without it two appends at one offset
// both passed the check, both landed on the file, and the upload held twice
// what it declared and twice what was reserved — an admitted sender's way
// past the quotas, bounded only by the in-flight cap. The lock is held
// across the body copy on purpose; a SQLite transaction is not, because a
// transaction open for the length of a network read would hold the one
// connection every other request needs.
func (s *Store) AppendUpload(id string, offset int64, r func(w *os.File, limit int64) (int64, error)) (int64, error) {
	unlock := s.uploadLock(id)
	defer unlock()
	u, err := s.Upload(id)
	if err != nil {
		return 0, err
	}
	if offset != u.Received {
		return u.Received, ErrUploadOffset
	}
	remaining := u.Size - u.Received
	if remaining <= 0 {
		return u.Received, nil
	}

	f, err := os.OpenFile(s.uploadPath(id), os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return u.Received, s.fault(s.uploadPath(id), err)
	}
	n, copyErr := r(f, remaining)
	if n > 0 {
		if err := f.Sync(); err != nil {
			// What did not reach the disk was not received. The file is put
			// back to what the row says, so that a resume appends at the
			// truth rather than after bytes the row does not know about.
			f.Truncate(u.Received)
			f.Close()
			return u.Received, s.fault(s.uploadPath(id), err)
		}
	}
	if err := f.Close(); err != nil {
		return u.Received, s.fault(s.uploadPath(id), err)
	}
	if n > 0 {
		if _, err := s.db.Exec(`UPDATE uploads SET received = received + ? WHERE id = ?`, n, id); err != nil {
			return u.Received, err
		}
	}
	// The copy's error is the write's when the disk is full: mapped like
	// every other write here, so a full disk is a 507 the sender can wait
	// out with what it has already sent kept, not a 500 that says nothing.
	// A read error from the request passes through unchanged.
	if copyErr != nil {
		return u.Received + n, s.fault(s.uploadPath(id), copyErr)
	}
	return u.Received + n, nil
}

// CompleteUpload turns a finished upload into a message.
//
// The file is renamed into place before the transaction commits, so the
// invariant Put keeps holds here too: after a commit there is always a file.
// Under the upload's lock, so that an append still copying cannot land on
// a file that has just been renamed into place: a completion waits for it,
// and then finds the row past its size or exactly at it.
func (s *Store) CompleteUpload(id string) (int64, error) {
	unlock := s.uploadLock(id)
	defer s.forgetUploadLock(id, unlock)
	u, err := s.Upload(id)
	if err != nil {
		return 0, err
	}
	if u.Received != u.Size {
		return 0, ErrUploadOffset
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO messages (to_fp, received, size, kind, channel) VALUES (?, ?, ?, 'stream', ?)`,
		u.To, time.Now().UTC().Format(time.RFC3339), u.Size, u.Channel)
	if err != nil {
		return 0, err
	}
	messageID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := adjustCounters(tx, u.To, 1, u.Size); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM uploads WHERE id = ?`, id); err != nil {
		return 0, err
	}
	if err := s.place(s.uploadPath(id), u.To, messageID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		s.removeMessage(u.To, messageID)
		return 0, err
	}
	return messageID, nil
}

// AbortUpload drops an upload and releases its reservation. Under the
// upload's lock, as CompleteUpload is, and the lock's entry goes with the
// upload.
func (s *Store) AbortUpload(id string) (bool, error) {
	unlock := s.uploadLock(id)
	defer s.forgetUploadLock(id, unlock)
	res, err := s.db.Exec(`DELETE FROM uploads WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if err := os.Remove(s.uploadPath(id)); err != nil && !os.IsNotExist(err) {
		return true, s.fault(s.uploadPath(id), err)
	}
	return true, nil
}

// uploadLock takes the lock for one upload, making it if this is the first
// operation on the id since the store opened, and returns what releases it.
func (s *Store) uploadLock(id string) func() {
	s.uploadsMu.Lock()
	if s.uploads == nil {
		s.uploads = map[string]*sync.Mutex{}
	}
	mu, ok := s.uploads[id]
	if !ok {
		mu = &sync.Mutex{}
		s.uploads[id] = mu
	}
	s.uploadsMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// forgetUploadLock releases an upload's lock and drops its entry, for the
// operations after which the upload no longer exists. The entry is removed
// under the map's lock before the upload's lock is released, so a caller
// that comes in next makes a fresh entry rather than taking a lock for an
// upload that is gone; one already waiting on the old lock takes it, finds
// no row, and answers as it would for any unknown upload.
func (s *Store) forgetUploadLock(id string, unlock func()) {
	s.uploadsMu.Lock()
	delete(s.uploads, id)
	s.uploadsMu.Unlock()
	unlock()
}

// PurgeUploads abandons uploads nobody finished. Their reservations go with
// them, which is what stops a forgotten upload holding a mailbox's quota for
// ever.
func (s *Store) PurgeUploads(now time.Time) (int, error) {
	rows, err := s.db.Query(`SELECT id FROM uploads WHERE expires < ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := s.AbortUpload(id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// MessageKind reports whether a message is an envelope or a stream, and how
// big it is, without reading it.
func (s *Store) MessageKind(toFP string, id int64) (kind string, size int64, err error) {
	err = s.db.QueryRow(`SELECT kind, size FROM messages WHERE to_fp = ? AND id = ?`, toFP, id).
		Scan(&kind, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNoMessage
	}
	return kind, size, err
}

// OpenMessage returns the stored file, for a caller that will stream it out.
func (s *Store) OpenMessage(toFP string, id int64) (*os.File, error) {
	f, err := os.Open(s.messagePath(toFP, id))
	return f, s.fault(s.messagePath(toFP, id), err)
}

// OpenUploadFile returns an upload's file, for a caller that will read the
// start of it.
func (s *Store) OpenUploadFile(id string) (*os.File, error) {
	f, err := os.Open(s.uploadPath(id))
	return f, s.fault(s.uploadPath(id), err)
}

// ErrNoMessage is returned for a message id nothing knows about.
var ErrNoMessage = errors.New("relay: no such message")

// ErrForm is a malformed request the store can recognise.
var ErrForm = errors.New("relay: malformed")
