package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
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
	// ErrShortAttempt is an attempt that stopped before the end: the
	// Received beside it says what, if anything, is kept.
	ErrShortAttempt = errors.New("relay: upload attempt stopped short of the end")
	// ErrNotAdmitted is an attempt that reached the end of an upload whose
	// sender or channel its placement no longer admits (R22): the upload
	// is gone whole, its file and its row.
	ErrNotAdmitted  = errors.New("relay: upload no longer admitted at its placement")
	ErrStreamTooBig = errors.New("relay: stream is larger than this relay accepts")
	// ErrOpenUploads is an open refused because the sender has as many
	// uploads open as the quotas allow. The error returned is an
	// *OpenUploadsError, which says how many and when the soonest expires.
	ErrOpenUploads = errors.New("relay: the sender has as many uploads open as this relay allows")
)

// OpenUploadsError is ErrOpenUploads with the count and the sender's
// soonest expiry, on the relay's clock, for the refusal to say when to
// come back. An expiry not after now is an upload the relay still holds
// past its promised end: mid-attempt, its lock held, or untouched since
// and not yet purged.
type OpenUploadsError struct {
	Open    int64
	Soonest time.Time
}

func (e *OpenUploadsError) Error() string {
	return fmt.Sprintf("%v (%d open, the soonest expiring %s)", ErrOpenUploads, e.Open,
		e.Soonest.UTC().Format(time.RFC3339))
}

func (e *OpenUploadsError) Unwrap() error { return ErrOpenUploads }

const uploadsName = "uploads"

// MaxStreamSize is the largest stream any relay takes, whatever its
// settings: relayapi.MaxStreamSize, 2^62 bytes, the protocol's ceiling,
// named here for the relay's own arithmetic.
const MaxStreamSize = relayapi.MaxStreamSize

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

// OpenUpload reserves room for a stream and creates its file. Whether
// there is room is roomFor's answer, the same one Put gets; before it,
// the sender's own count: at q.MaxOpenUploads rows of the sender's, in
// the same transaction so two opens cannot both be the last under the
// cap, the open is ErrOpenUploads, carrying the count and the soonest
// expiry among them. Every row counts, whatever its expiry: a first
// attempt of a large stream runs for as long as its bytes take, with its
// row's expiry — the open's plus the window, never moved during the copy
// — in the past for most of that, so a count of unexpired rows would not
// count an upload in flight, and four in flight would be no cap at all.
// The caller meets an expired row the way every upload route does, by
// letting it go, and asks again.
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

	if q.MaxOpenUploads > 0 {
		var open, soonest int64
		if err := tx.QueryRow(
			`SELECT COUNT(*), COALESCE(MIN(expires), 0) FROM uploads WHERE from_fp = ?`, fromFP).
			Scan(&open, &soonest); err != nil {
			return err
		}
		if open >= q.MaxOpenUploads {
			return &OpenUploadsError{Open: open, Soonest: time.Unix(soonest, 0)}
		}
	}
	if err := roomFor(tx, toFP, size, q); err != nil {
		return err
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

// roomFor is the one arithmetic for what a mailbox and the relay may take
// on: whether size more bytes, as one more message, fit under the quotas
// beside what is queued and what open uploads have reserved. Put and
// OpenUpload both ask it, so an envelope and a stream are charged alike;
// when Put kept its own sum it counted queued bytes alone, and a sender
// who opened a stream for everything free could post envelopes into the
// reservation and complete the stream on top, ending a mailbox and the
// relay over their quotas by up to one stream.
//
// The reservations count as though they were already queued, so two
// concurrent streams cannot each be told there is room for the last
// gigabyte. The size is compared, never added: queued and reserved are
// each non-negative and together under any quota, so quota minus both is
// what is left and cannot wrap, and a size near MaxInt64 is over it.
// Adding first wrapped the sum negative, which is under any quota, and
// once such a row existed SUM(size) overflowed inside SQLite and every
// later open for the mailbox was a storage error rather than a refusal.
// With no quota at all the same bound is kept against MaxInt64, after the
// quota's own answer, so the sum SQLite computes on the next open still
// fits; an envelope, bounded by max_bytes, can never reach it.
func roomFor(tx *sql.Tx, toFP string, size int64, q Quotas) error {
	var queuedMessages, queuedBytes int64
	err := tx.QueryRow(`SELECT queued_messages, queued_bytes FROM mailboxes WHERE fp = ?`, toFP).
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
	if q.MailboxMaxBytes > 0 && size > q.MailboxMaxBytes-queuedBytes-reservedBytes {
		return ErrMailboxFull
	}
	if size > math.MaxInt64-queuedBytes-reservedBytes {
		return ErrStreamTooBig
	}
	if q.RelayMaxBytes > 0 {
		var relayBytes, relayReserved int64
		if err := tx.QueryRow(`SELECT queued_bytes FROM relay_stats WHERE id = 1`).Scan(&relayBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM uploads`).Scan(&relayReserved); err != nil {
			return err
		}
		if size > q.RelayMaxBytes-relayBytes-relayReserved {
			return ErrRelayFull
		}
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

// Received is what one attempt left behind: the message id when the
// stream was placed, or the offset the upload now stands at and whether
// anything of it is kept for a resume.
type Received struct {
	// Placed is the message's id in the mailbox, when the attempt reached
	// the end; zero otherwise.
	Placed int64
	// Offset is where the upload stands after the attempt: the size when
	// placed, the kept partial's length when kept, zero when nothing is.
	Offset int64
	// Kept says a partial remains for one resumed attempt within the
	// window; false when the attempt placed the stream or left nothing.
	Kept bool
	// Expires is when a kept partial goes, on the relay's clock.
	Expires time.Time
	// Gone says this attempt deleted the upload whole, its file, its row
	// and its reservation: an attempt that stopped short and left
	// nothing, or a kept partial or a finished copy the disk or the
	// database would not take, with the row as it stood before the
	// attempt. It is false when the row survives the attempt's failure
	// — a sync that failed with the file put back, a placement that
	// failed — and when the row was already gone. The caller charged the
	// sender for the row and settles that charge on Gone by the row as it
	// stood, giving nothing back for a row at zero.
	Gone bool
}

// ReceiveUpload is one attempt: it copies the stream's bytes from offset
// to the end onto the upload's file, and either places the message or
// applies the rule for an attempt that stopped short.
//
// The copy streams: nothing larger than the buffer is held, whatever the
// sender sends. offset must match what the relay already has, so a sender
// that lost a connection is told where to resume by the 409 that carries
// the truth. r is given the file and how many bytes are wanted, and
// returns how many it wrote and the error that ended it, if one did; the
// caller's r is also where the shape of the first bytes is judged.
//
// One attempt at a time per upload, and no abort or purge while one runs:
// the upload's lock is held from the offset check through the copy, the
// sync and the row's update or the file's removal, so two attempts at one
// offset cannot both land, an abort sees the row before or after and
// never between, and the purge, which never waits on a sender, skips an
// upload mid-attempt. A SQLite transaction is not held across the copy,
// since a transaction open for the length of a network read would hold
// the one connection every other request needs.
//
// When the copy reaches size the stream is synced and placed, under the
// same lock, and the message's id answered. When it stops short: a first
// attempt (offset zero) that leaves at least threshold bytes on the disk
// is kept for one resumed attempt, its bytes synced and the row's
// received and expires written, expires being the window from the
// moment the attempt stopped, read from now once the copy has ended and
// never from when the request began — a transfer that ran longer than
// the window before its link dropped would otherwise be kept already
// expired; anything else — a first
// attempt under the threshold, or a resumed attempt, whose one resume is
// then spent — leaves nothing: the upload is deleted whole, its file and
// its row, and the reservation with it. So the relay never keeps less
// than a threshold's worth for an upload that did not complete, and a
// message is placed by at most two attempts on one id. A copy the file
// itself cut short — a full disk — is the store's fault (ErrRelayFull for
// ENOSPC), reported after the same rule has run.
func (s *Store) ReceiveUpload(id string, offset int64, threshold int64, now func() time.Time, window time.Duration,
	r func(w *os.File, want int64) (int64, error)) (Received, error) {
	return s.ReceiveUploadAdmitted(id, offset, threshold, now, window, r, nil)
}

// ReceiveUploadAdmitted is ReceiveUpload with mayPlace asked, under the
// upload's lock, once the copy has reached the end and before the stream
// is placed (R22): a sender the recipient has removed while the attempt
// ran, or a channel that has closed, places nothing, and the upload goes
// whole, its file and its row, as a resumed attempt that stops short does,
// answered ErrNotAdmitted. A mayPlace that cannot judge, its error, leaves
// the upload as a placement that failed does, the file put back to what
// the row says for the sender's next attempt. A nil mayPlace admits
// everything.
func (s *Store) ReceiveUploadAdmitted(id string, offset int64, threshold int64, now func() time.Time, window time.Duration,
	r func(w *os.File, want int64) (int64, error), mayPlace func() (bool, error)) (Received, error) {

	unlock := s.uploadLock(id)
	u, err := s.Upload(id)
	if errors.Is(err, ErrNoUpload) {
		// Aborted or purged since the caller looked, or never there: the
		// entry the lock made for it goes too, since ids are never reused
		// and nothing will come for it again. Kept, it was one mutex per
		// such race until the store closed.
		s.forgetUploadLock(id, unlock)
		return Received{}, err
	}
	if err != nil {
		unlock()
		return Received{}, err
	}
	if offset != u.Received {
		unlock()
		return Received{Offset: u.Received, Kept: u.Received > 0, Expires: u.Expires}, ErrUploadOffset
	}
	want := u.Size - u.Received
	if want <= 0 {
		unlock()
		return Received{Offset: u.Received}, ErrUploadOffset
	}

	// The file is opened by its handle: the directory is the relay's own,
	// but what stands under an upload's name is not taken on trust.
	f, err := regular.OpenFile(s.uploadPath(id), os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		unlock()
		return Received{Offset: u.Received}, s.fault(s.uploadPath(id), err)
	}
	n, copyErr := r(f, want)
	if n == want && copyErr == nil {
		// The end. Synced and placed under the lock, the lock's entry gone
		// with the upload. A sync that fails puts the file back to what
		// the row says; if that fails too, or the close does, the file
		// is longer than its row and the upload is aborted whole rather
		// than kept: a row naming fewer bytes than the file holds would
		// have the next attempt append after the extra ones and place a
		// corrupt stream.
		if err := f.Sync(); err != nil {
			if terr := f.Truncate(u.Received); terr != nil {
				f.Close()
				s.abortLocked(id)
				s.forgetUploadLock(id, unlock)
				return Received{Gone: true}, s.fault(s.uploadPath(id), err)
			}
			f.Close()
			unlock()
			return Received{Offset: u.Received}, s.fault(s.uploadPath(id), err)
		}
		if err := f.Close(); err != nil {
			s.abortLocked(id)
			s.forgetUploadLock(id, unlock)
			return Received{Gone: true}, s.fault(s.uploadPath(id), err)
		}
		if mayPlace != nil {
			admitted, err := mayPlace()
			if err != nil {
				if terr := s.truncateUpload(id, u.Received); terr != nil {
					s.abortLocked(id)
					s.forgetUploadLock(id, unlock)
					return Received{Gone: true}, err
				}
				unlock()
				return Received{Offset: u.Received}, err
			}
			if !admitted {
				// Put back to what the row says first, so that an abort
				// that fails leaves a file its row names and never one
				// the next attempt would append a second copy to.
				s.truncateUpload(id, u.Received)
				gone, abortErr := s.abortLocked(id)
				s.forgetUploadLock(id, unlock)
				if abortErr != nil {
					return Received{Gone: gone != nil}, fmt.Errorf("%w: %v", ErrNotAdmitted, abortErr)
				}
				return Received{Gone: true}, ErrNotAdmitted
			}
		}
		messageID, err := s.placeUpload(u)
		if err != nil {
			// The row stands as it was, at received, and the file holds
			// the whole stream under the upload's name, or is gone with a
			// message file placeUpload removed. Left so, the sender's
			// next attempt from received would append a second copy
			// after the first and place a stream of twice its size,
			// which the blob route drops as damaged: a busy database or
			// a rename that failed would have lost the message. So the
			// file is put back to what the row says, and the next
			// attempt lands where the row does; where that cannot be
			// done, the upload goes whole and the sender opens anew.
			if terr := s.truncateUpload(id, u.Received); terr != nil {
				s.abortLocked(id)
				s.forgetUploadLock(id, unlock)
				return Received{Gone: true}, err
			}
			unlock()
			return Received{Offset: u.Received}, err
		}
		s.forgetUploadLock(id, unlock)
		return Received{Placed: messageID, Offset: u.Size}, nil
	}

	// Stopped short. A first attempt that reached the threshold is kept;
	// everything else leaves nothing. The window runs from this moment,
	// the copy's end, not from the request's start.
	held := u.Received + n
	if u.Received == 0 && held >= threshold && n > 0 {
		expires := now().Add(window)
		if err := f.Sync(); err != nil {
			f.Truncate(0)
			f.Close()
			s.abortLocked(id)
			s.forgetUploadLock(id, unlock)
			return Received{Gone: true}, s.fault(s.uploadPath(id), err)
		}
		if _, err := s.db.Exec(`UPDATE uploads SET received = ?, expires = ? WHERE id = ?`, held, expires.Unix(), id); err != nil {
			// A partial the row cannot name is not kept: a file longer
			// than its row would be appended to at the wrong place.
			f.Truncate(0)
			f.Close()
			s.abortLocked(id)
			s.forgetUploadLock(id, unlock)
			return Received{Gone: true}, err
		}
		f.Close()
		unlock()
		return Received{Offset: held, Kept: true, Expires: expires}, s.shortCause(id, copyErr)
	}
	f.Truncate(u.Received)
	f.Close()
	gone, abortErr := s.abortLocked(id)
	s.forgetUploadLock(id, unlock)
	if abortErr != nil {
		return Received{Gone: gone != nil}, abortErr
	}
	return Received{Gone: true}, s.shortCause(id, copyErr)
}

// shortCause is the error an attempt that stopped short is answered with:
// ErrShortAttempt for a sender that stopped, wrapped around the copy's
// own error where there was one, or the disk's fault where the file cut
// it short.
func (s *Store) shortCause(id string, copyErr error) error {
	if isFileError(copyErr) {
		return s.fault(s.uploadPath(id), copyErr)
	}
	if copyErr != nil {
		return fmt.Errorf("%w: %v", ErrShortAttempt, copyErr)
	}
	return ErrShortAttempt
}

// isFileError reports whether a copy's error came from the file and not
// from the request: os.File's writes wrap theirs in *fs.PathError, and a
// body's reader never does; a full disk's errno is named too, for a
// caller that hands it over bare.
func isFileError(err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

// truncateUpload puts an upload's file back to n bytes, by the handle,
// synced: what a failed placement leaves at full size is cut to the
// length its row names, so the next attempt appends where the row says.
func (s *Store) truncateUpload(id string, n int64) error {
	f, err := regular.OpenFile(s.uploadPath(id), os.O_WRONLY, fileMode)
	if err != nil {
		return s.fault(s.uploadPath(id), err)
	}
	if err := f.Truncate(n); err != nil {
		f.Close()
		return s.fault(s.uploadPath(id), err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return s.fault(s.uploadPath(id), err)
	}
	return s.fault(s.uploadPath(id), f.Close())
}

// placeUpload turns a finished upload into a message, under the upload's
// lock, which the caller holds.
//
// The file is renamed into place before the transaction commits, so the
// invariant Put keeps holds here too: after a commit there is always a
// file. On any failure it leaves no orphan: a message file left by a
// failure after the rename — the directory's sync, the commit — is
// removed, so that the caller finds the upload's file where it was or
// gone, never a third thing.
func (s *Store) placeUpload(u *Upload) (int64, error) {
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
	if _, err := tx.Exec(`DELETE FROM uploads WHERE id = ?`, u.ID); err != nil {
		return 0, err
	}
	if err := s.place(s.uploadPath(u.ID), u.To, messageID); err != nil {
		s.removeMessage(u.To, messageID)
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		s.removeMessage(u.To, messageID)
		return 0, err
	}
	return messageID, nil
}

// AbortUpload drops an upload and releases its reservation, and hands
// back the row as it stood, nil when there was none, so the caller can
// settle what it was charged. Under the upload's lock, as an attempt is,
// and the lock's entry goes with the upload.
func (s *Store) AbortUpload(id string) (*Upload, error) {
	unlock := s.uploadLock(id)
	defer s.forgetUploadLock(id, unlock)
	return s.abortLocked(id)
}

// abortLocked is AbortUpload with the upload's lock already held. The
// row is read before it is deleted: under the lock nothing else writes
// it, so what is read is what goes. A row deleted whose file would not
// go is returned with the fault, since the row is gone and its charge
// with it.
func (s *Store) abortLocked(id string) (*Upload, error) {
	u, err := s.Upload(id)
	if errors.Is(err, ErrNoUpload) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	res, err := s.db.Exec(`DELETE FROM uploads WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if err := os.Remove(s.uploadPath(id)); err != nil && !os.IsNotExist(err) {
		return u, s.fault(s.uploadPath(id), err)
	}
	return u, nil
}

// uploadLock takes the lock for one upload, making it if this is the first
// operation on the id since the store opened, and returns what releases it.
func (s *Store) uploadLock(id string) func() {
	mu := s.uploadMutex(id)
	mu.Lock()
	return mu.Unlock
}

// tryUploadLock is uploadLock for a caller that must not wait: the purge,
// which runs inside an unrelated request. It says whether the lock was
// taken; when not, an append, a completion or an abort holds it, and the
// caller comes back another time.
func (s *Store) tryUploadLock(id string) (unlock func(), ok bool) {
	mu := s.uploadMutex(id)
	if !mu.TryLock() {
		return nil, false
	}
	return mu.Unlock, true
}

// uploadMutex is one upload's mutex, made on first use.
func (s *Store) uploadMutex(id string) *sync.Mutex {
	s.uploadsMu.Lock()
	defer s.uploadsMu.Unlock()
	if s.uploads == nil {
		s.uploads = map[string]*sync.Mutex{}
	}
	mu, ok := s.uploads[id]
	if !ok {
		mu = &sync.Mutex{}
		s.uploads[id] = mu
	}
	return mu
}

// uploadLocked reports whether an entry is held for id, for a test that
// asks what the map remembers.
func (s *Store) uploadLocked(id string) bool {
	s.uploadsMu.Lock()
	defer s.uploadsMu.Unlock()
	_, ok := s.uploads[id]
	return ok
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
// ever. It hands back the rows it removed, as each stood, so the caller
// can settle what each was charged, and says how many it left for next
// time.
//
// Housekeeping never waits on a sender. The purge runs inside an unrelated
// caller's request, and an attempt holds its upload's lock across the copy
// of the request body, so a purge that took the lock as an abort does
// stood behind a dribbling sender for as long as the read timeout let it,
// with that caller's slot held and its answer unsent. An upload whose lock
// is held is skipped and met at the next purge; by then the attempt has
// ended, or the expiry has refused it and aborted the row itself.
func (s *Store) PurgeUploads(now time.Time) (purged []Upload, skipped int, err error) {
	rows, err := s.db.Query(`SELECT id FROM uploads WHERE expires < ?`, now.Unix())
	if err != nil {
		return nil, 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for _, id := range ids {
		unlock, ok := s.tryUploadLock(id)
		if !ok {
			skipped++
			continue
		}
		gone, err := s.abortLocked(id)
		s.forgetUploadLock(id, unlock)
		if gone != nil {
			purged = append(purged, *gone)
		}
		if err != nil {
			return purged, skipped, err
		}
	}
	return purged, skipped, nil
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
	f, err := regular.Open(s.messagePath(toFP, id))
	return f, s.fault(s.messagePath(toFP, id), err)
}

// ErrNoMessage is returned for a message id nothing knows about.
var ErrNoMessage = errors.New("relay: no such message")

// ErrForm is a malformed request the store can recognise.
var ErrForm = errors.New("relay: malformed")
