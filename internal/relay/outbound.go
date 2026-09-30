package relay

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The queue a relay keeps for mail it has taken and has still to hand to a
// neighbour, and the table of envelopes it has already carried.
//
// Nothing here is inline. A relay on somebody's home internet is a relay
// that is sometimes down, and forwarding inside the sender's own request
// would hand every outage to the sender as a refusal; store and forward at
// every hop, always, is one path rather than two. So a post that names a
// path writes a row and a file in one transaction and answers at once, and
// a worker per neighbour empties the queue afterwards.

// The three states an outbound row is in.
const (
	// OutWaiting is a row the neighbour has not taken yet.
	OutWaiting = "waiting"
	// OutHanded is a row the neighbour took. Its file is gone and its
	// recipient is blanked; what is left names the poster, the neighbour
	// and the address, and waits for an undeliverable that may never come.
	OutHanded = "handed"
	// OutFinal is a row that will not be delivered, with the code and the
	// sentence saying why, kept a day so the poster can read it.
	OutFinal = "final"
)

// KindReport is a queue row that carries an undeliverable back one hop rather
// than an envelope onward: no file, no hash, and a body of three fields.
//
// It is this package's word and not relayapi's, and deliberately. The
// outbound table's kind column holds relayapi.KindEnvelope or this; the
// messages column holds relayapi's three and a client refuses a fourth by
// name on every listing row. No answer carries this one — a queue row on the
// wire has no kind at all — so the two sets never meet, and the client's is
// untouched by construction rather than by a constant somebody remembered to
// keep out of it.
const KindReport = "report"

// carriedDomain separates this hash from every other hash this tree makes.
//
// It is not a signing domain and no signature covers it: the carried table
// is local to one relay, so the domain's job is not agreement between
// relays but that a hash over an envelope cannot be confused with a hash
// over anything else, which is the same reason every signed thing here has
// one. It is the twelfth ccx constant, and the development guide's recount
// paragraph names it.
const carriedDomain = "ccx-carried-v1"

// CarriedHash identifies an envelope for the carried table: the recipient
// and the ciphertext, domain-separated and length-prefixed.
//
// It is over the parsed envelope and not over the bytes of the request that
// carried it. The bytes are a hop's to choose — a relay forwarding an
// envelope re-marshals the request around it, and nothing stops it adding a
// space — so a hash over them would let a lying hop make one envelope look
// like two and carry it round a loop as often as it liked. The recipient and
// the ciphertext are the two things a hop cannot touch without the envelope
// failing to open, so they are what the hash is over, and a relay that
// re-spaces the JSON changes nothing.
//
// The channel is left out on purpose. It is outside the seal, so a hop can
// change it as freely as whitespace, and the same ciphertext is always the
// same message however it is filed.
func CarriedHash(env *envelope.Envelope) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(carriedDomain), []byte(env.To), env.CT} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Outbound is one row of the queue.
type Outbound struct {
	ID        int64
	PosterFP  string
	Neighbour string
	// Path is what is left of the address, and Via the hops so far, each
	// joined by "!" as a name cannot hold one.
	Path string
	Via  string
	// ToFP is the recipient, held only while the row is waiting: it is
	// blanked the moment the neighbour takes the envelope.
	ToFP string
	Hash string
	Size int64
	// Kind is relayapi.KindEnvelope for mail being carried onward, or
	// KindReport for an undeliverable being carried back. The column holds
	// those two words and no others; a mailbox row's kind is a different
	// column with a different set.
	Kind string

	Received time.Time
	State    string
	Tries    int64
	LastTry  time.Time
	NextTry  time.Time
	GivesUp  time.Time
	TheirID  int64
	Code     string
	Said     string
}

// ErrCarried is the answer to an envelope this relay has already taken.
var ErrCarried = errors.New("relay: already carried")

// ErrCarriedFull is the answer when the carried table is at its ceiling. A
// hash is never evicted to make room: the table is what makes a retry
// idempotent and a loop die, so the relay stops taking new mail instead.
var ErrCarriedFull = errors.New("relay: carried table is full")

// ErrQueueFull is the answer when the queue has no room for one more row,
// whether the bound reached was the relay's or the poster's.
var ErrQueueFull = errors.New("relay: forwarding queue is full")

// outboundDir holds one file per envelope waiting to leave, named by the row
// that owns it. The name is an integer this relay allocated, so nothing a
// sender or a neighbour chose reaches the path.
const outboundDir = "outbound"

// outboundPath is where one queued envelope's bytes live: sharded, as a
// mailbox's messages are sharded, so that a relay carrying a great deal for a
// neighbour that is down does not put a million entries in one directory.
// The shard is the id's last two digits, which spreads evenly because the ids
// are consecutive, and every part of the name is an integer this relay
// allocated.
func (s *Store) outboundPath(id int64) string {
	return filepath.Join(s.outboundShard(id), strconv.FormatInt(id, 10))
}

func (s *Store) outboundShard(id int64) string {
	return filepath.Join(s.dir, outboundDir, fmt.Sprintf("%02d", id%100))
}

// Enqueue takes an envelope this relay is to carry: one row, one file, one
// transaction, and the hash written before either.
//
// The order is the order the route needs. The hash goes in first, so that an
// envelope this relay has already taken is refused before anything is
// stored and before any bound is spent on it; then the carried ceiling, then
// the queue's room; then the row, its counters and its file. The file is
// placed before the commit, so a committed row always has its bytes, and is
// removed if the commit fails.
func (s *Store) Enqueue(o *Outbound, raw []byte, q CourierQuotas, expires time.Time) (int64, error) {
	size := int64(len(raw))
	tmp, err := s.writeTemp(raw)
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp)

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if err := noteCarried(tx, o.Hash, q, expires); err != nil {
		return 0, err
	}
	if err := roomInQueue(tx, o.PosterFP, size, q); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO outbound
		(poster_fp, neighbour, path, via, to_fp, hash, size, kind, received, state, gives_up, next_try)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.PosterFP, o.Neighbour, o.Path, o.Via, o.ToFP, o.Hash, size, o.Kind,
		o.Received.Unix(), OutWaiting, o.GivesUp.Unix(), o.Received.Unix())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := adjustQueueCounters(tx, 1, size); err != nil {
		return 0, err
	}
	if err := s.placeOutbound(tmp, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		s.removeOutbound(id)
		return 0, err
	}
	return id, nil
}

// noteCarried writes an envelope's hash, or reports that it is already
// there.
//
// The ceiling is checked only when the hash is new, since a repeat stores
// nothing: a relay at its ceiling still answers a retry as it answered the
// first attempt, which is what makes the answer idempotent rather than
// dependent on how full the table is.
func noteCarried(tx *sql.Tx, hash string, q CourierQuotas, expires time.Time) error {
	var found int
	err := tx.QueryRow(`SELECT 1 FROM carried WHERE hash = ?`, hash).Scan(&found)
	if err == nil {
		return ErrCarried
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if q.CarriedMaxRows > 0 {
		var rows int64
		if err := tx.QueryRow(`SELECT COUNT(*) FROM carried`).Scan(&rows); err != nil {
			return err
		}
		if rows >= q.CarriedMaxRows {
			return ErrCarriedFull
		}
	}
	_, err = tx.Exec(`INSERT INTO carried (hash, expires) VALUES (?, ?)`, hash, expires.Unix())
	return err
}

// Carried reports whether this relay has already taken an envelope. It is
// the read the delivery path uses; Enqueue does the same check inside its
// own transaction, which is the one that decides.
func (s *Store) Carried(hash string) (bool, error) {
	var found int
	err := s.db.QueryRow(`SELECT 1 FROM carried WHERE hash = ?`, hash).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// PurgeCarried forgets the hashes whose window has passed.
//
// It runs on the nonce purge's timer, and it must run: the table is the only
// thing that grows without an owner, since a mailbox's mail goes when its
// owner fetches it and an upload's row goes when the upload ends, while a
// hash is kept for a message nobody here is waiting for. Without this the
// ceiling is not a ceiling but a wall, reached once and never left.
//
// A hash goes when the envelope it stands for can no longer be alive
// anywhere ahead of it, which is what CarriedWindow computes.
func (s *Store) PurgeCarried(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM carried WHERE expires <= ?`, now.Unix())
	return err
}

// CourierQuotas is what the queue and the carried table are bounded by.
// Zero is unlimited for every field, as everywhere else.
type CourierQuotas struct {
	QueueMaxBytes    int64
	QueueMaxMessages int64
	// QueueMaxRowsPerPoster is how many rows one poster may have waiting.
	// It is one field and one comparison for two settings, because a
	// courier is a poster like any other here and only the number differs:
	// CourierLimits.Quotas fills it from queue_max_messages_per_poster and
	// CourierQuotasFor from queue_max_messages_per_courier, so the rule is
	// in one place and which number it holds is decided where a caller is
	// already known to be one or the other.
	QueueMaxRowsPerPoster  int64
	QueueMaxBytesPerPoster int64
	CarriedMaxRows         int64
}

// roomInQueue answers whether there is room for one more row, by
// subtraction and never by a sum that can wrap, which is roomFor's rule and
// roomFor's reason: two callers with two arithmetics are a quota with a gap
// between them, and this is the one place the question is asked.
//
// The relay-wide bounds are over every row waiting; the per-poster bounds
// are over the rows this poster has waiting, whatever they are addressed to.
// A courier is held to the relay-wide pair, to a row bound of its own —
// larger than a person's because a courier carries many people's mail — and
// to no per-poster byte bound at all, since a busy neighbour's whole queue
// should not be refused for one person's worth of bytes. It is held to the
// relay-wide rows as well as the bytes because bytes do not bound rows —
// ten million hundred-byte envelopes are a gigabyte and ten million files.
func roomInQueue(tx *sql.Tx, posterFP string, size int64, q CourierQuotas) error {
	var allMessages, allBytes int64
	if err := tx.QueryRow(`SELECT outbound_messages, outbound_bytes FROM relay_stats WHERE id = 1`).
		Scan(&allMessages, &allBytes); err != nil {
		return err
	}
	if size > math.MaxInt64-allBytes {
		return ErrQueueFull
	}
	if q.QueueMaxBytes > 0 && size > q.QueueMaxBytes-allBytes {
		return ErrQueueFull
	}
	// The relay-wide row bound, which is the one a courier is held to as
	// well: bytes do not bound rows, and rows are files. The guard above it
	// is for the same reason the bytes have one — a counter that has been
	// corrupted, or has run up against the type, must refuse rather than
	// wrap into room — and it stands whether or not a bound is set, since
	// unlimited is a supported setting and is where nothing else would.
	if allMessages == math.MaxInt64 {
		return ErrQueueFull
	}
	if q.QueueMaxMessages > 0 && allMessages >= q.QueueMaxMessages {
		return ErrQueueFull
	}
	if q.QueueMaxRowsPerPoster > 0 || q.QueueMaxBytesPerPoster > 0 {
		var mine, mineBytes int64
		if err := tx.QueryRow(
			`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM outbound WHERE poster_fp = ? AND state = ?`,
			posterFP, OutWaiting).Scan(&mine, &mineBytes); err != nil {
			return err
		}
		if q.QueueMaxRowsPerPoster > 0 && mine >= q.QueueMaxRowsPerPoster {
			return ErrQueueFull
		}
		if q.QueueMaxBytesPerPoster > 0 && size > q.QueueMaxBytesPerPoster-mineBytes {
			return ErrQueueFull
		}
	}
	return nil
}

// adjustQueueCounters moves the queue's totals inside the caller's
// transaction, so a row is charged and charged off exactly once. They are
// counters and not aggregates, for the reason the mailbox's are: a SUM over
// the table on every post is a scan, and OpenStore reconciles these from the
// rows at every start as a backstop.
func adjustQueueCounters(tx *sql.Tx, messages, bytes int64) error {
	_, err := tx.Exec(
		`UPDATE relay_stats SET outbound_messages = outbound_messages + ?, outbound_bytes = outbound_bytes + ? WHERE id = 1`,
		messages, bytes)
	return err
}

// placeOutbound renames a temporary file into the queue's directory under
// the row's own id.
func (s *Store) placeOutbound(tmp string, id int64) error {
	dir := s.outboundShard(id)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return storageErr(err)
	}
	if err := os.Rename(tmp, s.outboundPath(id)); err != nil {
		return storageErr(err)
	}
	// The directory entry, not just the bytes: a rename that has not reached
	// the disk is a committed row with no file after a power cut, which is
	// the thing the placing-before-the-commit order is for. A message's own
	// place does this and says why.
	return s.fault(dir, fsyncDir(dir))
}

// OutboundBody is the envelope a row is waiting to hand over.
func (s *Store) OutboundBody(id int64) ([]byte, error) {
	return os.ReadFile(s.outboundPath(id))
}

// removeOutbound takes a row's file. A failure is the storage fault it is and
// never the caller's to answer with: the row is committed and the envelope
// taken, so there is nobody to answer it to, and it is noted for the
// operator. The startup sweep does not reach this directory — it walks the
// mailboxes — so a file left here by a failed unlink waits for the purge,
// which takes the file again as it takes the row: a handed row's file is
// asked for twice, once when the neighbour took it and once when the row's
// window runs out, and a disk that refused the first unlink will usually
// have been mended by the second. A file that survives both is an orphan
// nothing looks for, which is a fault of this relay's own storage twice
// over and is in the operator's log both times.
func (s *Store) removeOutbound(id int64) error {
	err := os.Remove(s.outboundPath(id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.faults.note(s.outboundPath(id), err)
		return err
	}
	return nil
}

// OutboundFor is the rows this poster has in the queue, at most limit of
// them: what is still waiting first, then what failed, then what was handed
// over, and oldest first within each.
//
// Every state, not the waiting ones alone: somebody asking what became of
// their mail wants the one that failed most of all, and a handed row is how
// they see that it went. But the order cannot be the id alone, and that is
// the whole reason this clause is here. A handed row is kept for as long as
// something could still come back about it — the carried window, three days
// at the defaults — while nothing bounds how many a poster accumulates the
// way the queue's own count bounds waiting ones. So an active sender's page
// fills with rows about mail that arrived, and the one stuck behind a dead
// neighbour or refused by the last hop is pushed off the end: invisible to
// the listing, uncounted by the line the inbox prints, and gone at its own
// gives_up without anybody being told. The rows that need an answer come
// first, and a handed row is what fills the room that is left.
//
// The index that serves it is outbound_poster, on the poster and the id, so
// a poster reads their own rows and not the table; the ordering is over that
// page and not over the table.
func (s *Store) OutboundFor(posterFP string, limit int) ([]*Outbound, error) {
	rows, err := s.db.Query(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said
		FROM outbound WHERE poster_fp = ?
		ORDER BY CASE state WHEN ? THEN 0 WHEN ? THEN 1 ELSE 2 END, id
		LIMIT ?`, posterFP, OutWaiting, OutFinal, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Outbound
	for rows.Next() {
		o, err := scanOutboundRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// EnqueueReport puts an undeliverable in the queue for the courier that
// posted the row it is about, so that the news travels back a hop at a time.
//
// It is Enqueue's shape with three things left out, each for the same reason:
// a report is not a message. There is no file, since what it carries is three
// fields and they fit in the row; no hash in the carried table, since a report
// is bound to a row the receiving relay already holds and is not a thing that
// could arrive twice from two directions; and no size charged, since the
// queue's byte bounds are about mail waiting on a disk. It is counted against
// the row bounds, because it is a row and rows are what those bound.
//
// their_id carries this relay's own row id, which is the number the courier
// being told holds: it took this relay's answer when it handed the envelope
// over and wrote that number into its own row.
func (s *Store) EnqueueReport(o *Outbound, q CourierQuotas) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := roomInQueue(tx, o.PosterFP, 0, q); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO outbound
		(poster_fp, neighbour, path, via, to_fp, hash, size, kind, received, state,
		 gives_up, next_try, their_id, code, said)
		VALUES (?, ?, '', '', '', '', 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.PosterFP, o.Neighbour, o.Kind, o.Received.Unix(), OutWaiting,
		o.GivesUp.Unix(), o.Received.Unix(), o.TheirID, o.Code, o.Said); err != nil {
		return err
	}
	// One row, no bytes: the counters move by one and by nothing, so a queue
	// full of reports is still refused by the row bound and a report never
	// makes a byte bound wrong.
	if err := adjustQueueCounters(tx, 1, 0); err != nil {
		return err
	}
	return tx.Commit()
}

// HandedTo is the row this relay handed to that courier under that id, for a
// report coming back about it.
//
// The pair is (this relay's name for the courier, the id the courier itself
// answered with), which is the one number both sides hold: this relay wrote
// it into the row as their_id when the courier took the envelope, and the
// courier wrote it as its own row's id. So a report names the id the
// reporting relay issued, and the relay receiving it looks up by the pair.
//
// The pair is not unique and cannot be. A neighbour whose database was
// recreated numbers its rows from one again, and this relay may still hold a
// handed row from before with the same pair, inside the window a report could
// still arrive in. So every row with the pair is read: none at all is no such
// row; among them the newest handed row by id is the one, since a report
// comes from the neighbour's present numbering and the newest row is the one
// that numbering produced; and rows with none handed is a row that is not
// one this relay is waiting to hear about — either never handed, or already
// told about, which is the same answer because a report is taken once.
//
// found says whether any row carried the pair, which is what tells 404 from
// 409; row is nil when found is true and none of them was handed.
func (s *Store) HandedTo(neighbour string, theirID int64) (row *Outbound, found bool, err error) {
	rows, err := s.db.Query(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said
		FROM outbound WHERE neighbour = ? AND their_id = ? ORDER BY id DESC`, neighbour, theirID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		o, err := scanOutboundRows(rows)
		if err != nil {
			return nil, false, err
		}
		found = true
		if o.State == OutHanded && row == nil {
			row = o
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return row, found, nil
}

// CarriedAnswer is what a relay tells a caller whose envelope it has already
// carried: the caller's own row for it, with its state and, for a final row,
// the code and the sentence it ended with; failing that, the id of the
// message the envelope became if this relay delivered it; failing both,
// nothing, and the 409 goes back bare.
//
// The three are the three causes of a repeat, and the neighbour that sent it
// has to tell them apart (rulings 44 and 45). A retry after a lost answer
// finds the caller's own row, and is handed if the row is waiting or handed
// and refused with the row's own words if it is final — the report of that
// failure having been refused at the caller, which had no id to match it to.
// A retry after a lost answer to a delivery finds the delivered id and is
// handed. A loop coming back finds neither, since the envelope was never the
// caller's here, and is refused.
//
// The row is keyed by the poster as well as the hash on purpose — a second
// caller posting the same envelope has no business learning another poster's
// row id, or how it ended — and the index that serves it is outbound_poster.
type CarriedAnswer struct {
	ID   int64
	Code string
	Said string
}

// CarriedAnswerFor looks up what CarriedAnswer says for this caller and
// envelope.
func (s *Store) CarriedAnswerFor(posterFP, hash string) (CarriedAnswer, error) {
	var a CarriedAnswer
	var state string
	err := s.db.QueryRow(`SELECT id, state, code, said FROM outbound WHERE poster_fp = ? AND hash = ?
		ORDER BY id DESC LIMIT 1`, posterFP, hash).Scan(&a.ID, &state, &a.Code, &a.Said)
	switch {
	case err == nil:
		if state != OutFinal {
			a.Code, a.Said = "", ""
		}
		return a, nil
	case !errors.Is(err, sql.ErrNoRows):
		return CarriedAnswer{}, err
	}
	err = s.db.QueryRow(`SELECT delivered FROM carried WHERE hash = ?`, hash).Scan(&a.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return CarriedAnswer{}, nil
	}
	if err != nil {
		return CarriedAnswer{}, err
	}
	return a, nil
}

// JoinPath and SplitPath are how a list of relay names travels in a column:
// joined by "!", which a name cannot hold, so the join is reversible and the
// empty list is the empty string.
func JoinPath(names []string) string { return strings.Join(names, "!") }

// SplitPath is JoinPath backwards. The empty string is the empty list and
// not a list of one empty name.
func SplitPath(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, "!")
}

// NextOutbound is the oldest row waiting for a neighbour whose next attempt
// is due, or nil when there is none.
func (s *Store) NextOutbound(neighbour string, now time.Time) (*Outbound, error) {
	row := s.db.QueryRow(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said
		FROM outbound WHERE neighbour = ? AND state = ? AND next_try <= ?
		ORDER BY id LIMIT 1`, neighbour, OutWaiting, now.Unix())
	o, err := scanOutbound(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return o, err
}

// scanOutbound reads one row, and scanOutboundRows one of many. The two
// exist because database/sql's Row and Rows share no interface for Scan and
// the column list must be written once; whichever is passed, the same
// columns in the same order make the same Outbound.
func scanOutbound(row *sql.Row) (*Outbound, error) { return outboundFrom(row.Scan) }

func scanOutboundRows(rows *sql.Rows) (*Outbound, error) { return outboundFrom(rows.Scan) }

func outboundFrom(scan func(...any) error) (*Outbound, error) {
	var o Outbound
	var received, lastTry, nextTry, givesUp int64
	if err := scan(&o.ID, &o.PosterFP, &o.Neighbour, &o.Path, &o.Via, &o.ToFP, &o.Hash,
		&o.Size, &o.Kind, &received, &o.State, &o.Tries, &lastTry, &nextTry, &givesUp,
		&o.TheirID, &o.Code, &o.Said); err != nil {
		return nil, err
	}
	o.Received = time.Unix(received, 0).UTC()
	// A row never offered has no last try, and the column says so with a
	// zero. That reads back as the zero time and not as a date in 1970:
	// the difference is what a person is shown, and "never" is the truth
	// where a date half a century ago is a number nobody wrote. received,
	// next_try and gives_up are set at the insert and are never zero, so
	// only this one can mean "not yet".
	if lastTry != 0 {
		o.LastTry = time.Unix(lastTry, 0).UTC()
	}
	o.NextTry = time.Unix(nextTry, 0).UTC()
	o.GivesUp = time.Unix(givesUp, 0).UTC()
	return &o, nil
}

// Handed records that the neighbour took the envelope: the file goes and the
// recipient is blanked at once, and what is left names the poster and the
// neighbour until the carried window is out.
//
// theirID is the id the neighbour answered with, which is the one number
// both sides hold and what an undeliverable coming back will name. From a
// 409 it is the row the neighbour holds for this relay's courier, or the
// message the envelope became there; a bare 409 is a refusal and never
// reaches here.
func (s *Store) Handed(id, theirID int64, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var size int64
	var state string
	if err := tx.QueryRow(`SELECT size, state FROM outbound WHERE id = ?`, id).Scan(&size, &state); err != nil {
		return err
	}
	if state != OutWaiting {
		return fmt.Errorf("relay: outbound %d is %s, not %s", id, state, OutWaiting)
	}
	if _, err := tx.Exec(`UPDATE outbound SET state = ?, to_fp = '', their_id = ?, last_try = ?, tries = tries + 1
		WHERE id = ?`, OutHanded, theirID, now.Unix(), id); err != nil {
		return err
	}
	if err := adjustQueueCounters(tx, -1, -size); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// After the commit, as Put removes a replaced knock's body: the row is
	// committed and the envelope handed over, so a failure here is the
	// operator's line and not an answer to anybody.
	s.removeOutbound(id)
	return nil
}

// Failed records that this row will not be delivered, with the code and the
// sentence a person reads. The file goes and the recipient is blanked as at
// a handing, since neither is any use now.
func (s *Store) Failed(id int64, code, said string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var size int64
	var state string
	if err := tx.QueryRow(`SELECT size, state FROM outbound WHERE id = ?`, id).Scan(&size, &state); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE outbound SET state = ?, to_fp = '', code = ?, said = ?, last_try = ?,
		tries = tries + 1 WHERE id = ?`, OutFinal, code, said, now.Unix(), id); err != nil {
		return err
	}
	// A row that was waiting is still charged to the queue; one that was
	// already handed was charged off when it was handed.
	if state == OutWaiting {
		if err := adjustQueueCounters(tx, -1, -size); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removeOutbound(id)
	return nil
}

// FailHandedOnce finals a row if it is still handed, and says whether this call
// is the one that did it.
//
// Taking a report is a read and a write: HandedTo finds the row, to tell a row
// this relay never handed to that courier from one it is not waiting to hear
// about, and then the row is ended. Those are two statements, and the one
// connection the store has serialises statements and not pairs — so two reports
// naming one id both read handed and both took it. What that cost: a duplicate
// report row charged to the hop behind's share of this relay's queue, which a
// neighbour reporting concurrently could spend to have that hop's honest
// forwards refused 507; and a second report arriving at the hop behind, which
// answers 409 as it should, which this relay then writes up as a neighbour
// refusing an undeliverable — a false line in the operator's log about news
// that did travel. Both documents say a report is taken "and once", and it was
// not.
//
// The guard is in the UPDATE's own WHERE, so the deciding and the writing are
// one statement. A handed row was charged off the queue when it was handed, so
// no counter moves here, which is the only way this differs from Failed.
func (s *Store) FailHandedOnce(id int64, code, said string, now time.Time) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE outbound SET state = ?, to_fp = '', code = ?, said = ?, last_try = ?,
		tries = tries + 1 WHERE id = ? AND state = ?`,
		OutFinal, code, said, now.Unix(), id, OutHanded)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		// Somebody else took it between the read and here. Nothing was
		// written, so there is nothing to commit and nothing to undo.
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.removeOutbound(id)
	return true, nil
}

// Retry puts a row back for another attempt at next, counting the one that
// just failed.
func (s *Store) Retry(id int64, now, next time.Time) error {
	_, err := s.db.Exec(`UPDATE outbound SET tries = tries + 1, last_try = ?, next_try = ? WHERE id = ?`,
		now.Unix(), next.Unix(), id)
	return err
}

// PurgeOutbound removes the rows whose time is up: a final row a day after
// it failed, a handed row when the carried window it was waiting through has
// passed. It returns how many went.
//
// A waiting row is never purged here: its own gives_up is what ends it, and
// that is the worker's to notice, so that the poster is told rather than
// finding their mail gone.
//
// This runs inside somebody's request, every hundredth, on the one
// connection the store has, over a table whose size is a neighbour's
// traffic: so it reads only rows that could be due and writes once. Only
// could-be-due, by asking the index for the rows whose last attempt is
// older than the shortest retention either rule allows — a row newer than
// that is due under neither, and reading it to decide so is the scan this
// purge used to be. Once, because a delete per row was a transaction per
// row, each with its own fsync, where what is wanted is that the rows go
// together or not at all. handedFor must not answer less for a longer path
// than for a shorter one, which is what makes the cutoff sound;
// CourierLimits.CarriedWindow, its only caller, is one hop's time per hop.
func (s *Store) PurgeOutbound(now time.Time, finalFor time.Duration, handedFor func(pathLeft int) time.Duration) (int, error) {
	shortest := min(finalFor, handedFor(0))
	if shortest < 0 {
		shortest = 0
	}
	rows, err := s.db.Query(`SELECT id, state, path, last_try FROM outbound
		WHERE state IN (?, ?) AND last_try <= ?`,
		OutFinal, OutHanded, now.Add(-shortest).Unix())
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id, lastTry int64
		var state, path string
		if err := rows.Scan(&id, &state, &path, &lastTry); err != nil {
			rows.Close()
			return 0, err
		}
		// A handed row waits out the window its own envelope could still
		// be alive in, which is the window its hash was written with and
		// depends on how far it had left to go; the shortest window would
		// take a two-hop row while the hop after it was still trying.
		keep := finalFor
		if state == OutHanded {
			keep = handedFor(len(SplitPath(path)))
		}
		if time.Unix(lastTry, 0).Add(keep).After(now) {
			continue
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM outbound WHERE id = ?`, id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	// After the commit, as a handing takes its file after the commit: the
	// rows are gone, so a failure here is the operator's line and nobody's
	// answer. Most of these files went when the row ended; this is the
	// second ask, for the one whose unlink failed then.
	for _, id := range ids {
		s.removeOutbound(id)
	}
	return len(ids), nil
}

// GiveUp ends every row whose gives_up has passed, with the sentence that
// says how long the relay tried and since when the neighbour has been
// unreachable. It answers how many it ended.
//
// It does not end them itself: end does, and end is the worker's fail, which
// is the one place that finals a row and passes the news back a hop. Giving up
// is the third way a row ends — the route's report and the worker's refusal
// are the other two — and the news travels from it exactly as it does from a
// refusal. Ending rows here with Failed, which is what this did, left the hop
// behind told nothing, and its sender told nothing at all rather than told
// something wrong: that relay handed the envelope over successfully, so its row
// is handed and not waiting, and the query below only ever finds waiting rows,
// so its row is never given up on either and goes at the purge with nobody
// told. CodeGaveUp is only ever produced here, so nothing emitted it.
//
// The row passed to end carries four fields and no others: ID, PosterFP, Kind
// and Received. They are what fail and reportBack read, and the query selects
// exactly them because a neighbour down for the whole of forward_ttl can leave
// a great many rows due at once and a full row apiece would be the envelope's
// address and hash held in memory for every one of them. A field added to
// either of those readers has to be added here.
//
// One row per transaction, since each is a file removed as well as a row and a
// counter moved, and there can be a great many of them: a worker only reaches
// this when its neighbour's backoff lifts, so one pass can cover an hour of
// arrivals. That is why it takes a context. A relay stopping must not wait out
// the whole of it — the stop is what runs before the listener's own grace
// period, so an unbounded wait here is a relay that is killed rather than
// stopped — and a row left for the next start is a row still waiting, which is
// the state it was already in.
func (s *Store) GiveUp(ctx context.Context, neighbour string, now time.Time, ttl time.Duration,
	end func(row *Outbound, code, said string)) (int, error) {

	rows, err := s.db.Query(`SELECT id, poster_fp, kind, received FROM outbound
		WHERE neighbour = ? AND state = ? AND gives_up <= ?`, neighbour, OutWaiting, now.Unix())
	if err != nil {
		return 0, err
	}
	var ended []*Outbound
	for rows.Next() {
		var o Outbound
		var received int64
		if err := rows.Scan(&o.ID, &o.PosterFP, &o.Kind, &received); err != nil {
			rows.Close()
			return 0, err
		}
		o.Received = time.Unix(received, 0).UTC()
		ended = append(ended, &o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for i, o := range ended {
		if ctx.Err() != nil {
			return i, nil
		}
		end(o, relayapi.CodeGaveUp, fmt.Sprintf("gave up after %s; %s has been unreachable since %s",
			ttl, neighbour, o.Received.Format(time.RFC3339)))
	}
	return len(ended), nil
}
