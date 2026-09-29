package relay

import (
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

// OutWaiting is a row the neighbour has not taken yet, which is every row
// this commit writes.
//
// The column's other two words, for a row a neighbour has taken and one that
// will not be delivered, arrive with the worker that writes them: the table's
// comment in store.go describes all three, because the table holds all three
// from the moment it exists, but a constant nothing writes is a name a reader
// has to guess the use of.
const OutWaiting = "waiting"

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
	QueueMaxBytes          int64
	QueueMaxMessages       int64
	QueueMaxBytesPerPoster int64
	CarriedMaxRows         int64
}

// roomInQueue answers whether there is room for one more row, by
// subtraction and never by a sum that can wrap, which is roomFor's rule and
// roomFor's reason: two callers with two arithmetics are a quota with a gap
// between them, and this is the one place the question is asked.
//
// The relay-wide bound is over every row; the per-poster bounds are over the
// rows this poster has waiting. A courier's rows are counted against the
// relay's bound alone: a courier carries many people's mail, and holding it
// to one poster's share would refuse a neighbour's whole queue for being
// busy, which the relay-wide bound and the couriers file already answer.
func roomInQueue(tx *sql.Tx, posterFP string, size int64, q CourierQuotas) error {
	var allBytes int64
	if err := tx.QueryRow(`SELECT outbound_bytes FROM relay_stats WHERE id = 1`).Scan(&allBytes); err != nil {
		return err
	}
	if size > math.MaxInt64-allBytes {
		return ErrQueueFull
	}
	if q.QueueMaxBytes > 0 && size > q.QueueMaxBytes-allBytes {
		return ErrQueueFull
	}
	if q.QueueMaxMessages > 0 || q.QueueMaxBytesPerPoster > 0 {
		var mine, mineBytes int64
		if err := tx.QueryRow(
			`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM outbound WHERE poster_fp = ? AND state = ?`,
			posterFP, OutWaiting).Scan(&mine, &mineBytes); err != nil {
			return err
		}
		if q.QueueMaxMessages > 0 && mine >= q.QueueMaxMessages {
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
// mailboxes — so a file left here by a failed unlink is an orphan until the
// queue's own purge, which arrives with the worker that ends rows.
func (s *Store) removeOutbound(id int64) error {
	err := os.Remove(s.outboundPath(id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.faults.note(s.outboundPath(id), err)
		return err
	}
	return nil
}

// OutboundIDFor is the id of the row this poster holds for an envelope, or
// zero when they hold none.
//
// It answers the 409 for a retry after a lost answer: the poster learns the
// id its first attempt was given, which is what an undeliverable coming back
// will name. It is keyed by the poster as well as the hash on purpose — a
// second caller posting the same envelope has no business learning another
// poster's row id — and the index that serves it is outbound_poster.
func (s *Store) OutboundIDFor(posterFP, hash string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM outbound WHERE poster_fp = ? AND hash = ? ORDER BY id DESC LIMIT 1`,
		posterFP, hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return id, nil
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
