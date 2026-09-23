// Package relay implements the store-and-forward server. It is deliberately
// dumb: it holds sealed envelopes it cannot read, and enforces only who may
// have a mailbox, who may drop mail into whose, how fast, and how much.
package relay

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"

	_ "modernc.org/sqlite"
)

// ErrNoMailbox is returned when a fingerprint has never registered.
var ErrNoMailbox = errors.New("relay: no such mailbox")

// ErrAmbiguousShort is a short id that more than one mailbox begins with.
var ErrAmbiguousShort = errors.New("relay: more than one mailbox begins with that short id; use the full fingerprint")

// ErrReplay is returned when an auth nonce has already been used.
var ErrReplay = errors.New("relay: nonce replayed")

// Quota failures. These are the recipient's problem or the operator's, never
// the sender's fault, so they are told apart from every other refusal.
var (
	// ErrMailboxFull means the recipient has not collected their mail.
	ErrMailboxFull = errors.New("relay: mailbox is full")
	// ErrRelayFull means the relay as a whole has run out of room.
	ErrRelayFull = errors.New("relay: storage is full")
	// ErrKnocksWaiting means the mailbox holds as many knocks as the relay
	// lets one hold; the knock is refused and nothing is stored.
	ErrKnocksWaiting = errors.New("relay: the mailbox has as many knocks waiting as allowed")
	// ErrTooManyMailboxes means the relay is not accepting new registrations.
	ErrTooManyMailboxes = errors.New("relay: mailbox limit reached")
)

// Enrolment failures. Each becomes its own message, because "your token did
// not work" is the least useful thing a relay can say to somebody trying to
// join it.
var (
	// ErrTokenUnknown means the token verifies but was never registered here.
	ErrTokenUnknown = errors.New("relay: token is not registered")
	// ErrTokenRevoked means an administrator withdrew it.
	ErrTokenRevoked = errors.New("relay: token is revoked")
	// ErrTokenSpent means every use has been redeemed.
	ErrTokenSpent = errors.New("relay: token has no uses left")
	// ErrDuplicateToken means a token with that id is already registered.
	ErrDuplicateToken = errors.New("relay: token is already registered")
	// ErrTokenWrongUse means the token is live but authorises something else.
	ErrTokenWrongUse = errors.New("relay: token does not authorise this")
)

// schemaVersion is the one shape this build reads and writes. A database is
// at it or is refused: there is no migration, since nothing on this
// machine is from before — every released version is retracted, so a
// database at another version is one nobody runs, and a path that
// migrated it would be a path nobody tests. The refusal says to delete the
// database and its message directory; the next start recreates both.
const schemaVersion = 11

// SchemaVersion is schemaVersion for the version line and the container
// suite.
const SchemaVersion = schemaVersion

// Store is the relay's SQLite-backed state.
type Store struct {
	db  *sql.DB
	dir string // message bodies, one file each; see filestore.go

	// faults says why, once a minute per path, when a file operation under
	// dir fails; see faults.go. Nil until a server gives it a logger.
	faults *faultLog

	reconciled int
	swept      SweepResult

	// uploads serialises the operations on one upload in progress: an
	// append, a completion and an abort each hold the upload's own lock
	// for their whole length, so that no two of them read the row and act
	// on the file between one another. See uploadLock.
	uploadsMu sync.Mutex
	uploads   map[string]*sync.Mutex
}

// SetFaultLog names where storage faults are reported and the clock they
// are limited by. NewServer calls it with the server's own; a store with no
// fault log answers its callers and says nothing.
func (s *Store) SetFaultLog(log *slog.Logger, now func() time.Time) {
	s.faults = newFaultLog(log, now)
}

// fault records a failed file operation under the message directory and
// returns the error as the caller should see it: a full disk mapped to
// ErrRelayFull, anything else as it came. Every read, write, rename and
// mkdir under dir reports through it, so none can fail in silence.
func (s *Store) fault(path string, err error) error {
	if err == nil {
		return nil
	}
	s.faults.note(path, err)
	return storageErr(err)
}

// Quotas bound what one Put may add. Zero means unlimited.
type Quotas struct {
	MailboxMaxMessages int64
	MailboxMaxBytes    int64
	RelayMaxBytes      int64
	// MaxOpenUploads is the most uploads one sender may have open at
	// once; zero is no cap.
	MaxOpenUploads int64
	// MaxKnocksWaiting is the most knockers one mailbox holds a knock
	// from, whatever the owner has read; zero is no cap. A knocker
	// already waiting is replaced rather than counted, so this bounds
	// knockers and not knocks. It is judged inside Put's transaction,
	// after the replacement and beside the
	// room, so two knocks at once cannot each be told there is room for
	// the last.
	MaxKnocksWaiting int64
}

// connectionPragmas apply to the connection, not the file, so they run on
// every open.
//
// secure_delete is here because two rows name a sender — an upload's
// from_fp and a knock's knocker — and both are promised to live no longer
// than the row. Without it SQLite leaves a deleted row's bytes and its
// index entries in free pages until something reuses them, so a backup or
// a stolen disk taken after a knock was acknowledged still yields who
// knocked at whom, which is the graph the relay is built not to keep. It
// costs a write of zeroes over what was freed, on a database that holds
// bookkeeping and no message body.
const connectionPragmas = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA secure_delete = ON;
`

// The tables, one constant each. Together they are the whole schema, and
// the one text a database is created from; a change to any of them is a
// new schemaVersion, at which every database from before is refused.
const (
	mailboxesTable = `CREATE TABLE IF NOT EXISTS mailboxes (
	fp              TEXT PRIMARY KEY,
	bundle          BLOB NOT NULL,
	name            TEXT NOT NULL,
	created         TEXT NOT NULL,
	queued_messages INTEGER NOT NULL DEFAULT 0,
	queued_bytes    INTEGER NOT NULL DEFAULT 0
);`
	// allowlists is one row per mailbox whose owner has pushed an allow
	// list: the signed document and its signature, verified against the
	// mailbox's bundle every time the list is enforced and served back to
	// the owner verbatim, its issue time as the document says it, a copy
	// for the administrator's eye that decides nothing (a push is held to
	// the time inside the verified document, never this column), and
	// how many senders it names, which is for the administrator's listing
	// and decides nothing. A row whose sig is empty — a signed row whose
	// signature was blanked, since nothing writes one without — is
	// broken, and refuses every sender until the owner pushes again. A
	// mailbox with no row takes mail from any registered sender.
	allowlistsTable = `CREATE TABLE IF NOT EXISTS allowlists (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	count  INTEGER NOT NULL
);`
	// cards is one row per mailbox whose owner has pushed a card: the
	// signed document and its signature, verified against the mailbox's
	// bundle every time a knock is let past the allow list and served
	// verbatim to the owner and, when listed, to every registered
	// identity; its issue time as the document says it, a copy that
	// decides nothing, as the allow list's is; and the two
	// words the relay parsed from it at the push, listed for the listing's
	// query and knocks for the administrator's line, neither of which
	// decides anything: what decides is the document, verified. The name
	// is not stored a second time, since nothing on the relay needs it. A
	// row whose sig is empty is broken, as an allow list's is. A mailbox
	// with no row is not listed and takes no knocks.
	cardsTable = `CREATE TABLE IF NOT EXISTS cards (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	listed INTEGER NOT NULL,
	knocks INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cards_listed ON cards(listed, fp);`
	// The body is not here: it is a file, and size is what the counters and
	// the quotas are computed from.
	//
	// channel is the name the sender posted to, in the clear on the outer
	// envelope; the relay routes by it and reports it in every listing. It
	// is one owner-published label per message, and the security model
	// says so.
	//
	// kind is envelope, stream or knock, the word the relay lists the row
	// under.
	//
	// knocker is the one other exception to the rule that no stored row
	// names a sender, beside the uploads table: the verified fingerprint
	// of whoever knocked, on a knock row and empty on every other, kept
	// only for as long as the row is — until the owner's fetch
	// acknowledges it, until that knocker knocks again and replaces it,
	// or until the mailbox goes. It is what lets a second knock from one
	// key replace the first, so the waiting cap counts knockers rather
	// than knocks and no one identity can fill a mailbox's share of it.
	// The index serves both: the replacement's lookup by all three
	// columns, and the cap's count by its (to_fp, kind) prefix.
	messagesTable = `CREATE TABLE IF NOT EXISTS messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	size     INTEGER NOT NULL,
	kind     TEXT NOT NULL DEFAULT 'envelope',
	channel  TEXT NOT NULL DEFAULT 'default',
	knocker  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS messages_to ON messages(to_fp, id);
CREATE INDEX IF NOT EXISTS messages_knocker ON messages(to_fp, kind, knocker);`

	// uploads is the one place the relay records who sent a message, because
	// it must know who may append to a half-finished one. The row is deleted
	// when the upload completes or is abandoned; the message it becomes
	// carries no sender at all. The index on from_fp is what makes the
	// sender's count at an open a range and not a scan, as messages_to
	// does for a mailbox's page.
	uploadsTable = `CREATE TABLE IF NOT EXISTS uploads (
	id       TEXT PRIMARY KEY,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	from_fp  TEXT NOT NULL,
	size     INTEGER NOT NULL,
	received INTEGER NOT NULL DEFAULT 0,
	created  TEXT NOT NULL,
	expires  INTEGER NOT NULL,
	channel  TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS uploads_expires ON uploads(expires);
CREATE INDEX IF NOT EXISTS uploads_from_fp ON uploads(from_fp);`

	noncesTable = `CREATE TABLE IF NOT EXISTS nonces (
	nonce   TEXT PRIMARY KEY,
	expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_expires ON nonces(expires);`
	statsTable = `CREATE TABLE IF NOT EXISTS relay_stats (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	queued_messages INTEGER NOT NULL,
	queued_bytes    INTEGER NOT NULL
);
INSERT OR IGNORE INTO relay_stats (id, queued_messages, queued_bytes) VALUES (1, 0, 0);`

	// tokensTable holds registered enrolment tokens. There is deliberately no
	// column recording which mailbox redeemed which token: that link belongs
	// in the operator's audit log, not in a database the relay keeps forever.
	tokensTable = `CREATE TABLE IF NOT EXISTS tokens (
	id            TEXT PRIMARY KEY,
	issuer        TEXT NOT NULL,
	use           TEXT NOT NULL,
	relay         TEXT NOT NULL,
	subject       TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL,
	not_before    INTEGER NOT NULL,
	not_after     INTEGER NOT NULL,
	uses          INTEGER NOT NULL,
	uses_left     INTEGER NOT NULL,
	revoked       INTEGER NOT NULL DEFAULT 0,
	created       TEXT NOT NULL,
	last_redeemed TEXT
);
CREATE INDEX IF NOT EXISTS tokens_not_after ON tokens(not_after);`
	// certs is one row per client certificate the relay has issued. It is
	// what makes revocation a row update rather than a distribution problem:
	// every request already resolves the caller's mailbox, so resolving the
	// certificate's serial beside it costs one indexed read.
	//
	// There is no column for the token that paid for it. Which token created
	// what is enrolment lineage, which PLAN-ADMIN keeps out of the database
	// and in the audit log the operator controls.
	certsTable = `CREATE TABLE IF NOT EXISTS certs (
	serial     TEXT PRIMARY KEY,
	fp         TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	spki       TEXT NOT NULL,
	label      TEXT NOT NULL,
	not_before INTEGER NOT NULL,
	not_after  INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0,
	revoked_by TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL DEFAULT '',
	created    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS certs_fp ON certs(fp, not_after);`

	blocksTable = `CREATE TABLE IF NOT EXISTS blocks (
	fp      TEXT PRIMARY KEY,
	reason  TEXT NOT NULL,
	created TEXT NOT NULL,
	by_fp   TEXT NOT NULL
);`

	// directories is one row per mailbox whose owner has pushed a channel
	// directory: the signed document and its signature, served back
	// verbatim, and its issue time as the document says it, a copy the
	// watch compares and a push is never held to (a push is held to the
	// time inside the verified document, as the allow list's and the
	// card's are). A mailbox with no row has the one channel, default. It
	// is a table of its own rather than three columns on mailboxes, as
	// allowlists is.
	directoriesTable = `CREATE TABLE IF NOT EXISTS directories (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL
);`
	// channels is the directory unpacked at the push, one row per
	// channel, kept for the administrator's count and for the owner's own
	// listing, which position keeps the owner's order for. Nothing routes
	// by these rows: a post's channel and its period come out of the
	// signed document, verified at the post itself, and a document that
	// does not verify closes the mailbox rather than falling back to
	// these. So a row inserted or edited by somebody with the database
	// open changes what an operator is shown and not where a message
	// goes. Do not make them the router again — that is the fault this
	// table's shape invites and the verification exists to close.
	channelsTable = `CREATE TABLE IF NOT EXISTS channels (
	fp          TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	description TEXT NOT NULL,
	not_before  TEXT,
	not_after   TEXT,
	position    INTEGER NOT NULL,
	PRIMARY KEY (fp, name)
);`
)

// schema creates a database from nothing.
const schema = mailboxesTable + "\n" + messagesTable + "\n" +
	noncesTable + "\n" + statsTable + "\n" + tokensTable + "\n" + blocksTable + "\n" +
	uploadsTable + "\n" + certsTable + "\n" + directoriesTable + "\n" + channelsTable + "\n" +
	allowlistsTable + "\n" + cardsTable

// OpenStore opens or creates the relay database at dbPath, with message bodies
// under messagesDir.
//
// It creates a new database at schemaVersion, refuses one at any other
// version, reconciles the directory against the table, and reconciles the
// queued-message counters against the rows. A crash in the middle of
// anything leaves work for the next start rather than a wrong answer.
func OpenStore(dbPath, messagesDir string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// SQLite writes serialise anyway; one connection keeps WAL and busy_timeout
	// behaviour predictable under the modest load a relay sees.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(connectionPragmas); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: pragmas: %w", err)
	}
	s := &Store{db: db, dir: messagesDir}
	if err := s.prepareDirs(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.prepareSchema(dbPath); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.refuseLostDatabase(dbPath); err != nil {
		db.Close()
		return nil, err
	}
	if s.swept, err = s.sweep(); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: sweeping the message directory: %w", err)
	}
	if s.reconciled, err = s.reconcile(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// refuseLostDatabase stops a database with no mailboxes from starting a relay
// beside mail it knows nothing about. The sweep that follows takes every file
// no row claims as an orphan and removes it, so a relay.db that was lost, or
// restored from before anybody registered, would become a fresh relay in
// silence and the queued mail would go with it. Only a message file counts:
// Deregister removes the rows and then the directory, and a crash between the
// two leaves an empty directory, which is nothing to refuse over; tmp/ and
// uploads/ hold no mail.
func (s *Store) refuseLostDatabase(dbPath string) error {
	var mailboxes int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&mailboxes); err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	if mailboxes > 0 {
		return nil
	}
	held, err := s.mailboxesHoldingFiles()
	if err != nil {
		return fmt.Errorf("relay: reading the message directory: %w", err)
	}
	if held == 0 {
		return nil
	}
	boxes := "mailboxes"
	if held == 1 {
		boxes = "mailbox"
	}
	return fmt.Errorf("relay: %s is new but %s holds mail for %d %s: the database was lost. "+
		"Restore %s from a backup, or move the message directory aside to start the relay empty",
		dbPath, s.dir, held, boxes, dbPath)
}

// prepareSchema creates the schema in an empty file, or refuses a file that
// is not at schemaVersion.
//
// A version above this build's was written by a newer release, and the
// sentence says so. Any other version — one below it, or zero with tables
// in it, which is a database from before the version was recorded — is a
// database from before this version, and there is no reading it: the
// sentence names the file and the message directory and says to delete
// both, since a message directory left beside a new database is the lost
// database refuseLostDatabase refuses to start over.
func (s *Store) prepareSchema(dbPath string) error {
	db := s.db
	version, err := readVersion(db)
	if err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("relay: database is schema version %d, but this relay understands %d; "+
			"it was written by a newer release", version, schemaVersion)
	}
	if version == schemaVersion {
		return nil
	}
	if version == 0 {
		populated, err := hasTables(db)
		if err != nil {
			return err
		}
		if !populated {
			// A new file: create everything at once and claim the version.
			if _, err := db.Exec(schema); err != nil {
				return fmt.Errorf("relay: schema: %w", err)
			}
			return setVersion(db, schemaVersion)
		}
	}
	return fmt.Errorf("relay: %s is schema version %d, but this relay writes version %d and migrates nothing: "+
		"delete it and the message directory beside it, %s, and the relay recreates both at the next start; "+
		"every machine enrolled on it enrols again", dbPath, version, schemaVersion, s.dir)
}

func readVersion(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("relay: reading schema version: %w", err)
	}
	return version, nil
}

func setVersion(db *sql.DB, v int) error {
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		return fmt.Errorf("relay: recording schema version: %w", err)
	}
	return nil
}

// hasTables reports whether the file holds any table at all, which is what
// tells a database from before the version was recorded from an empty file.
func hasTables(db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("relay: inspecting database: %w", err)
	}
	return n > 0, nil
}

// reconcile recomputes the queued counters from the messages table, which is
// the only authority. It reports how many mailboxes disagreed.
func (s *Store) reconcile() (int, error) {
	var wrong int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM mailboxes m WHERE
			m.queued_messages <> (SELECT COUNT(*) FROM messages WHERE to_fp = m.fp)
			OR m.queued_bytes <> (SELECT COALESCE(SUM(size), 0) FROM messages WHERE to_fp = m.fp)`).
		Scan(&wrong)
	if err != nil {
		return 0, fmt.Errorf("relay: checking counters: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		UPDATE mailboxes SET
			queued_messages = (SELECT COUNT(*) FROM messages WHERE to_fp = mailboxes.fp),
			queued_bytes = (SELECT COALESCE(SUM(size), 0) FROM messages WHERE to_fp = mailboxes.fp)`); err != nil {
		return 0, fmt.Errorf("relay: reconciling mailbox counters: %w", err)
	}
	if _, err := tx.Exec(`
		UPDATE relay_stats SET
			queued_messages = (SELECT COUNT(*) FROM messages),
			queued_bytes = (SELECT COALESCE(SUM(size), 0) FROM messages)
		WHERE id = 1`); err != nil {
		return 0, fmt.Errorf("relay: reconciling relay counters: %w", err)
	}
	return wrong, tx.Commit()
}

// Reconciled reports how many mailboxes had counters that disagreed with the
// messages table when the database was opened. Anything but zero is worth a
// line in the log: it means the last shutdown was not clean, or somebody has
// been editing the database by hand.
func (s *Store) Reconciled() int { return s.reconciled }

// Swept reports what the startup sweep of the message directory found. Any
// non-zero field is worth a line in the log: it means the last shutdown was
// not clean, or somebody has been editing the directory by hand.
func (s *Store) Swept() SweepResult { return s.swept }

func (s *Store) Close() error { return s.db.Close() }

// Mailbox is a registered recipient.
type Mailbox struct {
	FP      string
	Bundle  []byte
	Name    string
	Created time.Time
	// Blocked reports that an administrator has barred this identity. It is
	// carried here so that authenticating a caller costs one query rather
	// than two.
	Blocked bool
}

// RegisterOptions is the policy applied to one registration attempt.
type RegisterOptions struct {
	// MaxMailboxes caps how many mailboxes the relay will hold. Zero is
	// unlimited, and it never applies to a fingerprint already registered.
	MaxMailboxes int64
	// TokenID, when set, is an enrolment token to redeem. It is checked and
	// decremented in the same transaction as the insert.
	TokenID string
	// TokenUse is what TokenID must authorise: register for a new mailbox,
	// cert for another machine of one that exists. Checked inside the
	// transaction, beside uses_left, so a token cannot be spent on the wrong
	// thing however the two requests interleave.
	TokenUse string
	// Cert, when set, is a client certificate to record. It is inserted in
	// the same transaction as the mailbox, so a machine never ends up with a
	// certificate the relay has no row for, or a row for one the machine
	// never received.
	Cert *CertRow
	// Now stamps the token's last redemption.
	Now time.Time
}

// Register creates or updates a mailbox. Re-registering with different key
// material for the same fingerprint is impossible: the fingerprint commits to
// the bundle, so only the name can ever change.
//
// The order inside the transaction is the order of the plan: the mailbox cap
// first, then the token. A registration refused by the cap costs the holder
// nothing, because their token has not been touched yet.
func (s *Store) Register(fp string, bundle []byte, name string, opt RegisterOptions) error {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existing int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE fp = ?`, fp).Scan(&existing); err != nil {
		return err
	}
	if existing == 0 {
		if opt.MaxMailboxes > 0 {
			var total int64
			if err := tx.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&total); err != nil {
				return err
			}
			if total >= opt.MaxMailboxes {
				return ErrTooManyMailboxes
			}
		}
	}
	// A token is spent whenever the caller supplied one, whether or not the
	// mailbox is new: an existing mailbox asking for another machine's
	// certificate pays a cert token for it.
	if opt.TokenID != "" {
		if err := redeem(tx, opt.TokenID, opt.TokenUse, opt.Now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, ?, ?, ?)
		 ON CONFLICT(fp) DO UPDATE SET name = excluded.name`,
		fp, bundle, name, opt.Now.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if opt.Cert != nil {
		if err := insertCert(tx, *opt.Cert); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// redeem spends one use of a token inside the caller's transaction.
//
// The use is checked here as well as by the handler, in the transaction that
// spends it, so that what a token authorises and what it is spent on cannot
// come apart.
func redeem(tx *sql.Tx, id, use string, now time.Time) error {
	var usesLeft int
	var revoked int
	var stored string
	err := tx.QueryRow(`SELECT uses_left, revoked, use FROM tokens WHERE id = ?`, id).
		Scan(&usesLeft, &revoked, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTokenUnknown
	}
	if err != nil {
		return err
	}
	if revoked != 0 {
		return ErrTokenRevoked
	}
	if use != "" && stored != use {
		return ErrTokenWrongUse
	}
	if usesLeft <= 0 {
		return ErrTokenSpent
	}
	_, err = tx.Exec(`UPDATE tokens SET uses_left = uses_left - 1, last_redeemed = ? WHERE id = ?`,
		now.UTC().Format(time.RFC3339), id)
	return err
}

// Mailbox looks up one mailbox.
func (s *Store) Mailbox(fp string) (*Mailbox, error) {
	var m Mailbox
	var created string
	var blocked int
	err := s.db.QueryRow(`
		SELECT m.fp, m.bundle, m.name, m.created,
			EXISTS (SELECT 1 FROM blocks b WHERE b.fp = m.fp)
		FROM mailboxes m WHERE m.fp = ?`, fp).
		Scan(&m.FP, &m.Bundle, &m.Name, &created, &blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoMailbox
	}
	if err != nil {
		return nil, err
	}
	m.Created, _ = time.Parse(time.RFC3339, created)
	m.Blocked = blocked != 0
	return &m, nil
}

// MailboxByShort is Mailbox for the 16-character short id listings print.
// A short id that more than one mailbox begins with names none of them.
func (s *Store) MailboxByShort(short string) (*Mailbox, error) {
	if !identity.ValidShortID(short) {
		return nil, ErrNoMailbox
	}
	rows, err := s.db.Query(`SELECT fp FROM mailboxes WHERE fp LIKE ? ORDER BY fp LIMIT 2`, short+"%")
	if err != nil {
		return nil, err
	}
	var fps []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return nil, err
		}
		fps = append(fps, fp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(fps) {
	case 0:
		return nil, ErrNoMailbox
	case 1:
		return s.Mailbox(fps[0])
	default:
		return nil, ErrAmbiguousShort
	}
}

// MailboxState reports whether a mailbox exists and whether its owner is
// blocked, in one query. It is what the post and register paths need, and
// neither of them wants the bundle.
func (s *Store) MailboxState(fp string) (exists, blocked bool, err error) {
	var e, b int
	err = s.db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM mailboxes WHERE fp = ?),
		       EXISTS (SELECT 1 FROM blocks WHERE fp = ?)`, fp, fp).Scan(&e, &b)
	return e != 0, b != 0, err
}

// Exists reports whether a mailbox is registered.
func (s *Store) Exists(fp string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM mailboxes WHERE fp = ?`, fp).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Put stores a sealed envelope under a channel, as the kind it will be
// listed under, envelope or knock, and returns its relay id. The channel
// is the caller's to have checked against the directory; the row records
// whatever name it is given. The kind is the route's word: the post route
// stores an envelope and the knock route a knock. knocker is the verified
// fingerprint of whoever knocked, required on a knock and empty on every
// other kind; a caller that gets that wrong is a programming fault and is
// told so rather than storing a row nothing can account for.
//
// A knock replaces that knocker's earlier knock to the same mailbox, and
// is then held to the mailbox's knock cap, both inside the one
// transaction: so one identity occupies one of the mailbox's places
// however often it knocks, the cap counts knockers rather than knocks,
// and two knocks at once cannot each be told there is room for the last.
// The replacement comes before roomFor as well as before the count,
// since a knock that nets to zero must not be refused by a mailbox at
// its message quota.
//
// The body is written to a temporary file and fsynced, then the row is
// inserted and the file renamed into place, all before the transaction
// commits. That ordering is what makes the invariant hold: after a commit
// there is always a file, and every crash leaves at most an unreferenced file
// for the sweep, never a row promising a message that is not there.
func (s *Store) Put(toFP, channel, kind, knocker string, raw []byte, q Quotas) (int64, error) {
	if (kind == relayapi.KindKnock) != (knocker != "") {
		return 0, fmt.Errorf("relay: a %s row carries knocker %q: a knock names its knocker and nothing else does",
			kind, knocker)
	}
	size := int64(len(raw))
	tmp, err := s.writeTemp(raw)
	if err != nil {
		return 0, err
	}
	// A no-op once the rename has happened.
	defer os.Remove(tmp)

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// The knocker's earlier knock goes first, so the room and the cap are
	// judged on what is left.
	replaced, err := replaceKnock(tx, toFP, kind, knocker)
	if err != nil {
		return 0, err
	}
	// Room is one question with one answer, roomFor's, and open uploads'
	// reservations are in it: an envelope is charged as a stream is.
	if err := roomFor(tx, toFP, size, q); err != nil {
		return 0, err
	}
	if kind == relayapi.KindKnock {
		if err := roomForKnock(tx, toFP, q); err != nil {
			return 0, err
		}
	}

	res, err := tx.Exec(`INSERT INTO messages (to_fp, received, size, kind, channel, knocker) VALUES (?, ?, ?, ?, ?, ?)`,
		toFP, time.Now().UTC().Format(time.RFC3339), size, kind, channel, knocker)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := adjustCounters(tx, toFP, 1, size); err != nil {
		return 0, err
	}
	// Before the commit, so a committed row always has its file.
	if err := s.place(tmp, toFP, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		// The file is now unreferenced; the sweep would take it, but there is
		// no reason to leave it.
		s.removeMessage(toFP, id)
		return 0, err
	}
	// The replaced row's body, after the commit, as Delete removes one.
	// This is the one place that is not literally Delete's: Delete
	// reports the unlink's failure to its caller, and here the row is
	// committed and the message taken, so a failure cannot be answered
	// with a 500 for a message the relay holds. removeMessage has
	// already noted it as a storage fault, which is the operator's line,
	// and the startup sweep takes a file no row names.
	if replaced != 0 {
		s.removeMessage(toFP, replaced)
	}
	return id, nil
}

// replaceKnock removes the knocker's earlier knock to this mailbox and
// reports its id, or zero when there was none. It runs inside Put's
// transaction and decrements the counters there, as Delete does; the body
// file is the caller's to remove after the commit.
//
// The lookup is by (to_fp, kind, knocker), which the messages_knocker
// index serves whole. There is at most one such row, since this is the
// only place a knock is stored and every one of them passes here.
func replaceKnock(tx *sql.Tx, toFP, kind, knocker string) (replaced int64, err error) {
	if kind != relayapi.KindKnock {
		return 0, nil
	}
	var id, size int64
	err = tx.QueryRow(`SELECT id, size FROM messages WHERE to_fp = ? AND kind = ? AND knocker = ?`,
		toFP, relayapi.KindKnock, knocker).Scan(&id, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM messages WHERE to_fp = ? AND id = ?`, toFP, id); err != nil {
		return 0, err
	}
	if err := adjustCounters(tx, toFP, -1, -size); err != nil {
		return 0, err
	}
	return id, nil
}

// roomForKnock is the one arithmetic for the knock cap: the knocks the
// mailbox holds, counted, against q.MaxKnocksWaiting, in the transaction
// the row is inserted in and after the knocker's own earlier row has gone
// from it, so the count is of other knockers and the cap counts knockers.
// The count is over one mailbox's rows under the messages_knocker index,
// whose (to_fp, kind) prefix serves it, bounded by mailbox_max_messages,
// which is why a count is right here where the guide's counter rule,
// about sums over the whole table, keeps the mailbox's counters instead:
// a knock is the rare row, and a counter for it would be one more thing
// the sweep must correct.
func roomForKnock(tx *sql.Tx, toFP string, q Quotas) error {
	if q.MaxKnocksWaiting <= 0 {
		return nil
	}
	var waiting int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ? AND kind = ?`,
		toFP, relayapi.KindKnock).Scan(&waiting); err != nil {
		return err
	}
	if waiting >= q.MaxKnocksWaiting {
		return ErrKnocksWaiting
	}
	return nil
}

// Row is one stored message. Envelope is nil for a stream, which the client
// fetches separately. Channel is the name it was posted under, which every
// row carries.
type Row struct {
	ID       int64
	Received time.Time
	Size     int64
	Kind     string
	Channel  string
	Envelope []byte
}

// Listing is one page of a mailbox beside the count of everything queued
// in it. The two are read in one transaction so that they agree: a message
// posted or acknowledged between two separate reads could make a page that
// is empty beside a count that is not, which is exactly what a client takes
// to mean its cursor has skipped mail. The count is of rows, the same table
// the page is read from, and not the mailbox's counter: the counter is kept
// for quotas and is corrected by the sweep, and between a row lost from the
// table and the next start it counts a message the page can never show,
// which the container suite's M05 found telling a client its cursor was
// past mail.
type Listing struct {
	Rows   []Row
	Queued int64
}

// List returns messages with id greater than after, oldest first.
func (s *Store) List(toFP string, after int64, limit int) ([]Row, error) {
	l, err := s.Listing(toFP, after, limit, false)
	return l.Rows, err
}

// Listing returns messages with id greater than after, oldest first, and how
// many the mailbox holds in all. A mailbox that is not there is ErrNoMailbox.
//
// A row whose file has gone is omitted rather than failing the whole list: the
// sweep will remove the row at the next start, and in the meantime the other
// messages in the mailbox are still deliverable. It is taken off the count
// too, since the count is there to tell a client whether the relay holds
// mail it is not being shown, and a row nothing can serve is not that: left
// in, an empty page beside it would read as a cursor past mail when the
// truth is a file gone from this disk (the container suite's M03).
// Listing is the rows after an id, and the count of everything the mailbox
// holds. With stubs, the rows are answered from the database alone: no
// message file is opened and none is missed, so a row whose file has gone
// is listed here and hidden by the ordinary listing, until the relay's next
// start reconciles the two. That is the right answer for a client checking
// which of the messages it kept are still queued, which is what stubs is
// for, and it is why stubs does not stat either.
func (s *Store) Listing(toFP string, after int64, limit int, stubs bool) (Listing, error) {
	return s.ListingWithin(toFP, after, limit, stubs, 0)
}

// ListingWithin is Listing under a byte budget: the page ends before an
// envelope that would take its inline bytes past budget, except the
// first, which is admitted whatever its size so that a page is never
// empty. So a page's inline bytes never exceed the budget unless its
// first envelope alone does, and with the budget max_bytes only an
// envelope posted under a larger earlier max_bytes can; the rows the
// budget left off are the next page's. A page had no bound in bytes
// before: up to MaxListLimit envelopes of up to max_bytes each, which is
// a page a client cannot hold, and a mailbox nobody could list is one
// nobody could acknowledge. Zero is no budget. Stubs carry no body and
// are not counted.
func (s *Store) ListingWithin(toFP string, after int64, limit int, stubs bool, budget int64) (Listing, error) {
	var l Listing
	tx, err := s.db.Begin()
	if err != nil {
		return l, err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRow(`SELECT 1 FROM mailboxes WHERE fp = ?`, toFP).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNoMailbox
	}
	if err != nil {
		return l, err
	}
	// The index on (to_fp, id) makes this a range count, not a scan.
	if err := tx.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ?`, toFP).Scan(&l.Queued); err != nil {
		return l, err
	}
	rows, err := tx.Query(
		`SELECT id, received, size, kind, channel FROM messages WHERE to_fp = ? AND id > ? ORDER BY id LIMIT ?`,
		toFP, after, limit)
	if err != nil {
		return l, err
	}
	type stub struct {
		id       int64
		received time.Time
		size     int64
		kind     string
		channel  string
	}
	var listed []stub
	for rows.Next() {
		var st stub
		var received string
		if err := rows.Scan(&st.id, &received, &st.size, &st.kind, &st.channel); err != nil {
			rows.Close()
			return l, err
		}
		st.received, _ = time.Parse(time.RFC3339, received)
		listed = append(listed, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return l, err
	}
	if err := tx.Commit(); err != nil {
		return l, err
	}

	out := make([]Row, 0, len(listed))
	var inline int64
	for _, st := range listed {
		row := Row{ID: st.id, Received: st.received, Size: st.size, Kind: st.kind, Channel: st.channel}
		// A stream is fetched from its own endpoint: it may be larger than
		// memory, which is the whole reason it is a stream.
		if !stubs && st.kind != relayapi.KindStream {
			body, err := s.readMessage(toFP, st.id)
			if os.IsNotExist(err) {
				l.Queued--
				continue
			}
			if err != nil {
				return l, err
			}
			// The budget: the page ends before an envelope that would
			// take it past, unless the page is still empty.
			if budget > 0 && len(out) > 0 && inline+int64(len(body)) > budget {
				break
			}
			inline += int64(len(body))
			row.Envelope = body
		}
		out = append(out, row)
	}
	l.Rows = out
	return l, nil
}

// Delete acknowledges and removes one message. It reports whether a row went.
//
// Acknowledgement is the only thing that frees quota, so the counters come
// down in the same transaction as the row. The file is unlinked after the
// commit: the message is gone from the relay's point of view the moment the
// row is, and a failed unlink leaves an orphan for the sweep rather than a
// message that cannot be acknowledged.
func (s *Store) Delete(toFP string, id int64) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var size int64
	err = tx.QueryRow(`SELECT size FROM messages WHERE to_fp = ? AND id = ?`, toFP, id).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM messages WHERE to_fp = ? AND id = ?`, toFP, id); err != nil {
		return false, err
	}
	if err := adjustCounters(tx, toFP, -1, -size); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, s.removeMessage(toFP, id)
}

// adjustCounters moves the per-mailbox and relay-wide totals by the same
// amount, inside the caller's transaction.
func adjustCounters(tx *sql.Tx, fp string, messages, bytes int64) error {
	if _, err := tx.Exec(
		`UPDATE mailboxes SET queued_messages = queued_messages + ?, queued_bytes = queued_bytes + ? WHERE fp = ?`,
		messages, bytes, fp); err != nil {
		return err
	}
	_, err := tx.Exec(
		`UPDATE relay_stats SET queued_messages = queued_messages + ?, queued_bytes = queued_bytes + ? WHERE id = 1`,
		messages, bytes)
	return err
}

// Usage is what one mailbox currently occupies.
type Usage struct {
	Messages int64
	Bytes    int64
}

// MailboxUsage reports a mailbox's queued totals in O(1).
func (s *Store) MailboxUsage(fp string) (Usage, error) {
	var u Usage
	err := s.db.QueryRow(`SELECT queued_messages, queued_bytes FROM mailboxes WHERE fp = ?`, fp).
		Scan(&u.Messages, &u.Bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNoMailbox
	}
	return u, err
}

// RelayUsage reports the relay-wide queued totals in O(1).
func (s *Store) RelayUsage() (Usage, error) {
	var u Usage
	err := s.db.QueryRow(`SELECT queued_messages, queued_bytes FROM relay_stats WHERE id = 1`).
		Scan(&u.Messages, &u.Bytes)
	return u, err
}

// UseNonce records a nonce, returning ErrReplay if it has been seen before.
//
// The primary key is the replay check. A failed insert is only a replay if the
// row is actually there afterwards: otherwise it is a storage fault, and
// reporting that as a replay would hide a broken relay behind a 401.
func (s *Store) UseNonce(nonce string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO nonces (nonce, expires) VALUES (?, ?)`, nonce, expires.Unix())
	if err == nil {
		return nil
	}
	var one int
	if qErr := s.db.QueryRow(`SELECT 1 FROM nonces WHERE nonce = ?`, nonce).Scan(&one); qErr == nil {
		return ErrReplay
	}
	return fmt.Errorf("relay: recording nonce: %w", err)
}

// PurgeNonces drops nonces that can no longer be replayed inside the clock skew
// window.
func (s *Store) PurgeNonces(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM nonces WHERE expires < ?`, now.Unix())
	return err
}
