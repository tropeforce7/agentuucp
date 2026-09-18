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

// schemaVersion is the shape this build understands. Version zero means a
// database from before any of this, which is refused rather than migrated:
// nothing was ever deployed, so no migration path back that far is owed.
const schemaVersion = 7

// SchemaVersion is schemaVersion for the start-up log.
const SchemaVersion = schemaVersion

// Store is the relay's SQLite-backed state.
type Store struct {
	db  *sql.DB
	dir string // message bodies, one file each; see filestore.go

	// faults says why, once a minute per path, when a file operation under
	// dir fails; see faults.go. Nil until a server gives it a logger.
	faults *faultLog

	reconciled   int
	swept        SweepResult
	migratedFrom int
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
}

// connectionPragmas apply to the connection, not the file, so they run on
// every open.
const connectionPragmas = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
`

// The tables, one constant each, so that creating a database fresh and
// migrating one forward produce byte-identical DDL. SQLite stores the text of
// every CREATE statement, and a test compares the two.
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
	// the owner verbatim, its issue time for refusing an older one, and
	// how many senders it names, which is for the administrator's listing
	// and decides nothing. A row whose sig is empty — a list converted from
	// the table kept before lists were signed, or a signed row whose
	// signature was blanked — is broken, and refuses every sender until
	// the owner pushes again. A mailbox with no row takes mail from any
	// registered sender.
	allowlistsTable = `CREATE TABLE IF NOT EXISTS allowlists (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	count  INTEGER NOT NULL
);`
	// The body is not here: it is a file, and size is what the counters and
	// the quotas are computed from.
	//
	// channel is the name the sender posted to, in the clear on the outer
	// envelope; the relay routes by it and reports it in every listing. It
	// is one owner-published label per message, and the security model
	// says so.
	messagesTable = `CREATE TABLE IF NOT EXISTS messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	size     INTEGER NOT NULL,
	kind     TEXT NOT NULL DEFAULT 'envelope',
	channel  TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS messages_to ON messages(to_fp, id);`

	// uploads is the one place the relay records who sent a message, because
	// it must know who may append to a half-finished one. The row is deleted
	// when the upload completes or is abandoned; the message it becomes
	// carries no sender at all.
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
CREATE INDEX IF NOT EXISTS uploads_expires ON uploads(expires);`
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
	// verbatim, and its issue time for refusing an older one. A mailbox
	// with no row has the one channel, default. It is a table of its own
	// rather than three columns on mailboxes because mailboxes is the
	// parent of four foreign keys, and SQLite rewrites every child's
	// REFERENCES clause when a parent is renamed, which the rename-and-copy
	// migration the DDL identity test requires would have to do.
	directoriesTable = `CREATE TABLE IF NOT EXISTS directories (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL
);`
	// channels is the directory unpacked, one row per channel, so that a
	// post can be checked against a name and a period with one indexed
	// read and the administrator can count them. position keeps the
	// owner's order for the owner's own listing.
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
	allowlistsTable

// migrations[v] upgrades a database from version v to version v+1. Each runs
// in its own transaction and sets user_version on the way out, so an
// interrupted upgrade resumes rather than half-applying.
//
// There is no entry for 0: a version-zero database with tables in it predates
// the schema version and is refused.
var migrations = map[int]string{
	1: tokensTable + "\n" + blocksTable,
	// The bodies have already been written to files by preMigrations[2].
	//
	// The old table is renamed out of the way and the new one created from the
	// same constant the fresh path uses, rather than ALTER TABLE ADD COLUMN.
	// A NOT NULL column added to an existing table must carry a default, so
	// that route cannot produce the same DDL, and the sqlite_master comparison
	// in the tests would rightly call it drift. The index is dropped by name
	// first: a rename leaves it attached to the old table, where IF NOT EXISTS
	// would then skip recreating it and DROP TABLE would take it away.
	2: `ALTER TABLE messages RENAME TO messages_v2;
DROP INDEX IF EXISTS messages_to;
` + messagesTable + `
INSERT INTO messages (id, to_fp, received, size)
	SELECT id, to_fp, received, length(envelope) FROM messages_v2;
DROP TABLE messages_v2;`,
	// Streams. The messages table is rebuilt again rather than altered, for
	// the same reason: a NOT NULL column added to an existing table must
	// carry a default the fresh schema does not have.
	3: `ALTER TABLE messages RENAME TO messages_v3;
DROP INDEX IF EXISTS messages_to;
` + messagesTable + `
INSERT INTO messages (id, to_fp, received, size, kind)
	SELECT id, to_fp, received, size, 'envelope' FROM messages_v3;
DROP TABLE messages_v3;
` + uploadsTable,
	// Client certificates. A new table and nothing else: a relay with
	// client certificates off never writes a row, so an existing database
	// migrates without any of its contents changing.
	4: certsTable,
	// Channels. messages and uploads are rebuilt as before, every existing
	// row becoming 'default', and the two new tables are created from
	// their constants. A rename carries the table's sqlite_sequence row to
	// the new name and the copy sets the new table's to the highest id
	// copied, which is lower than the old sequence whenever the newest
	// messages had been acknowledged; the old value is put back so that no
	// id is ever handed out twice, since a client's cursor is the last id
	// it acknowledged and a repeated id would sit behind it unseen.
	5: `ALTER TABLE messages RENAME TO messages_v5;
DROP INDEX IF EXISTS messages_to;
` + messagesTable + `
INSERT INTO messages (id, to_fp, received, size, kind, channel)
	SELECT id, to_fp, received, size, kind, 'default' FROM messages_v5;
DELETE FROM sqlite_sequence WHERE name = 'messages';
INSERT INTO sqlite_sequence (name, seq) SELECT 'messages', seq FROM sqlite_sequence WHERE name = 'messages_v5';
DROP TABLE messages_v5;
ALTER TABLE uploads RENAME TO uploads_v5;
DROP INDEX IF EXISTS uploads_expires;
` + uploadsTable + `
INSERT INTO uploads (id, to_fp, from_fp, size, received, created, expires, channel)
	SELECT id, to_fp, from_fp, size, received, created, expires, 'default' FROM uploads_v5;
DROP TABLE uploads_v5;
` + directoriesTable + "\n" + channelsTable,
	// Signed allow lists. preMigrations[6] has already created allowlists
	// from its constant and written one row per mailbox that had a list;
	// the constant here is a no-op that keeps the fresh and the migrated
	// DDL the same text, and the old table goes.
	6: allowlistsTable + `
DROP TABLE allowlist;`,
}

// OpenStore opens or creates the relay database at dbPath, with message bodies
// under messagesDir.
//
// It creates a new database at the current schema version, migrates an older
// one forward, refuses one this build does not understand, reconciles the
// directory against the table, and reconciles the queued-message counters
// against the rows. A crash in the middle of anything leaves work for the next
// start rather than a wrong answer.
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
	if err := s.prepareSchema(); err != nil {
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

// prepareSchema brings the file to schemaVersion, or refuses it.
func (s *Store) prepareSchema() error {
	db := s.db
	version, err := readVersion(db)
	if err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("relay: database is schema version %d, but this relay understands %d; "+
			"it was written by a newer release", version, schemaVersion)
	}
	if version == 0 {
		populated, err := hasTables(db)
		if err != nil {
			return err
		}
		if populated {
			return errors.New("relay: database is from a pre-release version; " +
				"delete it and let the relay recreate it")
		}
		// A new file: create everything at once and claim the current version.
		if _, err := db.Exec(schema); err != nil {
			return fmt.Errorf("relay: schema: %w", err)
		}
		return setVersion(db, schemaVersion)
	}
	if version < schemaVersion {
		s.migratedFrom = version
	}
	for v := version; v < schemaVersion; v++ {
		// A migration that has work to do outside its transaction does it
		// here, and must be safe to run twice.
		if before, ok := preMigrations[v]; ok {
			if err := before(s); err != nil {
				return err
			}
		}
		stmts, ok := migrations[v]
		if !ok {
			return fmt.Errorf("relay: no migration from schema version %d", v)
		}
		if err := migrate(db, v, stmts); err != nil {
			return err
		}
	}
	return nil
}

// preMigrations run before the transaction of the same number, outside it, and
// MUST be idempotent: a crash between one and its transaction leaves the old
// version, and the next start runs it again.
var preMigrations = map[int]func(*Store) error{
	2: writeBlobsToFiles,
	6: convertAllowlists,
}

// writeBlobsToFiles is the file half of migrating 2 to 3. It copies every
// stored envelope out of the table and into its file, skipping any that is
// already there with the right size, so it can be interrupted and repeated.
func writeBlobsToFiles(s *Store) error {
	if err := requireSQLite(s.db, 3, 35); err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT to_fp, id, envelope FROM messages ORDER BY id`)
	if err != nil {
		return fmt.Errorf("relay: reading stored envelopes: %w", err)
	}
	defer rows.Close()
	type item struct {
		fp   string
		id   int64
		body []byte
	}
	var pending []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.fp, &it.id, &it.body); err != nil {
			return err
		}
		pending = append(pending, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// The query is drained before any writing: one connection, and a write
	// while a read is open would deadlock.
	for _, it := range pending {
		if info, err := os.Stat(s.messagePath(it.fp, it.id)); err == nil &&
			info.Size() == int64(len(it.body)) {
			continue
		}
		tmp, err := s.writeTemp(it.body)
		if err != nil {
			return err
		}
		if err := s.place(tmp, it.fp, it.id); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// requireSQLite refuses a library too old for what a migration needs, with a
// message naming the version, rather than failing obscurely inside it.
func requireSQLite(db *sql.DB, major, minor int) error {
	var v string
	if err := db.QueryRow(`SELECT sqlite_version()`).Scan(&v); err != nil {
		return fmt.Errorf("relay: reading the SQLite version: %w", err)
	}
	var gotMajor, gotMinor, gotPatch int
	if _, err := fmt.Sscanf(v, "%d.%d.%d", &gotMajor, &gotMinor, &gotPatch); err != nil {
		return fmt.Errorf("relay: SQLite version %q is not a version", v)
	}
	if gotMajor > major || (gotMajor == major && gotMinor >= minor) {
		return nil
	}
	return fmt.Errorf("relay: this migration needs SQLite %d.%d or later for ALTER TABLE DROP COLUMN, "+
		"but the library is %s", major, minor, v)
}

// migrate applies one step inside a transaction, so an interrupted upgrade
// leaves the version where it was and can simply be run again.
func migrate(db *sql.DB, from int, stmts string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(stmts); err != nil {
		return fmt.Errorf("relay: migrating schema version %d to %d: %w", from, from+1, err)
	}
	// PRAGMA does not take a placeholder, and from is an int this file owns.
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", from+1)); err != nil {
		return fmt.Errorf("relay: recording schema version %d: %w", from+1, err)
	}
	return tx.Commit()
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

// hasTables reports whether this is one of our databases rather than an empty
// file, which is what tells a pre-release database from a new one.
func hasTables(db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
		AND name IN ('mailboxes', 'allowlist', 'messages', 'nonces')`).Scan(&n)
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

// MigratedFrom is the schema version the database was at when it was
// opened, when that was older than this build's, and zero when nothing was
// migrated. It is for the start-up log, so an upgrade that changed the
// database says so once.
func (s *Store) MigratedFrom() int { return s.migratedFrom }

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

// Put stores a sealed envelope under a channel and returns its relay id.
// The channel is the caller's to have checked against the directory; the
// row records whatever name it is given.
//
// The body is written to a temporary file and fsynced, then the row is
// inserted and the file renamed into place, all before the transaction
// commits. That ordering is what makes the invariant hold: after a commit
// there is always a file, and every crash leaves at most an unreferenced file
// for the sweep, never a row promising a message that is not there.
func (s *Store) Put(toFP, channel string, raw []byte, q Quotas) (int64, error) {
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

	var messages, bytes int64
	err = tx.QueryRow(`SELECT queued_messages, queued_bytes FROM mailboxes WHERE fp = ?`, toFP).
		Scan(&messages, &bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNoMailbox
	}
	if err != nil {
		return 0, err
	}
	if q.MailboxMaxMessages > 0 && messages >= q.MailboxMaxMessages {
		return 0, ErrMailboxFull
	}
	if q.MailboxMaxBytes > 0 && bytes+size > q.MailboxMaxBytes {
		return 0, ErrMailboxFull
	}
	if q.RelayMaxBytes > 0 {
		var relayBytes int64
		if err := tx.QueryRow(`SELECT queued_bytes FROM relay_stats WHERE id = 1`).Scan(&relayBytes); err != nil {
			return 0, err
		}
		if relayBytes+size > q.RelayMaxBytes {
			return 0, ErrRelayFull
		}
	}

	res, err := tx.Exec(`INSERT INTO messages (to_fp, received, size, channel) VALUES (?, ?, ?, ?)`,
		toFP, time.Now().UTC().Format(time.RFC3339), size, channel)
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
	return id, nil
}

// Row is one stored message. Envelope is nil for a stream, which the client
// fetches separately. Channel is the name it was posted under, which is
// always present from this relay: a listing without it is from a relay
// from before channels.
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
