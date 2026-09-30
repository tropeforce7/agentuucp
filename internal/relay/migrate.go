package relay

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// firstKeptVersion is the oldest schema a relay carries forward. It is 11
// because that is what the production relay
// wrote, v0.0.0-20260923032722-a5fdd9dd92fd, the first relay that was
// running when a new schema arrived; a database from before it is refused
// with the delete sentence, as every database from before was until then.
// Raising it is this number and the removal of the steps below it, with
// their constants in schemahistory, once no relay runs that version.
const firstKeptVersion = 11

// errNoStep is a version with no step to it, which the tree cannot hold by
// construction and which the loop refuses rather than leave a database
// half way.
var errNoStep = errors.New("relay: no step to this schema version")

// Each step is what its version added, written out as it was written then
// and frozen. A step is never the table constant it corresponds to: the
// constant is today's table, and a step to 12 that ran carriedTable would
// create carried with the delivered column 13 adds, and the step to 13
// would then fail on a duplicate column. What holds the steps to the
// constants is TestADatabaseAtEachKeptVersionIsCarriedForward, which
// compares every table and index of a carried database with a fresh one.
// SQLite's ADD COLUMN appends, which is where each added column stands in
// the constant too.

// stepTo12 is what 23ef264 added: the via column on messages, the
// outbound queue with the three indexes it had then, the carried table
// without its delivered column, and the queue's two counters.
const stepTo12 = `
ALTER TABLE messages ADD COLUMN via TEXT NOT NULL DEFAULT '';
CREATE TABLE outbound (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	poster_fp TEXT NOT NULL,
	neighbour TEXT NOT NULL,
	path      TEXT NOT NULL DEFAULT '',
	via       TEXT NOT NULL DEFAULT '',
	to_fp     TEXT NOT NULL DEFAULT '',
	hash      TEXT NOT NULL,
	size      INTEGER NOT NULL,
	kind      TEXT NOT NULL DEFAULT 'envelope',
	received  INTEGER NOT NULL,
	state     TEXT NOT NULL DEFAULT 'waiting',
	tries     INTEGER NOT NULL DEFAULT 0,
	last_try  INTEGER NOT NULL DEFAULT 0,
	next_try  INTEGER NOT NULL DEFAULT 0,
	gives_up  INTEGER NOT NULL,
	their_id  INTEGER NOT NULL DEFAULT 0,
	code      TEXT NOT NULL DEFAULT '',
	said      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX outbound_work ON outbound(neighbour, state, next_try);
CREATE INDEX outbound_poster ON outbound(poster_fp, id);
CREATE INDEX outbound_handed ON outbound(neighbour, their_id);
CREATE TABLE carried (
	hash    TEXT PRIMARY KEY,
	expires INTEGER NOT NULL
);
CREATE INDEX carried_expires ON carried(expires);
ALTER TABLE relay_stats ADD COLUMN outbound_messages INTEGER NOT NULL DEFAULT 0;
ALTER TABLE relay_stats ADD COLUMN outbound_bytes INTEGER NOT NULL DEFAULT 0;
`

// stepTo13 is what 7ec7e11 added, the carried row's delivered id, and the
// two indexes that reached outbound while the schema was still 12:
// outbound_purge at e8ca901 and outbound_share at 766a345. Neither came
// with a new version, so a version 12 file has neither, one, or both, by
// the build that made it, and IF NOT EXISTS on those two is the one
// tolerance in the steps: it is there because 12 was not one shape, and
// nowhere else, since every other version was.
const stepTo13 = `
ALTER TABLE carried ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS outbound_purge ON outbound(state, last_try);
CREATE INDEX IF NOT EXISTS outbound_share ON outbound(poster_fp, state, size);
`

// migrateStep runs the step to version to inside tx. A version with no
// case is errNoStep.
func migrateStep(tx *sql.Tx, to int) error {
	switch to {
	case 12:
		_, err := tx.Exec(stepTo12)
		return err
	case 13:
		_, err := tx.Exec(stepTo13)
		return err
	}
	return errNoStep
}

// CarriedForward says what the open did to a database from a kept version:
// the version found, the version written, and the copy kept beside it. The
// zero value is a database that was already at this build's schema, or new.
type CarriedForward struct {
	From, To int
	Copy     string
}

// CarriedForward reports what OpenStore carried forward, for the line
// auu-relay writes at the start.
func (s *Store) CarriedForward() CarriedForward { return s.carried }

// copyPath is where the copy of a database at version found is kept:
// beside it, so it lands on the same filesystem under the same owner.
func copyPath(dbPath string, found int) string {
	return fmt.Sprintf("%s.before-schema-%d", dbPath, found)
}

// carryForward takes a database at found, a kept version below this
// build's, to schemaVersion. A copy is kept first, and without it nothing
// moves; then one step per version, each in its own transaction with the
// version written inside it, so a database is always at some whole
// version and a failed step leaves it at the one before, with the copy
// beside it. The copy is the operator's: the relay never removes it, and
// never replaces one that is already there.
//
// A database named as a file: URI is refused before anything moves: SQLite
// resolves the URI for the copy while the file calls around it would act on
// the name as written, so the copy would land somewhere the relay did not
// create it, under whatever mode SQLite chose.
func (s *Store) carryForward(dbPath string, found int) error {
	if strings.HasPrefix(dbPath, "file:") {
		return fmt.Errorf("relay: %s is schema version %d and is named as a file: URI, which is not carried forward: "+
			"name the database by its path; nothing was changed", dbPath, found)
	}
	cp := copyPath(dbPath, found)
	if err := s.keepCopy(cp); errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("relay: %s is schema version %d and is carried forward only after a copy is kept at %s, "+
			"and something is already there, which the relay never replaces: move it aside, or remove it once it "+
			"is no longer wanted; nothing was changed", dbPath, found, cp)
	} else if err != nil {
		return fmt.Errorf("relay: %s is schema version %d and is carried forward only after a copy is kept, "+
			"and the copy could not be made at %s: %v; nothing was changed", dbPath, found, cp, err)
	}
	at := found
	for v := found + 1; v <= schemaVersion; v++ {
		if err := s.step(v); err != nil {
			return stepFailed(dbPath, found, v, at, cp, err)
		}
		at = v
	}
	s.carried = CarriedForward{From: found, To: schemaVersion, Copy: cp}
	return nil
}

// stepFailed is the sentence for a step that failed. When no step had
// completed, the database is still at the version the copy was made at, so
// the next start would keep its copy at the same path and refuses; it says
// so, and what to do. When an earlier step had, the database is at a newer
// version, and the next start keeps a copy of its own under that version's
// name, so there is nothing to move and the sentence does not ask for it.
func stepFailed(dbPath string, found, v, at int, cp string, err error) error {
	next := ""
	if at == found {
		next = ", which the next start refuses to write over: move it aside before starting again"
	}
	return fmt.Errorf("relay: carrying %s forward, the step to schema version %d failed: %v; "+
		"the database is still at version %d, and the copy made before the first step is %s%s",
		dbPath, v, err, at, cp, next)
}

// step runs one step and writes its version in the same transaction.
func (s *Store) step(v int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := migrateStep(tx, v); err != nil {
		return err
	}
	if err := setVersionTx(tx, v); err != nil {
		return err
	}
	return tx.Commit()
}

// keepCopy writes a consistent copy of the database to path, mode 0600.
// The file is created first, empty, exclusive and 0600, so that it is the
// owner's from its first moment and nothing that already stands at the
// path, a copy from before or anything else, is ever written over; then
// the WAL is folded in and VACUUM INTO fills it, in one statement with the
// path bound, keeping the mode the file was made with. VACUUM INTO writes
// by a path the file-open ledger's walk cannot see, being SQL: its
// provenance is the OpenFile row's beside it. A copy that fails after the
// file was made removes the file, which this call made, so that nothing
// was changed.
func (s *Store) keepCopy(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		os.Remove(path)
		return err
	}
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// setVersionTx records the schema version inside tx, so it commits or
// rolls back with the DDL beside it.
func setVersionTx(tx *sql.Tx, v int) error {
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		return fmt.Errorf("relay: recording schema version: %w", err)
	}
	return nil
}
