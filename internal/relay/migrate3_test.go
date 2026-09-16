package relay

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The version 2 schema, written out as it shipped. Deriving it from the
// current constants would defeat the point: changing an existing table without
// a migration must fail here.
const schemaV2Messages = `CREATE TABLE messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	envelope BLOB NOT NULL
);
CREATE INDEX messages_to ON messages(to_fp, id);`

// buildV2 makes a database in the shape version 2 left behind, with bodies in
// the table where they used to live.
func buildV2(t *testing.T, dir string, bodies map[int64][]byte, fp string, bundle []byte) string {
	t.Helper()
	path := filepath.Join(dir, "v2.db")
	db := openRaw(t, path)
	defer db.Close()

	stmts := mailboxesTable + "\n" + allowlistTable + "\n" + schemaV2Messages + "\n" +
		noncesTable + "\n" + statsTable + "\n" + tokensTable + "\n" + blocksTable
	if _, err := db.Exec(stmts); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, ?, 'bob', ?)`,
		fp, bundle, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	var total int64
	for id, body := range bodies {
		if _, err := db.Exec(
			`INSERT INTO messages (id, to_fp, received, envelope) VALUES (?, ?, ?, ?)`,
			id, fp, time.Now().UTC().Format(time.RFC3339), body); err != nil {
			t.Fatal(err)
		}
		total += int64(len(body))
	}
	if _, err := db.Exec(
		`UPDATE mailboxes SET queued_messages = ?, queued_bytes = ?`, len(bodies), total); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`UPDATE relay_stats SET queued_messages = ?, queued_bytes = ? WHERE id = 1`, len(bodies), total); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMigrationFromVersionTwo(t *testing.T) {
	dir := t.TempDir()
	bob := ids(t, "bob")[0]
	fp := bob.Fingerprint()
	bodies := map[int64][]byte{
		1: []byte(`{"v":1,"to":"x","ct":"aaaa"}`),
		2: bytes.Repeat([]byte("b"), 4096),
		7: bytes.Repeat([]byte("c"), 1),
	}
	path := buildV2(t, dir, bodies, fp, bob.Public().Bundle())

	msgs := filepath.Join(dir, "messages")
	migrated, err := OpenStore(path, msgs)
	if err != nil {
		t.Fatalf("a version 2 database would not open: %v", err)
	}
	defer migrated.Close()

	var version int
	if err := migrated.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("version %d after migrating, want %d", version, schemaVersion)
	}

	// Every body is now a file with identical bytes.
	for id, want := range bodies {
		got, err := os.ReadFile(filepath.Join(msgs, fp[:2], fp, strconv.FormatInt(id, 10)))
		if err != nil {
			t.Fatalf("message %d was not written out: %v", id, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d changed in the migration", id)
		}
	}
	// The column is gone and the sizes came across.
	if _, err := migrated.db.Exec(`SELECT envelope FROM messages`); err == nil {
		t.Fatal("the envelope column survived")
	}
	for id, want := range bodies {
		var size int64
		if err := migrated.db.QueryRow(`SELECT size FROM messages WHERE id = ?`, id).Scan(&size); err != nil {
			t.Fatal(err)
		}
		if size != int64(len(want)) {
			t.Fatalf("message %d has size %d, want %d", id, size, len(want))
		}
	}
	assertCounters(t, migrated)
	if !migrated.Swept().Empty() {
		t.Fatalf("the migration left work for the sweep: %+v", migrated.Swept())
	}

	// A migrated database and a fresh one must be the same shape.
	fresh, err := OpenStore(filepath.Join(dir, "fresh.db"), filepath.Join(dir, "fresh-messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if want, got := tableDDL(t, fresh), tableDDL(t, migrated); want != got {
		t.Fatalf("migrated differs from fresh:\n--- fresh ---\n%s\n--- migrated ---\n%s", want, got)
	}

	// And it still works as a relay store.
	if _, err := migrated.Put(fp, "default", []byte("after the migration"), Quotas{}); err != nil {
		t.Fatal(err)
	}
	rows, err := migrated.List(fp, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(bodies)+1 {
		t.Fatalf("listed %d messages, want %d", len(rows), len(bodies)+1)
	}
}

// The file pass runs outside the transaction, so a crash between the two must
// leave a database the next start can finish migrating.
func TestMigrationTwoIsResumable(t *testing.T) {
	dir := t.TempDir()
	bob := ids(t, "bob")[0]
	fp := bob.Fingerprint()
	bodies := map[int64][]byte{1: []byte("one"), 2: []byte("two")}
	path := buildV2(t, dir, bodies, fp, bob.Public().Bundle())
	msgs := filepath.Join(dir, "messages")

	// The file half only, as if the process died before the transaction.
	db := openRaw(t, path)
	crashed := &Store{db: db, dir: msgs}
	if err := crashed.prepareDirs(); err != nil {
		t.Fatal(err)
	}
	if err := writeBlobsToFiles(crashed); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("the file pass changed the version to %d", version)
	}
	db.Close()

	// The second attempt must skip every file and finish.
	s, err := OpenStore(path, msgs)
	if err != nil {
		t.Fatalf("the interrupted migration could not be resumed: %v", err)
	}
	defer s.Close()
	for id, want := range bodies {
		got, err := os.ReadFile(filepath.Join(msgs, fp[:2], fp, strconv.FormatInt(id, 10)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("message %d is wrong after resuming: %v", id, err)
		}
	}
	if !s.Swept().Empty() {
		t.Fatalf("resuming left work for the sweep: %+v", s.Swept())
	}
	assertCounters(t, s)
}

// A library too old for the migration must say so rather than fail obscurely.
func TestMigrationChecksTheSQLiteVersion(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "v.db"))
	defer db.Close()
	if err := requireSQLite(db, 3, 35); err != nil {
		t.Fatalf("the bundled SQLite is too old for the migration: %v", err)
	}
	err := requireSQLite(db, 99, 0)
	if err == nil {
		t.Fatal("an impossible requirement was satisfied")
	}
	for _, want := range []string{"99.0", "DROP COLUMN"} {
		if !contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	var _ *sql.DB = db
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
