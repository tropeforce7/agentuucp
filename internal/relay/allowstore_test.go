package relay

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The version 6 allow list table, written out as it shipped rather than
// derived from a constant that no longer exists, so that the migration
// tests build the past as it was.
const schemaV6Allowlist = `CREATE TABLE IF NOT EXISTS allowlist (
	fp        TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	sender_fp TEXT NOT NULL,
	PRIMARY KEY (fp, sender_fp)
);`

// signedList signs a list for owner, issued at, naming the senders.
func signedList(t *testing.T, owner *identity.Identity, at time.Time, senders ...string) (*allowlist.Document, []byte, []byte) {
	t.Helper()
	d := &allowlist.Document{Issued: at, Senders: senders}
	doc, sig, err := allowlist.Sign(owner, d)
	if err != nil {
		t.Fatal(err)
	}
	return d, doc, sig
}

// A relay upgrading in place with allow lists in the old table: every
// list comes across as a legacy row whose document decodes and names the
// same senders, sorted, without the owner; a mailbox with no list has no
// row; the old table is gone; and the migrated database is the fresh
// database's shape.
func TestMigrationFromVersionSix(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v6.db")
	msgs := filepath.Join(dir, "messages")
	people := ids(t, "alice", "bob", "carol", "dave")
	alice, bob, carol, dave := people[0], people[1], people[2], people[3]

	db := openRaw(t, dbPath)
	stmts := mailboxesTable + "\n" + schemaV6Allowlist + "\n" + messagesTable + "\n" +
		noncesTable + "\n" + statsTable + "\n" + tokensTable + "\n" + blocksTable + "\n" +
		uploadsTable + "\n" + certsTable + "\n" + directoriesTable + "\n" + channelsTable
	if _, err := db.Exec(stmts); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, id := range people {
		if _, err := db.Exec(`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, ?, ?, ?)`,
			id.Fingerprint(), id.Public().Bundle(), id.Name, now); err != nil {
			t.Fatal(err)
		}
	}
	// alice admits carol and bob, in that order; bob has no list; carol's
	// list names carol herself, which the old table allowed and the
	// document may not hold, beside dave.
	for _, row := range [][2]string{
		{alice.Fingerprint(), carol.Fingerprint()},
		{alice.Fingerprint(), bob.Fingerprint()},
		{carol.Fingerprint(), carol.Fingerprint()},
		{carol.Fingerprint(), dave.Fingerprint()},
	} {
		if _, err := db.Exec(`INSERT INTO allowlist (fp, sender_fp) VALUES (?, ?)`, row[0], row[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`PRAGMA user_version = 6`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	before := time.Now().Add(-time.Second)
	migrated, err := OpenStore(dbPath, msgs)
	if err != nil {
		t.Fatalf("a version 6 database would not open: %v", err)
	}
	defer migrated.Close()
	if migrated.MigratedFrom() != 6 {
		t.Errorf("MigratedFrom is %d, want 6", migrated.MigratedFrom())
	}
	var version int
	if err := migrated.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("version %d after migrating, want %d", version, schemaVersion)
	}
	var old int
	if err := migrated.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'allowlist'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if old != 0 {
		t.Error("the old allowlist table is still there")
	}

	// alice's row: legacy, sorted, both senders.
	doc, sig, state, found, err := migrated.Allowlist(alice.Fingerprint())
	if err != nil || !found || state != relayapi.AllowLegacy || len(sig) != 0 {
		t.Fatalf("alice's list after the migration: found %v, state %q, sig %d bytes, %v", found, state, len(sig), err)
	}
	d, err := allowlist.Parse(doc)
	if err != nil {
		t.Fatalf("alice's converted document does not parse: %v\n%s", err, doc)
	}
	want := []string{bob.Fingerprint(), carol.Fingerprint()}
	if bob.Fingerprint() > carol.Fingerprint() {
		want = []string{carol.Fingerprint(), bob.Fingerprint()}
	}
	if d.Owner != alice.Fingerprint() || strings.Join(d.Senders, ",") != strings.Join(want, ",") || d.Issued.Before(before) {
		t.Errorf("alice's converted document: %+v", d)
	}
	// bob has no row.
	if _, _, state, found, err := migrated.Allowlist(bob.Fingerprint()); err != nil || found || state != relayapi.AllowNone {
		t.Errorf("bob's list after the migration: found %v, state %q, %v", found, state, err)
	}
	// carol's row names dave alone: the owner is dropped, since she may not
	// be listed and is always admitted.
	doc, _, state, _, err = migrated.Allowlist(carol.Fingerprint())
	if err != nil || state != relayapi.AllowLegacy {
		t.Fatalf("carol's list after the migration: state %q, %v", state, err)
	}
	if d, err = allowlist.Parse(doc); err != nil || len(d.Senders) != 1 || d.Senders[0] != dave.Fingerprint() {
		t.Errorf("carol's converted document: %+v, %v", d, err)
	}
	// The counts, for the administrator.
	rec, err := migrated.MailboxRecord(alice.Fingerprint())
	if err != nil || rec.AllowlistSize != 2 || rec.Allow != relayapi.AllowLegacy {
		t.Errorf("alice's record: %+v, %v", rec, err)
	}

	// The legacy lists are enforced as they were.
	for _, c := range []struct {
		to, from *identity.Identity
		want     bool
	}{
		{alice, bob, true}, {alice, carol, true}, {alice, dave, false},
		{bob, dave, true},
		{carol, dave, true}, {carol, alice, false}, {carol, carol, true},
	} {
		got, err := migrated.MayPost(c.to.Fingerprint(), c.from.Fingerprint())
		if err != nil || got != c.want {
			t.Errorf("MayPost(%s, %s) = %v, %v; want %v", c.to.Name, c.from.Name, got, err, c.want)
		}
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
}

// The conversion runs outside its transaction and must be safe to run
// twice: run by hand, then again through the migration, the rows are what
// they would have been once.
func TestMigrationSixIsResumable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v6.db")
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]

	db := openRaw(t, dbPath)
	stmts := mailboxesTable + "\n" + schemaV6Allowlist + "\n" + messagesTable + "\n" +
		noncesTable + "\n" + statsTable + "\n" + tokensTable + "\n" + blocksTable + "\n" +
		uploadsTable + "\n" + certsTable + "\n" + directoriesTable + "\n" + channelsTable
	if _, err := db.Exec(stmts); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, id := range people {
		if _, err := db.Exec(`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, ?, ?, ?)`,
			id.Fingerprint(), id.Public().Bundle(), id.Name, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO allowlist (fp, sender_fp) VALUES (?, ?)`, alice.Fingerprint(), bob.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 6`); err != nil {
		t.Fatal(err)
	}
	// The first run, interrupted before its transaction.
	if err := convertAllowlists(&Store{db: db}); err != nil {
		t.Fatalf("the first conversion: %v", err)
	}
	db.Close()

	migrated, err := OpenStore(dbPath, filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatalf("the second run would not open: %v", err)
	}
	defer migrated.Close()
	var rows int
	if err := migrated.db.QueryRow(`SELECT COUNT(*) FROM allowlists`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("%d allowlists rows after two runs, want 1", rows)
	}
	if ok, err := migrated.MayPost(alice.Fingerprint(), bob.Fingerprint()); err != nil || !ok {
		t.Errorf("bob may not post to alice after the resumed migration: %v, %v", ok, err)
	}
}

// The store's own rules for a push: verified by the caller, ordered by
// issue, the same bytes a no-op, a legacy row replaced whatever its time.
func TestSetAllowlistOrdersByIssueAndReplacesLegacy(t *testing.T) {
	s, alice, bob := directoryStore(t)
	at := time.Date(2026, 9, 17, 10, 4, 0, 0, time.UTC)

	// A legacy row issued in the future, as a relay whose clock is ahead
	// would have written it.
	legacy, _ := json.Marshal(&allowlist.Document{V: 1, Owner: alice.Fingerprint(), Issued: at.Add(time.Hour), Senders: []string{}})
	if _, err := s.db.Exec(`INSERT INTO allowlists (fp, doc, sig, issued, count) VALUES (?, ?, X'', ?, 0)`,
		alice.Fingerprint(), legacy, at.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowLegacy {
		t.Fatalf("state %q, want legacy", state)
	}
	d, doc, sig := signedList(t, alice, at, bob.Fingerprint())
	if stored, err := s.SetAllowlist(alice.Fingerprint(), d, doc, sig); err != nil || !stored {
		t.Fatalf("a signed list over a legacy row issued later: stored %v, %v", stored, err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowSigned {
		t.Fatalf("state %q after the signed push, want signed", state)
	}

	// The same bytes again: nothing written, no error.
	if stored, err := s.SetAllowlist(alice.Fingerprint(), d, doc, sig); err != nil || stored {
		t.Fatalf("the same list again: stored %v, %v", stored, err)
	}
	// Issued earlier: refused, naming what is held.
	older, oldDoc, oldSig := signedList(t, alice, at.Add(-time.Second), bob.Fingerprint())
	_, err := s.SetAllowlist(alice.Fingerprint(), older, oldDoc, oldSig)
	var e *AllowlistOlderError
	if !errors.As(err, &e) || !e.Issued.Equal(at) {
		t.Fatalf("an older list: %v", err)
	}
	// The same instant, different bytes: refused too.
	same, sameDoc, sameSig := signedList(t, alice, at)
	if _, err := s.SetAllowlist(alice.Fingerprint(), same, sameDoc, sameSig); !errors.As(err, &e) {
		t.Fatalf("a different list at the same instant: %v", err)
	}
	// Issued later: replaces.
	newer, newDoc, newSig := signedList(t, alice, at.Add(time.Nanosecond))
	if stored, err := s.SetAllowlist(alice.Fingerprint(), newer, newDoc, newSig); err != nil || !stored {
		t.Fatalf("a newer list: stored %v, %v", stored, err)
	}
	got, _, _, _, _ := s.Allowlist(alice.Fingerprint())
	if string(got) != string(newDoc) {
		t.Fatal("the newer list was not stored")
	}
	// No such mailbox.
	if _, err := s.SetAllowlist(strings.Repeat("0", 64), d, doc, sig); err != ErrNoMailbox {
		t.Fatalf("a push for no mailbox: %v", err)
	}
}
