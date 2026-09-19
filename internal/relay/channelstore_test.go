package relay

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The version 5 messages and uploads tables, written out as they shipped
// rather than derived from the current constants, so that changing either
// without a migration fails here. The other tables did not change in 6 and
// come from the constants, as buildV2 does.
const (
	schemaV5Messages = `CREATE TABLE messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	size     INTEGER NOT NULL,
	kind     TEXT NOT NULL DEFAULT 'envelope'
);
CREATE INDEX messages_to ON messages(to_fp, id);`
	schemaV5Uploads = `CREATE TABLE uploads (
	id       TEXT PRIMARY KEY,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	from_fp  TEXT NOT NULL,
	size     INTEGER NOT NULL,
	received INTEGER NOT NULL DEFAULT 0,
	created  TEXT NOT NULL,
	expires  INTEGER NOT NULL
);
CREATE INDEX uploads_expires ON uploads(expires);`
)

// A relay upgrading in place with mail queued: every row comes across under
// default, the counters do not move, an upload in progress survives, and
// the id sequence is not wound back to the newest row.
func TestMigrationFromVersionFive(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v5.db")
	msgs := filepath.Join(dir, "messages")
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	fp := bob.Fingerprint()

	db := openRaw(t, dbPath)
	stmts := mailboxesTable + "\n" + schemaV6Allowlist + "\n" + schemaV5Messages + "\n" +
		noncesTable + "\n" + statsTable + "\n" + tokensTable + "\n" + blocksTable + "\n" +
		schemaV5Uploads + "\n" + certsTable
	if _, err := db.Exec(stmts); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, ?, 'bob', ?)`,
		fp, bob.Public().Bundle(), now); err != nil {
		t.Fatal(err)
	}
	// An envelope and a stream, ids 3 and 5, with their files; the ids
	// above them were acknowledged, so the sequence stands at 9.
	bodies := map[int64][]byte{3: []byte("an envelope"), 5: []byte("a stream")}
	if err := os.MkdirAll(filepath.Join(msgs, fp[:2], fp), 0o700); err != nil {
		t.Fatal(err)
	}
	var total int64
	for id, body := range bodies {
		kind := "envelope"
		if id == 5 {
			kind = "stream"
		}
		if _, err := db.Exec(`INSERT INTO messages (id, to_fp, received, size, kind) VALUES (?, ?, ?, ?, ?)`,
			id, fp, now, len(body), kind); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(msgs, fp[:2], fp, strconv.FormatInt(id, 10)), body, 0o600); err != nil {
			t.Fatal(err)
		}
		total += int64(len(body))
	}
	if _, err := db.Exec(`UPDATE sqlite_sequence SET seq = 9 WHERE name = 'messages'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE mailboxes SET queued_messages = 2, queued_bytes = ?`, total); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE relay_stats SET queued_messages = 2, queued_bytes = ? WHERE id = 1`, total); err != nil {
		t.Fatal(err)
	}
	// An upload half way through.
	uploadID := strings.Repeat("ab", 16)
	if _, err := db.Exec(`INSERT INTO uploads (id, to_fp, from_fp, size, received, created, expires)
		VALUES (?, ?, ?, 100, 40, ?, ?)`, uploadID, fp, alice.Fingerprint(), now, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(msgs, uploadsName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(msgs, uploadsName, uploadID), make([]byte, 40), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 5`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	migrated, err := OpenStore(dbPath, msgs)
	if err != nil {
		t.Fatalf("a version 5 database would not open: %v", err)
	}
	defer migrated.Close()

	var version int
	if err := migrated.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("version %d after migrating, want %d", version, schemaVersion)
	}
	if migrated.MigratedFrom() != 5 {
		t.Errorf("MigratedFrom is %d, want 5, for the start-up log", migrated.MigratedFrom())
	}
	// Every row is under default, with its kind and size as they were.
	l, err := migrated.Listing(fp, 0, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Rows) != 2 || l.Queued != 2 {
		t.Fatalf("listed %d rows, queued %d; want 2 and 2", len(l.Rows), l.Queued)
	}
	for _, row := range l.Rows {
		if row.Channel != "default" {
			t.Errorf("message %d is under %q after the migration, want default", row.ID, row.Channel)
		}
		if row.Size != int64(len(bodies[row.ID])) {
			t.Errorf("message %d has size %d, want %d", row.ID, row.Size, len(bodies[row.ID]))
		}
	}
	if l.Rows[0].ID != 3 || l.Rows[0].Kind != "envelope" || string(l.Rows[0].Envelope) != "an envelope" ||
		l.Rows[1].ID != 5 || l.Rows[1].Kind != "stream" || l.Rows[1].Envelope != nil {
		t.Errorf("the rows did not come across as they were: %+v", l.Rows)
	}
	// The counters did not move, and the sweep found nothing to do.
	u, err := migrated.MailboxUsage(fp)
	if err != nil || u.Messages != 2 || u.Bytes != total {
		t.Errorf("mailbox usage after the migration: %+v (%v), want 2 and %d", u, err, total)
	}
	assertCounters(t, migrated)
	if migrated.Reconciled() != 0 {
		t.Errorf("the migration left %d counters to reconcile", migrated.Reconciled())
	}
	if !migrated.Swept().Empty() {
		t.Errorf("the migration left work for the sweep: %+v", migrated.Swept())
	}
	// The upload is still in progress, under default.
	up, err := migrated.Upload(uploadID)
	if err != nil {
		t.Fatalf("the upload did not survive: %v", err)
	}
	if up.Channel != "default" || up.Received != 40 || up.Size != 100 || up.From != alice.Fingerprint() {
		t.Errorf("the upload after the migration: %+v", up)
	}
	// The next message takes the id after the old sequence, not after the
	// newest surviving row: a client whose cursor stands at 9 must not
	// find a message at 6 behind it.
	id, err := migrated.Put(fp, "default", []byte("after the migration"), Quotas{})
	if err != nil {
		t.Fatal(err)
	}
	if id != 10 {
		t.Errorf("the first message after the migration is id %d, want 10", id)
	}
	var seqRows, seq int64
	if err := migrated.db.QueryRow(`SELECT COUNT(*), MAX(seq) FROM sqlite_sequence WHERE name LIKE 'messages%'`).
		Scan(&seqRows, &seq); err != nil {
		t.Fatal(err)
	}
	if seqRows != 1 || seq != 10 {
		t.Errorf("sqlite_sequence has %d messages rows, highest %d; want one at 10", seqRows, seq)
	}
	// Both new tables are usable.
	if exists, _, err := migrated.ChannelState(fp, "default"); err != nil || !exists {
		t.Errorf("ChannelState after the migration: %v, %v", exists, err)
	}
	if _, _, found, err := migrated.Directory(fp); err != nil || found {
		t.Errorf("Directory after the migration: found %v, %v", found, err)
	}

	// A migrated database and a fresh one must be the same shape.
	fresh, err := OpenStore(filepath.Join(dir, "fresh.db"), filepath.Join(dir, "fresh-messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.MigratedFrom() != 0 {
		t.Errorf("a fresh database says it was migrated from %d", fresh.MigratedFrom())
	}
	if want, got := tableDDL(t, fresh), tableDDL(t, migrated); want != got {
		t.Fatalf("migrated differs from fresh:\n--- fresh ---\n%s\n--- migrated ---\n%s", want, got)
	}
}

// directoryStore is a store with two registered identities, for the
// directory tests.
func directoryStore(t *testing.T) (*Store, *identity.Identity, *identity.Identity) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	people := ids(t, "alice", "bob")
	for _, id := range people {
		if err := s.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return s, people[0], people[1]
}

// signedDirectory signs a directory for owner, issued at the given time.
func signedDirectory(t *testing.T, owner *identity.Identity, issued time.Time, chs ...channels.Channel) (*channels.Directory, []byte, []byte) {
	t.Helper()
	d := &channels.Directory{Issued: issued, Channels: chs}
	doc, sig, err := channels.Sign(owner, d)
	if err != nil {
		t.Fatal(err)
	}
	return d, doc, sig
}

func TestSetDirectoryRefusesAnOlderIssue(t *testing.T) {
	s, _, bob := directoryStore(t)
	fp := bob.Fingerprint()
	at := time.Date(2026, 9, 13, 1, 19, 29, 500_000_000, time.UTC)

	first, firstDoc, firstSig := signedDirectory(t, bob, at, channels.Channel{Name: "default"}, channels.Channel{Name: "bugs"})
	if stored, err := s.SetDirectory(fp, first, firstDoc, firstSig); err != nil || !stored {
		t.Fatalf("the first push: stored %v, %v", stored, err)
	}
	doc, sig, found, err := s.Directory(fp)
	if err != nil || !found || string(doc) != string(firstDoc) || string(sig) != string(firstSig) {
		t.Fatalf("Directory did not give back what was pushed: found %v, %v", found, err)
	}

	// A second earlier, from another machine of the same identity.
	older, olderDoc, olderSig := signedDirectory(t, bob, at.Add(-time.Second), channels.Channel{Name: "default"})
	_, err = s.SetDirectory(fp, older, olderDoc, olderSig)
	if !errors.Is(err, ErrDirectoryOlder) {
		t.Fatalf("an older directory: %v, want ErrDirectoryOlder", err)
	}
	if !strings.HasSuffix(err.Error(), "(issued 2026-09-13T01:19:29Z)") {
		t.Errorf("the refusal does not say when the stored one was issued: %v", err)
	}
	// Nothing changed: the bytes and the channels are the first push's.
	if doc, _, _, _ := s.Directory(fp); string(doc) != string(firstDoc) {
		t.Fatal("a refused directory replaced the stored one")
	}
	if exists, _, _ := s.ChannelState(fp, "bugs"); !exists {
		t.Fatal("a refused directory removed a channel")
	}

	// The same instant with different bytes is refused too.
	same, sameDoc, sameSig := signedDirectory(t, bob, at, channels.Channel{Name: "default"})
	if _, err := s.SetDirectory(fp, same, sameDoc, sameSig); !errors.Is(err, ErrDirectoryOlder) {
		t.Fatalf("a different directory at the same instant: %v, want ErrDirectoryOlder", err)
	}
	// The same bytes at the same instant are the directory already there:
	// a push that catches a relay up must not be refused for having caught
	// it up already. Nothing is written, and the store says so, since a
	// watcher of the directory is woken only by a change.
	if stored, err := s.SetDirectory(fp, first, firstDoc, firstSig); err != nil || stored {
		t.Fatalf("pushing the stored directory again: stored %v, %v", stored, err)
	}
	// One nanosecond later is later.
	newer, newerDoc, newerSig := signedDirectory(t, bob, at.Add(time.Nanosecond), channels.Channel{Name: "default"})
	if stored, err := s.SetDirectory(fp, newer, newerDoc, newerSig); err != nil || !stored {
		t.Fatalf("a directory issued a nanosecond later: stored %v, %v", stored, err)
	}
	if doc, _, _, _ := s.Directory(fp); string(doc) != string(newerDoc) {
		t.Fatal("the newer directory was not stored")
	}
	if exists, _, _ := s.ChannelState(fp, "bugs"); exists {
		t.Fatal("the newer directory did not replace the channel rows")
	}

	// A mailbox that is not there.
	if _, err := s.SetDirectory(strings.Repeat("0", 64), first, firstDoc, firstSig); !errors.Is(err, ErrNoMailbox) {
		t.Fatalf("a directory for no mailbox: %v, want ErrNoMailbox", err)
	}
}

// Delete deletes: a directory that drops a channel leaves what was queued
// under it, still under that name, and the counts say so.
func TestAReplacedDirectoryLeavesARemovedChannelsMail(t *testing.T) {
	s, alice, bob := directoryStore(t)
	fp := bob.Fingerprint()
	at := time.Date(2026, 9, 13, 1, 19, 29, 0, time.UTC)

	d, doc, sig := signedDirectory(t, bob, at, channels.Channel{Name: "default"}, channels.Channel{Name: "bugs"})
	if _, err := s.SetDirectory(fp, d, doc, sig); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, ch := range []string{"bugs", "default", "bugs"} {
		id, err := s.Put(fp, ch, sealed(t, alice, bob.Public(), "x"), Quotas{})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	counts, err := s.ChannelCounts(fp)
	if err != nil || counts["bugs"] != 2 || counts["default"] != 1 || len(counts) != 2 {
		t.Fatalf("counts before: %v (%v)", counts, err)
	}

	d2, doc2, sig2 := signedDirectory(t, bob, at.Add(time.Minute), channels.Channel{Name: "default"})
	if _, err := s.SetDirectory(fp, d2, doc2, sig2); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := s.ChannelState(fp, "bugs"); exists {
		t.Fatal("bugs is still in the directory")
	}
	l, err := s.Listing(fp, 0, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Rows) != 3 || l.Queued != 3 {
		t.Fatalf("after the delete: %d rows, queued %d; want 3", len(l.Rows), l.Queued)
	}
	for i, row := range l.Rows {
		want := []string{"bugs", "default", "bugs"}[i]
		if row.ID != ids[i] || row.Channel != want {
			t.Errorf("row %d is id %d under %q, want id %d under %q", i, row.ID, row.Channel, ids[i], want)
		}
	}
	counts, err = s.ChannelCounts(fp)
	if err != nil || counts["bugs"] != 2 || counts["default"] != 1 {
		t.Fatalf("counts after: %v (%v)", counts, err)
	}
	assertCounters(t, s)
}

func TestChannelStateWithoutADirectoryIsDefaultAlone(t *testing.T) {
	s, _, bob := directoryStore(t)
	fp := bob.Fingerprint()

	exists, ch, err := s.ChannelState(fp, "default")
	if err != nil || !exists || ch.Name != "default" || ch.NotBefore != nil || ch.NotAfter != nil {
		t.Fatalf("default without a directory: %v %+v %v", exists, ch, err)
	}
	if exists, _, err := s.ChannelState(fp, "bugs"); err != nil || exists {
		t.Fatalf("bugs without a directory: %v %v", exists, err)
	}

	// A directory without default takes default away, and a period comes
	// back as it went in.
	opens := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	closes := time.Date(2026, 12, 31, 23, 59, 59, 0, time.FixedZone("AEST", 10*3600))
	d, doc, sig := signedDirectory(t, bob, time.Now(),
		channels.Channel{Name: "bugs", Description: "one per message", NotBefore: &opens, NotAfter: &closes},
		channels.Channel{Name: "open", Description: "no period"})
	if _, err := s.SetDirectory(fp, d, doc, sig); err != nil {
		t.Fatal(err)
	}
	if exists, _, err := s.ChannelState(fp, "default"); err != nil || exists {
		t.Fatalf("default with a directory that lacks it: %v %v", exists, err)
	}
	exists, ch, err = s.ChannelState(fp, "bugs")
	if err != nil || !exists {
		t.Fatalf("bugs: %v %v", exists, err)
	}
	if ch.Name != "bugs" || ch.Description != "one per message" ||
		ch.NotBefore == nil || !ch.NotBefore.Equal(opens) || ch.NotAfter == nil || !ch.NotAfter.Equal(closes) {
		t.Fatalf("bugs came back as %+v", ch)
	}
	if open, why := ch.OpenAt(opens.Add(-time.Second)); open || why != "opens 2026-10-01T00:00:00Z" {
		t.Fatalf("OpenAt through the store: %v %q", open, why)
	}
	exists, ch, err = s.ChannelState(fp, "open")
	if err != nil || !exists || ch.NotBefore != nil || ch.NotAfter != nil {
		t.Fatalf("open: %v %+v %v", exists, ch, err)
	}
	// Byte for byte.
	if exists, _, _ := s.ChannelState(fp, "Bugs"); exists {
		t.Fatal("a name matched case-insensitively")
	}
}

// The directories and channels rows hang off the mailbox by foreign key, so
// deregistering takes them too. Asserted rather than assumed: it is the
// cascade the whole table design relies on.
func TestADeregisteredMailboxTakesItsDirectoryWithIt(t *testing.T) {
	s, _, bob := directoryStore(t)
	fp := bob.Fingerprint()
	d, doc, sig := signedDirectory(t, bob, time.Now(),
		channels.Channel{Name: "default"}, channels.Channel{Name: "bugs"})
	if _, err := s.SetDirectory(fp, d, doc, sig); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		var n int
		if err := s.db.QueryRow(q, fp).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(`SELECT COUNT(*) FROM directories WHERE fp = ?`) != 1 || count(`SELECT COUNT(*) FROM channels WHERE fp = ?`) != 2 {
		t.Fatal("the rows were not written")
	}
	if gone, err := s.Deregister(fp); err != nil || !gone {
		t.Fatalf("Deregister: %v %v", gone, err)
	}
	if n := count(`SELECT COUNT(*) FROM directories WHERE fp = ?`); n != 0 {
		t.Errorf("%d directories rows survive the mailbox", n)
	}
	if n := count(`SELECT COUNT(*) FROM channels WHERE fp = ?`); n != 0 {
		t.Errorf("%d channels rows survive the mailbox", n)
	}
	if _, _, found, err := s.Directory(fp); err != nil || found {
		t.Errorf("Directory after deregistering: found %v, %v", found, err)
	}
}

// A stream is opened for a channel, carries it through the upload, and the
// message it becomes is filed under it.
func TestAStreamCompletesUnderItsChannel(t *testing.T) {
	s, alice, bob := directoryStore(t)
	fp := bob.Fingerprint()
	id, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.OpenUpload(id, fp, alice.Fingerprint(), "bugs", 5, now, now.Add(time.Hour), Quotas{}, 0); err != nil {
		t.Fatal(err)
	}
	up, err := s.Upload(id)
	if err != nil || up.Channel != "bugs" {
		t.Fatalf("the upload's channel: %+v %v", up, err)
	}
	received, err := s.ReceiveUpload(id, 0, 1<<20, time.Now, time.Minute, func(w *os.File, want int64) (int64, error) {
		n, err := w.Write([]byte("hello"))
		return int64(n), err
	})
	if err != nil || received.Placed == 0 {
		t.Fatalf("the attempt: %+v %v; want the stream placed", received, err)
	}
	msgID := received.Placed
	l, err := s.Listing(fp, 0, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Rows) != 1 || l.Rows[0].ID != msgID || l.Rows[0].Kind != "stream" || l.Rows[0].Channel != "bugs" {
		t.Fatalf("the completed stream: %+v", l.Rows)
	}
	counts, err := s.ChannelCounts(fp)
	if err != nil || counts["bugs"] != 1 {
		t.Fatalf("counts: %v (%v)", counts, err)
	}
}
