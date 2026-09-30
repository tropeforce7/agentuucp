package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// dir returns the store's message directory, which the harness knows because
// it created it.
func (h *harness) messagesDir() string { return h.store.dir }

func TestStoredEnvelopeIsAFileAtTheDerivedPath(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	sent := sealed(t, alice, bob.Public(), "on disk please")
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sent, nil)
	if status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	var resp relayapi.PostResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	fp := bob.Fingerprint()
	path := filepath.Join(h.messagesDir(), fp[:2], fp, strconv.FormatInt(resp.ID, 10))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no file at the derived path: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("stored message is mode %04o, want 0600", perm)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, sent) {
		t.Fatal("the stored file is not the bytes that were posted")
	}

	var size int64
	if err := h.store.db.QueryRow(`SELECT size FROM messages WHERE id = ?`, resp.ID).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if size != info.Size() {
		t.Fatalf("the row says %d bytes, the file is %d", size, info.Size())
	}
	// And the body is not in the database any more.
	if _, err := h.store.db.Exec(`SELECT envelope FROM messages`); err == nil {
		t.Fatal("the envelope column still exists")
	}
}

// A message is not visible at its final path until Put has returned, so a
// reader can never see a half-written file.
func TestNothingIsVisibleUntilPutReturns(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 32 << 20})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	boxDir := filepath.Join(h.messagesDir(), fp[:2], fp)

	// A large body, so the write takes long enough to be worth watching.
	big := make([]byte, 16<<20)
	copy(big, sealed(t, alice, bob.Public(), "x"))

	stop := make(chan struct{})
	bad := make(chan string, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			entries, err := os.ReadDir(boxDir)
			if err != nil {
				continue // not created yet, which is fine
			}
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				// Any file here must already be whole: the rename is the only
				// thing that puts one here, and it renames a finished file.
				if info.Size() != 0 && info.Size() < int64(len(big)) {
					select {
					case bad <- fmt.Sprintf("%s is %d bytes, partial", e.Name(), info.Size()):
					default:
					}
					return
				}
			}
		}
	}()

	h.store.Put(fp, "default", relayapi.KindEnvelope, "", big, Quotas{}, Forwarded{})
	close(stop)
	select {
	case msg := <-bad:
		t.Fatalf("a partially written message was visible: %s", msg)
	default:
	}

	// Nothing left behind in tmp either.
	entries, err := os.ReadDir(filepath.Join(h.messagesDir(), "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d temp files left after a successful Put", len(entries))
	}
}

func TestDeleteRemovesTheFile(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	id, err := h.store.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	path := h.store.messagePath(bob.Fingerprint(), id)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	deleted, err := h.store.Delete(bob.Fingerprint(), id)
	if err != nil || !deleted {
		t.Fatalf("delete: %v %v", deleted, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the file survived the delete: %v", err)
	}
	// A second delete is clean.
	if deleted, err := h.store.Delete(bob.Fingerprint(), id); err != nil || deleted {
		t.Fatalf("second delete: %v %v", deleted, err)
	}
	h.assertCountersAgree()
}

func TestDeregisterAndPurgeRemoveFiles(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]

	setup := func(h *harness) string {
		h.register(alice)
		h.register(bob)
		for range 3 {
			if _, err := h.store.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "",
				sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{}); err != nil {
				t.Fatal(err)
			}
		}
		return h.store.mailboxDir(bob.Fingerprint())
	}

	t.Run("purge keeps the mailbox directory", func(t *testing.T) {
		h := newHarness(t, Config{})
		dir := setup(h)
		if _, err := h.store.PurgeMailbox(bob.Fingerprint()); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("the mailbox directory went with a purge: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("%d files survived the purge", len(entries))
		}
		h.assertCountersAgree()
	})

	t.Run("deregister takes the directory too", func(t *testing.T) {
		h := newHarness(t, Config{})
		dir := setup(h)
		if _, err := h.store.Deregister(bob.Fingerprint()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("the mailbox directory survived deregistration: %v", err)
		}
		h.assertCountersAgree()
	})
}

// The sweep is what makes every crash recoverable, so each of its cases is
// built by hand and the store reopened on it.
func TestStartupSweep(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	fp := bob.Fingerprint()

	// build returns a store with n messages and the paths it wrote.
	build := func(t *testing.T, dir string, n int) []string {
		t.Helper()
		s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []*identity.Identity{alice, bob} {
			if err := s.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, RegisterOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		var paths []string
		for range n {
			id, err := s.Put(fp, "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{})
			if err != nil {
				t.Fatal(err)
			}
			paths = append(paths, s.messagePath(fp, id))
		}
		s.Close()
		return paths
	}
	reopen := func(t *testing.T, dir string) *Store {
		t.Helper()
		s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	count := func(t *testing.T, s *Store) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("temp files are removed", func(t *testing.T) {
		dir := t.TempDir()
		build(t, dir, 2)
		stale := filepath.Join(dir, "messages", "tmp", "leftover")
		if err := os.WriteFile(stale, []byte("half a message"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := reopen(t, dir)
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Fatal("a temp file survived the sweep")
		}
		if got := s.Swept().Temp; got != 1 {
			t.Fatalf("swept %d temp files, want 1", got)
		}
		if count(t, s) != 2 {
			t.Fatal("the sweep touched a good message")
		}
	})

	t.Run("a file with no row is removed", func(t *testing.T) {
		dir := t.TempDir()
		build(t, dir, 2)
		orphan := filepath.Join(dir, "messages", fp[:2], fp, "9999")
		if err := os.WriteFile(orphan, []byte("nobody claims me"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := reopen(t, dir)
		if _, err := os.Stat(orphan); !os.IsNotExist(err) {
			t.Fatal("an orphan file survived the sweep")
		}
		if got := s.Swept().Orphans; got != 1 {
			t.Fatalf("swept %d orphans, want 1", got)
		}
		if count(t, s) != 2 {
			t.Fatal("the sweep removed a good row")
		}
	})

	t.Run("a row with no file is removed", func(t *testing.T) {
		dir := t.TempDir()
		paths := build(t, dir, 3)
		if err := os.Remove(paths[1]); err != nil {
			t.Fatal(err)
		}
		s := reopen(t, dir)
		if got := s.Swept().Missing; got != 1 {
			t.Fatalf("reported %d missing, want 1", got)
		}
		if n := count(t, s); n != 2 {
			t.Fatalf("%d rows left, want 2", n)
		}
		assertCounters(t, s)
	})

	t.Run("a file of the wrong size is treated as missing", func(t *testing.T) {
		dir := t.TempDir()
		paths := build(t, dir, 2)
		if err := os.Truncate(paths[0], 10); err != nil {
			t.Fatal(err)
		}
		s := reopen(t, dir)
		if got := s.Swept().Missing; got != 1 {
			t.Fatalf("reported %d missing, want 1", got)
		}
		if _, err := os.Stat(paths[0]); !os.IsNotExist(err) {
			t.Fatal("the truncated file was left behind")
		}
		if n := count(t, s); n != 1 {
			t.Fatalf("%d rows left, want 1", n)
		}
		assertCounters(t, s)
	})

	t.Run("a clean store sweeps nothing", func(t *testing.T) {
		dir := t.TempDir()
		build(t, dir, 3)
		s := reopen(t, dir)
		if !s.Swept().Empty() {
			t.Fatalf("a clean store reported %+v", s.Swept())
		}
	})
}

// A database with no mailboxes beside a message directory that holds mail is
// a database that was lost: the sweep would take every file as an orphan and
// the relay would come up fresh in silence. The container suite's R20 found
// it did exactly that. Only a message file counts, since Deregister removes
// the rows and then the directory and a crash between the two leaves an empty
// one; tmp/ and uploads/ are not mail.
func TestAFreshDatabaseBesideOldMailIsRefused(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	fpA, fpB := alice.Fingerprint(), bob.Fingerprint()

	open := func(t *testing.T, dir string) (*Store, error) {
		t.Helper()
		s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err == nil {
			t.Cleanup(func() { s.Close() })
		}
		return s, err
	}
	plant := func(t *testing.T, dir string, rel ...string) {
		t.Helper()
		path := filepath.Join(append([]string{dir, "messages"}, rel...)...)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("sealed bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	refusal := func(dir string, n int) string {
		boxes := "mailboxes"
		if n == 1 {
			boxes = "mailbox"
		}
		return fmt.Sprintf("relay: %s is new but %s holds mail for %d %s: the database was lost. "+
			"Restore %s from a backup, or move the message directory aside to start the relay empty",
			filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"), n, boxes, filepath.Join(dir, "relay.db"))
	}

	t.Run("a mailbox with a file refuses a new database", func(t *testing.T) {
		dir := t.TempDir()
		plant(t, dir, fpB[:2], fpB, "17")
		_, err := open(t, dir)
		if err == nil {
			t.Fatal("a new database opened beside mail and would have swept it")
		}
		if err.Error() != refusal(dir, 1) {
			t.Fatalf("refused with %q, want %q", err, refusal(dir, 1))
		}
		if _, err := os.Stat(filepath.Join(dir, "messages", fpB[:2], fpB, "17")); err != nil {
			t.Fatalf("the refusal did not leave the mail alone: %v", err)
		}
	})

	t.Run("mailboxes are counted, not files", func(t *testing.T) {
		dir := t.TempDir()
		plant(t, dir, fpB[:2], fpB, "17")
		plant(t, dir, fpB[:2], fpB, "18")
		plant(t, dir, fpA[:2], fpA, "3")
		_, err := open(t, dir)
		if err == nil || err.Error() != refusal(dir, 2) {
			t.Fatalf("refused with %v, want %q", err, refusal(dir, 2))
		}
	})

	t.Run("a database that has lost its mailboxes is refused too", func(t *testing.T) {
		// The schema is there, from an earlier open, but no mailbox is: a
		// backup from before anybody registered, restored beside their mail.
		dir := t.TempDir()
		s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		plant(t, dir, fpB[:2], fpB, "17")
		if _, err := open(t, dir); err == nil || err.Error() != refusal(dir, 1) {
			t.Fatalf("refused with %v, want %q", err, refusal(dir, 1))
		}
	})

	t.Run("an empty directory beside an empty database opens", func(t *testing.T) {
		if _, err := open(t, t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an empty mailbox directory opens", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "messages", fpB[:2], fpB), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := open(t, dir); err != nil {
			t.Fatalf("an empty mailbox directory, as a crash in Deregister leaves, refused the database: %v", err)
		}
	})

	t.Run("a file under tmp alone opens", func(t *testing.T) {
		dir := t.TempDir()
		plant(t, dir, "tmp", "leftover")
		s, err := open(t, dir)
		if err != nil {
			t.Fatal(err)
		}
		if s.Swept().Temp != 1 {
			t.Fatalf("swept %d temp files, want 1", s.Swept().Temp)
		}
	})

	t.Run("a file under uploads alone opens", func(t *testing.T) {
		dir := t.TempDir()
		plant(t, dir, "uploads", "0123456789abcdef0123456789abcdef")
		if _, err := open(t, dir); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a database that knows its mailboxes opens beside their mail", func(t *testing.T) {
		dir := t.TempDir()
		s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Register(fpB, bob.Public().Bundle(), bob.Name, RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Put(fpB, "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{}); err != nil {
			t.Fatal(err)
		}
		s.Close()
		if _, err := open(t, dir); err != nil {
			t.Fatalf("a database with its mailbox refused to open beside that mailbox's mail: %v", err)
		}
	})
}

// Between an unlink and the next start, List omits the row rather than
// failing the whole mailbox, and takes it off the count the page carries:
// the count is there to say whether the relay holds mail the page does not
// show, and a row nothing can serve is not that. The container suite's M03
// would otherwise have had the client told its cursor was past mail. The
// mailbox's own counter is left for the sweep.
func TestListOmitsAMessageWhoseFileHasGone(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	var ids []int64
	for range 3 {
		id, err := h.store.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := os.Remove(h.store.messagePath(bob.Fingerprint(), ids[1])); err != nil {
		t.Fatal(err)
	}

	listing, err := h.store.Listing(bob.Fingerprint(), 0, 100, false)
	if err != nil {
		t.Fatalf("List failed because of one missing file: %v", err)
	}
	rows := listing.Rows
	if len(rows) != 2 {
		t.Fatalf("List returned %d messages, want the 2 that still exist", len(rows))
	}
	for _, r := range rows {
		if r.ID == ids[1] {
			t.Fatal("List returned the message whose file is gone")
		}
	}
	if listing.Queued != 2 {
		t.Fatalf("the page counts %d, want the 2 it can serve", listing.Queued)
	}
	// After the last id: an empty page beside nothing, not beside the
	// row nothing can serve.
	if after, err := h.store.Listing(bob.Fingerprint(), ids[2], 100, false); err != nil || len(after.Rows) != 0 || after.Queued != 3 {
		t.Fatalf("after the last id: %d rows, count %d (%v); the page did not meet the missing file, so it counts 3", len(after.Rows), after.Queued, err)
	}
	if messages, _ := h.queued(bob.Fingerprint()); messages != 3 {
		t.Fatalf("the mailbox's counter is %d, want 3 untouched until the sweep", messages)
	}

	// The other way round, a row lost with its file left: the counter
	// still counts it, the page cannot show it, and the count the page
	// carries is of rows, so it does not either. The container suite's
	// M05 would otherwise have told the client its cursor was past mail.
	if _, err := h.store.db.Exec(`DELETE FROM messages WHERE id = ?`, ids[2]); err != nil {
		t.Fatal(err)
	}
	rowless, err := h.store.Listing(bob.Fingerprint(), ids[0], 100, false)
	if err != nil || len(rowless.Rows) != 0 || rowless.Queued != 1 {
		t.Fatalf("with a row lost: %d rows, count %d (%v); want an empty page after the first id counting the one row left", len(rowless.Rows), rowless.Queued, err)
	}
	if messages, _ := h.queued(bob.Fingerprint()); messages != 3 {
		t.Fatalf("the mailbox's counter is %d, want 3 untouched until the sweep", messages)
	}
}

// The path is built from validated components, so it cannot leave the
// message directory. Asserted for every fingerprint the identity package
// accepts, not just a convenient one.
func TestDerivedPathsCannotEscape(t *testing.T) {
	h := newHarness(t, Config{})
	r, seed := testutil.Seed(t)

	check := func(fp string, id int64) {
		t.Helper()
		if !identity.ValidFingerprint(fp) {
			t.Fatalf("seed %d: %q is not a fingerprint, so the test is wrong", seed, fp)
		}
		rel, err := filepath.Rel(h.messagesDir(), h.store.messagePath(fp, id))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatalf("seed %d: %s escapes the message directory", seed, rel)
		}
	}

	const hexDigits = "0123456789abcdef"
	for range 200 {
		fp := make([]byte, 64)
		for i := range fp {
			fp[i] = hexDigits[r.IntN(16)]
		}
		check(string(fp), int64(r.Uint64()>>1))
	}
	check(strings.Repeat("0", 64), 0)
	check(strings.Repeat("f", 64), 1<<62)
}

// A relay that cannot write must answer 507, not 500: a full disk is the
// operator's problem and the sender should be told to try later.
func TestUnwritableDirectoryIsRelayFull(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	tmp := filepath.Join(h.messagesDir(), "tmp")
	if err := os.Chmod(tmp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tmp, 0o700) })

	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "nowhere to go"), nil)
	// EACCES is not ENOSPC, so this is a 500; what matters is that the row
	// count is unchanged and nothing was half-stored.
	if status != http.StatusInternalServerError && status != http.StatusInsufficientStorage {
		t.Fatalf("status %d, want 500 or 507: %s", status, body)
	}
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a failed write left %d rows", n)
	}
}

// assertCounters is assertCountersAgree for a store the harness does not own.
func assertCounters(t *testing.T, s *Store) {
	t.Helper()
	var storedN, storedB, realN, realB int64
	if err := s.db.QueryRow(
		`SELECT COALESCE(SUM(queued_messages),0), COALESCE(SUM(queued_bytes),0) FROM mailboxes`).
		Scan(&storedN, &storedB); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size),0) FROM messages`).Scan(&realN, &realB); err != nil {
		t.Fatal(err)
	}
	if storedN != realN || storedB != realB {
		t.Fatalf("counters say %d/%d, the table says %d/%d", storedN, storedB, realN, realB)
	}
}
