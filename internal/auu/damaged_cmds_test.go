package auu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/vouch"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// storeOf opens a user's home.
func storeOf(t *testing.T, u *user) *store.Store {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// lsDamaged is what auu damaged ls --json says, and what it wrote on
// standard error.
func lsDamaged(t *testing.T, u *user) ([]damagedJSON, string) {
	t.Helper()
	var out string
	stderr := captureStderr(t, func() { out = u.run("damaged", "ls", "--json") })
	var rows []damagedJSON
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("damaged ls --json: %v\n%s", err, out)
	}
	return rows, stderr
}

// reopenDamaged runs auu damaged reopen and returns what it printed on
// each stream and its error.
func reopenDamaged(t *testing.T, u *user, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	stderr = captureStderr(t, func() { stdout, err = u.tryRun(append([]string{"damaged", "reopen"}, args...)...) })
	return stdout, stderr, err
}

// reopenJSONOf runs auu damaged reopen --json and decodes it.
func reopenJSONOf(t *testing.T, u *user, args ...string) []reopenJSON {
	t.Helper()
	out, stderr, err := reopenDamaged(t, u, append(args, "--json")...)
	if err != nil {
		t.Fatalf("damaged reopen %v: %v\n%s\n%s", args, err, out, stderr)
	}
	var rows []reopenJSON
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("damaged reopen --json: %v\n%s", err, out)
	}
	return rows
}

// keptPair is the bytes of a kept message's two files.
func keptPair(t *testing.T, s *store.Store, relay string, id int64) [2][]byte {
	t.Helper()
	bin, err := s.DamagedPath(relay, id)
	if err != nil {
		t.Fatal(err)
	}
	var pair [2][]byte
	for i, p := range []string{bin, strings.TrimSuffix(bin, ".bin") + ".json"} {
		if pair[i], err = os.ReadFile(p); err != nil {
			t.Fatalf("the kept file: %v", err)
		}
	}
	return pair
}

// keptGone fails the test unless both of a kept message's files are gone.
func keptGone(t *testing.T, s *store.Store, relay string, id int64) {
	t.Helper()
	bin, err := s.DamagedPath(relay, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bin, strings.TrimSuffix(bin, ".bin") + ".json"} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there: %v", p, err)
		}
	}
}

// writeRecord replaces a kept message's record with rec, written as the
// store writes one.
func writeRecord(t *testing.T, s *store.Store, rec store.DamagedRecord) {
	t.Helper()
	bin, err := s.DamagedPath(rec.Relay, rec.RelayID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(bin, ".bin")+".json", append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// moveKept moves a kept message to another relay's directory, as kept by a
// relay of that name received at the time given: a relay this home no
// longer has, for a test of reopening what such a relay delivered.
func moveKept(t *testing.T, s *store.Store, from string, id int64, to string, received time.Time) {
	t.Helper()
	pair := keptPair(t, s, from, id)
	rec := damagedRecord(t, s, from, id)
	if err := s.RemoveDamaged(from, id); err != nil {
		t.Fatal(err)
	}
	bin, err := s.DamagedPath(to, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, pair[0], 0o600); err != nil {
		t.Fatal(err)
	}
	rec.Relay, rec.Received = to, received
	writeRecord(t, s, rec)
}

// sealWithSections seals an ask with sections as a newer build would, and
// returns it with the sender's client, for a test that posts it more than
// once.
func sealWithSections(t *testing.T, from, to *user, subject string, sections []wire.Section) (*envelope.Envelope, func()) {
	t.Helper()
	id, c := sender(t, from)
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := envelope.SealSections(id, mustParseBundle(t, mustBundle(t, to)), "",
		message.Body{Type: message.TypeAsk, Thread: thread, Subject: subject, Text: "sealed by a newer build"}, sections)
	if err != nil {
		t.Fatal(err)
	}
	return env, func() {
		t.Helper()
		if _, err := c.Post(context.Background(), env, ""); err != nil {
			t.Fatal(err)
		}
	}
}

// peeredGated is peered on a relay that counts every request it is sent.
func peeredGated(t *testing.T) (alice, bob *user, gate *waitGate) {
	t.Helper()
	url, gate, _ := startGatedRelayStore(t)
	alice = newUser(t, "alice", url)
	bob = newUser(t, "bob", url)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	return alice, bob, gate
}

// keptNewer fetches for bob and returns the ids of what was kept as newer,
// oldest first, wanting n of them.
func keptNewer(t *testing.T, bob *user, n int) []int64 {
	t.Helper()
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Kept != n {
		t.Fatalf("fetch: %+v; want %d kept as newer\n%s", in.Fetch, n, stderr)
	}
	rows, _ := lsDamaged(t, bob)
	var ids []int64
	for _, r := range rows {
		if !strings.HasPrefix(r.Cause, store.CauseNewer+": ") {
			t.Fatalf("a kept row of another cause: %+v", r)
		}
		ids = append(ids, r.ID)
	}
	if len(ids) != n {
		t.Fatalf("damaged ls lists %d; want %d", len(ids), n)
	}
	return ids
}

// S12: a message kept because it needed a newer auu is listed with its
// section, and once this build knows the section, reopen files it in the
// inbox with the relay and the received time the record kept, as no
// longer on the relay, and both kept files go.
func TestAKeptNewerEnvelopeIsReadAfterTheUpdate(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "from a newer build", critical("reopen-later"))
	in, _ := fetchJSON(t, bob)
	if in.Fetch.Kept != 1 {
		t.Fatalf("fetch: %+v; want the message kept", in.Fetch)
	}
	relayName := bob.defaultRelayName()
	rows, _ := lsDamaged(t, bob)
	if len(rows) != 1 || rows[0].Relay != relayName || rows[0].Section != "reopen-later" ||
		rows[0].Cause != `newer: section "reopen-later"` || rows[0].Size <= 0 {
		t.Fatalf("damaged ls: %+v", rows)
	}
	id := rows[0].ID
	bs := storeOf(t, bob)
	// What the listing said of the row is in the record, from this
	// release.
	rec := damagedRecord(t, bs, relayName, id)
	if rec.Kind != relayapi.KindEnvelope || rec.Channel != "default" || rec.Size <= 0 || rec.Via != "" {
		t.Fatalf("the record does not carry what the listing said: %+v", rec)
	}
	if spoolHas(t, bob, store.Inbox, "from a newer build") {
		t.Fatal("the message is in the inbox before the update")
	}

	t.Cleanup(wire.Register("reopen-later", wire.OnMessage))
	out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(id, 10))
	if want := fmt.Sprintf("%s %d: opened and filed in the inbox\n", relayName, id); out != want {
		t.Errorf("reopen said %q; want %q", out, want)
	}
	m := recordOf(t, bob, store.Inbox, "from a newer build")
	if m.Relay != rec.Relay || !m.Received.Equal(rec.Received) || m.RelayID != id || m.OnRelay || m.RelaySize != rec.Size || m.Channel != "" {
		t.Errorf("the filed record: relay %q received %v id %d on relay %v size %d channel %q; want %q, %v, %d, false, %d, default",
			m.Relay, m.Received, m.RelayID, m.OnRelay, m.RelaySize, m.Channel, rec.Relay, rec.Received, id, rec.Size)
	}
	keptGone(t, bs, relayName, id)
	if entries, strays, err := bs.DamagedEntries(); err != nil || len(entries) != 0 || len(strays) != 0 {
		t.Errorf("damaged/ after the reopen: %+v, strays %v, %v; want empty", entries, strays, err)
	}
	if out := bob.run("read", m.Inner.ID); !strings.Contains(out, "sealed by a newer build") {
		t.Errorf("read of the reopened message:\n%s", out)
	}
}

// Reopened by a build that still does not know the section, a kept message
// is left where it is and said to still need a newer auu, naming the
// section.
func TestAKeptNewerEnvelopeStillRefusedIsLeft(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "still from a newer build", critical("still-later"))
	id := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	out, _, err := reopenDamaged(t, bob, relayName, strconv.FormatInt(id, 10))
	want := fmt.Sprintf("%s %d: still needs a newer auu (section \"still-later\") and is left where it is\n", relayName, id)
	if err != nil || out != want {
		t.Fatalf("reopen: %v, said %q; want %q", err, out, want)
	}
	rows := reopenJSONOf(t, bob, "--all")
	if len(rows) != 1 || rows[0].Outcome != reopenNewer || rows[0].Detail != `section "still-later"` || rows[0].Box != "" {
		t.Errorf("reopen --all --json: %+v", rows)
	}
	if spoolHas(t, bob, store.Inbox, "still from a newer build") || len(bob.quarantined()) != 0 {
		t.Error("a message still refused was filed")
	}
	if left, _ := lsDamaged(t, bob); len(left) != 1 || left[0].ID != id {
		t.Errorf("damaged ls after: %+v", left)
	}
}

// What is still refused as newer is left byte for byte, and nothing kept
// is evicted by the attempt.
func TestAStillNewerRecordIsLeftByteForByte(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "one", critical("byte-later"))
	postSections(t, alice, bob, "two", critical("byte-later"))
	ids := keptNewer(t, bob, 2)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	before := map[int64][2][]byte{}
	for _, id := range ids {
		before[id] = keptPair(t, bs, relayName, id)
	}
	n, size, err := bs.DamagedKept()
	if err != nil {
		t.Fatal(err)
	}
	reopenDamaged(t, bob, relayName, strconv.FormatInt(ids[0], 10))
	reopenDamaged(t, bob, "--all")
	for _, id := range ids {
		if after := keptPair(t, bs, relayName, id); !bytes.Equal(after[0], before[id][0]) || !bytes.Equal(after[1], before[id][1]) {
			t.Errorf("relay message %d's kept files changed", id)
		}
	}
	if n2, size2, err := bs.DamagedKept(); err != nil || n2 != n || size2 != size {
		t.Errorf("damaged/ holds %d of %d bytes after (%v); want %d of %d", n2, size2, err, n, size)
	}
}

// A message kept for any cause but newer could not be opened by any auu:
// reopen refuses it by name, quoting the cause, and --all passes over it,
// leaving it as it was, while it opens what was kept as newer. So is bytes
// kept beside a record that does not read, here one that says newer but
// has no received time: reopen refuses it at exit 1 with the reason, and
// --all passes over it, whatever its record says.
func TestAMalformedRecordIsNeverReopened(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "the newer one", critical("beside-malformed"))
	newerID := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	for i, cause := range []string{"malformed", "misfiled", "did not decrypt"} {
		id := int64(1000 + i)
		if kept, _, err := bs.KeepDamaged(store.DamagedRecord{RelayID: id, Relay: relayName, Received: time.Now(), Cause: cause}, []byte("not an envelope")); err != nil || !kept {
			t.Fatal(err)
		}
		usageError(t, bob, fmt.Sprintf("%s %d was kept with the cause %q, which is never reopened; only a message kept as needing a newer auu is",
			relayName, id, cause), "damaged", "reopen", relayName, strconv.FormatInt(id, 10))
	}
	// A record that does not read: it says newer, but no received time.
	if kept, _, err := bs.KeepDamaged(store.DamagedRecord{RelayID: 2000, Relay: relayName, Received: time.Now(), Cause: "malformed"}, []byte("not an envelope")); err != nil || !kept {
		t.Fatal(err)
	}
	badBin := damagedPathOf(t, bs, relayName, 2000)
	badRecord := strings.TrimSuffix(badBin, ".bin") + ".json"
	if err := os.WriteFile(badRecord, []byte(`{"relay_id":2000,"relay":"`+relayName+`","received":"0001-01-01T00:00:00Z","cause":"newer: section \"beside-malformed\""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	usageError(t, bob, fmt.Sprintf("%s 2000 is kept beside a record that does not read (%s: the record has no received time), which is never reopened; "+
		"only a message kept as needing a newer auu is", relayName, badRecord), "damaged", "reopen", relayName, "2000")
	badBefore := keptPair(t, bs, relayName, 2000)
	before := keptPair(t, bs, relayName, 1000)
	t.Cleanup(wire.Register("beside-malformed", wire.OnMessage))
	rows := reopenJSONOf(t, bob, "--all")
	if len(rows) != 1 || rows[0].ID != newerID || rows[0].Outcome != reopenFiled {
		t.Fatalf("reopen --all: %+v; want the newer one filed and nothing else", rows)
	}
	if after := keptPair(t, bs, relayName, 1000); !bytes.Equal(after[0], before[0]) || !bytes.Equal(after[1], before[1]) {
		t.Error("the malformed record changed")
	}
	if after := keptPair(t, bs, relayName, 2000); !bytes.Equal(after[0], badBefore[0]) || !bytes.Equal(after[1], badBefore[1]) {
		t.Error("the pair beside a record that does not read changed")
	}
	if n, _, err := bs.DamagedKept(); err != nil || n != 4 {
		t.Errorf("damaged/ holds %d (%v); want the four never reopened", n, err)
	}
	// An id with nothing kept is said so.
	usageError(t, bob, fmt.Sprintf("nothing is kept for %s 999; auu damaged ls lists what is", relayName),
		"damaged", "reopen", relayName, "999")
}

// Bytes kept with no record beside them, a keep cut off before its record
// was written, are listed and counted but never reopened: reopen refuses
// them by name at exit 1, --all passes over them, and the bytes are left.
func TestABinWithNoRecordIsNeverReopened(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "kept with its record", critical("beside-cut-off"))
	newerID := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	// The kept message's own bytes, its record gone, under another id: as
	// a keep leaves them when it is cut off between the two writes.
	bin := damagedPathOf(t, bs, relayName, newerID)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	cutOff := filepath.Join(filepath.Dir(bin), "77.bin")
	if err := os.WriteFile(cutOff, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bs.ReadDamaged(relayName, 77); !errors.Is(err, store.ErrNoRecord) {
		t.Fatalf("ReadDamaged of bytes with no record: %v; want ErrNoRecord", err)
	}
	t.Cleanup(wire.Register("beside-cut-off", wire.OnMessage))
	usageError(t, bob, relayName+" 77 is bytes kept with no record, a keep cut off before its record was written, "+
		"which is never reopened; only a message kept as needing a newer auu is", "damaged", "reopen", relayName, "77")
	rows := reopenJSONOf(t, bob, "--all")
	if len(rows) != 1 || rows[0].ID != newerID || rows[0].Outcome != reopenFiled {
		t.Fatalf("reopen --all: %+v; want the one with its record filed and nothing else", rows)
	}
	if after, err := os.ReadFile(cutOff); err != nil || !bytes.Equal(after, data) {
		t.Errorf("the bytes with no record changed: %v", err)
	}
	if _, err := os.Lstat(strings.TrimSuffix(cutOff, ".bin") + ".json"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a record appeared beside the cut-off bytes: %v", err)
	}
	if n, _, err := bs.DamagedKept(); err != nil || n != 1 {
		t.Errorf("damaged/ counts %d (%v); want the cut-off bytes alone", n, err)
	}
	msgs, err := bs.List(store.Inbox)
	if err != nil || len(msgs) != 1 {
		t.Errorf("the inbox holds %d (%v); want the one reopened", len(msgs), err)
	}
}

// A stranger's message kept as newer is filed where the fetch would have
// filed it: the quarantine.
func TestReopenFilesAStrangerInQuarantine(t *testing.T) {
	srv, _, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	carol := newUser(t, "carol", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	postSections(t, carol, bob, "a stranger's newer ask", critical("stranger-later"))
	id := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	t.Cleanup(wire.Register("stranger-later", wire.OnMessage))
	out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(id, 10))
	if want := fmt.Sprintf("%s %d: opened and filed in the quarantine\n", relayName, id); out != want {
		t.Errorf("reopen said %q; want %q", out, want)
	}
	if spoolHas(t, bob, store.Inbox, "a stranger's newer ask") || !spoolHas(t, bob, store.Quarantine, "a stranger's newer ask") {
		t.Error("the stranger's message was not filed in the quarantine alone")
	}
	keptGone(t, storeOf(t, bob), relayName, id)
}

// A locked agent moves nothing. Locked before the command, reopen is exit
// 4 and every kept file is as it was. Locked between two records under
// --all, the one before is filed, the command stops at exit 4 at the next
// and says how many were filed, and the next is as it was. The lock is
// taken while the second record waits for its relay's fetch lock, which
// the test holds, so the first is certainly done and the second certainly
// not begun.
func TestReopenUnderALockedAgentMovesNothing(t *testing.T) {
	srv, _, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := encryptedUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	postSections(t, alice, bob, "first", critical("lock-later"))
	postSections(t, alice, bob, "second", critical("lock-later"))
	ids := keptNewer(t, bob, 2)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	t.Cleanup(wire.Register("lock-later", wire.OnMessage))

	bob.run("lock")
	before := snapshotHome(t, filepath.Join(bob.home, "damaged"))
	for _, args := range [][]string{{relayName, strconv.FormatInt(ids[0], 10)}, {"--all"}} {
		_, _, err := reopenDamaged(t, bob, args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitLocked {
			t.Fatalf("reopen %v with the agent locked: %v; want exit %d", args, err, exitLocked)
		}
	}
	if after := snapshotHome(t, filepath.Join(bob.home, "damaged")); !reflect.DeepEqual(before, after) {
		t.Fatal("a locked reopen changed damaged/")
	}
	if spoolHas(t, bob, store.Inbox, "first") || spoolHas(t, bob, store.Inbox, "second") {
		t.Fatal("a locked reopen filed a message")
	}

	// Between two: the first kept by a relay this home no longer has, so
	// it takes no lock and is reopened first; the second waits on the lock.
	bob.run("unlock", "--passphrase-file", passphraseFile(t, agentPassphrase))
	moveKept(t, bs, relayName, ids[0], "gone.example", time.Now().Add(-time.Hour))
	second := keptPair(t, bs, relayName, ids[1])
	r, err := bs.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(filepath.Join(bs.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	locked := false
	fetchLockSleep = func(time.Duration) {
		if locked {
			return
		}
		locked = true
		if !spoolHas(t, bob, store.Inbox, "first") {
			t.Error("the second record was waited on before the first was filed")
		}
		if _, stderr, code := bob.inAnotherProcess("lock"); code != 0 {
			t.Errorf("lock: exit %d\n%s", code, stderr)
		}
		held.Release()
	}
	t.Cleanup(func() { fetchLockSleep = time.Sleep })
	_, stderr, err := reopenDamaged(t, bob, "--all")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked {
		t.Fatalf("reopen --all locked between records: %v; want exit %d\n%s", err, exitLocked, stderr)
	}
	if !locked {
		t.Fatal("the second record never waited on its relay's fetch lock")
	}
	if !strings.Contains(stderr, "auu: 1 reopened and filed before the key locked; the rest are where they were") {
		t.Errorf("stderr does not say how many were filed:\n%s", stderr)
	}
	m := recordOf(t, bob, store.Inbox, "first")
	if m.Relay != "gone.example" {
		t.Errorf("the first was filed as from %q", m.Relay)
	}
	keptGone(t, bs, "gone.example", ids[0])
	if spoolHas(t, bob, store.Inbox, "second") {
		t.Error("the second was filed under a locked agent")
	}
	if after := keptPair(t, bs, relayName, ids[1]); !bytes.Equal(after[0], second[0]) || !bytes.Equal(after[1], second[1]) {
		t.Error("the second record changed under a locked agent")
	}
}

// Reopen reads the record again once it holds the relay's fetch lock, and
// holds it to the cause again: a fetch that ran while reopen waited may
// have kept another message under the same id, for another cause. The
// test holds the lock, and while reopen waits on it rewrites the record's
// cause to malformed before letting go; reopen then leaves the message,
// saying what the record now says, files nothing and changes no file.
func TestReopenRechecksTheCauseUnderTheLock(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "kept as newer, then not", critical("recheck-later"))
	id := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	// Known to this build, so that the record's cause is all that keeps
	// it from opening.
	t.Cleanup(wire.Register("recheck-later", wire.OnMessage))
	r, err := bs.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(filepath.Join(bs.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	var rewritten map[string][]byte
	waited := false
	fetchLockSleep = func(time.Duration) {
		if waited {
			return
		}
		waited = true
		rec := damagedRecord(t, bs, relayName, id)
		rec.Cause = "malformed"
		writeRecord(t, bs, rec)
		rewritten = snapshotHome(t, bs.DamagedDir())
		held.Release()
	}
	t.Cleanup(func() { fetchLockSleep = time.Sleep })
	out, stderr, err := reopenDamaged(t, bob, relayName, strconv.FormatInt(id, 10))
	if err != nil {
		t.Fatalf("reopen: %v\n%s\n%s", err, out, stderr)
	}
	if !waited {
		t.Fatal("reopen never waited on its relay's fetch lock")
	}
	if want := fmt.Sprintf("%s %d: its record now says \"malformed\", and is left where it is\n", relayName, id); out != want {
		t.Errorf("reopen said %q; want %q", out, want)
	}
	if after := snapshotHome(t, bs.DamagedDir()); !reflect.DeepEqual(after, rewritten) {
		t.Error("damaged/ changed after the record was rewritten")
	}
	if spoolHas(t, bob, store.Inbox, "kept as newer, then not") || len(bob.quarantined()) != 0 {
		t.Error("a record no longer newer was filed")
	}
}

// Under --all, a stop after something was filed says how many were, for
// any cause and not only a locked key: here the second record's relay is
// fetching, its fetch lock held past the wait. The first, kept by a relay
// this home no longer has, takes no lock and is filed; the command stops
// at exit 2 at the second, says that one was filed before it stopped, and
// leaves the second as it was.
func TestAHeldLockMidwayIsSaidWithTheCount(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "first", critical("midway-later"))
	postSections(t, alice, bob, "second", critical("midway-later"))
	ids := keptNewer(t, bob, 2)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	t.Cleanup(wire.Register("midway-later", wire.OnMessage))
	moveKept(t, bs, relayName, ids[0], "gone.example", time.Now().Add(-time.Hour))
	second := keptPair(t, bs, relayName, ids[1])
	r, err := bs.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(filepath.Join(bs.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { held.Release() })
	fetchLockWait = 200 * time.Millisecond
	waited := false
	fetchLockSleep = func(d time.Duration) {
		if !waited && !spoolHas(t, bob, store.Inbox, "first") {
			t.Error("the second record was waited on before the first was filed")
		}
		waited = true
		time.Sleep(d)
	}
	t.Cleanup(func() { fetchLockWait, fetchLockSleep = time.Minute, time.Sleep })
	_, stderr, err := reopenDamaged(t, bob, "--all")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("reopen --all with the second's relay fetching: %v; want exit %d\n%s", err, exitTransport, stderr)
	}
	if !waited {
		t.Fatal("the second record never waited on its relay's fetch lock")
	}
	if !strings.Contains(stderr, "auu: 1 reopened and filed before this stopped; the rest are where they were\n") {
		t.Errorf("stderr does not say how many were filed:\n%s", stderr)
	}
	if m := recordOf(t, bob, store.Inbox, "first"); m.Relay != "gone.example" {
		t.Errorf("the first was filed as from %q", m.Relay)
	}
	keptGone(t, bs, "gone.example", ids[0])
	if spoolHas(t, bob, store.Inbox, "second") {
		t.Error("the second was filed while its relay's fetch lock was held")
	}
	if after := keptPair(t, bs, relayName, ids[1]); !bytes.Equal(after[0], second[0]) || !bytes.Equal(after[1], second[1]) {
		t.Error("the second record changed")
	}
}

// One message posted twice and kept twice, once per relay id: the first
// reopen files it, and the second finds it held from the same signer and
// removes the kept copy, leaving the held record as it was. Neither makes
// a request of the relay: the fetch acknowledged both when it kept them.
func TestReopenOfACopyKeptTwiceAcksNothing(t *testing.T) {
	alice, bob, gate := peeredGated(t)
	_, post := sealWithSections(t, alice, bob, "posted twice", critical("twice-later"))
	post()
	post()
	ids := keptNewer(t, bob, 2)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	t.Cleanup(wire.Register("twice-later", wire.OnMessage))
	gate.requests.Store(0)

	out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(ids[0], 10))
	if want := fmt.Sprintf("%s %d: opened and filed in the inbox\n", relayName, ids[0]); out != want {
		t.Fatalf("the first reopen said %q; want %q", out, want)
	}
	held := recordOf(t, bob, store.Inbox, "posted twice")
	rows := reopenJSONOf(t, bob, "--all")
	if len(rows) != 1 || rows[0].ID != ids[1] || rows[0].Outcome != reopenHeld {
		t.Fatalf("the second: %+v; want already held", rows)
	}
	if again := recordOf(t, bob, store.Inbox, "posted twice"); !reflect.DeepEqual(again, held) {
		t.Errorf("the held record changed:\n%+v\nwas\n%+v", again, held)
	}
	msgs, err := bs.List(store.Inbox)
	if err != nil || len(msgs) != 1 {
		t.Errorf("the inbox holds %d (%v); want the one message", len(msgs), err)
	}
	keptGone(t, bs, relayName, ids[0])
	keptGone(t, bs, relayName, ids[1])
	if n := gate.requests.Load(); n != 0 {
		t.Errorf("reopen made %d relay requests: %v", n, gate.since(0))
	}
}

// Reopen makes no relay request, whether the relay is this home's or one
// it no longer has: what it files was acknowledged when it was kept.
func TestReopenMakesNoRelayRequest(t *testing.T) {
	alice, bob, gate := peeredGated(t)
	postSections(t, alice, bob, "on a relay of this home", critical("quiet-later"))
	postSections(t, alice, bob, "on a relay since removed", critical("quiet-later"))
	ids := keptNewer(t, bob, 2)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	moveKept(t, bs, relayName, ids[1], "gone.example", time.Now())
	t.Cleanup(wire.Register("quiet-later", wire.OnMessage))
	gate.requests.Store(0)
	rows := reopenJSONOf(t, bob, "--all")
	if len(rows) != 2 || rows[0].Outcome != reopenFiled || rows[1].Outcome != reopenFiled {
		t.Fatalf("reopen --all: %+v; want both filed", rows)
	}
	if m := recordOf(t, bob, store.Inbox, "on a relay since removed"); m.Relay != "gone.example" || m.OnRelay {
		t.Errorf("the message from a removed relay: relay %q on relay %v", m.Relay, m.OnRelay)
	}
	if m := recordOf(t, bob, store.Inbox, "on a relay of this home"); m.Relay != relayName || m.OnRelay {
		t.Errorf("the message from this home's relay: relay %q on relay %v", m.Relay, m.OnRelay)
	}
	if n := gate.requests.Load(); n != 0 {
		t.Errorf("reopen made %d relay requests: %v", n, gate.since(0))
	}
}

// damaged ls lists every kept message by relay, id, received time, size and
// cause, naming the section of one kept as newer, bytes whose record was
// never written as such, and bytes beside a record that does not read as
// an unreadable record with the reason, at the bytes' own time, never
// counted as newer whatever the record says; a stray is said on standard
// error by its path and not listed; --json rows are {relay, id, received,
// size, cause, section}, with no cause and no section for a row whose
// record is missing or does not read.
func TestDamagedLsListsWhatIsKept(t *testing.T) {
	alice, bob, _ := peered(t)
	bs := storeOf(t, bob)
	out := bob.run("damaged", "ls")
	if want := "nothing is kept under " + bs.DamagedDir() + "\n"; out != want {
		t.Errorf("ls of nothing: %q; want %q", out, want)
	}
	if out := bob.run("damaged", "ls", "--json"); strings.TrimSpace(out) != "[]" {
		t.Errorf("ls --json of nothing: %q", out)
	}
	postSections(t, alice, bob, "kept as newer", critical("ls-later"))
	newerID := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	old := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if kept, _, err := bs.KeepDamaged(store.DamagedRecord{RelayID: 50, Relay: relayName, Received: old, Cause: "did not decrypt"}, []byte("garbled")); err != nil || !kept {
		t.Fatal(err)
	}
	dir := filepath.Join(bs.DamagedDir(), relayName)
	cutOff := filepath.Join(dir, "51.bin")
	if err := os.WriteFile(cutOff, []byte("cut"), 0o600); err != nil {
		t.Fatal(err)
	}
	cutTime := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(cutOff, cutTime, cutTime); err != nil {
		t.Fatal(err)
	}
	// Bytes beside a record that names another id than its file, and says
	// it was kept as newer: listed as a record that does not read, at the
	// bytes' own time, and not counted as newer.
	misnamed := filepath.Join(dir, "60.bin")
	if err := os.WriteFile(misnamed, []byte("misnamed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "60.json"), []byte(`{"relay_id":61,"relay":"`+relayName+`","received":"2026-10-01T00:00:00Z","cause":"newer: section \"x\""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	misTime := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(misnamed, misTime, misTime); err != nil {
		t.Fatal(err)
	}
	// Strays: a .bin whose name is no id, and a directory whose name is no
	// relay's.
	strays := []string{filepath.Join(dir, "x.bin"), filepath.Join(bs.DamagedDir(), "a b")}
	if err := os.WriteFile(strays[0], []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(strays[1], 0o700); err != nil {
		t.Fatal(err)
	}
	sort.Strings(strays)
	var wantWarnings strings.Builder
	for _, p := range strays {
		fmt.Fprintf(&wantWarnings, "warning: %s is not a kept message and is not listed\n", p)
	}

	var text string
	stderr := captureStderr(t, func() { text = bob.run("damaged", "ls") })
	if stderr != wantWarnings.String() {
		t.Errorf("ls's warnings:\n%s\nwant:\n%s", stderr, wantWarnings.String())
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("ls printed %d lines; want four rows, a blank and the count:\n%s", len(lines), text)
	}
	for i, want := range []struct {
		id   int64
		tail string
	}{{50, "did not decrypt"}, {51, "no record: a keep cut off before its record was written"},
		{60, `unreadable record: the record names relay "` + relayName + `" and id 61`}, {newerID, `newer: section "ls-later"`}} {
		f := strings.Fields(lines[i])
		if len(f) < 3 || f[0] != relayName || f[1] != strconv.FormatInt(want.id, 10) || !strings.HasSuffix(lines[i], "  "+want.tail) {
			t.Errorf("row %d: %q; want relay message %d ending %q", i, lines[i], want.id, want.tail)
		}
	}
	if !strings.HasPrefix(lines[0], fmt.Sprintf("%-20s %8d  %s", relayName, 50, old.Format(time.RFC3339))) {
		t.Errorf("row 0's relay, id and time: %q", lines[0])
	}
	if !strings.HasPrefix(lines[2], fmt.Sprintf("%-20s %8d  %s", relayName, 60, misTime.Format(time.RFC3339))) {
		t.Errorf("the unreadable record's row is not at its bytes' time: %q", lines[2])
	}
	if lines[4] != "" || lines[5] != "1 kept as needing a newer auu; auu damaged reopen --all opens them with this one" {
		t.Errorf("ls's last lines: %q", lines[4:])
	}
	for _, p := range strays {
		if strings.Contains(text, filepath.Base(p)) {
			t.Errorf("ls listed the stray %s", p)
		}
	}

	var raw string
	stderr = captureStderr(t, func() { raw = bob.run("damaged", "ls", "--json") })
	if stderr != wantWarnings.String() {
		t.Errorf("ls --json's warnings:\n%s", stderr)
	}
	var shapes []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &shapes); err != nil || len(shapes) != 4 {
		t.Fatalf("ls --json: %v\n%s", err, raw)
	}
	keys := func(m map[string]json.RawMessage) string {
		var k []string
		for key := range m {
			k = append(k, key)
		}
		sort.Strings(k)
		return strings.Join(k, ",")
	}
	if got := keys(shapes[3]); got != "cause,id,received,relay,section,size" {
		t.Errorf("the newer row's keys: %s", got)
	}
	for _, i := range []int{0, 1, 2} {
		if got := keys(shapes[i]); got != "cause,id,received,relay,size" {
			t.Errorf("row %d, with no section, has the keys: %s", i, got)
		}
	}
	var rows []damagedJSON
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatal(err)
	}
	newerBin, err := os.ReadFile(damagedPathOf(t, bs, relayName, newerID))
	if err != nil {
		t.Fatal(err)
	}
	want := []damagedJSON{
		{Relay: relayName, ID: 50, Received: old, Size: int64(len("garbled")), Cause: "did not decrypt"},
		{Relay: relayName, ID: 51, Received: cutTime, Size: 3},
		{Relay: relayName, ID: 60, Received: misTime, Size: int64(len("misnamed"))},
		{Relay: relayName, ID: newerID, Received: rows[3].Received, Size: int64(len(newerBin)), Cause: `newer: section "ls-later"`, Section: "ls-later"},
	}
	for i := range want {
		if !rows[i].Received.Equal(want[i].Received) {
			t.Errorf("row %d received %v; want %v", i, rows[i].Received, want[i].Received)
		}
		rows[i].Received = want[i].Received
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("ls --json:\n%+v\nwant:\n%+v", rows, want)
	}
	if rec := damagedRecord(t, bs, relayName, newerID); !rows[3].Received.Equal(rec.Received) {
		t.Errorf("the newer row's time %v is not its record's %v", rows[3].Received, rec.Received)
	}
}

// A record an earlier release wrote says nothing of what the listing said:
// it reopens, running the envelope's own half of each check, and says
// which checks could not run, in the line and as unchecked in --json.
func TestAnEarlierReleasesRecordReopensAndSaysWhatCouldNotRun(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "kept by v0.16.0", critical("old-record"))
	postSections(t, alice, bob, "also kept by v0.16.0", critical("old-record"))
	ids := keptNewer(t, bob, 2)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	for _, id := range ids {
		rec := damagedRecord(t, bs, relayName, id)
		when, err := json.Marshal(rec.Received)
		if err != nil {
			t.Fatal(err)
		}
		cause, err := json.Marshal(rec.Cause)
		if err != nil {
			t.Fatal(err)
		}
		// The four fields v0.15.0 and v0.16.0 wrote, as they wrote them.
		old := fmt.Sprintf("{\n  \"relay_id\": %d,\n  \"relay\": %q,\n  \"received\": %s,\n  \"cause\": %s\n}\n", id, relayName, when, cause)
		bin := damagedPathOf(t, bs, relayName, id)
		if err := os.WriteFile(strings.TrimSuffix(bin, ".bin")+".json", []byte(old), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if rows, stderr := lsDamaged(t, bob); len(rows) != 2 || stderr != "" {
		t.Fatalf("an earlier release's records are not listed: %+v\n%s", rows, stderr)
	}
	t.Cleanup(wire.Register("old-record", wire.OnMessage))
	out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(ids[0], 10))
	want := fmt.Sprintf("%s %d: opened and filed in the inbox; its record does not say the kind it was listed under or "+
		"the channel it was listed under, so that check could not run\n", relayName, ids[0])
	if out != want {
		t.Errorf("reopen said:\n%q\nwant:\n%q", out, want)
	}
	rows := reopenJSONOf(t, bob, "--all")
	if len(rows) != 1 || rows[0].Outcome != reopenFiled || rows[0].Box != "inbox" ||
		!reflect.DeepEqual(rows[0].Unchecked, []string{"the kind it was listed under", "the channel it was listed under"}) {
		t.Errorf("reopen --all --json: %+v", rows)
	}
	for _, subject := range []string{"kept by v0.16.0", "also kept by v0.16.0"} {
		if m := recordOf(t, bob, store.Inbox, subject); m.Relay != relayName || m.OnRelay || m.RelaySize != 0 {
			t.Errorf("%q filed with relay %q on relay %v size %d", subject, m.Relay, m.OnRelay, m.RelaySize)
		}
	}
}

// A record that says the relay listed the message as a knock, or filed it
// under another channel than it was sealed for, fails the check the fetch
// would have run: it is left byte for byte and said. A record's via is
// carried onto what is filed, as the fetch carries the listing's.
func TestAKeptRecordTheListingContradictsIsLeft(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "listed as a knock", critical("contradicted"))
	postSections(t, alice, bob, "filed elsewhere", critical("contradicted"))
	postSections(t, alice, bob, "came through another relay", critical("contradicted"))
	ids := keptNewer(t, bob, 3)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	edit := func(id int64, change func(*store.DamagedRecord)) {
		rec := damagedRecord(t, bs, relayName, id)
		change(&rec)
		writeRecord(t, bs, rec)
	}
	edit(ids[0], func(r *store.DamagedRecord) { r.Kind = relayapi.KindKnock })
	edit(ids[1], func(r *store.DamagedRecord) { r.Channel = "elsewhere" })
	edit(ids[2], func(r *store.DamagedRecord) { r.Via = "upstream.example" })
	before := map[int64][2][]byte{ids[0]: keptPair(t, bs, relayName, ids[0]), ids[1]: keptPair(t, bs, relayName, ids[1])}
	t.Cleanup(wire.Register("contradicted", wire.OnMessage))
	for id, want := range map[int64]string{
		ids[0]: `it was listed as "knock" and sealed as "ask", and is left where it is`,
		ids[1]: `it was filed under "elsewhere" and sealed for "default", and is left where it is`,
		ids[2]: "opened and filed in the inbox",
	} {
		out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(id, 10))
		if w := fmt.Sprintf("%s %d: %s\n", relayName, id, want); out != w {
			t.Errorf("reopen %d said %q; want %q", id, out, w)
		}
	}
	for id, pair := range before {
		if after := keptPair(t, bs, relayName, id); !bytes.Equal(after[0], pair[0]) || !bytes.Equal(after[1], pair[1]) {
			t.Errorf("relay message %d's kept files changed", id)
		}
	}
	for _, subject := range []string{"listed as a knock", "filed elsewhere"} {
		if spoolHas(t, bob, store.Inbox, subject) || spoolHas(t, bob, store.Quarantine, subject) {
			t.Errorf("%q was filed", subject)
		}
	}
	if m := recordOf(t, bob, store.Inbox, "came through another relay"); m.Via != "upstream.example" {
		t.Errorf("the filed record's via is %q; want the record's", m.Via)
	}
}

// TestLimitDamagedIds: a relay message id is 0 or more, to the type's
// maximum, wherever it comes from. Typed at auu damaged reopen, a value
// below 0, past the type's maximum or not a number in ASCII digits is
// refused as no id before anything is read; 0 and the maximum reach the
// record kept under them, and the text forms strconv reads as a number,
// a leading 0, a + and -0, reach the record of the number they read as.
// Read from damaged/, a stem is an id only as the store writes one, so
// that one id has one name: 07, +7, -1 and one past the maximum are
// strays, said and not listed.
func TestLimitDamagedIds(t *testing.T) {
	relayURL := startRelay(t)
	bob := newUser(t, "bob", relayURL)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	for _, id := range []int64{0, 7, math.MaxInt64} {
		if kept, _, err := bs.KeepDamaged(store.DamagedRecord{RelayID: id, Relay: relayName, Received: time.Now(), Cause: "malformed"}, []byte("x")); err != nil || !kept {
			t.Fatal(err)
		}
	}
	before := snapshotHome(t, bob.home)
	for _, text := range []string{"-1", "-9223372036854775808", "9223372036854775808", "18446744073709551616",
		" 7", "7 ", "0x7", "1e3", "1_000", "seven", "", "٧"} {
		// After --, as a person types a value that begins with a dash.
		usageError(t, bob, identity.PrintableText(text)+" is not a relay message id; auu damaged ls lists them",
			"damaged", "reopen", relayName, "--", text)
	}
	// Without --, a negative is read as a flag, and refused as one.
	for _, text := range []string{"-1", "-9223372036854775808"} {
		if _, err := bob.tryRun("damaged", "reopen", relayName, text); err == nil {
			t.Errorf("reopen with the id %s was accepted", text)
		} else if e, ok := err.(*exitError); !ok || e.code != exitUsage {
			t.Errorf("reopen with the id %s: %v; want a usage error", text, err)
		}
	}
	for text, id := range map[string]string{"0": "0", "-0": "0", "7": "7", "07": "7", "+7": "7",
		"9223372036854775807": "9223372036854775807"} {
		usageError(t, bob, relayName+" "+id+` was kept with the cause "malformed", which is never reopened; only a message kept as needing a newer auu is`,
			"damaged", "reopen", relayName, "--", text)
	}
	usageError(t, bob, "nothing is kept for "+relayName+" 1; auu damaged ls lists what is", "damaged", "reopen", relayName, "1")
	if after := snapshotHome(t, bob.home); !reflect.DeepEqual(before, after) {
		t.Error("a refused id changed the home")
	}

	dir := filepath.Join(bs.DamagedDir(), relayName)
	var strays []string
	for _, stem := range []string{"07", "+7", "-1", "9223372036854775808"} {
		bin := filepath.Join(dir, stem+".bin")
		if err := os.WriteFile(bin, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, stem+".json"), []byte(`{"relay_id":7,"relay":"`+relayName+`","received":"2026-10-01T00:00:00Z","cause":"malformed"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		strays = append(strays, bin)
	}
	rows, stderr := lsDamaged(t, bob)
	var listed []int64
	for _, r := range rows {
		listed = append(listed, r.ID)
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i] < listed[j] })
	if !reflect.DeepEqual(listed, []int64{0, 7, math.MaxInt64}) {
		t.Errorf("ls listed ids %v; want 0, 7 and the maximum", listed)
	}
	for _, p := range strays {
		if !strings.Contains(stderr, "warning: "+p+" is not a kept message and is not listed\n") {
			t.Errorf("the stray %s was not said:\n%s", p, stderr)
		}
	}
	if n, _, err := bs.DamagedKept(); err != nil || n != 3 {
		t.Errorf("damaged/ counts %d (%v); want the three kept and no stray", n, err)
	}
}

// TestLimitDamagedReopenNames: the relay name and id typed at auu damaged
// reopen become damaged/<relay>/<id>.bin and .json, which reopen reads and
// removes. Each value of the traversal set, as the relay name and as the
// id, is refused at the command before any file is touched, and the
// store's ReadDamaged and RemoveDamaged refuse each name themselves; a
// kept pair planted where each relative name would land, and a witness
// outside the home, are still there and as they were. Two of the set are
// relay names, a name ending in a dot, which an older home may hold, and
// the upper case of an id: each is taken as a name, finds nothing kept
// and is refused as that, with the same files untouched.
func TestLimitDamagedReopenNames(t *testing.T) {
	relayURL := startRelay(t)
	scratch := t.TempDir()
	bob := &user{t: t, home: filepath.Join(scratch, "home")}
	bob.run("init", "--name", "bob", "--relay", relayURL)
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	if err := os.MkdirAll(bs.DamagedDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(scratch, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	// Where damaged/<name>/1.bin lands for the relative names: a kept
	// message's pair, as reopen would read and remove it.
	record := `{"relay_id":1,"relay":"work","received":"2026-10-01T00:00:00Z","cause":"newer: section \"x\""}`
	for _, d := range []string{bob.home, filepath.Join(bob.home, "x"), filepath.Join(bob.home, "y"),
		filepath.Join(bs.DamagedDir(), "a", "b"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "1.bin"), []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "1.json"), []byte(record), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotHome(t, scratch)
	for _, name := range append(pathSet(), outside) {
		_, err := bob.tryRun("damaged", "reopen", name, "1")
		var e *exitError
		if store.ValidRelayName(name) == nil {
			if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "nothing is kept for") {
				t.Errorf("reopen with the relay name %q: %v; want it refused as nothing kept", name, err)
			}
			if _, _, err := bs.ReadDamaged(name, 1); !errors.Is(err, store.ErrNotDamaged) {
				t.Errorf("ReadDamaged with the relay name %q: %v; want nothing kept", name, err)
			}
			continue
		}
		if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "relay name ") {
			t.Errorf("reopen with the relay name %q: %v; want it refused as no relay name", name, err)
		}
		if _, _, err := bs.ReadDamaged(name, 1); err == nil || errors.Is(err, store.ErrNotDamaged) {
			t.Errorf("ReadDamaged with the relay name %q: %v; want the refusal", name, err)
		}
		if err := bs.RemoveDamaged(name, 1); err == nil {
			t.Errorf("RemoveDamaged with the relay name %q was accepted", name)
		}
	}
	for _, id := range pathSet() {
		_, err := bob.tryRun("damaged", "reopen", relayName, id)
		var e *exitError
		if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "is not a relay message id") {
			t.Errorf("reopen with the id %q: %v; want it refused as no id", id, err)
		}
	}
	for _, id := range []int64{-1, math.MinInt64} {
		if err := bs.RemoveDamaged(relayName, id); err == nil {
			t.Errorf("RemoveDamaged with the id %d was accepted", id)
		}
		if _, _, err := bs.ReadDamaged(relayName, id); err == nil {
			t.Errorf("ReadDamaged with the id %d was accepted", id)
		}
	}
	if after := snapshotHome(t, scratch); !reflect.DeepEqual(before, after) {
		var changed []string
		for k := range after {
			if !bytes.Equal(before[k], after[k]) {
				changed = append(changed, k)
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				changed = append(changed, k+" (gone)")
			}
		}
		t.Errorf("a refused name touched files: %v", changed)
	}
}

// An id already held from another sender is a collision: reopen leaves the
// kept message where it is, byte for byte, says so, and leaves the held
// record alone. The held record is made by hand under the kept message's
// own inner id, which the test learns by opening the kept bytes itself.
func TestReopenOfAnIdHeldFromAnotherSenderIsLeft(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "the kept one", critical("collide-later"))
	id := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	before := keptPair(t, bs, relayName, id)
	bobID, err := bs.Identity()
	if err != nil {
		t.Fatal(err)
	}
	var env envelope.Envelope
	if err := json.Unmarshal(before[0], &env); err != nil {
		t.Fatal(err)
	}
	unregister := wire.Register("collide-later", wire.OnMessage)
	inner, _, err := envelope.Open(bobID, &env)
	unregister()
	if err != nil {
		t.Fatalf("opening the kept bytes: %v", err)
	}
	carol, err := identity.Generate("carol")
	if err != nil {
		t.Fatal(err)
	}
	inner.From, inner.FromBundle = carol.Fingerprint(), carol.Public().Bundle()
	inner.Body.Subject = "carol's, under the same id"
	if err := bs.Save(store.Inbox, &store.Stored{RelayID: 1, Relay: relayName, Received: time.Now().UTC(), Inner: inner}); err != nil {
		t.Fatal(err)
	}
	held, err := bs.Load(store.Inbox, inner.ID)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(wire.Register("collide-later", wire.OnMessage))
	out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(id, 10))
	if want := fmt.Sprintf("%s %d: its id is held from another sender, so it is left where it is\n", relayName, id); out != want {
		t.Errorf("reopen said %q; want %q", out, want)
	}
	if rows := reopenJSONOf(t, bob, "--all"); len(rows) != 1 || rows[0].Outcome != reopenCollided {
		t.Errorf("reopen --all --json: %+v; want collided", rows)
	}
	if after := keptPair(t, bs, relayName, id); !bytes.Equal(after[0], before[0]) || !bytes.Equal(after[1], before[1]) {
		t.Error("the kept files changed")
	}
	if again, err := bs.Load(store.Inbox, inner.ID); err != nil || !reflect.DeepEqual(again, held) {
		t.Errorf("the held record changed (%v):\n%+v\nwas\n%+v", err, again, held)
	}
	if msgs, err := bs.List(store.Inbox); err != nil || len(msgs) != 1 {
		t.Errorf("the inbox holds %d (%v); want the held record alone", len(msgs), err)
	}
}

// A vouch for the reader kept as newer is, once reopened, kept for the
// reader's knocks as keepVouches keeps one after a fetch: reopen runs it
// over what it filed.
func TestAReopenedVouchIsKeptForKnocks(t *testing.T) {
	alice, bob, _ := peered(t)
	aliceID, c := sender(t, alice)
	bobPub := mustParseBundle(t, mustBundle(t, bob))
	now := time.Now()
	doc, sig, err := vouch.Sign(aliceID, &vouch.Document{
		Subject: bobPub.Fingerprint(), Bundle: bobPub.Bundle(), Name: "bob", Issued: now.UTC(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := envelope.SealSections(aliceID, bobPub, "", message.Body{
		Type: message.TypeVouch, Thread: thread, Subject: "vouch for bob", Vouch: &message.Carried{Document: doc, Signature: sig},
	}, critical("vouch-later"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(context.Background(), env, ""); err != nil {
		t.Fatal(err)
	}
	id := keptNewer(t, bob, 1)[0]
	bs := storeOf(t, bob)
	if _, err := bs.KeptVouch(aliceID.Fingerprint()); !errors.Is(err, store.ErrNoVouch) {
		t.Fatalf("a vouch was kept before the reopen: %v", err)
	}
	t.Cleanup(wire.Register("vouch-later", wire.OnMessage))
	bob.run("damaged", "reopen", bob.defaultRelayName(), strconv.FormatInt(id, 10))
	kept, err := bs.KeptVouch(aliceID.Fingerprint())
	if err != nil {
		t.Fatalf("the reopened vouch was not kept: %v", err)
	}
	if !bytes.Equal(kept.Document, doc) {
		t.Error("the kept vouch is not the one sent")
	}
}

// A knock kept as newer by an earlier release, whose record does not say
// it was listed as a knock, reopens: the kind check, which the envelope
// has no half of, is skipped rather than run against a listing the record
// does not have, which would leave every such knock as miskinded. It is
// filed in the quarantine, since its knocker is nobody's peer, never as
// kept on the relay, and the line says the check could not run.
func TestAnEarlierReleasesKnockReopensWithoutTheKindCheck(t *testing.T) {
	relayURL := startRelay(t)
	carol := newUser(t, "carol", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--knocks")
	carolID, c := sender(t, carol)
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := envelope.SealSections(carolID, mustParseBundle(t, mustBundle(t, bob)), "",
		message.Body{Type: message.TypeKnock, Thread: thread, Name: "carol", Text: "a knock from a newer build"}, critical("knock-later"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Knock(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	id := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	rec := damagedRecord(t, bs, relayName, id)
	if rec.Kind != relayapi.KindKnock {
		t.Fatalf("the record does not say the row was listed as a knock: %+v", rec)
	}
	when, err := json.Marshal(rec.Received)
	if err != nil {
		t.Fatal(err)
	}
	cause, err := json.Marshal(rec.Cause)
	if err != nil {
		t.Fatal(err)
	}
	// The four fields v0.15.0 and v0.16.0 wrote, as they wrote them.
	old := fmt.Sprintf("{\n  \"relay_id\": %d,\n  \"relay\": %q,\n  \"received\": %s,\n  \"cause\": %s\n}\n", id, relayName, when, cause)
	bin := damagedPathOf(t, bs, relayName, id)
	if err := os.WriteFile(strings.TrimSuffix(bin, ".bin")+".json", []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wire.Register("knock-later", wire.OnMessage))
	out := bob.run("damaged", "reopen", relayName, strconv.FormatInt(id, 10))
	want := fmt.Sprintf("%s %d: opened and filed in the quarantine; its record does not say the kind it was listed under or "+
		"the channel it was listed under, so that check could not run\n", relayName, id)
	if out != want {
		t.Errorf("reopen said:\n%q\nwant:\n%q", out, want)
	}
	keptGone(t, bs, relayName, id)
	held := bob.quarantined()
	if len(held) != 1 {
		t.Fatalf("the quarantine holds %d; want the knock", len(held))
	}
	if m := held[0]; m.Inner.Body.Type != message.TypeKnock || m.Inner.Body.Text != "a knock from a newer build" ||
		m.OnRelay || m.Relay != relayName || m.RelayID != id {
		t.Errorf("the filed knock: type %q text %q on relay %v relay %q id %d; want the knock, not on the relay, from %s %d",
			m.Inner.Body.Type, m.Inner.Body.Text, m.OnRelay, m.Relay, m.RelayID, relayName, id)
	}
	if msgs, err := bs.List(store.Inbox); err != nil || len(msgs) != 0 {
		t.Errorf("the inbox holds %d (%v); want nothing", len(msgs), err)
	}
}

// A record that decodes under encoding/json's rule but not the wire's,
// here one with a field this build does not know, does not read: damaged
// ls says so with the decoder's reason, reopen refuses it at exit 1 naming
// the record and the reason, --all passes over it, and its files are left.
func TestAKeptRecordWithAnUnknownFieldIsNeverReopened(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "beside a future field", critical("future-field"))
	id := keptNewer(t, bob, 1)[0]
	relayName := bob.defaultRelayName()
	bs := storeOf(t, bob)
	rec := damagedRecord(t, bs, relayName, id)
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	record := strings.TrimSuffix(damagedPathOf(t, bs, relayName, id), ".bin") + ".json"
	if err := os.WriteFile(record, append(bytes.TrimSuffix(data, []byte("}")), []byte(`,"future":1}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	before := keptPair(t, bs, relayName, id)
	if out := bob.run("damaged", "ls"); !strings.Contains(out, `unreadable record: json: unknown field "future"`) {
		t.Errorf("damaged ls does not say the record does not read:\n%s", out)
	}
	t.Cleanup(wire.Register("future-field", wire.OnMessage))
	usageError(t, bob, fmt.Sprintf("%s %d is kept beside a record that does not read (%s: json: unknown field \"future\"), which is never reopened; "+
		"only a message kept as needing a newer auu is", relayName, id, record), "damaged", "reopen", relayName, strconv.FormatInt(id, 10))
	if rows := reopenJSONOf(t, bob, "--all"); len(rows) != 0 {
		t.Errorf("reopen --all: %+v; want nothing reopened", rows)
	}
	if after := keptPair(t, bs, relayName, id); !bytes.Equal(after[0], before[0]) || !bytes.Equal(after[1], before[1]) {
		t.Error("the pair beside a record that does not read changed")
	}
	if spoolHas(t, bob, store.Inbox, "beside a future field") {
		t.Error("a message beside a record that does not read was filed")
	}
}

// A kept record naming its relay in another case is that relay (S62), by
// the rule the home's names are taken under: reopen waits on that relay's
// fetch lock and files the message as from it. It matched the name byte for
// byte, so on a filesystem that folds case it reached the relay's directory
// under a name the home does not have, with no lock taken, and on one that
// does not it took the relay for one since removed. A record naming a
// relay since removed still reaches no other (TestAHeldLockMidwayIsSaidWithTheCount).
func TestReopenFindsTheRelayARecordNamesInAnotherCase(t *testing.T) {
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "kept under another case", critical("fold-later"))
	id := keptNewer(t, bob, 1)[0]
	bob.run("relay", "rename", bob.defaultRelayName(), "work")
	bs := storeOf(t, bob)
	t.Cleanup(wire.Register("fold-later", wire.OnMessage))
	entries, _, err := bs.DamagedEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("the kept message: %+v, %v", entries, err)
	}
	moveKept(t, bs, entries[0].Relay, id, "WORK", time.Now().Add(-time.Hour))
	r, err := bs.Relay("work")
	if err != nil || r.Name != "work" {
		t.Fatalf("the relay: %+v, %v", r, err)
	}
	held, err := lockfile.Try(filepath.Join(bs.RelayDir(r), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	waited := false
	fetchLockSleep = func(time.Duration) {
		waited = true
		held.Release()
	}
	t.Cleanup(func() { held.Release(); fetchLockSleep = time.Sleep })
	out, stderr, err := reopenDamaged(t, bob, "--all")
	if err != nil {
		t.Fatalf("reopen: %v\n%s\n%s", err, out, stderr)
	}
	if !waited {
		t.Fatal("reopen of a record naming WORK never waited on work's fetch lock")
	}
	if m := recordOf(t, bob, store.Inbox, "kept under another case"); m.Relay != "work" {
		t.Errorf("the message was filed as from %q; want work", m.Relay)
	}
	keptGone(t, bs, "WORK", id)
}
