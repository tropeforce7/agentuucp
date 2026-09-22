package relay

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
)

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

// The store's own rules for a push: ordered by issue between two rows that
// verify, the same bytes a no-op, a row that does not verify replaced
// whatever its time, and the column never read to decide.
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

	// A row that no longer verifies, its issued moved an hour ahead by
	// the same editor: the signature blanked, one bit of it flipped, then
	// the document edited under the intact signature. Each is no bar to a
	// push issued now, since the rule holds only between two directories
	// the owner signed; against the rule as it was, the owner was refused
	// for a time an editor chose. Then the column alone moved a century
	// ahead under a row that verifies, and a column that is not a time:
	// the push is held to the time inside the document, so each is taken.
	ahead := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	repair := func(what string) {
		t.Helper()
		d, doc, sig := signedDirectory(t, bob, time.Now(), channels.Channel{Name: "default"}, channels.Channel{Name: "repaired"})
		if stored, err := s.SetDirectory(fp, d, doc, sig); err != nil || !stored {
			t.Fatalf("a push over %s: stored %v, %v", what, stored, err)
		}
		if got, gotSig, _, _ := s.Directory(fp); string(got) != string(doc) || string(gotSig) != string(sig) {
			t.Fatalf("after the push over %s the stored pair is not the pushed one", what)
		}
		if exists, _, _ := s.ChannelState(fp, "repaired"); !exists {
			t.Fatalf("after the push over %s the channel rows are not the pushed ones", what)
		}
	}
	if _, err := s.db.Exec(`UPDATE directories SET sig = X'', issued = ? WHERE fp = ?`, ahead, fp); err != nil {
		t.Fatal(err)
	}
	repair("a blanked signature issued ahead")
	_, currentSig, _, _ := s.Directory(fp)
	flipped := append([]byte{}, currentSig...)
	flipped[len(flipped)/2] ^= 0x01
	if _, err := s.db.Exec(`UPDATE directories SET sig = ?, issued = ? WHERE fp = ?`, flipped, ahead, fp); err != nil {
		t.Fatal(err)
	}
	repair("a flipped signature issued ahead")
	current, _, _, _ := s.Directory(fp)
	edited := strings.Replace(string(current), `"name":"repaired"`, `"name":"replaced"`, 1)
	if edited == string(current) {
		t.Fatal("the document has no channel name to edit")
	}
	if _, err := s.db.Exec(`UPDATE directories SET doc = ?, issued = ? WHERE fp = ?`, []byte(edited), ahead, fp); err != nil {
		t.Fatal(err)
	}
	repair("an edited document issued ahead")
	if _, err := s.db.Exec(`UPDATE directories SET issued = '2126-01-01T00:00:00Z' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	repair("a verified row whose column alone was moved a century ahead")
	if _, err := s.db.Exec(`UPDATE directories SET issued = 'yesterday' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	repair("a verified row whose column is not a time")

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
