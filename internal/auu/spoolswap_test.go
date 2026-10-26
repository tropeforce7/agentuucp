package auu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// An identical sealed message can be delivered through two relays. A failed
// download of the second copy must preserve the already verified first copy.
func TestAnInterruptedSecondRelayDeliveryKeepsTheStoredAttachments(t *testing.T) {
	work, workStore := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	personal, personalStore := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	var served, cuts atomic.Int64
	var drop atomic.Bool
	front := adv2CountingFront(t, personal, &served, &cuts, &drop)
	alice := onBothRelays(t, "alice", work.URL, front.URL)
	bob := onBothRelays(t, "bob", work.URL, front.URL)
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "keep", "default", "off")
	as, aid, _ := alice.opened()
	bs, bid, _ := bob.opened()
	payload := bytes.Repeat([]byte("verified content"), 20000)
	sources := []stream.Source{{Name: "data.bin", Media: "application/octet-stream", Size: int64(len(payload)), Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }}}
	mid := strings.Repeat("a", 32)
	m, err := stream.BuildManifest(aid, bid.Public(), mid, stream.Body{Type: "ask", Thread: mid, Subject: "two relays", Text: "same sealed copy"}, sources, stream.DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, aid, bid.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"work", "personal"} {
		r, err := as.Relay(name)
		if err != nil {
			t.Fatal(err)
		}
		c, err := dial(as, aid, r)
		if err != nil {
			t.Fatal(err)
		}
		upload, err := c.OpenStream(context.Background(), bid.Fingerprint(), "", int64(blob.Len()), 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.PutStream(context.Background(), upload.Upload, 0, bytes.NewReader(blob.Bytes()), int64(blob.Len())); err != nil {
			t.Fatal(err)
		}
	}
	bob.run("inbox", "--relay", "work", "--json")
	path := filepath.Join(bs.AttachmentDir(store.Inbox, mid), "0")
	before, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, payload) {
		t.Fatalf("first delivery: %v", err)
	}
	if rows := adv2RowIDs(t, workStore, bid.Fingerprint()); len(rows) != 0 {
		t.Fatalf("first copy not acknowledged: %v", rows)
	}
	drop.Store(true)
	_, err = bob.tryRun("inbox", "--relay", "personal", "--json")
	if err == nil || cuts.Load() == 0 {
		t.Fatalf("expected interrupted second download, cuts=%d err=%v", cuts.Load(), err)
	}
	t.Logf("second fetch: %v; cuts=%d", err, cuts.Load())
	rec, err := bs.Load(store.Inbox, mid)
	if err != nil || rec.Relay != "work" {
		t.Fatalf("original record: %+v %v", rec, err)
	}
	if rows := adv2RowIDs(t, personalStore, bid.Fingerprint()); len(rows) != 1 {
		t.Fatalf("second copy should remain retryable: %v", rows)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, payload) {
		t.Errorf("failed second delivery destroyed verified first attachment: %v", readErr)
	}
	drop.Store(false)
	bob.run("inbox", "--relay", "personal", "--json")
	recovered, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(recovered, payload) {
		t.Fatalf("retry control: %v", err)
	}
}

// The swap's own rows (G29, R44), on a store of its own: a fill that fails
// leaves the placed files as they were; a save that fails puts the old
// files back, and leaves no files for a first delivery whose record would
// not save; a swap a crash cut short, the old files aside and none in
// place, is put back by the next; and two swaps of one message never run
// their saves at once.
func TestASpoolIsSwappedOnlyWhenTheCopyIsWhole(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.AttachmentDir(store.Inbox, strings.Repeat("b", 32))
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	fillWith := func(text string) func(string) error {
		return func(target string) error {
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(target, "0"), []byte(text), 0o600)
		}
	}
	holds := func(want string) {
		t.Helper()
		got, err := os.ReadFile(filepath.Join(dir, "0"))
		if err != nil || string(got) != want {
			t.Fatalf("the spool holds %q, %v; want %q", got, err, want)
		}
		left, _ := filepath.Glob(dir + ".*")
		if len(left) != 0 {
			t.Fatalf("left beside the spool: %v", left)
		}
	}
	ok := func() error { return nil }
	ctx := context.Background()

	// A first delivery whose save fails leaves nothing.
	if err := replaceSpool(ctx, s, dir, fillWith("first"), func() error { return io.ErrUnexpectedEOF }); err == nil {
		t.Fatal("a failed save was not said")
	}
	if _, err := os.Lstat(dir); err == nil {
		t.Fatal("a first delivery whose record did not save left its files")
	}
	if err := replaceSpool(ctx, s, dir, fillWith("first"), ok); err != nil {
		t.Fatal(err)
	}
	holds("first")
	// A fill that fails, as a download cut short does.
	if err := replaceSpool(ctx, s, dir, func(string) error { return io.ErrUnexpectedEOF }, ok); err == nil {
		t.Fatal("a failed fill was not said")
	}
	holds("first")
	// A save that fails puts the old files back.
	if err := replaceSpool(ctx, s, dir, fillWith("second"), func() error { return io.ErrUnexpectedEOF }); err == nil {
		t.Fatal("a failed save was not said")
	}
	holds("first")
	if err := replaceSpool(ctx, s, dir, fillWith("second"), ok); err != nil {
		t.Fatal(err)
	}
	holds("second")
	// A crash between moving the old files aside and placing the new.
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSpool(ctx, s, dir, func(string) error { return io.ErrUnexpectedEOF }, ok); err == nil {
		t.Fatal("a failed fill was not said")
	}
	if _, err := os.Lstat(dir + ".old"); err != nil {
		t.Fatal("a failed fill touched what a crash left; the next swap puts it back")
	}
	if err := replaceSpool(ctx, s, dir, fillWith("third"), ok); err != nil {
		t.Fatal(err)
	}
	holds("third")
	// A crash after the save and before the old files were removed: the
	// old files aside beside the placed ones go at the next swap.
	if err := os.Mkdir(dir+".old", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := replaceSpool(ctx, s, dir, fillWith("third again"), ok); err != nil {
		t.Fatal(err)
	}
	holds("third again")

	// Two swaps at once: the second's save waits for the first's.
	var inSave, overlapped atomic.Bool
	save := func() error {
		if inSave.Swap(true) {
			overlapped.Store(true)
		}
		time.Sleep(50 * time.Millisecond)
		inSave.Store(false)
		return nil
	}
	errs := make(chan error, 2)
	for _, text := range []string{"fourth", "fifth"} {
		go func() { errs <- replaceSpool(ctx, s, dir, fillWith(text), save) }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if overlapped.Load() {
		t.Fatal("two swaps of one spool saved at once")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "0")); string(got) != "fourth" && string(got) != "fifth" {
		t.Fatalf("after two swaps the spool holds %q", got)
	}
	if left, _ := filepath.Glob(dir + ".*"); len(left) != 0 {
		t.Fatalf("left beside the spool after two swaps: %v", left)
	}
}

// A swap's staged lock that a sweep of another swap won, in the instant
// between Try's creating the file and its locking it, failed the delivery
// as held at once (S86, seen on macOS in TestASpoolIsSwappedOnlyWhenTheCopyIsWhole).
// The test holds the first name's lock as such a sweep would: the swap goes
// through under a second name and leaves the held lock alone; and with every
// name held it gives up as held once spoolLockWait is over, leaving nothing.
func TestASwapWhoseStagedLockASweepHoldsTakesAFreshName(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.AttachmentDir(store.Inbox, strings.Repeat("b", 32))
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	fresh := newStagedTag
	t.Cleanup(func() { newStagedTag = fresh })
	var tags []string
	newStagedTag = func() (string, error) {
		if len(tags) == 0 {
			tags = append(tags, "held")
			return "held", nil
		}
		tag, err := fresh()
		tags = append(tags, tag)
		return tag, err
	}
	heldLock := dir + ".new-held" + stagedLockSuffix
	held, err := lockfile.Try(heldLock)
	if err != nil {
		t.Fatal(err)
	}
	var filled []string
	fill := func(target string) error {
		filled = append(filled, target)
		if err := os.Mkdir(target, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, "0"), []byte("new"), 0o600)
	}
	if err := replaceSpool(context.Background(), s, dir, fill, func() error { return nil }); err != nil {
		t.Fatalf("a swap whose first staged lock was held: %v", err)
	}
	if len(tags) != 2 || len(filled) != 1 || filled[0] != dir+".new-"+tags[1] {
		t.Fatalf("tags %v, filled %v; want the second tag filled", tags, filled)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "0")); err != nil || string(got) != "new" {
		t.Fatalf("the spool holds %q, %v", got, err)
	}
	if _, err := os.Lstat(heldLock); err != nil {
		t.Fatalf("the swap touched the lock it found held: %v", err)
	}
	if _, err := lockfile.Try(heldLock); !errors.Is(err, lockfile.ErrHeld) {
		t.Fatalf("the held lock is not held after the swap: %v", err)
	}
	held.Release()
	if err := os.Remove(heldLock); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(dir + ".*"); len(left) != 0 {
		t.Fatalf("left beside the spool: %v", left)
	}

	// Every name held: the swap asks again until spoolLockWait is over and
	// then says ErrHeld, filling nothing and leaving nothing of its own.
	wait := spoolLockWait
	t.Cleanup(func() { spoolLockWait = wait })
	spoolLockWait = 3 * lockfile.PollInterval
	asked := 0
	newStagedTag = func() (string, error) { asked++; return "held", nil }
	held, err = lockfile.Try(heldLock)
	if err != nil {
		t.Fatal(err)
	}
	filled = nil
	start := time.Now()
	err = replaceSpool(context.Background(), s, dir, fill, func() error { return nil })
	if !errors.Is(err, lockfile.ErrHeld) {
		t.Fatalf("a swap whose every staged lock was held: %v; want ErrHeld", err)
	}
	if took := time.Since(start); took < spoolLockWait {
		t.Fatalf("the swap gave up after %v, before spoolLockWait %v", took, spoolLockWait)
	}
	if asked < 2 || len(filled) != 0 {
		t.Fatalf("asked %d times, filled %v; want asked again and nothing filled", asked, filled)
	}
	held.Release()
	if left, _ := filepath.Glob(dir + ".*"); len(left) != 1 || left[0] != heldLock {
		t.Fatalf("beside the spool: %v; want the test's own lock alone", left)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "0")); err != nil || string(got) != "new" {
		t.Fatalf("a swap that gave up changed the spool: %q, %v", got, err)
	}
}

// TestLimitAStagedCopyIsSweptOnlyWhenItsLockIsFree: the sweep takes its
// paths from a listing of a box's directory, held to the names the glob
// *.d.new-*.lock matches there; a staged copy a dead process left, whose
// lock is free, goes with its .part at the next swap, and one a live
// delivery holds is left alone.
func TestLimitAStagedCopyIsSweptOnlyWhenItsLockIsFree(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box := filepath.Dir(s.AttachmentDir(store.Inbox, strings.Repeat("b", 32)))
	if err := os.MkdirAll(box, 0o700); err != nil {
		t.Fatal(err)
	}
	fill := func(target string) error { return os.Mkdir(target, 0o700) }
	// A staged copy a dead process left, and one a live delivery holds:
	// the swap sweeps the first and leaves the second.
	dead := filepath.Join(box, strings.Repeat("c", 32)+".d.new-dead")
	live := filepath.Join(box, strings.Repeat("d", 32)+".d.new-live")
	for _, base := range []string{dead, live} {
		if err := os.MkdirAll(base+".part", 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base+".part", "0"), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(dead+stagedLockSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := lockfile.Try(live + stagedLockSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceSpool(context.Background(), s, filepath.Join(box, strings.Repeat("e", 32)+".d"), fill, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dead + ".part"); err == nil {
		t.Fatal("a staged copy a dead process left was not swept")
	}
	if _, err := os.Lstat(dead + stagedLockSuffix); err == nil {
		t.Fatal("a dead staged copy's lock was not swept")
	}
	if _, err := os.Lstat(filepath.Join(live+".part", "0")); err != nil {
		t.Fatalf("a staged copy a live delivery holds was swept: %v", err)
	}
	held.Release()
	os.RemoveAll(live + ".part")
	os.Remove(live + stagedLockSuffix)
}

// TestLimitTheSweepReadsTheHomesPathAsAPath: sweepStaged found the staged
// copies with a glob over the box's joined path, so the home's path was a
// pattern too, and a home at a path holding [x] matched a sibling x and
// removed its staged-looking entries (F3, tracer B's B-2). The box's own
// entries are now read and matched by name: the sibling is untouched and
// the home's own dead staged copy is swept.
func TestLimitTheSweepReadsTheHomesPathAsAPath(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "[x]", "home")
	s, err := store.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	box := filepath.Dir(s.AttachmentDir(store.Inbox, strings.Repeat("b", 32)))
	rel, err := filepath.Rel(home, box)
	if err != nil {
		t.Fatal(err)
	}
	// What the home's path matches as a pattern: x in place of [x].
	sibling := filepath.Join(root, "x", "home", rel)
	own := filepath.Join(box, strings.Repeat("c", 32)+".d.new-dead")
	other := filepath.Join(sibling, strings.Repeat("c", 32)+".d.new-dead")
	for _, base := range []string{own, other} {
		if err := os.MkdirAll(base+".part", 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base+".part", "0"), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(base+stagedLockSuffix, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fill := func(target string) error { return os.Mkdir(target, 0o700) }
	if err := replaceSpool(context.Background(), s, filepath.Join(box, strings.Repeat("e", 32)+".d"), fill, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(other+".part", "0"), other + stagedLockSuffix} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("the sweep removed %s, beside the home: %v", p, err)
		}
	}
	if _, err := os.Lstat(own + ".part"); err == nil {
		t.Error("the home's own dead staged copy was not swept")
	}
}

// Quarantine trust asks the quarantine by name (G31, R46): with a record of
// the same message in the inbox too, as a move cut short before this
// release could leave, Find answers the inbox's and trust's lookup the
// quarantine's, so a trust asked again reaches the move again.
func TestTrustFindsTheQuarantinedRecordBesideAnInboxOne(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("f", 32)
	for _, box := range []store.Box{store.Quarantine, store.Inbox} {
		m := &store.Stored{RelayID: 1, Relay: "relay", Received: time.Now().UTC(), Inner: &envelope.Inner{
			ID: id, From: strings.Repeat("a", 64), To: strings.Repeat("b", 64),
			Body: message.Body{Type: message.TypeAsk, Thread: strings.Repeat("0", 32), Text: string(box)},
		}}
		if err := s.Save(box, m); err != nil {
			t.Fatal(err)
		}
	}
	if box, _, err := s.Find(id); err != nil || box != store.Inbox {
		t.Fatalf("Find answered %s, %v; the case needs the inbox first", box, err)
	}
	for _, asked := range []string{id, id[:8], strings.ToUpper(id[:8])} {
		m, err := quarantined(s, asked)
		if err != nil || m.Inner.Body.Text != string(store.Quarantine) {
			t.Fatalf("trust's lookup of %s: %+v, %v; want the quarantined record", asked, m, err)
		}
	}
	if _, err := quarantined(s, strings.Repeat("e", 32)); err == nil {
		t.Fatal("a message in no box was found")
	}
}
