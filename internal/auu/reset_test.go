package auu

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A cursor past everything a relay holds (reset.go): the relay's numbering
// begun again, the newest mail removed, and the cases a reset must leave as
// they were.

// resettable is a relay behind the counting gate whose database the test
// can reach, so that its numbering can be begun again as an operator who
// deleted the database would begin it, without losing the mailboxes the
// test's people are registered in.
type resettable struct {
	url  string
	gate *waitGate
	st   *relay.Store
	db   string
}

func startResettable(t *testing.T) *resettable {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "relay.db")
	st, err := relay.OpenStore(db, filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	gate := &waitGate{inner: relay.NewServer(st, relay.Config{
		Streams: true,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limits:  relay.DefaultLimits(),
	})}
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)
	return &resettable{url: srv.URL, gate: gate, st: st, db: db}
}

// renumber empties a mailbox and begins the relay's numbering again from
// 1, which is what a relay whose database was deleted does: the next
// message posted is 1 whatever any machine's cursor says.
func (r *resettable) renumber(t *testing.T, fp string) {
	t.Helper()
	for _, id := range queuedOn(t, r.st, fp) {
		if gone, err := r.st.Delete(fp, id); err != nil || !gone {
			t.Fatalf("delete %d: %v %v", id, gone, err)
		}
	}
	db, err := sql.Open("sqlite", r.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM sqlite_sequence WHERE name = 'messages'`); err != nil {
		t.Fatal(err)
	}
}

// cursorIs is the cursor file's number.
func cursorIs(t *testing.T, u *user) int64 {
	t.Helper()
	data, err := os.ReadFile(u.cursorPath(u.defaultRelayName()))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// fetchSaying is inbox --json with what it said on standard error.
func fetchSaying(t *testing.T, u *user, args ...string) (inboxJSON, string) {
	t.Helper()
	var in inboxJSON
	said := captureStderr(t, func() { in = u.inboxJSON(args...) })
	return in, said
}

// spoolFiles counts the records in a box, which is what says a message met
// twice is one message on disk.
func spoolFiles(t *testing.T, u *user, box store.Box) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(u.home, string(box)))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// The plan's four cursors against what the relay holds. Above everything,
// with mail this machine has never had: fetched once, from the relay's
// first id, with the sentence, and the cursor at the last id fetched.
// Above an empty mailbox: back to zero, nothing delivered and nothing said,
// since nothing was found. Inside the span: what is after it, and silence.
// Below the first: everything, and silence.
func TestACursorPastEverythingTheRelayHolds(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "one", "1")
	alice.run("send", "--to", "bob", "--subject", "two", "2")
	ids := queuedOn(t, r.st, bob.exportFingerprint())
	bob.setCursor(name, strconv.FormatInt(ids[1]+1, 10)+"\n")
	in, said := fetchSaying(t, bob)
	want := name + ": this machine's cursor was " + strconv.FormatInt(ids[1]+1, 10) + " and the relay's mail is numbered " +
		strconv.FormatInt(ids[0], 10) + " to " + strconv.FormatInt(ids[1], 10) +
		", so the cursor was reset and mail is fetched from the beginning; nothing is delivered twice here\n"
	if in.Fetch.Delivered != 2 || said != want {
		t.Fatalf("cursor above both: %+v, said %q, want %q", in.Fetch, said, want)
	}
	if got := cursorIs(t, bob); got != ids[1] {
		t.Fatalf("the cursor after the reset is %d, want %d", got, ids[1])
	}
	if n := spoolFiles(t, bob, store.Inbox); n != 2 {
		t.Fatalf("the inbox holds %d records, want 2", n)
	}
	// Once only: the next fetch says nothing and fetches nothing.
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch after: %+v, said %q", in.Fetch, said)
	}

	// An empty mailbox: back to zero, silently, without a listing of
	// stubs, since there is nothing to match.
	for _, id := range ids {
		bob.run("rm", recordByRelayID(t, bob, id).Inner.ID[:12])
	}
	bob.setCursor(name, "3\n")
	stubs := r.gate.stubsLists.Load()
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("cursor 3 against an empty mailbox: %+v, said %q", in.Fetch, said)
	}
	if got := cursorIs(t, bob); got != 0 {
		t.Fatalf("the cursor against an empty mailbox is %d, want 0", got)
	}
	if n := r.gate.stubsLists.Load() - stubs; n != 0 {
		t.Fatalf("%d stubs listings for an empty mailbox, want none", n)
	}

	// Inside the span: the cursor is believed, and what is after it is
	// fetched, with nothing said. The three before it are kept mail this
	// machine fetched.
	for i := range 3 {
		alice.run("send", "--to", "bob", "--subject", "five "+strconv.Itoa(i), "x")
	}
	bob.run("inbox")
	for i := 3; i < 5; i++ {
		alice.run("send", "--to", "bob", "--subject", "five "+strconv.Itoa(i), "x")
	}
	five := queuedOn(t, r.st, bob.exportFingerprint())
	if got := cursorIs(t, bob); got != five[2] {
		t.Fatalf("the cursor before the two is %d, want %d", got, five[2])
	}
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 2 || said != "" {
		t.Fatalf("a cursor inside the span: %+v, said %q", in.Fetch, said)
	}
	// Below the first: everything after it, and silence.
	for _, id := range five {
		bob.run("rm", recordByRelayID(t, bob, id).Inner.ID[:12])
	}
	alice.run("send", "--to", "bob", "--subject", "six", "x")
	alice.run("send", "--to", "bob", "--subject", "seven", "x")
	bob.setCursor(name, strconv.FormatInt(five[1], 10)+"\n")
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 2 || said != "" {
		t.Fatalf("a cursor below the first: %+v, said %q", in.Fetch, said)
	}
}

// recordByRelayID is the inbox record a relay id was fetched as.
func recordByRelayID(t *testing.T, u *user, id int64) *store.Stored {
	t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(store.Inbox)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.RelayID == id {
			return m
		}
	}
	t.Fatalf("no record fetched as %d", id)
	return nil
}

// The ordinary day: the newest message kept on the relay is removed, which
// leaves the cursor above the relay's last id with nothing wrong. The next
// fetch is silent, delivers nothing and leaves every record, read mark and
// all, as it was; it costs one stubs listing a page of the relay's rows and
// downloads no envelope. Five hundred kept messages is three pages.
func TestRemovingTheNewestMailIsNotAReset(t *testing.T) {
	if testing.Short() {
		t.Skip("sends five hundred messages")
	}
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	const n = 500
	// Sealed by alice and put on the relay directly: five hundred posts
	// through the route would meet its posts-per-minute limit, which is
	// not what this is about.
	_, aliceID, _ := alice.opened()
	_, bobID, _ := bob.opened()
	bobPub := bobID.Public()
	for i := range n {
		env, _, err := envelope.SealFor(aliceID, bobPub, "", message.Body{Type: message.TypeAsk,
			Thread: strings.Repeat("a", 32), Subject: "kept " + strconv.Itoa(i), Text: "x"})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.st.Put(bob.exportFingerprint(), "default", relayapi.KindEnvelope, "", raw, relay.Quotas{}, relay.Forwarded{}); err != nil {
			t.Fatal(err)
		}
	}
	// The fetch itself, without the command's listing: five hundred
	// messages printed would fill the pipe this test reads output from.
	fetchDirect := func() (fetchResult, string) {
		t.Helper()
		s, id, relays := bob.opened()
		c, err := dial(s, id, relays[0])
		if err != nil {
			t.Fatal(err)
		}
		var res fetchResult
		said := captureStderr(t, func() { res, _, err = fetch(context.Background(), s, id, c, relays[0], 0) })
		if err != nil {
			t.Fatal(err)
		}
		return res, said
	}
	if res, _ := fetchDirect(); res.Delivered != n {
		t.Fatalf("delivered %d, want %d", res.Delivered, n)
	}
	first := recordOf(t, bob, store.Inbox, "kept 0")
	bob.run("read", first.Inner.ID[:12])
	before := map[string]string{}
	snapshot := func() map[string]string {
		out := map[string]string{}
		entries, _ := os.ReadDir(filepath.Join(bob.home, "inbox"))
		for _, e := range entries {
			data, _ := os.ReadFile(filepath.Join(bob.home, "inbox", e.Name()))
			out[e.Name()] = string(data)
		}
		return out
	}
	newest := recordOf(t, bob, store.Inbox, "kept "+strconv.Itoa(n-1))
	bob.run("rm", newest.Inner.ID[:12])
	before = snapshot()
	stubs, lists, requests := r.gate.stubsLists.Load(), r.gate.lists.Load(), r.gate.requests.Load()
	res, said := fetchDirect()
	if res.Delivered != 0 || said != "" {
		t.Fatalf("the fetch after removing the newest: %+v, said %q", res, said)
	}
	after := snapshot()
	if len(after) != len(before) {
		t.Fatalf("%d records before, %d after", len(before), len(after))
	}
	for name, data := range before {
		if after[name] != data {
			t.Fatalf("the record %s changed:\n%s\nto\n%s", name, data, after[name])
		}
	}
	if !recordOf(t, bob, store.Inbox, "kept 0").Read {
		t.Fatal("the read mark went")
	}
	if got := cursorIs(t, bob); got != newest.RelayID-1 {
		t.Fatalf("the cursor is %d, want the relay's last, %d", got, newest.RelayID-1)
	}
	// Three pages of stubs, and two listings besides: the first, empty
	// page that found the cursor past, and the one after the cursor was
	// set back, empty too. No blob, no body.
	pages := int32((n - 1 + 199) / 200)
	if got := r.gate.stubsLists.Load() - stubs; got != pages {
		t.Fatalf("%d stubs listings, want %d", got, pages)
	}
	if got := r.gate.lists.Load() - lists - (r.gate.stubsLists.Load() - stubs); got != 2 {
		t.Fatalf("%d listings with bodies asked for, want the two empty pages", got)
	}
	// And one more, the health answer the dial asks for, which every
	// fetch makes: nothing else.
	if got := r.gate.requests.Load() - requests - (r.gate.lists.Load() - lists); got != 1 {
		t.Fatalf("%d requests that were not listings, want the dial's one", got)
	}
}

// A relay whose numbering began again. Before: bob kept the fifth of six
// messages and removed the rest, and his cursor is at six. After: five new
// messages numbered 1 to 5, one of them under the fifth's old id. The fetch
// resets, says so, delivers the five, and marks the old fifth as no longer
// on the relay, so that 'auu rm --remote-only' on it removes nothing there:
// its relay id now names somebody else's new message.
func TestARelayWhoseNumberingBeganAgain(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	for i := range 6 {
		alice.run("send", "--to", "bob", "--subject", "before "+strconv.Itoa(i), "x")
	}
	bob.run("inbox")
	old := recordOf(t, bob, store.Inbox, "before 4")
	for i := range 6 {
		if i != 4 {
			bob.run("rm", recordOf(t, bob, store.Inbox, "before "+strconv.Itoa(i)).Inner.ID[:12])
		}
	}
	was := cursorIs(t, bob)
	r.renumber(t, fp)
	for i := range 5 {
		alice.run("send", "--to", "bob", "--subject", "after "+strconv.Itoa(i), "a longer text than before, so no size is the same")
	}
	now := queuedOn(t, r.st, fp)
	if len(now) != 5 || now[0] != 1 || now[4] != 5 || now[4] < old.RelayID {
		t.Fatalf("the relay's ids after the restart: %v (old record %d)", now, old.RelayID)
	}
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 5 || !strings.Contains(said, "this machine's cursor was "+strconv.FormatInt(was, 10)+
		" and the relay's mail is numbered 1 to 5, so the cursor was reset") {
		t.Fatalf("after the restart: %+v, said %q", in.Fetch, said)
	}
	again := recordOf(t, bob, store.Inbox, "before 4")
	if again.OnRelay || again.RelayID != old.RelayID {
		t.Fatalf("the old record after the restart: %+v", again)
	}
	out := bob.run("rm", "--remote-only", old.Inner.ID[:12])
	if !strings.Contains(out, "not on the relay") {
		t.Fatalf("rm --remote-only of the old record said %q", out)
	}
	if got := queuedOn(t, r.st, fp); len(got) != 5 {
		t.Fatalf("the relay holds %v after rm --remote-only of a record from before, want all five", got)
	}
	if got := cursorIs(t, bob); got != 5 {
		t.Fatalf("the cursor after the reset is %d, want 5", got)
	}
}

// What the relay holds again that this machine let go: a message from a
// channel set not to keep, and one removed from the relay alone. A restored
// copy is met by its own id, not delivered, and acknowledged again, so the
// person's choice stands; its record is as it was but for what it says of
// the relay's copy. Nothing new was found, so nothing is said.
func TestMailLetGoThatComesBackIsLetGoAgain(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	// The relay's own bytes for each, kept by the test as a backup is.
	backup := func() []byte {
		t.Helper()
		rows, err := r.st.List(fp, 0, 10)
		if err != nil || len(rows) != 1 {
			t.Fatalf("the relay holds %d (%v), want the one just sent", len(rows), err)
		}
		return rows[0].Envelope
	}
	bob.run("channel", "keep", "default", "off")
	alice.run("send", "--to", "bob", "--subject", "not kept", "x")
	notKeptBytes := backup()
	bob.run("inbox")
	bob.run("channel", "keep", "default", "on")
	alice.run("send", "--to", "bob", "--subject", "removed there", "y")
	removedBytes := backup()
	bob.run("inbox")
	removed := recordOf(t, bob, store.Inbox, "removed there")
	bob.run("rm", "--remote-only", removed.Inner.ID[:12])
	notKept := recordOf(t, bob, store.Inbox, "not kept")
	bob.run("read", notKept.Inner.ID[:12])
	if len(queuedOn(t, r.st, fp)) != 0 {
		t.Fatal("the relay still holds something")
	}
	// The relay's numbering begins again and its operator restores both
	// from a backup: they come back under new ids, received now.
	r.renumber(t, fp)
	// Something for somebody else first, as a busy relay would have, so
	// that neither comes back under the id it had.
	if _, err := r.st.Put(alice.exportFingerprint(), "default", relayapi.KindEnvelope, "", removedBytes, relay.Quotas{}, relay.Forwarded{}); err != nil {
		t.Fatal(err)
	}
	for _, env := range [][]byte{notKeptBytes, removedBytes} {
		if _, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", env, relay.Quotas{}, relay.Forwarded{}); err != nil {
			t.Fatal(err)
		}
	}
	restored := queuedOn(t, r.st, fp)
	bob.setCursor(bob.defaultRelayName(), "7\n")
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("mail let go, back again: %+v, said %q", in.Fetch, said)
	}
	// Each record now names the relay's copy as the relay lists it.
	if m := recordOf(t, bob, store.Inbox, "not kept"); m.RelayID != restored[0] {
		t.Fatalf("the not-kept record's relay id is %d, want the restored copy's %d", m.RelayID, restored[0])
	}
	if m := recordOf(t, bob, store.Inbox, "removed there"); m.RelayID != restored[1] {
		t.Fatalf("the removed record's relay id is %d, want the restored copy's %d", m.RelayID, restored[1])
	}
	if got := queuedOn(t, r.st, fp); len(got) != 0 {
		t.Fatalf("the relay holds %v, want both acknowledged again", got)
	}
	if m := recordOf(t, bob, store.Inbox, "not kept"); !m.Read || m.OnRelay {
		t.Fatalf("the not-kept record: %+v", m)
	}
	if m := recordOf(t, bob, store.Inbox, "removed there"); m.OnRelay {
		t.Fatalf("the record removed from the relay: %+v", m)
	}
	if n := spoolFiles(t, bob, store.Inbox); n != 2 {
		t.Fatalf("the inbox holds %d records, want 2", n)
	}
}

// A message removed here alone and left on the relay is not delivered
// again by a reset: it is met by its own id and remembered under the relay
// id it was met under.
func TestAResetDoesNotBringBackWhatWasRemovedHere(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "removed here", "x")
	bob.run("inbox")
	gone := recordOf(t, bob, store.Inbox, "removed here")
	bob.run("rm", "--local-only", gone.Inner.ID[:12])
	alice.run("send", "--to", "bob", "--subject", "never fetched", "y")
	bob.setCursor(name, "999\n")
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 1 || !strings.Contains(said, "so the cursor was reset") {
		t.Fatalf("the reset: %+v, said %q", in.Fetch, said)
	}
	if spoolHas(t, bob, store.Inbox, "removed here") {
		t.Fatal("the message removed here came back")
	}
	s, _, _ := bob.opened()
	if left, err := s.LeftBehind(name); err != nil || len(left) != 1 || left[0].ID != gone.Inner.ID || left[0].RelayID != gone.RelayID {
		t.Fatalf("left behind after the reset: %v (%v)", left, err)
	}
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch after: %+v, said %q", in.Fetch, said)
	}
}

// A stranger's stream whose payload was left on the relay: a reset meets
// it at the manifest and asks for no payload; and after a restart that
// took it, its record says the body is gone, and neither trust nor rm asks
// the relay for anything under its old id.
func TestAResetAndAStreamLeftOnTheRelay(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	name := bob.defaultRelayName()
	fp := bob.exportFingerprint()
	bob.run("allow", "clear")
	stranger := newUser(t, "stranger", r.url)
	stranger.run("peers", "add", bob.exportLine())
	file := filepath.Join(t.TempDir(), "unasked.bin")
	if err := os.WriteFile(file, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	stranger.run("send", "--to", fp, "--subject", "unasked", "--attach", file, "hello")
	if in := bob.inboxJSON(); in.Fetch.Quarantined != 1 {
		t.Fatalf("the stranger's stream: %+v", in.Fetch)
	}
	held := recordOf(t, bob, store.Quarantine, "unasked")
	// The record names the relay's copy as the relay lists it: its time
	// and size, as an envelope's record does, not this machine's clock.
	rows, err := r.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 || !held.Received.Equal(rows[0].Received) || held.RelaySize != rows[0].Size {
		t.Fatalf("the stream's record %v %d against the relay's row %+v (%v)", held.Received, held.RelaySize, rows, err)
	}
	alice.run("send", "--to", "bob", "--subject", "never fetched", "y")
	bob.setCursor(name, "999\n")
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Quarantined != 0 || !strings.Contains(said, "so the cursor was reset") {
		t.Fatalf("the reset beside a stream: %+v, said %q", in.Fetch, said)
	}
	if m := recordOf(t, bob, store.Quarantine, "unasked"); !m.PayloadOnRelay || m.PayloadGone || m.RelayID != held.RelayID {
		t.Fatalf("the stream's record after the reset: %+v", m)
	}
	if _, err := os.Stat(filepath.Join(bob.home, "quarantine", held.Inner.ID)); !os.IsNotExist(err) {
		t.Fatalf("the payload was fetched: %v", err)
	}

	// The relay begins again without it.
	r.renumber(t, fp)
	alice.run("send", "--to", "bob", "--subject", "after", "z")
	if in, _ := fetchSaying(t, bob); in.Fetch.Delivered != 1 {
		t.Fatalf("after the restart: %+v", in.Fetch)
	}
	m := recordOf(t, bob, store.Quarantine, "unasked")
	if !m.PayloadOnRelay || !m.PayloadGone {
		t.Fatalf("the stream's record after the restart: %+v", m)
	}
	if ls := bob.run("quarantine", "ls"); !strings.Contains(ls, "body not fetched, and gone from the relay") {
		t.Fatalf("the quarantine listing:\n%s", ls)
	}
	requests := r.gate.requests.Load()
	if _, err := bob.answer("stranger", "quarantine", "trust", m.Inner.ID[:12]); err == nil ||
		!strings.Contains(err.Error(), "its body is no longer on the relay") {
		t.Fatalf("trust of a stream whose body is gone: %v", err)
	}
	if out := bob.run("rm", "--remote-only", m.Inner.ID[:12]); !strings.Contains(out, "not on the relay") {
		t.Fatalf("rm --remote-only of a stream whose body is gone: %q", out)
	}
	if n := r.gate.requests.Load() - requests; n != 0 {
		t.Fatalf("%d requests to the relay for a body that is gone", n)
	}
	if got := queuedOn(t, r.st, fp); len(got) != 1 {
		t.Fatalf("the relay holds %v, want the one new message", got)
	}
}

// wait and watch --fetch share the fetch, and the reset with it.
func TestWaitAndWatchFetchReset(t *testing.T) {
	r := startResettable(t)
	alice, bob, thread := peersWithAThread(t, r.url)
	name := bob.defaultRelayName()
	bob.setCursor(name, "999\n")
	var out string
	var err error
	said := captureStderr(t, func() {
		out, err = bob.tryRun("wait", "--thread", thread, "--timeout", "30s", "--interval", "5s", "--json")
	})
	if err != nil || !strings.Contains(out, "reply when you can") || !strings.Contains(said, "so the cursor was reset") {
		t.Fatalf("wait past everything: %v, %q, said %q", err, out, said)
	}

	alice.run("send", "--to", "bob", "--subject", "watched", "w")
	bob.setCursor(name, "999\n")
	said = captureStderr(t, func() {
		out, err = bob.tryRun("watch", "--fetch", "--json", "--timeout", "10s")
	})
	if err != nil || !strings.Contains(said, "so the cursor was reset") {
		t.Fatalf("watch --fetch past everything: %v, said %q", err, said)
	}
	var fetched struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &fetched); err != nil {
		t.Fatalf("watch printed %q: %v", out, err)
	}
	if len(fetched.Events) != 1 || fetched.Events[0]["messages"] == nil {
		t.Fatalf("watch --fetch's events: %v", fetched.Events)
	}
	if spoolFiles(t, bob, store.Inbox) != 2 {
		t.Fatalf("the inbox after both: %d records", spoolFiles(t, bob, store.Inbox))
	}

	// A plain watch writes nothing and says only what is new.
	alice.run("send", "--to", "bob", "--subject", "plain", "p")
	bob.setCursor(name, "999\n")
	out, err = bob.tryRun("watch", "--json", "--timeout", "10s")
	var plain struct {
		Events []map[string]any `json:"events"`
	}
	if err == nil {
		err = json.Unmarshal([]byte(out), &plain)
	}
	if err != nil || len(plain.Events) != 1 || plain.Events[0]["type"] != "message" || plain.Events[0]["messages"] != nil {
		t.Fatalf("a plain watch past everything: %v, %q", err, out)
	}
	if got := cursorIs(t, bob); got != 999 {
		t.Fatalf("a plain watch wrote the cursor: %d", got)
	}
}

// A record that says it was let go from the relay, whose copy the relay
// still lists under the same id, time and size, as a relay restored from
// its own backup lists it: the check before a re-fetch matches it, and it
// is acknowledged again without anything downloaded, so the earlier choice
// stands. The record is said to be let go here by editing it, which is
// what an acknowledgement the relay then lost leaves behind.
func TestAMatchedRecordLetGoIsAcknowledgedAgain(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	alice.run("send", "--to", "bob", "--subject", "let go", "x")
	alice.run("send", "--to", "bob", "--subject", "newest", "y")
	bob.run("inbox")
	s, _, _ := bob.opened()
	m := recordOf(t, bob, store.Inbox, "let go")
	m.OnRelay = false
	if err := s.Save(store.Inbox, m); err != nil {
		t.Fatal(err)
	}
	bob.run("rm", recordOf(t, bob, store.Inbox, "newest").Inner.ID[:12])
	requests := int(r.gate.requests.Load())
	stubs := r.gate.stubsLists.Load()
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch: %+v, said %q", in.Fetch, said)
	}
	seen := r.gate.since(requests)
	if got := queuedOn(t, r.st, fp); len(got) != 0 {
		t.Fatalf("the relay holds %v, want the let-go copy acknowledged again", got)
	}
	if n := r.gate.stubsLists.Load() - stubs; n != 1 {
		t.Fatalf("%d stubs listings, want 1", n)
	}
	// One acknowledgement, of the let-go copy, and no blob: nothing was
	// downloaded but the listings, three, two of them empty pages.
	deletes, lists := 0, 0
	for _, req := range seen {
		switch {
		case strings.HasSuffix(req, "/blob"):
			t.Fatalf("a blob was asked for: %v", seen)
		case strings.HasPrefix(req, "DELETE /v1/mailbox/"):
			deletes++
		case req == "GET /v1/mailbox/"+fp:
			lists++
		}
	}
	if deletes != 1 || lists != 3 {
		t.Fatalf("%d acknowledgements and %d listings, want 1 and 3: %v", deletes, lists, seen)
	}
}

// A copy restored later under the same id and at the same size is not the
// same copy: the relay received it at another time, so the check before a
// re-fetch does not match it, and the re-fetch meets it by its own id,
// saying of the record what the relay now lists.
func TestACopyRestoredLaterIsMetNotMatched(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	alice.run("send", "--to", "bob", "--subject", "restored", "x")
	rows, err := r.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the relay holds %d (%v)", len(rows), err)
	}
	bob.run("inbox")
	before := recordOf(t, bob, store.Inbox, "restored")
	bob.run("rm", "--remote-only", before.Inner.ID[:12])
	r.renumber(t, fp)
	// Received at least a second later, which is the relay's resolution.
	time.Sleep(time.Until(before.Received.Add(1100 * time.Millisecond)))
	id, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{})
	if err != nil || id != before.RelayID {
		t.Fatalf("restored as %d (%v), want the same id %d", id, err, before.RelayID)
	}
	again, err := r.st.List(fp, 0, 10)
	if err != nil || len(again) != 1 || again[0].Size != before.RelaySize || again[0].Received.Equal(before.Received) {
		t.Fatalf("the restored row %+v (%v) against the record %v %d", again, err, before.Received, before.RelaySize)
	}
	bob.setCursor(bob.defaultRelayName(), "7\n")
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch: %+v, said %q", in.Fetch, said)
	}
	if m := recordOf(t, bob, store.Inbox, "restored"); !m.Received.Equal(again[0].Received) || m.OnRelay {
		t.Fatalf("the record after: %+v, want the restored copy's time %v and not on the relay", m, again[0].Received)
	}
	if got := queuedOn(t, r.st, fp); len(got) != 0 {
		t.Fatalf("the relay holds %v, want the copy acknowledged again", got)
	}
}

// A reset cut off part-way leaves the cursor before the relay's first id
// with nothing to say a reset was under way (ruling 53). The fetch after
// it meets what this machine holds as any fetch does: the read mark stands,
// a message removed here alone stays removed, the new message is delivered
// once, and what the relay no longer holds stops being marked there. The
// sentence is the one thing lost.
func TestAnInterruptedResetDeliversNothingTwice(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	name := bob.defaultRelayName()
	alice.run("send", "--to", "bob", "--subject", "read", "a")
	alice.run("send", "--to", "bob", "--subject", "removed here", "b")
	alice.run("send", "--to", "bob", "--subject", "gone", "c")
	bob.run("inbox")
	read := recordOf(t, bob, store.Inbox, "read")
	bob.run("read", read.Inner.ID[:12])
	bob.run("rm", "--local-only", recordOf(t, bob, store.Inbox, "removed here").Inner.ID[:12])
	gone := recordOf(t, bob, store.Inbox, "gone")
	// Taken from the relay by another machine of bob's.
	if ok, err := r.st.Delete(bob.exportFingerprint(), gone.RelayID); err != nil || !ok {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "new", "d")
	bob.setCursor(name, "999\n")

	// The first page, past everything, and the stubs are served; the
	// re-fetch's page is dropped, every time it is asked for, since a
	// dropped GET is asked for again by the transport.
	r.gate.mu.Lock()
	r.gate.mode, r.gate.left, r.gate.pass = "drop", -1, 2
	r.gate.mu.Unlock()
	if _, err := bob.tryRun("inbox"); err == nil {
		t.Fatal("the fetch whose re-fetch was dropped succeeded")
	}
	r.gate.set("", 0)
	if got := cursorIs(t, bob); got >= 999 {
		t.Fatalf("the cursor after the interruption is %d, want it set back", got)
	}

	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 1 || said != "" {
		t.Fatalf("the fetch after the interruption: %+v, said %q", in.Fetch, said)
	}
	if !recordOf(t, bob, store.Inbox, "read").Read {
		t.Fatal("the read mark went")
	}
	if spoolHas(t, bob, store.Inbox, "removed here") {
		t.Fatal("the message removed here came back")
	}
	if m := recordOf(t, bob, store.Inbox, "gone"); m.OnRelay {
		t.Fatalf("the record the relay no longer holds is still marked there: %+v", m)
	}
	if n := spoolFiles(t, bob, store.Inbox); n != 3 {
		t.Fatalf("the inbox holds %d records, want read, gone and new", n)
	}
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch after: %+v, said %q", in.Fetch, said)
	}
}

// A message the relay serves again — an acknowledgement it lost, so it
// lists the same envelope once more under a new id — is met: not counted,
// its record and read mark as they were, and acknowledged again, since the
// record says it was let go. Before ruling 53 it was saved over its record
// and counted as delivered.
func TestAMessageServedAgainIsMet(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	bob.run("channel", "keep", "default", "off")
	alice.run("send", "--to", "bob", "--subject", "once", "x")
	rows, err := r.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the relay holds %d (%v)", len(rows), err)
	}
	bob.run("inbox")
	first := recordOf(t, bob, store.Inbox, "once")
	bob.run("read", first.Inner.ID[:12])
	again, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the message served again: %+v, said %q", in.Fetch, said)
	}
	m := recordOf(t, bob, store.Inbox, "once")
	if !m.Read || m.OnRelay || m.RelayID != again {
		t.Fatalf("the record after: %+v, want read, let go, and naming %d", m, again)
	}
	if got := queuedOn(t, r.st, fp); len(got) != 0 {
		t.Fatalf("the relay holds %v, want it acknowledged again", got)
	}
}

// After a relay's numbering began again, a new message can have the id a
// kept record names. The mark is matched by the relay's time and size as
// well as the id, so it is cleared at the end of the fetch, and the new
// message, which is behind a cursor at the relay's last id, is said to be
// skipped in that same fetch rather than counted as the kept one.
func TestAMarkIsNotKeptByANewMessageUnderItsID(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	alice.run("send", "--to", "bob", "--subject", "kept", "x")
	bob.run("inbox")
	kept := recordOf(t, bob, store.Inbox, "kept")
	if !kept.OnRelay || kept.RelayID != 1 {
		t.Fatalf("the kept record: %+v", kept)
	}
	r.renumber(t, fp)
	alice.run("send", "--to", "bob", "--subject", "new", "a longer text, so the size is not the kept one's")
	if got := queuedOn(t, r.st, fp); len(got) != 1 || got[0] != kept.RelayID {
		t.Fatalf("the relay holds %v, want the new message under the kept one's id %d", got, kept.RelayID)
	}
	_, err := bob.tryRun("inbox")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitDamaged || !strings.Contains(err.Error(), "1 message is waiting on") {
		t.Fatalf("the fetch: %v, want the new message said to be skipped", err)
	}
	if m := recordOf(t, bob, store.Inbox, "kept"); m.OnRelay {
		t.Fatalf("the kept record is still marked on the relay: %+v", m)
	}
}

// A message this machine holds as fetched from another relay is not met
// here: it is saved as it always was, the record now naming this relay,
// so that it is not left queued here behind the cursor for every later
// fetch to call skipped mail.
func TestAMessageHeldFromAnotherRelayIsSavedAsBefore(t *testing.T) {
	workURL, workSt := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	personalURL, personalSt := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", workURL, personalURL)
	bob := onBothRelays(t, "bob", workURL, personalURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("send", "--to", "bob", "--subject", "twice", "x", "--relay", "work")
	rows, err := workSt.List(bob.exportFingerprint(), 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("work holds %d (%v)", len(rows), err)
	}
	bob.run("inbox", "--relay", "work")
	if _, err := personalSt.Put(bob.exportFingerprint(), "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{}); err != nil {
		t.Fatal(err)
	}
	if in := bob.inboxJSON("--relay", "personal"); in.Fetch.Delivered != 1 {
		t.Fatalf("the copy on personal: %+v", in.Fetch)
	}
	if m := recordOf(t, bob, store.Inbox, "twice"); m.Relay != "personal" {
		t.Fatalf("the record names %q, want personal", m.Relay)
	}
	if _, err := bob.tryRun("inbox", "--relay", "personal"); err != nil {
		t.Fatalf("the fetch after: %v", err)
	}
}

// A message removed here alone that the relay serves again under a new id
// is met by its own id and not delivered, and its left-behind entry moves
// to the new id, so the refresh at the end of the fetch keeps it.
func TestALeftBehindMessageServedAgainMoves(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	name := bob.defaultRelayName()
	fp := bob.exportFingerprint()
	alice.run("send", "--to", "bob", "--subject", "removed here", "x")
	rows, err := r.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the relay holds %d (%v)", len(rows), err)
	}
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "removed here")
	bob.run("rm", "--local-only", m.Inner.ID[:12])
	if ok, err := r.st.Delete(fp, m.RelayID); err != nil || !ok {
		t.Fatal(err)
	}
	again, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch: %+v, said %q", in.Fetch, said)
	}
	if spoolHas(t, bob, store.Inbox, "removed here") {
		t.Fatal("the message removed here came back")
	}
	s, _, _ := bob.opened()
	if left, err := s.LeftBehind(name); err != nil || len(left) != 1 || left[0].RelayID != again || left[0].ID != m.Inner.ID {
		t.Fatalf("left behind: %v (%v), want %s under %d", left, err, m.Inner.ID, again)
	}
}

// A stranger's stream whose payload was left on the relay and taken from it
// there is said to be gone by the refresh at the end of an ordinary fetch,
// as a reset says it, so that trust does not ask the relay under its id.
func TestAPayloadTakenFromTheRelayIsGoneAfterAFetch(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	bob.run("allow", "clear")
	stranger := newUser(t, "stranger", r.url)
	stranger.run("peers", "add", bob.exportLine())
	file := filepath.Join(t.TempDir(), "unasked.bin")
	if err := os.WriteFile(file, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	stranger.run("send", "--to", fp, "--subject", "unasked", "--attach", file, "hello")
	// And a newer message kept there, so the cursor stays inside the
	// relay's span: this is the refresh's, not a reset's.
	alice.run("send", "--to", "bob", "--subject", "newer", "y")
	bob.run("inbox")
	held := recordOf(t, bob, store.Quarantine, "unasked")
	if ok, err := r.st.Delete(fp, held.RelayID); err != nil || !ok {
		t.Fatal(err)
	}
	stubs := r.gate.stubsLists.Load()
	bob.run("inbox")
	if m := recordOf(t, bob, store.Quarantine, "unasked"); !m.PayloadOnRelay || !m.PayloadGone {
		t.Fatalf("the record after the fetch: %+v", m)
	}
	if n := r.gate.stubsLists.Load() - stubs; n != 1 {
		t.Fatalf("%d stubs listings, want the refresh's one", n)
	}
}

// A record of a message's id that will not read is not met when the relay
// serves the message again: the message is saved over it, putting a good
// copy where the broken one was, and the fetch goes on.
func TestABrokenRecordIsSavedOverWhenServedAgain(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	bob.run("channel", "keep", "default", "off")
	alice.run("send", "--to", "bob", "--subject", "broken", "x")
	rows, err := r.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the relay holds %d (%v)", len(rows), err)
	}
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "broken")
	if err := os.WriteFile(filepath.Join(bob.home, "inbox", m.Inner.ID+".json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{}); err != nil {
		t.Fatal(err)
	}
	if in, _ := fetchSaying(t, bob); in.Fetch.Delivered != 1 {
		t.Fatalf("the fetch over a broken record: %+v", in.Fetch)
	}
	if got := recordOf(t, bob, store.Inbox, "broken"); got.Inner.ID != m.Inner.ID {
		t.Fatalf("the record after: %+v", got)
	}
}

// sealAs is a message from somebody, to bob, under an id they chose, as
// one who learned another message's id could seal it.
func sealAs(t *testing.T, from *identity.Identity, to *identity.Public, id, subject string) []byte {
	t.Helper()
	inner := &envelope.Inner{V: envelope.Version, From: from.Fingerprint(), FromBundle: from.Public().Bundle(), To: to.Fingerprint(),
		ID: id, Time: time.Now().UTC().Truncate(time.Second),
		Body: message.Body{Type: message.TypeAsk, Thread: strings.Repeat("b", 32), Subject: subject, Text: "x"}}
	raw, err := json.Marshal(sealInnerByHand(t, from, to, inner))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A message carrying the id of one this machine holds, signed by somebody
// else, is not met and not saved over the record: it is kept beside it as
// damaged under its relay id and acknowledged, the sentence says so, and
// the record it would have taken — a peer's in the inbox, or a stranger's
// stream waiting in the quarantine with its body on the relay, or mail
// removed here alone and remembered in left-behind — is as it was.
func TestAnotherSendersMessageUnderAHeldIDIsKeptBesideIt(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	_, bobID, _ := bob.opened()
	mallory := newUser(t, "mallory", r.url)
	_, malloryID, _ := mallory.opened()

	alice.run("send", "--to", "bob", "--subject", "real", "x")
	bob.run("inbox")
	real := recordOf(t, bob, store.Inbox, "real")
	bob.run("read", real.Inner.ID[:12])

	bob.run("allow", "clear")
	file := filepath.Join(t.TempDir(), "unasked.bin")
	if err := os.WriteFile(file, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	stranger := newUser(t, "stranger", r.url)
	stranger.run("peers", "add", bob.exportLine())
	stranger.run("send", "--to", fp, "--subject", "unasked", "--attach", file, "hello")
	bob.run("inbox")
	waiting := recordOf(t, bob, store.Quarantine, "unasked")

	// And mail removed here alone, remembered in left-behind with its
	// signer.
	bob.run("allow", "push")
	alice.run("send", "--to", "bob", "--subject", "removed here", "y")
	bob.run("inbox")
	removed := recordOf(t, bob, store.Inbox, "removed here")
	bob.run("rm", "--local-only", removed.Inner.ID[:12])

	for _, victim := range []*store.Stored{real, waiting, removed} {
		id, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", sealAs(t, malloryID, bobID.Public(), victim.Inner.ID, "forged"),
			relay.Quotas{}, relay.Forwarded{})
		if err != nil {
			t.Fatal(err)
		}
		in, said := fetchSaying(t, bob)
		if in.Fetch.Delivered != 0 || in.Fetch.Quarantined != 0 || in.Fetch.Kept != 1 ||
			!strings.Contains(said, "relay message "+strconv.FormatInt(id, 10)+" carries the id of a message this machine already holds, "+
				"and is from somebody else; it was kept as ") || !strings.Contains(said, "the message you have is unchanged") {
			t.Fatalf("against %q: %+v, said %q", victim.Inner.Body.Subject, in.Fetch, said)
		}
		for _, q := range queuedOn(t, r.st, fp) {
			if q == id {
				t.Fatalf("the forged message %d is still on the relay", id)
			}
		}
	}
	if m := recordOf(t, bob, store.Inbox, "real"); m.Inner.From != real.Inner.From || m.RelayID != real.RelayID || !m.Read {
		t.Fatalf("the inbox record after: %+v", m)
	}
	m := recordOf(t, bob, store.Quarantine, "unasked")
	if m.Inner.From != waiting.Inner.From || m.RelayID != waiting.RelayID || !m.PayloadOnRelay || m.PayloadGone {
		t.Fatalf("the quarantined record after: %+v", m)
	}
	if spoolHas(t, bob, store.Inbox, "forged") || spoolHas(t, bob, store.Quarantine, "forged") {
		t.Fatal("the forged message was filed")
	}
	s, _, _ := bob.opened()
	if left, err := s.LeftBehind(bob.defaultRelayName()); err != nil || len(left) != 1 ||
		left[0].RelayID != removed.RelayID || left[0].From != removed.Inner.From {
		t.Fatalf("left behind after: %v (%v), want the removed message as it was", left, err)
	}
}

// A reset whose only new row is another sender's message under a held id
// says what it did: that message was kept as damaged, which is handled and
// is not mail this machine had.
func TestAResetThatFindsOnlyACollisionSaysSo(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	_, bobID, _ := bob.opened()
	mallory := newUser(t, "mallory", r.url)
	_, malloryID, _ := mallory.opened()
	alice.run("send", "--to", "bob", "--subject", "real", "x")
	bob.run("inbox")
	real := recordOf(t, bob, store.Inbox, "real")
	if _, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", sealAs(t, malloryID, bobID.Public(), real.Inner.ID, "forged"),
		relay.Quotas{}, relay.Forwarded{}); err != nil {
		t.Fatal(err)
	}
	bob.setCursor(bob.defaultRelayName(), "999\n")
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 0 || in.Fetch.Kept != 1 || !strings.Contains(said, "so the cursor was reset") ||
		!strings.Contains(said, "carries the id of a message this machine already holds") {
		t.Fatalf("the reset: %+v, said %q", in.Fetch, said)
	}
}
