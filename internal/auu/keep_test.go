package auu

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// Mail kept on the relay: what a fetch leaves behind, what says so, and
// what happens when somebody else takes it away.

// queuedOn is the relay ids still queued for a user.
func queuedOn(t *testing.T, st *relay.Store, fp string) []int64 {
	t.Helper()
	rows, err := st.List(fp, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// recordOf is one stored message from a user's inbox, by subject.
func recordOf(t *testing.T, u *user, box store.Box, subject string) *store.Stored {
	t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(box)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Inner.Body.Subject == subject {
			return m
		}
	}
	t.Fatalf("no message %q in %s", subject, box)
	return nil
}

// A fetch from a channel that keeps leaves the message queued, marks the
// record, moves the cursor, and says so in the listing and the JSON.
func TestAFetchKeepsWhatTheChannelSaysToKeep(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	name := bob.defaultRelayName()

	alice.run("send", "--to", "bob", "--subject", "kept", "stays there")
	in := bob.inboxJSON()
	if in.Fetch.Delivered != 1 {
		t.Fatalf("the fetch: %+v", in.Fetch)
	}
	if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v after a fetch that keeps, want the one message", left)
	}
	if m := recordOf(t, bob, store.Inbox, "kept"); !m.OnRelay || m.Relay != name {
		t.Fatalf("the record: %+v", m)
	}
	if cursorOf(t, bob) == 0 {
		t.Fatal("the cursor did not move for a message that was kept")
	}
	if len(in.Messages) != 1 || !in.Messages[0].OnRelay {
		t.Fatalf("the JSON: %+v", in.Messages)
	}
	// The line says where it is, and so does the count line under it.
	out := bob.run("inbox")
	if !strings.Contains(out, "  on relay") {
		t.Fatalf("the listing does not mark it:\n%s", out)
	}
	if want := name + ": 1 message(s) on the relay; auu rm removes them\n"; !strings.Contains(out, want) {
		t.Fatalf("the listing does not count what is on the relay:\n%s\nwant %s", out, want)
	}
	// And so does read.
	if r := bob.run("read", recordOf(t, bob, store.Inbox, "kept").Inner.ID[:12]); !strings.Contains(r, "relay:   kept\n") {
		t.Fatalf("read:\n%s", r)
	}
}

// With the channel set to off the fetch acknowledges as it always did: the
// relay is empty, the record is unmarked, and nothing is said about it.
func TestAFetchFromAChannelSetToOffAcknowledgesAsBefore(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	bob.run("channel", "create", "bugs")
	bob.run("channel", "keep", "bugs", "off")
	bob.run("channel", "keep", "default", "off")

	alice.run("send", "--to", "bob", "--subject", "gone", "acknowledged away")
	alice.run("send", "--to", "bob", "--channel", "bugs", "--subject", "also gone", "under bugs")
	out := bob.run("inbox")
	if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("the relay holds %v after a fetch that does not keep", left)
	}
	for _, subject := range []string{"gone", "also gone"} {
		if m := recordOf(t, bob, store.Inbox, subject); m.OnRelay {
			t.Fatalf("%q is marked as on the relay: %+v", subject, m)
		}
	}
	if strings.Contains(out, "on relay") || strings.Contains(out, "auu rm removes them") {
		t.Fatalf("the listing says something about the relay:\n%s", out)
	}
	if r := bob.run("read", recordOf(t, bob, store.Inbox, "gone").Inner.ID[:12]); !strings.Contains(r, "relay:   removed\n") {
		t.Fatalf("read:\n%s", r)
	}
	// A channel with no setting of its own keeps, beside one that does
	// not: the setting is per channel, not per home.
	bob.run("channel", "create", "cfp")
	alice.run("send", "--to", "bob", "--channel", "cfp", "--subject", "kept", "under cfp")
	bob.run("inbox")
	if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v, want the cfp message alone", left)
	}
	if m := recordOf(t, bob, store.Inbox, "kept"); !m.OnRelay {
		t.Fatalf("the cfp record: %+v", m)
	}
	// And mail queued under a channel since deleted takes that channel's
	// setting, not the default's.
	bob.run("channel", "keep", "since-deleted", "off")
	bob.run("channel", "create", "since-deleted")
	alice.run("send", "--to", "bob", "--channel", "since-deleted", "--subject", "orphan", "queued")
	bob.run("channel", "delete", "since-deleted")
	bob.run("inbox")
	if m := recordOf(t, bob, store.Inbox, "orphan"); m.OnRelay {
		t.Fatalf("mail under a deleted channel ignored its setting: %+v", m)
	}
}

// A stream is kept the same way, and a quarantined stream's payload is
// still left on the relay whatever the setting says; trusting the sender
// fetches the body and, under keep, leaves the message queued.
func TestAStreamAndAQuarantinedStreamUnderKeep(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}

	alice.run("send", "--to", "bob", "--subject", "a stream", "--attach", big, "streamed")
	bob.run("inbox")
	if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v after a stream that keeps", left)
	}
	m := recordOf(t, bob, store.Inbox, "a stream")
	if !m.OnRelay || m.PayloadOnRelay || !m.Streamed {
		t.Fatalf("the stream's record: %+v", m)
	}

	// A stranger's stream: quarantined from its manifest, the payload
	// deliberately not fetched and nothing acknowledged, whatever keep
	// says.
	bob.run("allow", "clear")
	stranger := newUser(t, "stranger", relayURL)
	stranger.run("peers", "add", bob.exportLine())
	stranger.run("send", "--to", bob.exportFingerprint(), "--subject", "unasked", "--attach", big, "hello")
	bob.run("inbox")
	q := recordOf(t, bob, store.Quarantine, "unasked")
	if !q.PayloadOnRelay || q.OnRelay {
		t.Fatalf("the quarantined stream: %+v", q)
	}
	out := bob.run("quarantine", "ls")
	if !strings.Contains(out, "body not fetched") {
		t.Fatalf("the quarantine listing:\n%s", out)
	}
	// Trusted: the body is fetched, so the payload is no longer on the
	// relay, and the message is kept there because default keeps.
	if _, err := bob.answer("stranger", "quarantine", "trust", q.Inner.ID[:12]); err != nil {
		t.Fatal(err)
	}
	m = recordOf(t, bob, store.Inbox, "unasked")
	if m.PayloadOnRelay || !m.OnRelay {
		t.Fatalf("the trusted stream: %+v", m)
	}
	if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != 2 {
		t.Fatalf("the relay holds %v, want both streams kept", left)
	}
}

// The refresh: a message removed from the relay by somebody else stops
// being marked at the next fetch, and the count line goes with it.
func TestTheRefreshClearsAMarkForMailThatHasGone(t *testing.T) {
	relayURL, gate, st := startGatedRelayStore(t)
	alice, bob := watchers(t, relayURL)
	// A fetch with nothing marked has nothing to check, and asks nothing.
	bob.run("inbox")
	if n := gate.stubsLists.Load(); n != 0 {
		t.Fatalf("%d refresh listings for a home with nothing on the relay", n)
	}
	alice.run("send", "--to", "bob", "--subject", "first", "one")
	alice.run("send", "--to", "bob", "--subject", "second", "two")
	bob.run("inbox")
	first := recordOf(t, bob, store.Inbox, "first")
	if !first.OnRelay {
		t.Fatalf("the first record: %+v", first)
	}

	// Another machine of bob's, or an administrator, removes one.
	if gone, err := st.Delete(bob.exportFingerprint(), first.RelayID); err != nil || !gone {
		t.Fatalf("delete on the relay: %v %v", gone, err)
	}
	out := bob.run("inbox")
	if m := recordOf(t, bob, store.Inbox, "first"); m.OnRelay {
		t.Fatalf("the mark survived the message: %+v", m)
	}
	if m := recordOf(t, bob, store.Inbox, "second"); !m.OnRelay {
		t.Fatalf("the other mark went too: %+v", m)
	}
	if strings.Count(out, "  on relay") != 1 {
		t.Fatalf("the listing marks the wrong number:\n%s", out)
	}
	// Everything gone: the marks go without a listing at all, since the
	// relay's own count answered it.
	if gone, err := st.Delete(bob.exportFingerprint(), recordOf(t, bob, store.Inbox, "second").RelayID); err != nil || !gone {
		t.Fatalf("delete on the relay: %v %v", gone, err)
	}
	before := gate.stubsLists.Load()
	out = bob.run("inbox")
	for _, subject := range []string{"first", "second"} {
		if m := recordOf(t, bob, store.Inbox, subject); m.OnRelay {
			t.Fatalf("%q is still marked: %+v", subject, m)
		}
	}
	// The relay's own count answered it: an empty mailbox means every
	// mark is stale, and no listing was made to learn that.
	if n := gate.stubsLists.Load(); n != before {
		t.Fatalf("%d refresh listings for a relay that said its mailbox is empty", n-before)
	}
	if strings.Contains(out, "on relay") || strings.Contains(out, "auu rm") {
		t.Fatalf("the listing still says something about the relay:\n%s", out)
	}
}

// Kept mail is behind the cursor and counted as left there on purpose, so
// the cursor-past-mail diagnosis stays quiet; mail that is neither kept nor
// fetched is what it is for.
func TestAFetchLeavesKeptMailWhereTheCursorIsPastIt(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	if left, err := leftOn(bob, bob.defaultRelayName()); err != nil || left != 1 {
		t.Fatalf("left on the relay on purpose: %d (%v), want 1", left, err)
	}
	// Quiet: the relay counts one and this machine knows it left it.
	if out := bob.run("inbox"); strings.Contains(out, "before this machine's cursor") {
		t.Fatalf("a fetch with kept mail behind the cursor:\n%s", out)
	}
	// A watch is the same: kept mail behind the cursor is not mail it has
	// missed, so it runs to its timeout rather than diagnosing a home.
	_, err := bob.tryRun("watch", "--timeout", "1s")
	var exit *exitError
	if !asExit(err, &exit) || exit.code != exitTimeout {
		t.Fatalf("a watch with kept mail behind the cursor: %v", err)
	}
	// One more, never fetched, with the cursor put past both: that is mail
	// this machine has not seen, and a cursor above everything the relay
	// holds is reset and fetched again from the relay's first id. The kept
	// one is met, its record as it was; the skipped one is delivered, and
	// the sentence says so.
	kept := recordOf(t, bob, store.Inbox, "kept")
	bob.run("read", kept.Inner.ID[:12])
	alice.run("send", "--to", "bob", "--subject", "skipped", "two")
	rows := queuedOn(t, st, bob.exportFingerprint())
	if len(rows) != 2 {
		t.Fatalf("the relay holds %v, want the kept one and the skipped one", rows)
	}
	bob.setCursor(bob.defaultRelayName(), "999999\n")
	var in inboxJSON
	stderr := captureStderr(t, func() { in = bob.inboxJSON() })
	if in.Fetch.Delivered != 1 || !strings.Contains(stderr, "this machine's cursor was 999999 and the relay's mail is numbered "+
		strconv.FormatInt(rows[0], 10)+" to "+strconv.FormatInt(rows[1], 10)+", so the cursor was reset") {
		t.Fatalf("a cursor past both: %+v, said %q", in.Fetch, stderr)
	}
	if again := recordOf(t, bob, store.Inbox, "kept"); !again.Read || !again.OnRelay || again.RelayID != kept.RelayID {
		t.Fatalf("the kept record after the reset: %+v", again)
	}
	if data, err := os.ReadFile(bob.cursorPath(bob.defaultRelayName())); err != nil ||
		string(data) != strconv.FormatInt(rows[1], 10)+"\n" {
		t.Fatalf("the cursor after the reset: %q (%v), want the last id", data, err)
	}
}

// Kept mail fills the mailbox: the relay's limits count what is queued,
// and reading it does not make room.
func TestKeptMailStillFillsTheMailbox(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.MailboxMaxMessages = 1
	relayURL := startRelayWith(t, limits)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	alice.run("send", "--to", "bob", "--subject", "first", "fits")
	bob.run("inbox")
	_, err := alice.tryRun("send", "--to", "bob", "--subject", "second", "does not fit")
	if err == nil || !strings.Contains(err.Error(), "bob's mailbox on the relay is full; they need to run 'auu rm' to make room") {
		t.Fatalf("a send to a mailbox full of kept mail: %v", err)
	}
}

// A damaged settings file is refused by the fetch, before anything is
// fetched under a guess about what to do with it.
func TestAFetchRefusesADamagedSettingsFile(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	alice.run("send", "--to", "bob", "--subject", "waiting", "one")
	s, _, _ := bob.opened()
	if err := os.WriteFile(s.ChannelSettingsPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := bob.tryRun("inbox")
	// The read is strict now (G17, R24, R24b), so the sentence is "will
	// not read" where it was "is not valid JSON"; a file cut short keeps
	// encoding/json's words, since the file is walked by its decoder.
	var exit *exitError
	if !asExit(err, &exit) || exit.code != exitDamaged ||
		!strings.Contains(err.Error(), s.ChannelSettingsPath()+" will not read (unexpected end of JSON input): fix it") {
		t.Fatalf("a fetch with a damaged settings file: %v", err)
	}
	if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v; the refused fetch touched the mailbox", left)
	}
	if in := bob.inboxJSON("--no-fetch"); len(in.Messages) != 0 {
		t.Fatalf("the refused fetch delivered: %+v", in.Messages)
	}
}

// A refresh that fails on the wire is said once and does not fail the
// fetch: the mail is in the spool, the cursor has moved, and the marks are
// checked again next time.
func TestARefreshThatFailsIsSaidAndDoesNotFailTheFetch(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice, bob := watchers(t, relayURL)
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	alice.run("send", "--to", "bob", "--subject", "second", "two")

	// The gate drops the connection on a listing that asks for stubs, and
	// only on those: the fetch's own pages are served, and the refresh
	// that follows them is what meets the failure.
	gate.dropStubs.Store(true)
	var out string
	warning := captureStderr(t, func() { out = bob.run("inbox") })
	_ = out
	if !strings.HasPrefix(warning, bob.defaultRelayName()+": could not check which messages are still on the relay (") ||
		!strings.HasSuffix(warning, "); the marks are checked again next time\n") {
		t.Fatalf("stderr:\n%s", warning)
	}
	if strings.Count(warning, "\n") != 1 {
		t.Fatalf("said more than once:\n%s", warning)
	}
	if m := recordOf(t, bob, store.Inbox, "second"); !m.OnRelay {
		t.Fatalf("the fetch that met the failure did not keep its mail: %+v", m)
	}
}

// A quarantined stream's body can go from the relay while its record still
// says the body was never fetched — an administrator's purge, or another
// machine of this identity removing the message. The record is a statement
// about this machine, so it stands: the mark is not cleared by the refresh,
// the listing still says the body is not here, and trusting the sender says
// what has happened rather than failing as a transport error.
func TestAQuarantinedStreamWhoseBodyHasGoneFromTheRelay(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	_, bob := watchers(t, relayURL)
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	bob.run("allow", "clear")
	stranger := newUser(t, "stranger", relayURL)
	stranger.run("peers", "add", bob.exportLine())
	stranger.run("send", "--to", bob.exportFingerprint(), "--subject", "unasked", "--attach", big, "hello")
	bob.run("inbox")
	q := recordOf(t, bob, store.Quarantine, "unasked")
	if !q.PayloadOnRelay {
		t.Fatalf("the quarantined stream: %+v", q)
	}

	// Purged on the relay, behind this machine's back.
	if gone, err := st.Delete(bob.exportFingerprint(), q.RelayID); err != nil || !gone {
		t.Fatalf("delete on the relay: %v %v", gone, err)
	}
	// A fetch refreshes the marks and leaves this one alone: the body was
	// never fetched, and that is still true.
	bob.run("inbox")
	again := recordOf(t, bob, store.Quarantine, "unasked")
	if !again.PayloadOnRelay || again.OnRelay || !again.Streamed {
		t.Fatalf("the record after the purge: %+v", again)
	}
	if out := bob.run("quarantine", "ls"); !strings.Contains(out, "body not fetched") {
		t.Fatalf("the quarantine listing after the purge:\n%s", out)
	}
	// And trusting the sender says what has happened, at exit 2, with the
	// record as it was.
	_, err := bob.answer("stranger", "quarantine", "trust", q.Inner.ID[:12])
	var exit *exitError
	if !asExit(err, &exit) || exit.code != exitTransport ||
		err.Error() != q.Inner.ID[:12]+": its body is no longer on the relay; ask the sender to send it again" {
		t.Fatalf("trust with the body gone: %v", err)
	}
	if last := recordOf(t, bob, store.Quarantine, "unasked"); !last.PayloadOnRelay {
		t.Fatalf("the record after the refusal: %+v", last)
	}
}

// TestChannelKeepTakesNamesThatDifferByCase (R24b): a channel's name is
// case-sensitive in the directory, so "Bugs" and "bugs" are two channels,
// and channel-settings.json holds a keep for each. The strict read refused
// the pair as two keys alike under folding, so the second 'auu channel
// keep' failed on the file the first wrote, and so did every fetch after
// it. Here both commands succeed, and two fetches, with the settings one
// way and then the other, each leave on the relay the mail of the channel
// that keeps and acknowledge the other's.
func TestChannelKeepTakesNamesThatDifferByCase(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, relayURL)
	bob.run("channel", "create", "Bugs")
	bob.run("channel", "create", "bugs")
	if out := bob.run("channel", "keep", "Bugs", "off"); out != "Bugs: mail is removed from the relay once it is fetched\n" {
		t.Fatalf("keep Bugs off:\n%s", out)
	}
	if out := bob.run("channel", "keep", "bugs", "on"); out != "bugs: mail is kept on the relay after it is fetched\n" {
		t.Fatalf("keep bugs on:\n%s", out)
	}
	if bob.keepOf("Bugs") || !bob.keepOf("bugs") {
		t.Fatalf("Bugs keeps %v and bugs %v; want off and on", bob.keepOf("Bugs"), bob.keepOf("bugs"))
	}

	for round, upperKeeps := range []bool{false, true} {
		if round > 0 {
			bob.run("channel", "keep", "Bugs", "on")
			bob.run("channel", "keep", "bugs", "off")
		}
		upper, lower := fmt.Sprintf("upper %d", round), fmt.Sprintf("lower %d", round)
		alice.run("send", "--to", "bob", "--channel", "Bugs", "--subject", upper, "under Bugs")
		alice.run("send", "--to", "bob", "--channel", "bugs", "--subject", lower, "under bugs")
		in := bob.inboxJSON()
		if in.Fetch.Delivered != 2 {
			t.Fatalf("round %d: the fetch: %+v", round, in.Fetch)
		}
		u, l := recordOf(t, bob, store.Inbox, upper), recordOf(t, bob, store.Inbox, lower)
		if u.Channel != "Bugs" || l.Channel != "bugs" {
			t.Fatalf("round %d: the records are under %q and %q", round, u.Channel, l.Channel)
		}
		if u.OnRelay != upperKeeps || l.OnRelay != !upperKeeps {
			t.Fatalf("round %d: Bugs's mail on the relay %v, bugs's %v; want %v and %v",
				round, u.OnRelay, l.OnRelay, upperKeeps, !upperKeeps)
		}
		// What is left on the relay: bugs's first message, kept in round
		// 0, and in round 1 Bugs's as well.
		want := map[int]int{0: 1, 1: 2}[round]
		if left := queuedOn(t, st, bob.exportFingerprint()); len(left) != want {
			t.Fatalf("round %d: the relay holds %v, want %d", round, left, want)
		}
	}
}
