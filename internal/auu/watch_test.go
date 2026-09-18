package auu

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/term"
)

// watchOut is auu watch --json as a test reads it, the events decoded by
// their type.
type watchOut struct {
	Events []json.RawMessage `json:"events"`
	Waited string            `json:"waited"`
}

func (w watchOut) messages(t *testing.T) []messageEvent {
	t.Helper()
	var out []messageEvent
	for _, raw := range w.Events {
		var ev messageEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type == eventMessage {
			out = append(out, ev)
		}
	}
	return out
}

func (w watchOut) directories(t *testing.T) []directoryEvent {
	t.Helper()
	var out []directoryEvent
	for _, raw := range w.Events {
		var ev directoryEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type == eventDirectory {
			out = append(out, ev)
		}
	}
	return out
}

// waitedUnder asserts the watch reports it waited less than a bound.
func waitedUnder(t *testing.T, waited string, bound time.Duration) {
	t.Helper()
	d, err := time.ParseDuration(waited)
	if err != nil || d >= bound {
		t.Fatalf("waited %q, want under %s", waited, bound)
	}
}

// watchJSONOf runs a watch and decodes its answer. A watch here is given a
// minute unless the test says otherwise, so a watch that should have found
// something fails rather than sitting out the default ten.
func watchJSONOf(t *testing.T, u *user, args ...string) (watchOut, error) {
	t.Helper()
	out, err := u.tryRun(append([]string{"watch", "--json", "--timeout", "1m"}, args...)...)
	var got watchOut
	if out != "" {
		if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
			t.Fatalf("watch --json: %v\n%s", jsonErr, out)
		}
	}
	return got, err
}

// recordSleeps replaces the watch's pause with one that returns at once
// and records what was asked for.
func recordSleeps(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	var slept []time.Duration
	watchSleep = func(_ context.Context, d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		slept = append(slept, d)
	}
	t.Cleanup(func() { watchSleep = pauseUntil })
	return &slept
}

// watchers makes alice and bob on a relay, each on the other's list and
// each allowing only their peers.
func watchers(t *testing.T, relayURL string) (alice, bob *user) {
	t.Helper()
	alice = newUser(t, "alice", relayURL)
	bob = newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	return alice, bob
}

// elsewhere runs a command for this user in another process, for a command
// that must run while this process is in the middle of another: a run in
// this process would swap its standard output and home from under it.
func (u *user) elsewhere(args ...string) {
	u.t.Helper()
	stdout, stderr, code := u.inAnotherProcess(args...)
	if code != 0 {
		u.t.Errorf("auu %s elsewhere: exit %d\n%s%s", strings.Join(args, " "), code, stdout, stderr)
	}
}

// joined runs f in a goroutine the test waits for before it ends, whichever
// way it ends, so a failure f reports lands inside the test as a failure
// with its output, never after it as a panic that hides the output. CI's
// macOS runner had a create fail after its test had ended, and the panic
// that followed said nothing about why.
func joined(t *testing.T, f func()) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	go func() {
		defer close(done)
		f()
	}()
	return done
}

// onTheHold runs a command for this user in another process once the gate
// has seen a listing from the watch the test is about to run — its setup
// done, its baseline fetched, the relay holding — and joins it before the
// test ends. The gate's count is reset here, so each watch of a test waits
// on its own first listing. In place of a sleep of 300ms, which was a guess
// at how long the watch's setup takes: a dial and a directory fetch on a
// loaded machine can take longer, and then the change is in the baseline
// and never an event, and the watch runs to its timeout.
//
// It waits for this user's previous command in another process first:
// the watch that follows returns when the relay reports the change, which
// is before the process that made it has written its local record, and a
// next command started on the event rather than the exit read a directory
// not yet written. Wait for the process, not the event.
func (u *user) onTheHold(gate *waitGate, args ...string) {
	u.t.Helper()
	u.settle()
	gate.lists.Store(0)
	u.busy = joined(u.t, func() {
		awaitListing(gate)
		u.elsewhere(args...)
	})
}

// awaitListing returns once the gate has seen a listing, or after fifteen
// seconds of none.
func awaitListing(gate *waitGate) {
	deadline := time.Now().Add(15 * time.Second)
	for gate.lists.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// cursorOf reads a user's cursor for their default relay.
func cursorOf(t *testing.T, u *user) int64 {
	t.Helper()
	s, _, relays := u.opened()
	n, err := s.CursorFor(relays[0])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Mail already queued past the cursor is an event at once: auu inbox then
// auu watch has no gap, and the watch changes nothing — the spool stays
// empty, the cursor where it was, the message on the relay.
func TestAWatchReportsMailAlreadyQueuedAtOnce(t *testing.T) {
	slept := recordSleeps(t)
	relayURL, gate, st := startGatedRelayStore(t)
	alice, bob := watchers(t, relayURL)
	bob.run("channel", "create", "bugs", "--description", "one per message")
	alice.run("send", "--to", "bob", "--channel", "bugs", "--subject", "already there", "a bug")
	alice.run("send", "--to", "bob", "--subject", "and another", "plain")

	got, err := watchJSONOf(t, bob, "--interval", "20s")
	if err != nil {
		t.Fatalf("watch with mail waiting: %v", err)
	}
	waitedUnder(t, got.Waited, time.Second)
	events := got.messages(t)
	if len(got.Events) != 2 || len(events) != 2 {
		t.Fatalf("events: %s", got.Events)
	}
	if e := events[0]; e.Relay == "" || e.Channel != "bugs" || e.Kind != "envelope" || e.Size == 0 || e.ID != 1 || e.Received.IsZero() || e.Messages != nil || e.Fetch != nil {
		t.Fatalf("the first event: %+v", e)
	}
	if e := events[1]; e.Channel != "default" || e.ID != 2 {
		t.Fatalf("the second event: %+v", e)
	}
	if len(*slept) != 0 {
		t.Fatalf("slept %v with mail already waiting", *slept)
	}
	// Notify only: nothing fetched, nothing moved.
	if cursorOf(t, bob) != 0 {
		t.Fatal("the watch moved the cursor")
	}
	if n, _ := st.Listing(bob.fingerprint(), 0, 10, false); len(n.Rows) != 2 {
		t.Fatalf("the relay holds %d messages after the watch, want both", len(n.Rows))
	}
	if out := bob.run("inbox", "--no-fetch"); !strings.Contains(out, "inbox is empty") {
		t.Fatalf("the spool after a watch:\n%s", out)
	}
	if gate.lists.Load() != 1 {
		t.Fatalf("%d listings for a watch that found mail at once", gate.lists.Load())
	}

	// Plain: one line per relay per channel, sizes as the inbox prints
	// them, in the listing's order.
	out := bob.run("watch", "--timeout", "1m")
	relayName := events[0].Relay
	want := relayName + ": 1 message in \"bugs\" (" + term.HumanBytes(events[0].Size) + ")\n" +
		relayName + ": 1 message in \"default\" (" + term.HumanBytes(events[1].Size) + ")\n"
	if out != want {
		t.Fatalf("plain:\n%s\nwant\n%s", out, want)
	}
	// Two under one channel share a line.
	alice.run("send", "--to", "bob", "--channel", "bugs", "--subject", "third", "more")
	out = bob.run("watch", "--timeout", "1m")
	if !strings.Contains(out, relayName+": 2 messages in \"bugs\" (") || !strings.Contains(out, ", ") {
		t.Fatalf("plain with two under one channel:\n%s", out)
	}
}

// A post during the hold ends the watch when it lands, not at the next
// interval: the relay wakes the held listing.
func TestAWatchEndsWhenAPostLandsDuringTheHold(t *testing.T) {
	slept := recordSleeps(t)
	relayURL, gate := startGatedRelay(t)
	alice, bob := watchers(t, relayURL)
	gate.lists.Store(0)

	posted := make(chan time.Time, 1)
	joined(t, func() {
		awaitListing(gate)
		time.Sleep(200 * time.Millisecond)
		posted <- time.Now()
		alice.elsewhere("send", "--to", "bob", "--subject", "during the hold", "now")
	})
	got, err := watchJSONOf(t, bob, "--interval", "20s")
	ended := time.Now()
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	at := <-posted
	if ended.Sub(at) > 10*time.Second {
		t.Fatalf("the watch ended %s after the post; the hold did not end it", ended.Sub(at))
	}
	if events := got.messages(t); len(events) != 1 || events[0].Channel != "default" {
		t.Fatalf("events: %s", got.Events)
	}
	if len(*slept) != 0 {
		t.Fatalf("slept %v; a post during the hold needs no pause", *slept)
	}
	if held := time.Duration(gate.held.Load()); held < 150*time.Millisecond {
		t.Fatalf("the relay answered the held listing in %s; it was not held", held)
	}
}

// --channel keeps only matches: a post to another channel is not an event,
// the poll is empty, and the watch runs to its timeout with the pause seen
// once nothing came of the wake; then a post to the channel is reported.
func TestAWatchFiltersByChannel(t *testing.T) {
	slept := recordSleeps(t)
	relayURL, gate := startGatedRelay(t)
	alice, bob := watchers(t, relayURL)
	bob.run("channel", "create", "bugs")
	gate.lists.Store(0)
	joined(t, func() {
		awaitListing(gate)
		time.Sleep(200 * time.Millisecond)
		alice.elsewhere("send", "--to", "bob", "--subject", "elsewhere", "to default")
	})
	start := time.Now()
	raw, err := bob.tryRun("watch", "--json", "--channel", "bugs", "--timeout", "3s", "--interval", "20s")
	took := time.Since(start)
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout || e.Error() != "nothing happened in 3s" {
		t.Fatalf("a watch with nothing under its channel: %v, want exit %d", err, exitTimeout)
	}
	// One shape either way: an empty list, not null.
	if raw != "{\n  \"events\": [],\n  \"waited\": \"3s\"\n}\n" {
		t.Fatalf("the shape at the timeout:\n%s", raw)
	}
	if took < 3*time.Second || took > 15*time.Second {
		t.Fatalf("the watch took %s, want its own 3s", took)
	}
	// The wake for the post to default ended a hold with nothing to
	// report, and the watch paused for what was left before asking again;
	// and it asked again from past the row it dismissed, so the relay
	// held once more rather than answering at once with the same row
	// every poll.
	if len(*slept) == 0 {
		t.Fatal("the watch never paused after the empty poll")
	}
	if q := gate.asked.Load(); q == nil || !strings.HasPrefix(*q, "after=1&") {
		t.Fatalf("the last held listing asked from the cursor, want from past the dismissed row (after=1)")
	}
	if held := time.Duration(gate.held.Load()); held < time.Second {
		t.Fatalf("the relay held a listing for %s at most; after the dismissed row it answered at once", held)
	}
	// Now a post to bugs, and a default one beside it: one event.
	alice.run("send", "--to", "bob", "--channel", "bugs", "--subject", "a bug", "here")
	got, err := watchJSONOf(t, bob, "--channel", "bugs")
	if err != nil {
		t.Fatal(err)
	}
	if events := got.messages(t); len(events) != 1 || events[0].Channel != "bugs" || events[0].ID != 2 {
		t.Fatalf("events under --channel bugs: %s", got.Events)
	}
	// Two channels asked for keep both.
	got, err = watchJSONOf(t, bob, "--channel", "bugs", "--channel", "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.messages(t)) != 2 {
		t.Fatalf("events under two channels: %s", got.Events)
	}
}

// --fetch delivers: the messages are under the events whose ids they came
// as, the cursor advanced, the inbox has them; without it nothing moves.
func TestAWatchWithFetchDeliversAndWithoutItMovesNothing(t *testing.T) {
	recordSleeps(t)
	relayURL := startRelay(t)
	alice, bob := watchers(t, relayURL)
	alice.run("send", "--to", "bob", "--subject", "first", "one")
	alice.run("send", "--to", "bob", "--subject", "second", "two")

	got, err := watchJSONOf(t, bob)
	if err != nil {
		t.Fatal(err)
	}
	if cursorOf(t, bob) != 0 || len(got.messages(t)) != 2 {
		t.Fatalf("without --fetch: cursor %d, events %s", cursorOf(t, bob), got.Events)
	}
	if out := bob.run("inbox", "--no-fetch"); !strings.Contains(out, "inbox is empty") {
		t.Fatalf("the spool without --fetch:\n%s", out)
	}
	got, err = watchJSONOf(t, bob, "--fetch")
	if err != nil {
		t.Fatal(err)
	}
	events := got.messages(t)
	if len(events) != 2 {
		t.Fatalf("events with --fetch: %s", got.Events)
	}
	for i, e := range events {
		if len(e.Messages) != 1 || e.Messages[0].Subject == "" || e.Messages[0].Channel != "default" ||
			e.Fetch == nil || e.Fetch.Delivered != 2 || e.Fetch.Quarantined != 0 {
			t.Fatalf("event %d with --fetch: %+v", i, e)
		}
	}
	if events[0].Messages[0].Subject != "first" || events[1].Messages[0].Subject != "second" {
		t.Fatalf("the messages are not under the events they came as: %+v", events)
	}
	if cursorOf(t, bob) != 2 {
		t.Fatalf("the cursor after --fetch is %d, want 2", cursorOf(t, bob))
	}
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json", "--no-fetch")), &inbox); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range inbox.Messages {
		ids[m.ID] = true
	}
	if len(inbox.Messages) != 2 || !ids[events[0].Messages[0].ID] || !ids[events[1].Messages[0].ID] {
		t.Fatalf("the inbox after --fetch: %+v", inbox.Messages)
	}
	// Plain, with --fetch: the lines, then the messages as the inbox
	// lists them.
	alice.run("send", "--to", "bob", "--subject", "third", "three")
	out := bob.run("watch", "--fetch", "--timeout", "1m")
	if !strings.Contains(out, "1 message in \"default\"") || !strings.Contains(out, "third") ||
		!strings.Contains(out, "Read one with: auu read <id>") {
		t.Fatalf("plain with --fetch:\n%s", out)
	}
}

// A relay from before the hold answers at once, and the watch is a poller:
// the post lands during the pause and is reported at the next interval.
func TestAWatchPollsAnOldRelayAtItsInterval(t *testing.T) {
	old := &v5Relay{}
	srv := httptest.NewServer(old)
	defer srv.Close()
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	var slept []time.Duration
	watchSleep = func(_ context.Context, d time.Duration) {
		slept = append(slept, d)
		if len(slept) == 1 {
			alice.run("send", "--to", "bob", "--subject", "later", "at the next poll")
		}
	}
	t.Cleanup(func() { watchSleep = pauseUntil })
	var out string
	var err error
	warning := captureStderr(t, func() { out, err = bob.tryRun("watch", "--json", "--interval", "20s", "--timeout", "1m") })
	if err != nil || warning != "" {
		t.Fatalf("watch against an old relay: %v\n%s", err, warning)
	}
	var got watchOut
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	events := got.messages(t)
	if len(events) != 1 || events[0].Channel != "default" || events[0].Kind != "envelope" {
		t.Fatalf("events from an old relay: %s", got.Events)
	}
	if len(slept) != 1 || !aboutTheInterval(slept[0], 20*time.Second) {
		t.Fatalf("slept %v, want the full interval once", slept)
	}
	old.mu.Lock()
	listings := append([]string(nil), old.listings...)
	old.mu.Unlock()
	if len(listings) != 2 || !strings.HasSuffix(listings[0], "&wait=20s") || !strings.HasSuffix(listings[1], "&wait=20s") {
		t.Fatalf("the old relay saw listings %v, want two asking for a hold it ignores", listings)
	}
}

// Two relays are watched at once; a post on the second ends the watch and
// the first's hold is cancelled, which the gate in front of it sees as its
// context ending.
func TestAWatchOfTwoRelaysEndsOnEither(t *testing.T) {
	recordSleeps(t)
	workURL, gate := startGatedRelay(t)
	personalURL := startRelay(t)
	alice := onBothRelays(t, "alice", workURL, personalURL)
	bob := onBothRelays(t, "bob", workURL, personalURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	gate.lists.Store(0)
	joined(t, func() {
		awaitListing(gate)
		time.Sleep(200 * time.Millisecond)
		alice.elsewhere("send", "--to", "bob", "--relay", "personal", "--subject", "on personal", "x")
	})
	got, err := watchJSONOf(t, bob, "--interval", "20s")
	if err != nil {
		t.Fatal(err)
	}
	if events := got.messages(t); len(events) != 1 || events[0].Relay != "personal" {
		t.Fatalf("events: %s", got.Events)
	}
	// The hold on work was cut when personal reported: the relay behind
	// the gate saw the request's context end before it had answered.
	deadline := time.Now().Add(10 * time.Second)
	for !gate.cut.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the hold on work was never cancelled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// --relay narrows to one: with personal drained and mail on work, a
	// watch of personal alone runs to its timeout.
	bob.run("inbox")
	alice.run("send", "--to", "bob", "--relay", "work", "--subject", "on work", "y")
	got, err = watchJSONOf(t, bob, "--relay", "personal", "--timeout", "2s")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout || len(got.Events) != 0 {
		t.Fatalf("a watch narrowed to personal with mail on work: %v %s", err, got.Events)
	}
	got, err = watchJSONOf(t, bob, "--relay", "work")
	if err != nil || len(got.messages(t)) != 1 || got.messages(t)[0].Relay != "work" {
		t.Fatalf("a watch narrowed to work: %v %s", err, got.Events)
	}
}

// A relay that hangs is said once on stderr and tried again while the other
// reports; a refusal from every relay ends the watch at exit 2.
func TestAWatchOutlastsOneRelayAndStopsForEvery(t *testing.T) {
	recordSleeps(t)
	workURL, gate := startGatedRelay(t)
	personalURL, personalGate := startGatedRelay(t)
	alice := onBothRelays(t, "alice", workURL, personalURL)
	bob := onBothRelays(t, "bob", workURL, personalURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	// work drops the connection, for ever. The mail on personal is sent
	// once work has been asked twice: the warning is printed before the
	// pause that precedes the second attempt, so a second listing at the
	// gate is proof it is on stderr, and the event that ends the watch
	// cannot come first. With mail queued before the watch began, personal
	// answered its first listing at once and, on a slow machine, before
	// work's drop had been noticed, and work's goroutine then met the
	// cancelled context and said nothing, as it should.
	gate.set("drop", -1)
	gate.lists.Store(0)
	joined(t, func() {
		deadline := time.Now().Add(15 * time.Second)
		for gate.lists.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		alice.elsewhere("send", "--to", "bob", "--relay", "personal", "--subject", "on personal", "x")
	})
	var out string
	var err error
	warning := captureStderr(t, func() { out, err = bob.tryRun("watch", "--json", "--interval", "20s", "--timeout", "1m") })
	if err != nil {
		t.Fatalf("a watch with one relay down: %v", err)
	}
	if gate.lists.Load() < 2 {
		t.Fatalf("work was asked %d times before the watch ended, want at least twice", gate.lists.Load())
	}
	var got watchOut
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if events := got.messages(t); len(events) != 1 || events[0].Relay != "personal" {
		t.Fatalf("events: %s", got.Events)
	}
	if !strings.HasPrefix(warning, "work: unreachable (") || !strings.HasSuffix(warning, "); trying again in 20s\n") ||
		strings.Count(warning, "\n") != 1 {
		t.Fatalf("stderr for the relay that dropped:\n%s", warning)
	}

	// Both refuse for good: exit 2 with the first refusal, and no pause.
	gate.set("403 as the gate says", -1)
	personalGate.set("403 as the gate says", -1)
	warning = captureStderr(t, func() { _, err = bob.tryRun("watch", "--json", "--interval", "20s", "--timeout", "1m") })
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "relay returned 403: as the gate says") {
		t.Fatalf("a watch refused by every relay: %v, want exit %d", err, exitTransport)
	}
	if warning != "" {
		t.Fatalf("stderr for refusals:\n%s", warning)
	}
	// One refusing and one holding: the watch goes on with the other.
	personalGate.set("", 0)
	gate.set("403 as the gate says", -1)
	alice.run("send", "--to", "bob", "--relay", "personal", "--subject", "still here", "y")
	got, err = watchJSONOf(t, bob, "--interval", "20s")
	if err != nil || len(got.messages(t)) != 2 {
		t.Fatalf("a watch with one relay refusing: %v %s", err, got.Events)
	}
}

// A locked agent is the answer before any request is made.
func TestAWatchWithALockedAgentExits4BeforeAnyRequest(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	alice.run("lock")
	gate.requests.Store(0)
	_, err := alice.tryRun("watch", "--timeout", "1s")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked {
		t.Fatalf("watch with a locked agent: %v, want exit %d", err, exitLocked)
	}
	if gate.requests.Load() != 0 {
		t.Fatalf("%d requests were made by a locked watch", gate.requests.Load())
	}
}

// A directory watch: bob adding a channel is reported by name with the
// other two lists empty and the channels as they are now; a close as
// closed; a re-issue with nothing different as three empty lists; and
// your own directory, changed from another machine, as such.
func TestAWatchReportsADirectoryChangeByName(t *testing.T) {
	recordSleeps(t)
	relayURL, gate := startGatedRelay(t)
	alice, bob := watchers(t, relayURL)
	bob.run("channel", "create", "bugs", "--description", "one per message")

	// Added, during the hold.
	bob.onTheHold(gate, "channel", "create", "cfp", "--description", "talks")
	got, err := watchJSONOf(t, alice, "--event", "directory", "--peer", "bob", "--interval", "20s", "--timeout", "30s")
	if err != nil {
		t.Fatal(err)
	}
	dirs := got.directories(t)
	if len(got.Events) != 1 || len(dirs) != 1 {
		t.Fatalf("events: %s", got.Events)
	}
	d := dirs[0]
	if d.Peer != "bob" || d.Issued.IsZero() || strings.Join(d.Added, ",") != "cfp" || len(d.Removed) != 0 || len(d.Updated) != 0 ||
		len(d.Channels) != 3 || d.Channels[2].Name != "cfp" || d.Channels[2].Description != "talks" || !d.Channels[2].Open {
		t.Fatalf("the directory event: %+v", d)
	}
	if !strings.Contains(string(got.Events[0]), `"removed": []`) || !strings.Contains(string(got.Events[0]), `"updated": []`) {
		t.Fatalf("the empty lists are not written out: %s", got.Events[0])
	}
	// Closed: only not_after moved, to now.
	bob.onTheHold(gate, "channel", "close", "cfp")
	out := alice.run("watch", "--event", "directory", "--peer", "bob", "--interval", "20s", "--timeout", "30s")
	if !strings.HasSuffix(out, ": bob closed \"cfp\"\n") {
		t.Fatalf("plain for a close:\n%s", out)
	}
	// Updated: a description.
	bob.onTheHold(gate, "channel", "update", "bugs", "--description", "one per message, with the log")
	got, err = watchJSONOf(t, alice, "--event", "directory", "--peer", "bob", "--interval", "20s", "--timeout", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d := got.directories(t)[0]; strings.Join(d.Updated, ",") != "bugs" || len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("an updated description: %+v", d)
	}
	// Removed, and added, in one push.
	bob.onTheHold(gate, "channel", "delete", "cfp")
	out = alice.run("watch", "--event", "directory", "--peer", "bob", "--interval", "20s", "--timeout", "30s")
	if !strings.HasSuffix(out, ": bob removed \"cfp\"\n") {
		t.Fatalf("plain for a removal:\n%s", out)
	}
	// A re-issue with nothing different: the relay said the directory
	// changed, and the issue time did, so it is an event with three empty
	// lists, said as a change without a difference.
	bob.onTheHold(gate, "channel", "update", "bugs", "--description", "one per message, with the log")
	var plain string
	plain = alice.run("watch", "--event", "directory", "--peer", "bob", "--interval", "20s", "--timeout", "30s")
	if !strings.Contains(plain, ": bob changed their channels (issued ") {
		t.Fatalf("plain for a re-issue:\n%s", plain)
	}
	// Your own directory, from the other machine of the same identity: a
	// second home holding alice's identity pushes.
	other := &user{t: t, home: t.TempDir()}
	copyHome(t, alice.home, other.home)
	other.onTheHold(gate, "channel", "create", "from-elsewhere")
	out = alice.run("watch", "--event", "directory", "--interval", "20s", "--timeout", "30s")
	if !strings.Contains(out, ": you changed your channels elsewhere (issued ") {
		t.Fatalf("plain for your own directory:\n%s", out)
	}
	got, err = watchJSONOf(t, alice, "--event", "directory", "--peer", "self", "--timeout", "2s")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("nothing more from self: %v", err)
	}
	// Both kinds asked for: mail already queued is the event, at once;
	// with the mail drained, a directory change during the hold is.
	alice.run("send", "--to", "bob", "--subject", "beside it", "x")
	got, err = watchJSONOf(t, bob, "--event", "message", "--event", "directory", "--peer", "alice", "--interval", "20s", "--timeout", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.messages(t)) != 1 || len(got.directories(t)) != 0 {
		t.Fatalf("both kinds, with mail queued: %s", got.Events)
	}
	bob.run("inbox")
	// The other machine's push is newer than this one's file: taken first.
	alice.run("channel", "pull")
	alice.onTheHold(gate, "channel", "create", "from-alice")
	got, err = watchJSONOf(t, bob, "--event", "message", "--event", "directory", "--peer", "alice", "--interval", "20s", "--timeout", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.messages(t)) != 0 || len(got.directories(t)) != 1 || got.directories(t)[0].Peer != "alice" ||
		strings.Join(got.directories(t)[0].Added, ",") != "from-alice" {
		t.Fatalf("both kinds, with a directory change: %s", got.Events)
	}
}

// copyHome duplicates a home, as a second machine holding the identity.
func copyHome(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		src, dst := from+"/"+e.Name(), to+"/"+e.Name()
		if e.IsDir() {
			if err := os.MkdirAll(dst, 0o700); err != nil {
				t.Fatal(err)
			}
			copyHome(t, src, dst)
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := e.Info()
		if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
}

// A peer with no mailbox on the relay is skipped without a word; one who
// does not admit the watcher is named once and skipped; a directory the
// relay serves that does not verify is refused at exit 2.
func TestAWatchSkipsPeersItMayNotWatch(t *testing.T) {
	recordSleeps(t)
	relayURL, gate, st := startGatedRelayStore(t)
	alice, bob := watchers(t, relayURL)
	// carol is on alice's list but not on the relay; dave is on the relay
	// and admits nobody.
	carol := &user{t: t, home: t.TempDir()}
	carol.run("init", "--name", "carol", "--relay", relayURL)
	alice.run("peers", "add", carol.exportLine())
	dave := newUser(t, "dave", relayURL)
	dave.run("peers", "add", bob.exportLine())
	dave.run("allow", "push")
	alice.run("peers", "add", dave.exportLine())

	bob.onTheHold(gate, "channel", "create", "bugs")
	var out string
	var err error
	warning := captureStderr(t, func() {
		out, err = alice.tryRun("watch", "--json", "--event", "directory", "--interval", "20s", "--timeout", "1m")
	})
	if err != nil {
		t.Fatal(err)
	}
	var got watchOut
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if dirs := got.directories(t); len(dirs) != 1 || dirs[0].Peer != "bob" {
		t.Fatalf("events: %s", got.Events)
	}
	relayName := got.directories(t)[0].Relay
	if warning != relayName+": dave does not let you post, so their channels are not watched\n" {
		t.Fatalf("stderr:\n%s", warning)
	}
	// A directory that does not verify: the relay's store made to serve
	// one signed by somebody else under bob's name. A relay that lies is
	// not one to hold a request open with.
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	forged := &channels.Directory{V: 1, Owner: bob.fingerprint(), Issued: time.Now().Add(time.Hour),
		Channels: []channels.Channel{{Name: "send your keys here"}}}
	doc, sig, err := channels.Sign(mallory, forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetDirectory(bob.fingerprint(), forged, doc, sig); err != nil {
		t.Fatal(err)
	}
	// Refused during the setup, at once: the timeout is the usual minute,
	// so a slow fetch under the race detector cannot turn the refusal
	// into a timeout.
	_, err = alice.tryRun("watch", "--event", "directory", "--peer", "bob", "--timeout", "1m")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport ||
		err.Error() != "the directory "+relayName+" served for bob does not verify against the key you hold; do not trust it" {
		t.Fatalf("a watch of a directory that does not verify: %v", err)
	}
	// And your own, served wrong: preflight's sentence.
	forged.Owner = alice.fingerprint()
	doc, sig, err = channels.Sign(mallory, forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetDirectory(alice.fingerprint(), forged, doc, sig); err != nil {
		t.Fatal(err)
	}
	_, err = alice.tryRun("watch", "--event", "directory", "--peer", "self", "--timeout", "1m")
	if !asExit(err, &e) || e.code != exitTransport ||
		err.Error() != "the directory "+relayName+" serves for you does not verify against your key; do not trust it" {
		t.Fatalf("a watch of your own directory served wrong: %v", err)
	}
}

// The flags that mean nothing together, and the ones that are wrong alone,
// are refused before anything is opened.
func TestWatchFlagsThatMeanNothingAreUsageErrors(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice := newUser(t, "alice", relayURL)
	gate.lists.Store(0)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--event", "directory", "--channel", "x"}, "--channel applies to message events, and --event message was not asked for"},
		{[]string{"--event", "directory", "--fetch"}, "--fetch applies to message events, and --event message was not asked for"},
		{[]string{"--peer", "bob"}, "--peer applies to directory events, and --event directory was not asked for"},
		{[]string{"--event", "message", "--peer", "bob"}, "--peer applies to directory events, and --event directory was not asked for"},
		{[]string{"--event", "upload"}, `--event must be message or directory, got "upload"`},
		{[]string{"--channel", "a/b"}, `--channel "a/b": name contains "/"`},
		{[]string{"--interval", "4s"}, "--interval must be at least 5s; polling harder does not make replies arrive sooner"},
		{[]string{"--timeout", "-1s"}, "--timeout must not be negative; 0 means no limit"},
		{[]string{"--event", "directory", "--peer", "nobody"}, "--peer nobody: no peers yet: add one with 'auu peers add'"},
		{[]string{"extra"}, `unexpected argument "extra"`},
	} {
		// A short timeout, so a check that is missing shows as a watch
		// that ran rather than one that hung.
		_, err := alice.tryRun(append([]string{"watch", "--timeout", "1s"}, tc.args...)...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitUsage || err.Error() != tc.want {
			t.Errorf("watch %v: %v, want usage %q", tc.args, err, tc.want)
		}
	}
	if gate.lists.Load() != 0 {
		t.Fatalf("%d listings were made by watches refused for their flags", gate.lists.Load())
	}
	// --event message --event directory, and the same twice, are fine.
	if _, err := alice.tryRun("watch", "--event", "message", "--event", "directory", "--event", "message", "--timeout", "1s"); err == nil ||
		!strings.Contains(err.Error(), "nothing happened in 1s") {
		t.Fatalf("both events together: %v", err)
	}
}

// --timeout 0 is no limit: a pause that outlasts a one-second timeout ends
// a watch under it, and does not end one without.
func TestAWatchWithNoTimeoutRunsOn(t *testing.T) {
	old := &v5Relay{}
	srv := httptest.NewServer(old)
	defer srv.Close()
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	// The pause is real, longer than the timeout below, and the post lands
	// during it.
	var pauses atomic.Int32
	watchSleep = func(ctx context.Context, d time.Duration) {
		if pauses.Add(1) == 1 {
			alice.elsewhere("send", "--to", "bob", "--subject", "in the pause", "x")
		}
		pauseUntil(ctx, 1500*time.Millisecond)
	}
	t.Cleanup(func() { watchSleep = pauseUntil })

	got, err := watchJSONOf(t, bob, "--timeout", "1s", "--interval", "20s")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout || len(got.Events) != 0 {
		t.Fatalf("a 1s timeout outlasted by the pause: %v %s", err, got.Events)
	}
	bob.run("inbox")
	pauses.Store(0)
	got, err = watchJSONOf(t, bob, "--timeout", "0", "--interval", "20s")
	if err != nil || len(got.messages(t)) != 1 {
		t.Fatalf("no timeout: %v %s", err, got.Events)
	}
	if pauses.Load() < 1 {
		t.Fatal("the watch never paused")
	}
	waited, _ := time.ParseDuration(got.Waited)
	if waited < time.Second {
		t.Fatalf("waited %s, want past the 1s that ended the other watch", got.Waited)
	}
}

// A cursor past the relay's mail is the diagnosis a fetch makes, at its
// exit code, after the first hold ends with nothing after the cursor and
// the count above it.
func TestAWatchDiagnosesACursorPastTheMail(t *testing.T) {
	recordSleeps(t)
	relayURL := startRelay(t)
	alice, bob := watchers(t, relayURL)
	alice.run("send", "--to", "bob", "--subject", "behind", "x")
	s, _, relays := bob.opened()
	if err := s.SetCursorFor(relays[0], 5); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := bob.tryRun("watch", "--interval", "5s", "--timeout", "1m")
	took := time.Since(start)
	var e *exitError
	if !asExit(err, &e) || e.code != exitDamaged {
		t.Fatalf("a watch with the cursor past the mail: %v, want exit %d", err, exitDamaged)
	}
	want := "1 message is waiting on " + relays[0].Name + " before this machine's cursor; delete " +
		s.RelayDir(relays[0]) + "/cursor and run 'auu inbox --relay " + relays[0].Name + "' to fetch from the beginning"
	if err.Error() != want {
		t.Fatalf("the diagnosis:\n%v\nwant\n%s", err, want)
	}
	// After the first hold, not at once: the hold ran its 5s, since a
	// count above zero is not mail after the cursor.
	if took < 4*time.Second {
		t.Fatalf("diagnosed after %s; the first hold was not let run", took)
	}
}

// A hold ended by a wake for another key's subscriber — a directory push
// by a peer whose change diffs to nothing the watch reports — is an empty
// poll, and the watch goes on.
func TestOneWakeOneLookOneAnswerOnTheClientSide(t *testing.T) {
	slept := recordSleeps(t)
	relayURL, gate := startGatedRelay(t)
	alice, bob := watchers(t, relayURL)
	gate.lists.Store(0)
	joined(t, func() {
		awaitListing(gate)
		time.Sleep(200 * time.Millisecond)
		// A post to bob under a channel the watch does not want ends the
		// hold with nothing to report; then one it does.
		alice.elsewhere("send", "--to", "bob", "--subject", "not wanted", "x")
		time.Sleep(200 * time.Millisecond)
		bob.elsewhere("channel", "create", "wanted")
		time.Sleep(200 * time.Millisecond)
		alice.elsewhere("send", "--to", "bob", "--channel", "wanted", "--subject", "wanted", "y")
	})
	got, err := watchJSONOf(t, bob, "--channel", "wanted", "--interval", "20s")
	if err != nil {
		t.Fatal(err)
	}
	if events := got.messages(t); len(events) != 1 || events[0].Channel != "wanted" {
		t.Fatalf("events: %s", got.Events)
	}
	if len(*slept) == 0 || gate.lists.Load() < 2 {
		t.Fatalf("slept %v over %d polls; the unwanted post did not end a hold and start another", *slept, gate.lists.Load())
	}
}

// The plain sentence for a push that adds, closes and removes at once.
func TestTheDirectorySentenceNamesEveryChange(t *testing.T) {
	recordSleeps(t)
	relayURL, gate := startGatedRelay(t)
	alice, bob := watchers(t, relayURL)
	bob.run("channel", "create", "bugs")
	bob.run("channel", "create", "old")
	// One push with three changes: the file edited, then pushed from
	// another process while alice's watch holds.
	s, _, _ := bob.opened()
	d, _, err := s.Directory()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := range d.Channels {
		if d.Channels[i].Name == "bugs" {
			d.Channels[i].NotAfter = &now
		}
	}
	kept := d.Channels[:0:0]
	for _, ch := range d.Channels {
		if ch.Name != "old" {
			kept = append(kept, ch)
		}
	}
	d.Channels = append(kept, channels.Channel{Name: "cfp", Description: "talks"})
	d.Issued = time.Now()
	if err := s.SetDirectory(d); err != nil {
		t.Fatal(err)
	}
	bob.onTheHold(gate, "channel", "push")
	out := alice.run("watch", "--event", "directory", "--peer", "bob", "--interval", "20s", "--timeout", "30s")
	relayName := alice.defaultRelayName()
	if out != relayName+": bob added \"cfp\", closed \"bugs\", removed \"old\"\n" {
		t.Fatalf("plain:\n%s", out)
	}
}

// More peers with mailboxes on a relay than a listing may watch is a
// usage error naming the relay and the count, after the ones without a
// mailbox have been skipped; at the cap it is fine.
func TestAWatchOfTooManyPeersIsRefused(t *testing.T) {
	recordSleeps(t)
	relayURL, st := startRelayConfig(t, relay.Config{Streams: true})
	alice := newUser(t, "alice", relayURL)
	s, _, relays := alice.opened()
	// MaxWatchPeers peers on the relay, plus self, is one over; one of
	// them not on the relay brings it back under.
	var last *identity.Public
	for i := range relayapi.MaxWatchPeers {
		id, err := identity.Generate("peer" + strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		pub := id.Public()
		if _, err := s.AddPeer(pub); err != nil {
			t.Fatal(err)
		}
		if i == relayapi.MaxWatchPeers-1 {
			last = pub
			continue
		}
		if err := st.Register(pub.Fingerprint(), pub.Bundle(), "peer", relay.RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// 99 on the relay, one not, and self: 100, the cap, watched.
	_, err := alice.tryRun("watch", "--event", "directory", "--timeout", "1s", "--interval", "20s")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("a watch of %d peers: %v, want the timeout", relayapi.MaxWatchPeers, err)
	}
	if err := st.Register(last.Fingerprint(), last.Bundle(), "peer", relay.RegisterOptions{}); err != nil {
		t.Fatal(err)
	}
	// The refusal ends the run at once, whenever it comes, so the timeout
	// has nothing to prove and is the tests' usual minute: with a second,
	// the setup's hundred and one directory fetches under the race
	// detector on a loaded runner outran the deadline, and the watch
	// reported the timeout instead.
	_, err = alice.tryRun("watch", "--event", "directory", "--timeout", "1m", "--interval", "20s")
	want := "too many peers to watch on " + relays[0].Name + " (" + strconv.Itoa(relayapi.MaxWatchPeers+1) + "); narrow with --peer"
	if !asExit(err, &e) || e.code != exitUsage || err.Error() != want {
		t.Fatalf("a watch of %d peers: %v, want usage %q", relayapi.MaxWatchPeers+1, err, want)
	}
	// Narrowed, it is fine.
	if _, err := alice.tryRun("watch", "--event", "directory", "--peer", "self", "--timeout", "1s", "--interval", "20s"); err == nil ||
		!strings.Contains(err.Error(), "nothing happened") {
		t.Fatalf("narrowed with --peer: %v", err)
	}
}
