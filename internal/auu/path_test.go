package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// Sending to somebody on another relay. The address is a bang path —
// bar!bob, where bar is what *your* relay calls the relay bob is on, since a
// relay name is relative to the relay reading it — and it goes to your
// relay's forward route rather than to a mailbox. Your relay queues it for
// the neighbour and answers the id of the row, which is what an
// undeliverable coming back will one day name.
//
// The tests here are of the terminal: what the address rule refuses before
// anything is sealed, which spellings mean the same address, and what the
// sent record keeps.

// forwarding starts a relay that will carry mail to the named neighbours.
//
// The neighbours are ports nothing listens on: what these tests are about is
// what this relay accepts from a sender and writes down, and every one of
// them is over before a worker's first backoff has run out.
func forwarding(t *testing.T, neighbours ...string) (string, *relay.Store) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "courier")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("courier")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	for i, n := range neighbours {
		if _, err := s.AddRelay(n, fmt.Sprintf("http://127.0.0.1:%d", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	c, err := relay.NewCourier(relay.CourierConfig{Home: root, PublicURL: "https://mine.example"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// The store comes back with it, because what these tests have to look
	// at is the queue: a path that was dropped and a path that was carried
	// both leave the same answer at the terminal, the id being an id either
	// way and the path being the argument echoed. The row is the only thing
	// that tells them apart.
	return startRelayConfig(t, relay.Config{
		Courier: c, CourierLimits: relay.DefaultCourierLimits(), Limits: relay.DefaultLimits(),
	})
}

// queuedFor is the row this relay is holding for a neighbour, or nil.
func queuedFor(t *testing.T, st *relay.Store, neighbour string) *relay.Outbound {
	t.Helper()
	row, err := st.NextOutbound(neighbour, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// TestAMessageGoesByWayOfARelay: the whole of what this commit adds, at the
// terminal. An address naming a relay is queued at the first hop, the answer
// is a row's id, and the sent record says where it went.
func TestAMessageGoesByWayOfARelay(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	out := alice.run("send", "--to", "bar!bob", "--json", "hello over there")
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if sent.Path != "bar" {
		t.Errorf("the answer says path %q, want bar", sent.Path)
	}
	if sent.To != bob.exportFingerprint() {
		t.Errorf("to %q, want bob", sent.To)
	}

	// The relay's own queue, which is the only thing that says the message
	// went by the path rather than into a mailbox here. The answer cannot:
	// an id is an id either way, and the path in it is the argument read
	// back. Bob has a mailbox on this relay — one identity is on every
	// relay its home joins — so a dropped path succeeds just as loudly.
	row := queuedFor(t, relayStore, "bar")
	if row == nil {
		t.Fatal("nothing is queued for bar: the message went into a mailbox on this relay " +
			"and the path was dropped")
	}
	if row.ID != sent.RelayID {
		t.Errorf("the answer names %d and the queue holds %d", sent.RelayID, row.ID)
	}
	if row.ToFP != bob.exportFingerprint() {
		t.Errorf("the queued row is for %q, want bob", row.ToFP)
	}
	if row.Path != "" {
		t.Errorf("the queued row has %q left to travel, want nothing past bar", row.Path)
	}
	rec, err := relayStore.MailboxRecord(bob.exportFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if rec.QueuedMessages != 0 {
		t.Errorf("%d messages in bob's mailbox on the sending relay; the path was not taken, and "+
			"bob having a mailbox here is why that would otherwise look like success",
			rec.QueuedMessages)
	}

	// The sender's own copy says the same, since that is where they will
	// look when a report comes back naming the id.
	s, _, _ := alice.opened()
	msgs, err := s.List(store.Sent)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("%d sent records, want 1", len(msgs))
	}
	if msgs[0].Path != "bar" {
		t.Errorf("the sent record says path %q, want bar", msgs[0].Path)
	}
	if msgs[0].RelayID != sent.RelayID {
		t.Errorf("the record's id is %d and the answer's %d", msgs[0].RelayID, sent.RelayID)
	}

	// And an ordinary message to the same person keeps no path at all, so
	// the key says something by being there.
	alice.run("send", "--to", "bob", "hello here")
	msgs, err = s.List(store.Sent)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if strings.Contains(m.Inner.Body.Text, "hello here") && m.Path != "" {
			t.Errorf("a message to a mailbox on this relay kept path %q", m.Path)
		}
	}
}

// TestTheTwoSpellingsOfAnAddress: --to 'bar!bob' and --to bob --via bar are
// the same address, and both at once is a usage error rather than a guess.
func TestTheTwoSpellingsOfAnAddress(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar", "baz")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	for _, args := range [][]string{
		{"send", "--to", "bar!baz!bob", "--json", "one"},
		{"send", "--to", "bob", "--via", "bar!baz", "--json", "two"},
	} {
		out := alice.run(args...)
		var sent sentJSON
		if err := json.Unmarshal([]byte(out), &sent); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if sent.Path != "bar!baz" {
			t.Errorf("%v: path %q, want bar!baz", args, sent.Path)
		}
		// And the relay queued it for the first hop with the rest still to
		// go, which is what makes the two spellings the same address rather
		// than two arguments that print alike.
		row := queuedFor(t, relayStore, "bar")
		if row == nil {
			t.Fatalf("%v: nothing queued for bar", args)
		}
		if row.Path != "baz" {
			t.Errorf("%v: the row has %q left to travel, want baz", args, row.Path)
		}
		if err := relayStore.Failed(row.ID, "test", "read", time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	_, err := alice.tryRun("send", "--to", "bar!bob", "--via", "baz", "three")
	if err == nil || !strings.Contains(err.Error(), "--via is for giving them separately") {
		t.Errorf("--to with a path and --via together: %v", err)
	}
}

// TestWhatTheTerminalRefusesBeforeAnythingIsSealed: the address rule is the
// relay's own, store.CheckAddress, run here so that a person who mistyped is
// told by the program they typed it into rather than by a relay.
//
// The exit code is what carries that claim, and it is the whole of the test.
// Both ends run the same function and print the same sentence, so a test
// that reads the words alone passes with the terminal's check deleted — the
// relay refuses the same address in the same words, one round trip later. A
// refusal that reaches a relay comes back as a transport error, exit 2; one
// this program made is a usage error, exit 1, and that is the difference
// between being told what you typed is wrong and being told a relay would
// not take it.
func TestWhatTheTerminalRefusesBeforeAnythingIsSealed(t *testing.T) {
	relayURL, _ := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	for _, tc := range []struct {
		name, to, want string
	}{
		{"a name that is not a relay name", "b ar!bob", "relay name"},
		{"an empty name", "bar!!bob", "relay name"},
		{"a relay named twice", "bar!bar!bob", "named once"},
		{"named twice, folded", "bar!Bar!bob", "named once"},
		{"the reserved word", "self!bob", "relay name"},
		{"more relays than the protocol allows", strings.Repeat("r!", relayapi.MaxHops+1) + "bob", "at most"},
		{"relays and nobody to give it to", "bar!baz!", "ends in the recipient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := alice.tryRun("send", "--to", tc.to, "text")
			if err == nil {
				t.Fatalf("%q was accepted", tc.to)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%q: %v; want a sentence with %q", tc.to, err, tc.want)
			}
			var e *exitError
			if !errors.As(err, &e) || e.code != exitUsage {
				t.Errorf("%q: %v (exit %d); a refusal this program made is a usage error, and one "+
					"that came back from a relay is not — so this address reached the relay",
					tc.to, err, exitCodeOf(err))
			}
			// Nothing was sealed, dialled or written down.
			s, _, _ := alice.opened()
			msgs, err := s.List(store.Sent)
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != 0 {
				t.Errorf("%d sent records for an address that was refused", len(msgs))
			}
		})
	}
}

// TestALargeMessageDoesNotCrossARelayYet: a message that would become a
// stream cannot go by way of a relay, and the refusal is at the terminal.
//
// A stream is an upload held open at the relay it is going to and resumed by
// a route that names its id; no relay carries one to a neighbour. So the
// question the refusal asks has to be the same question the switch asks —
// would this become a stream — and the sizes here are chosen to hold it to
// that. Asked as "is this over the relay's 16 MiB limit" instead, everything
// from the 64 KiB threshold up to 16 MiB fell through to the stream, which
// takes a channel and no path: the message went into a mailbox on the
// sender's own relay, the path was dropped, and the answer said it was sent.
// The recipient having a mailbox on the sending relay — one identity is on
// every relay its home joins — is what makes that silent rather than an
// error.
func TestALargeMessageDoesNotCrossARelayYet(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"asked for", []string{"send", "--to", "bar!bob", "--stream", "text"}},
		// Just over the stream threshold, which is 64 KiB: the smallest
		// message that becomes one without being asked, and the bottom of
		// the window that used to fall through.
		{"just over the threshold", []string{"send", "--to", "bar!bob",
			"--attach", fileOfSize(t, 96<<10), "text"}},
		{"far over it, and far under the relay's limit", []string{"send", "--to", "bar!bob",
			"--attach", fileOfSize(t, 4<<20), "text"}},
		{"over the relay's limit too", []string{"send", "--to", "bar!bob",
			"--attach", fileOfSize(t, relayapi.DefaultMaxBytes), "text"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := alice.tryRun(tc.args...)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "a large message does not cross a relay yet") {
				t.Errorf("%v", err)
			}
			var e *exitError
			if !errors.As(err, &e) || e.code != exitUsage {
				t.Errorf("%v (exit %d); the refusal is this program's", err, exitCodeOf(err))
			}
			// And nothing went anywhere: not to the neighbour's queue, and
			// not into the recipient's mailbox on this relay, which is
			// where a dropped path would have put it.
			if row := queuedFor(t, relayStore, "bar"); row != nil {
				t.Errorf("row %d queued for bar by a refused send", row.ID)
			}
			rec, err := relayStore.MailboxRecord(bob.exportFingerprint())
			if err != nil {
				t.Fatal(err)
			}
			if rec.QueuedMessages != 0 {
				t.Errorf("%d messages in bob's mailbox here: the path was dropped and the message "+
					"was delivered to the wrong relay", rec.QueuedMessages)
			}
		})
	}

	// The same message without a path is a stream and goes, so the refusal
	// is about crossing a relay and not about the size.
	if out := alice.run("send", "--to", "bob", "--attach", fileOfSize(t, 96<<10), "text"); !strings.Contains(out, "sent") {
		t.Errorf("the same message to a mailbox on this relay:\n%s", out)
	}
}

// fileOfSize writes a file of n bytes and answers its path.
func fileOfSize(t *testing.T, n int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attachment")
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAKnockTakesNoPath: a knock asks a mailbox's own relay for its owner's
// card, and no relay carries one.
func TestAKnockTakesNoPath(t *testing.T) {
	relayURL, _ := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	_, err := alice.tryRun("knock", "bar!bob")
	if err == nil || !strings.Contains(err.Error(), "takes no path") {
		t.Errorf("a knock with a path: %v", err)
	}
}

// TestAnEnvelopeTheRelayAlreadyHoldsIsPlacedAndNotFailed: the relay answers
// 409 for an envelope already in its queue, and that is not a failure.
//
// Posting the same sealed bytes twice is what the test does directly,
// because nothing in `auu send` does it: a send seals afresh every time, so
// the hash is new, and the client retries only what a relay answered 503 or
// 429 to. The caller that meets a 409 in earnest is the relay's own worker,
// retrying bytes it has stored. This holds this end to the same reading of
// the route's contract, so that the message is reported as queued — once,
// in the row the id names — rather than as failed, which would have
// somebody send it again and the relay hold two.
func TestAnEnvelopeTheRelayAlreadyHoldsIsPlacedAndNotFailed(t *testing.T) {
	relayURL, _ := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	s, id, relays := alice.opened()
	c, err := dial(s, id, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := envelope.SealFor(id, recipient, "", message.Body{
		Type: message.TypeNote, Subject: "s", Thread: mustID(t), Text: "twice",
	})
	if err != nil {
		t.Fatal(err)
	}

	mode := sendMode{path: []string{"bar"}}
	first, err := postOrForward(c, env, mode)
	if err != nil {
		t.Fatalf("the first post: %v", err)
	}
	second, err := postOrForward(c, env, mode)
	if err != nil {
		t.Fatalf("the second post of the same envelope was reported as a failure: %v", err)
	}
	if second != first {
		t.Errorf("the second answered row %d and the first %d; both name the one row the relay made",
			second, first)
	}
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAFlagAfterTheTextStillReaches: parseArgs puts the flags anywhere, so
// the address is read whether it comes before the message or after it.
//
// It is the ordinary shape of a mistake — type the message, then remember
// where it is going — and a Go flag set left to itself stops at the first
// positional, which would have sent this to bob on this relay and said
// nothing about the relay named in an argument it ignored.
func TestAFlagAfterTheTextStillReaches(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	out := alice.run("send", "hello after the flags", "--to", "bar!bob", "--json")
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if sent.Path != "bar" {
		t.Errorf("path %q, want bar: the address after the text was not read", sent.Path)
	}
	row := queuedFor(t, relayStore, "bar")
	if row == nil {
		t.Fatal("nothing queued for bar: the address after the text was not acted on")
	}
	if err := relayStore.Failed(row.ID, "test", "read", time.Now()); err != nil {
		t.Fatal(err)
	}
	// And --via after the text, which is the same question for the other
	// spelling.
	out = alice.run("send", "again", "--to", "bob", "--via", "bar", "--json")
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if sent.Path != "bar" {
		t.Errorf("path %q, want bar: --via after the text was not read", sent.Path)
	}
	if queuedFor(t, relayStore, "bar") == nil {
		t.Fatal("nothing queued for bar: --via after the text was not acted on")
	}
}

// TestAChannelOnAPathIsSentAsWritten: which channels a recipient has is
// theirs to publish to the senders they admit, and the relay that knows is
// the last hop, not the first.
//
// So the name goes as written and is not checked here, and no hint is
// fetched: the first hop holds no directory for a mailbox it does not have,
// and asking it would answer about the wrong relay. A name the last hop
// refuses comes back as a failed row, which is what the client document
// says.
func TestAChannelOnAPathIsSentAsWritten(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	out := alice.run("send", "--to", "bar!bob", "--channel", "work", "--json", "for the work channel")
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if sent.Channel != "work" {
		t.Errorf("channel %q, want work", sent.Channel)
	}

	// On the wire, which is the claim. The answer above is the argument read
	// back and says nothing: the channel is the one field outside the seal,
	// SealFor leaves it to whoever posts, and a forward that did not set it
	// would send bytes with no channel in them at all — which the last hop
	// would file under default while the sealed copy inside said "work",
	// and which the recipient's client quarantines as misfiled.
	row := queuedFor(t, relayStore, "bar")
	if row == nil {
		t.Fatal("nothing queued for bar")
	}
	raw, err := relayStore.OutboundBody(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	var onTheWire envelope.Envelope
	if err := json.Unmarshal(raw, &onTheWire); err != nil {
		t.Fatal(err)
	}
	if onTheWire.Ch != "work" {
		t.Errorf("the queued envelope names channel %q; the last hop routes by this field, and "+
			"nothing else on the wire carries the channel", onTheWire.Ch)
	}
	if onTheWire.To != bob.exportFingerprint() {
		t.Errorf("the queued envelope is for %q", onTheWire.To)
	}
	// Bob has no such channel and has pushed no directory; on this relay
	// the same message is refused, which is the difference the path makes.
	if _, err := alice.tryRun("send", "--to", "bob", "--channel", "work", "here"); err == nil {
		t.Error("a channel nobody published was accepted for a mailbox on this relay")
	}
}

// exitCodeOf is what a failed command would have exited with, for a test
// that wants to say so in its message.
func exitCodeOf(err error) int {
	var e *exitError
	if errors.As(err, &e) {
		return e.code
	}
	return -1
}

// A message that came by way of another relay, from the receiving end: the
// record keeps the route, `read` shows it, and a reply goes back along it
// without being told.

// peeredPair is two relays that carry mail to each other, and one user on
// each. What it does not fake is the carrying: A's worker dials B as its
// courier, B delivers into the mailbox, and the reply comes back the same
// way, so what these tests read is what two relays actually did.
type peeredPair struct {
	alice *user
	bob   *user
}

// inbox is what this user's spool holds, oldest first.
func (u *user) inbox(t *testing.T) []*store.Stored {
	t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(store.Inbox)
	if err != nil {
		t.Fatal(err)
	}
	return msgs
}

// waitForInbox fetches until the mail has arrived, or gives up saying what it
// saw. A message that crosses relays takes a worker's turn to get there, so a
// single fetch is a race; this is the fetch a person would repeat.
func waitForInbox(t *testing.T, u *user, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		u.run("inbox")
		if got := len(u.inbox(t)); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d messages after 20s, want %d", len(u.inbox(t)), want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// setVia rewrites a spool record's via, for the cases an operator's own
// naming produces and a test cannot peer its way into: a name the receiving
// relay cannot dial, which is what a one-way or mismatched peering leaves in
// a record.
func setVia(t *testing.T, u *user, id, via string) {
	t.Helper()
	s, _, _ := u.opened()
	m, err := s.Load(store.Inbox, id)
	if err != nil {
		t.Fatal(err)
	}
	m.Via = via
	if err := s.Save(store.Inbox, m); err != nil {
		t.Fatal(err)
	}
}

// TestAMessageThatCameByARelayIsAnsweredBackAlongIt: the round trip, at the
// terminal, with nothing between the two relays faked.
func TestAMessageThatCameByARelayIsAnsweredBackAlongIt(t *testing.T) {
	p := peerTwoRelays(t)

	// Alice writes to Bob by way of her relay's name for his.
	out := p.alice.run("send", "--to", "beta!bob", "--subject", "hello", "--json", "over there")
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if sent.Path != "beta" {
		t.Fatalf("path %q, want beta", sent.Path)
	}

	// Bob's inbox, once his relay has it: the record says how it came.
	waitForInbox(t, p.bob, 1)
	msgs := p.bob.inbox(t)
	if len(msgs) != 1 {
		t.Fatalf("%d messages, want 1", len(msgs))
	}
	if msgs[0].Via == "" {
		t.Fatal("the record says nothing about how the message came")
	}
	// One hop, named by the relay that delivered: B's own name for A.
	if msgs[0].Via != "alpha" {
		t.Errorf("via %q, want alpha — B's name for A, not A's for B", msgs[0].Via)
	}

	// read shows it.
	shown := p.bob.run("read", msgs[0].Inner.ID[:12])
	if !strings.Contains(shown, "via:     alpha") {
		t.Errorf("read does not say how it came:\n%s", shown)
	}

	// And the reply goes back the way it came, without being told.
	out = p.bob.run("reply", msgs[0].Inner.ID[:12], "--json", "got it")
	var back sentJSON
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if back.Path != "alpha" {
		t.Errorf("the reply's path is %q, want alpha: a reply goes back the way the message came",
			back.Path)
	}
	waitForInbox(t, p.alice, 1)
	if got := p.alice.inbox(t); len(got) != 1 || got[0].Inner.Body.Text != "got it" {
		t.Errorf("%d messages back at alice", len(got))
	}
}

// TestAReplyToMailThatCameNoDistanceGoesToTheMailbox: the reversal applies to
// mail that travelled, and nothing else. A reply to a message posted on the
// same relay is an ordinary post, as it always was.
func TestAReplyToMailThatCameNoDistanceGoesToTheMailbox(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	alice.run("send", "--to", "bob", "--subject", "here", "on this relay")
	bob.run("inbox")
	msgs := bob.inbox(t)
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	if msgs[0].Via != "" {
		t.Fatalf("a message posted here says via %q", msgs[0].Via)
	}
	out := bob.run("reply", msgs[0].Inner.ID[:12], "--json", "back")
	var back sentJSON
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if back.Path != "" {
		t.Errorf("the reply took path %q; a message that came no distance is answered by a post",
			back.Path)
	}
	if row := queuedFor(t, relayStore, "bar"); row != nil {
		t.Errorf("row %d queued for a reply to a mailbox on this relay", row.ID)
	}
}

// TestHowSomebodyAnswersWhenTheReversalCannotRoute: the names in a via are
// each hop's own for the hop before, and a path is resolved against the
// courier home a relay dials from. Where an operator used one name in both
// the reversal routes; where they did not, or where the peering goes one way,
// it cannot — and what the person meets must be a sentence about their reply.
func TestHowSomebodyAnswersWhenTheReversalCannotRoute(t *testing.T) {
	relayURL, _ := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	// A record that says it came by a relay this one cannot dial, which is
	// what a mismatched or one-way peering leaves behind.
	alice.run("send", "--to", "bob", "--subject", "s", "text")
	bob.run("peers", "add", alice.exportLine())
	bob.run("inbox")
	msgs := bob.inbox(t)
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	setVia(t, bob, msgs[0].Inner.ID, "nowhere")

	_, err := bob.tryRun("reply", msgs[0].Inner.ID[:12], "back")
	if err == nil {
		t.Fatal("the reply was accepted down a path the relay cannot route")
	}
	for _, want := range []string{
		"cannot send back the way it came",
		"--via",
		"--relay",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v\nwant a sentence with %q", err, want)
		}
	}

	// And the override works, which is what the sentence points at: the
	// relay does know "bar".
	out, err := bob.tryRun("reply", msgs[0].Inner.ID[:12], "--via", "bar", "--json", "back")
	if err != nil {
		t.Fatalf("--via on a reply: %v\n%s", err, out)
	}
	if got := pathOf(t, out); got != "bar" {
		t.Errorf("--via gave path %q, want bar: it did not override the reversal", got)
	}
}

// TestAReplyOverriddenToSomebodyElseIsRefused: --to on a reply is for saying
// the address, not for changing who is being answered.
func TestAReplyOverriddenToSomebodyElseIsRefused(t *testing.T) {
	relayURL, _ := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("peers", "add", carol.exportLine())

	alice.run("send", "--to", "bob", "--subject", "s", "text")
	bob.run("inbox")
	msgs := bob.inbox(t)
	_, err := bob.tryRun("reply", msgs[0].Inner.ID[:12], "--to", "bar!carol", "text")
	if err == nil {
		t.Fatal("a reply was addressed to somebody else")
	}
	if !strings.Contains(err.Error(), "this is a reply to") || !strings.Contains(err.Error(), "--via") {
		t.Errorf("%v; want the two people named and --via offered", err)
	}
	// Naming the same person is fine: it is how somebody gives the address.
	out, err2 := bob.tryRun("reply", msgs[0].Inner.ID[:12], "--to", "bar!alice", "--json", "text")
	if err2 != nil {
		t.Fatalf("--to naming the same person: %v\n%s", err2, out)
	}
	if got := pathOf(t, out); got != "bar" {
		t.Errorf("--to naming the same person gave path %q, want bar", got)
	}
}

// peerTwoRelays starts two relays that carry mail to each other, and a user
// on each with the other as a peer.
//
// The names are deliberately different in each direction and each is the
// relay's own: A calls B "beta" and B calls A "alpha", in both halves of each
// peering — the courier home it dials from and the couriers file it accepts
// by. That is the convention an operator is meant to keep, and keeping it is
// what makes a reply's reversed address route.
//
// A mutual peering is a knot: each relay reads its neighbours' URLs when it
// starts, and neither URL exists until a listener does. So both listeners are
// opened first, around a handler that is filled in after — which is what lets
// each courier home name an address that is really listening, with nothing
// about the two relays faked.
func peerTwoRelays(t *testing.T) *peeredPair {
	t.Helper()
	// Each courier is named for what its neighbour calls the relay it
	// belongs to, because that is where the name comes from: a courier is
	// admitted by an export line in the neighbour's couriers file, and the
	// name in that line is the neighbour's name for that relay. It is what
	// the neighbour writes into via, so A's courier is "alpha" — B's name
	// for A — and B's is "beta".
	aCourier, bCourier := courierIdentity(t, "alpha"), courierIdentity(t, "beta")

	var aLate, bLate lateHandler
	aSrv := httptest.NewServer(&aLate)
	bSrv := httptest.NewServer(&bLate)
	t.Cleanup(aSrv.Close)
	t.Cleanup(bSrv.Close)

	// Each admits the other's courier, under its own name for that relay.
	aFile := filepath.Join(t.TempDir(), "a-couriers")
	bFile := filepath.Join(t.TempDir(), "b-couriers")
	writeCourierLines(t, aFile, bCourier)
	writeCourierLines(t, bFile, aCourier)

	// And each dials the other, under the same name it accepts it by.
	// Each relay also holds the other's courier as a registered identity,
	// since a courier forwards by being a user of the relay it forwards to.
	aLate.h = peeredRelay(t, aCourier, map[string]string{"beta": bSrv.URL}, aFile, bCourier)
	bLate.h = peeredRelay(t, bCourier, map[string]string{"alpha": aSrv.URL}, bFile, aCourier)

	alice := newUser(t, "alice", aSrv.URL)
	bob := newUser(t, "bob", bSrv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	return &peeredPair{alice: alice, bob: bob}
}

// lateHandler is a handler set after its listener is open, so that two relays
// can each be told the other's address.
type lateHandler struct{ h http.Handler }

func (l *lateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if l.h == nil {
		http.Error(w, "not started", http.StatusServiceUnavailable)
		return
	}
	l.h.ServeHTTP(w, r)
}

// peeredRelay is one relay of a peering: its own store, its courier home
// naming the neighbours it dials, and the file of couriers it accepts from.
func peeredRelay(t *testing.T, courier *identity.Identity, dials map[string]string, accepts string,
	enrol ...*identity.Identity) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	home := filepath.Join(dir, "courier")
	hs, err := store.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := hs.SaveIdentity(courier); err != nil {
		t.Fatal(err)
	}
	for name, url := range dials {
		if _, err := hs.AddRelay(name, url); err != nil {
			t.Fatal(err)
		}
	}
	c, err := relay.NewCourier(relay.CourierConfig{
		Home: home, AuthorizedFile: accepts, PublicURL: "https://mine.example",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// The couriers this relay is a neighbour to are registered here, which
	// is what "enrolled at its neighbour" means: a courier is a user of the
	// relay it forwards through, and the forward route refuses an identity
	// with no mailbox as it refuses any other. Done in the store rather than
	// over the wire, since registering spends budgets these tests measure.
	for _, id := range enrol {
		if err := st.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, relay.RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	logs := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay log:\n%s", logs.String())
		}
	})
	handler := relay.NewServer(st, relay.Config{
		Courier: c, CourierLimits: relay.DefaultCourierLimits(), Limits: relay.DefaultLimits(),
		Streams: true, Logger: slog.New(slog.NewTextHandler(logs, nil)),
	})
	t.Cleanup(handler.Close)
	return handler
}

// courierIdentity is a relay's own identity at its neighbours.
func courierIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// writeCourierLines writes a couriers file admitting the given identities, in
// the administrators file's format and with its mode.
func writeCourierLines(t *testing.T, path string, ids ...*identity.Identity) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# the relays this one accepts forwarded mail from\n\n")
	for _, id := range ids {
		b.WriteString(id.Public().ExportLine() + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// pathOf is the path out of a --json answer, parsed rather than matched: the
// output is indented, so a substring check would pass or fail on a space.
func pathOf(t *testing.T, out string) string {
	t.Helper()
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return sent.Path
}

// TestWhatAQueueLooksLikeToItsOwner: `auu queue` is what somebody reads when
// they ask where their mail has got to, and each state answers a different
// question, so each is printed differently.
func TestWhatAQueueLooksLikeToItsOwner(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	// Nothing queued: a sentence, not an empty screen.
	if out := alice.run("queue"); !strings.Contains(out, "nothing of yours is waiting") {
		t.Errorf("an empty queue:\n%s", out)
	}
	// And the inbox says nothing at all, which is the point of the line
	// being conditional: most relays forward nothing and most mail goes
	// nowhere near a queue.
	if out := alice.run("inbox"); strings.Contains(out, "waiting at") {
		t.Errorf("the inbox spoke about an empty queue:\n%s", out)
	}

	// Three rows, one in each state.
	waiting := queueOne(t, alice, "still going")
	handed := queueOne(t, alice, "gone")
	failed := queueOne(t, alice, "refused")
	if err := relayStore.Handed(handed, 9, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := relayStore.Failed(failed, "refused", "bar: no such mailbox", time.Now()); err != nil {
		t.Fatal(err)
	}

	out := alice.run("queue")
	for _, want := range []string{
		"waiting", "to bar",
		"next try", "gives up",
		"handed", "comes back as a report",
		"final", "refused: bar: no such mailbox",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the queue does not say %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, shortQueueID(waiting)) {
		t.Errorf("the waiting row's id is missing:\n%s", out)
	}

	// --json is the wire's own shape with the relay named, since one home
	// may be on several.
	var rows []queuedJSON
	if err := json.Unmarshal([]byte(alice.run("queue", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows in --json, want 3", len(rows))
	}
	for _, r := range rows {
		if r.Relay == "" {
			t.Error("a row does not say which relay holds it")
		}
	}

	// And the inbox now says one line about it, with the counts.
	out = alice.run("inbox")
	if !strings.Contains(out, "1 waiting at") || !strings.Contains(out, "1 failed") {
		t.Errorf("the inbox line:\n%s", out)
	}
	if !strings.Contains(out, "queue") {
		t.Errorf("the inbox line does not say what to run:\n%s", out)
	}
	// What the line says about a neighbour being unreachable is not asserted
	// here. It would depend on this relay's own worker having attempted a
	// dial before this line runs — near certain, and still a race, and a
	// flaky test is worse than no test. The clause has its deterministic
	// coverage in TestTheInboxClaimsNoMoreThanItKnows, which drives the line
	// as the function of its rows that it is, so an assertion here would be
	// redundant as well as racy.
}

// TestTheInboxClaimsNoMoreThanItKnows: the inbox's line about a queue says
// what the rows support and nothing beyond it.
//
// "Unreachable since" is a claim about a neighbour, and the only evidence for
// it is an attempt that failed. A row queued and not yet offered is not that:
// it says the relay has not got to it, which is a fact about the relay and
// not about the neighbour. So the clause is left out, and the line still says
// the count, the next try and when it gives up. Driven as a function of the
// rows, because that is what the line is.
func TestTheInboxClaimsNoMoreThanItKnows(t *testing.T) {
	at := func(s string) time.Time {
		t.Helper()
		when, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return when
	}
	row := func(state, neighbour string, tries int64, last, next, up time.Time) relayapi.QueuedMessage {
		return relayapi.QueuedMessage{ID: 1, Neighbour: neighbour, State: state, Tries: tries,
			LastTry: last, NextTry: next, GivesUp: up}
	}
	zero := time.Time{}
	next := at("2026-09-30T11:40:00Z")
	up := at("2026-10-03T10:40:00Z")
	tried := at("2026-09-30T10:40:00Z")

	for _, tc := range []struct {
		name  string
		rows  []relayapi.QueuedMessage
		want  []string
		avoid []string
	}{
		{"nothing queued", nil, nil, []string{"waiting", "failed"}},
		{"one waiting, never tried",
			[]relayapi.QueuedMessage{row("waiting", "bar", 0, zero, next, up)},
			[]string{"1 waiting at work for bar", "next try", "gives up", "queue"},
			[]string{"unreachable since"}},
		{"one waiting, tried",
			[]relayapi.QueuedMessage{row("waiting", "bar", 3, tried, next, up)},
			[]string{"1 waiting at work for bar", "unreachable since", "next try", "gives up"},
			nil},
		{"one failed and nothing waiting",
			[]relayapi.QueuedMessage{row("final", "bar", 1, tried, next, up)},
			[]string{"1 failed", "queue"},
			[]string{"waiting", "unreachable since"}},
		{"both",
			[]relayapi.QueuedMessage{
				row("waiting", "bar", 2, tried, next, up),
				row("final", "bar", 1, tried, next, up),
			},
			[]string{"1 waiting", "1 failed"}, nil},
		{"a handed row is neither, and is not counted",
			[]relayapi.QueuedMessage{row("handed", "bar", 1, tried, next, up)},
			nil, []string{"waiting", "failed"}},
		// The count beside a neighbour's name is that neighbour's own. The
		// times in the clause are one relay's and cannot be said of
		// several, so the line names the one holding the most — and what
		// is waiting for another is said separately rather than added to
		// it, since a number in front of a name is a claim about that name.
		{"the count beside a neighbour is that neighbour's",
			[]relayapi.QueuedMessage{
				row("waiting", "baz", 1, tried, next, up),
				row("waiting", "bar", 1, tried, next, up),
				row("waiting", "bar", 1, tried, next, up),
			},
			[]string{"2 waiting at work for bar", "1 more for other relays"},
			[]string{"3 waiting", "for baz ("}},
		{"one neighbour alone says nothing about others",
			[]relayapi.QueuedMessage{row("waiting", "bar", 1, tried, next, up)},
			[]string{"1 waiting at work for bar"}, []string{"more for other relays"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := queueLine(relayFetch{Relay: "work", Outbound: tc.rows})
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("%q does not contain %q", got, want)
				}
			}
			for _, avoid := range tc.avoid {
				if strings.Contains(got, avoid) {
					t.Errorf("%q contains %q, which the rows do not support", got, avoid)
				}
			}
			if len(tc.want) == 0 && got != "" {
				t.Errorf("%q; want silence", got)
			}
		})
	}
}

// queueOne posts one message down a path and answers the row's id.
func queueOne(t *testing.T, u *user, text string) int64 {
	t.Helper()
	out := u.run("send", "--to", "bar!bob", "--json", text)
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return sent.RelayID
}

// TestAFollowUpOnAThreadThatCrossedARelayGoesTheSameWay: the latest message
// on a thread you started and nobody has answered is your own, so a follow-up
// reaches a sent record — and a sent record keeps where it went, not where
// anything came from.
//
// Read as a received record it says nothing, and the follow-up was posted
// into a mailbox on the sender's own relay: either delivered to the wrong
// place with the answer saying it was sent, or refused as a recipient "not
// registered on this relay" about somebody they have been writing to all day.
// It is the same fault the commit before this one fixed for a large message,
// on the thread path.
func TestAFollowUpOnAThreadThatCrossedARelayGoesTheSameWay(t *testing.T) {
	relayURL, relayStore := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	out := alice.run("send", "--to", "bar!bob", "--subject", "s", "--json", "first")
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if sent.Path != "bar" {
		t.Fatalf("the first message went by %q", sent.Path)
	}
	first := queuedFor(t, relayStore, "bar")
	if first == nil {
		t.Fatal("the first message was not queued")
	}
	if err := relayStore.Handed(first.ID, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Replying by the thread, which is what the sentence for a sent id
	// tells somebody to do.
	out = alice.run("reply", sent.Thread[:12], "--json", "following up")
	var follow sentJSON
	if err := json.Unmarshal([]byte(out), &follow); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if follow.Path != "bar" {
		t.Errorf("the follow-up went by %q, want bar: a thread that crossed a relay keeps crossing it",
			follow.Path)
	}
	if row := queuedFor(t, relayStore, "bar"); row == nil {
		t.Error("nothing queued for bar: the follow-up was posted on the sender's own relay")
	}
	// And bob's mailbox on alice's own relay is untouched, which is where a
	// dropped address would have put it.
	rec, err := relayStore.MailboxRecord(bob.exportFingerprint())
	if err == nil && rec.QueuedMessages != 0 {
		t.Errorf("%d messages in bob's mailbox on the sending relay", rec.QueuedMessages)
	}
}

// TestAQueuesWordsAreEscapedWhereverTheyCameFrom: the code and the sentence
// on a failed row are another relay's words, and a terminal sees neither raw.
//
// The client holds both to a shape before this, so a relay that tries an
// escape is refused whole; this is the line under that rule rather than the
// rule, and it is here because the guide's rule is about the terminal and not
// about who checked first. Driven at printQueue, since the check upstream
// would otherwise refuse the row and nothing would be printed at all.
func TestAQueuesWordsAreEscapedWhereverTheyCameFrom(t *testing.T) {
	out := capture(t, func() {
		printQueue([]queuedJSON{{
			ID: 1, Neighbour: "bar", State: "final", Relay: "work",
			Code: "\x1b[2J\rgave-up",
			Said: "bar: \x1b[31mno such mailbox\n  forged line",
		}})
	})
	for _, raw := range []string{"\x1b", "\r", "\n  forged line"} {
		if strings.Contains(out, raw) {
			t.Errorf("a relay's byte %q reached the terminal:\n%q", raw, out)
		}
	}
	// And what it says is still readable.
	for _, want := range []string{"gave-up", "no such mailbox"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from:\n%s", want, out)
		}
	}
}

// capture is what a function printed to stdout.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	real := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = real
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(data)
}
