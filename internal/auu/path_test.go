package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
