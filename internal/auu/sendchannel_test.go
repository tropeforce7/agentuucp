package auu

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// peersAndDirectory sets up alice and bob as peers on one relay, with bob's
// directory holding default and bug reports.
func peersAndDirectory(t *testing.T) (*user, *user, *relay.Store) {
	t.Helper()
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "create", "bug reports", "--description", "One bug per message")
	return alice, bob, workStore
}

// storedOnRelay reads what the relay holds for a mailbox: the row and the
// bytes of its newest message.
func storedOnRelay(t *testing.T, st *relay.Store, fp string) (relay.Row, []byte) {
	t.Helper()
	l, err := st.Listing(fp, 0, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Rows) == 0 {
		t.Fatal("nothing on the relay")
	}
	row := l.Rows[len(l.Rows)-1]
	f, err := st.OpenMessage(fp, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return row, raw
}

// The outer ch, the sealed record and the relay's row agree on the channel
// for an envelope; the open-stream request, the signed manifest and the row
// for a stream; and a send that names nothing puts nothing on the wire.
func TestASendCarriesTheChannelOnTheWire(t *testing.T) {
	alice, bob, workStore := peersAndDirectory(t)
	_, bobID, _ := bob.opened()
	fp := bobID.Fingerprint()

	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "one", "--json", "a bug")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Channel != "bug reports" || sent.Kind != "envelope" {
		t.Fatalf("send --json: %+v", sent)
	}
	row, raw := storedOnRelay(t, workStore, fp)
	if row.Channel != "bug reports" {
		t.Fatalf("the relay filed the envelope under %q", row.Channel)
	}
	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.Ch != "bug reports" || !strings.Contains(string(raw), `"ch":"bug reports"`) {
		t.Fatalf("the outer envelope: %s", raw)
	}
	inner, _, err := envelope.Open(bobID, &env)
	if err != nil {
		t.Fatal(err)
	}
	if inner.Channel != "bug reports" {
		t.Fatalf("the sealed record carries %q", inner.Channel)
	}
	// The sent copy records it.
	s, _, _ := alice.opened()
	_, copy, err := s.Find(sent.ID)
	if err != nil || copy.Channel != "bug reports" || copy.Inner.Channel != "bug reports" {
		t.Fatalf("the sent copy: %+v %v", copy, err)
	}
	if text := alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "two", "another"); !strings.Contains(text, `sent to bob via `) ||
		!strings.Contains(text, ` to channel "bug reports"`+"\n") {
		t.Fatalf("the sent line:\n%s", text)
	}

	// A stream: the request, the manifest and the row.
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	sent = sentJSON{}
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "log", "--attach", big, "--json", "the log")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Kind != "stream" || sent.Channel != "bug reports" {
		t.Fatalf("a stream's send --json: %+v", sent)
	}
	row, blob := storedOnRelay(t, workStore, fp)
	if row.Kind != relayapi.KindStream || row.Channel != "bug reports" {
		t.Fatalf("the relay filed the stream as %s under %q", row.Kind, row.Channel)
	}
	n, err := stream.ManifestLength(blob[:stream.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	opened, err := stream.OpenManifest(bobID, blob[:stream.HeaderSize], blob[stream.HeaderSize:stream.HeaderSize+n])
	if err != nil {
		t.Fatal(err)
	}
	if opened.Manifest.Channel != "bug reports" {
		t.Fatalf("the manifest carries %q", opened.Manifest.Channel)
	}
	if _, copy, err := s.Find(sent.ID); err != nil || copy.Channel != "bug reports" || !copy.Streamed {
		t.Fatalf("the stream's sent copy: %+v %v", copy, err)
	}

	// Nothing named: nothing on the wire, and default on the row.
	sent = sentJSON{}
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "three", "--json", "plain")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Channel != "" {
		t.Fatalf("a plain send --json names a channel: %+v", sent)
	}
	row, raw = storedOnRelay(t, workStore, fp)
	if row.Channel != "default" || strings.Contains(string(raw), `"ch"`) {
		t.Fatalf("a plain send: row %q, wire %s", row.Channel, raw)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if inner, _, err := envelope.Open(bobID, &env); err != nil || inner.Channel != "" {
		t.Fatalf("a plain send's record: %v %q", err, inner.Channel)
	}
	if _, copy, err := s.Find(sent.ID); err != nil || copy.Channel != "" {
		t.Fatalf("a plain send's copy: %+v %v", copy, err)
	}
	if text := alice.run("send", "--to", "bob", "--subject", "four", "plain"); strings.Contains(text, "channel") {
		t.Fatalf("a plain send's line names a channel:\n%s", text)
	}
}

// The three sentences for a channel the relay does not have, and the
// relay's own for one outside its period, each at exit 2 with nothing
// queued.
func TestARefusedChannelIsSaidToBe(t *testing.T) {
	alice, bob, workStore := peersAndDirectory(t)
	_, bobID, _ := bob.opened()
	fp := bobID.Fingerprint()
	refused := func(want string, args ...string) {
		t.Helper()
		out, err := alice.tryRun(args...)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitTransport {
			t.Fatalf("auu %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		if err.Error() != want {
			t.Fatalf("auu %s:\n%v\nwant\n%s", strings.Join(args, " "), err, want)
		}
	}
	queuedBefore, _ := workStore.MailboxUsage(fp)

	refused("bob has no channel \"nope\"; their channels are:\n  default (open)\n  bug reports: One bug per message (open)",
		"send", "--to", "bob", "--channel", "nope", "--subject", "s", "x")
	// The same for a stream, whose refusal comes at the open.
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	refused("bob has no channel \"nope\"; their channels are:\n  default (open)\n  bug reports: One bug per message (open)",
		"send", "--to", "bob", "--channel", "nope", "--subject", "s", "--attach", big, "x")
	if _, err := os.Stat(filepath.Join(alice.home, "outbox")); err == nil {
		if entries, _ := os.ReadDir(filepath.Join(alice.home, "outbox")); len(entries) != 0 {
			t.Fatalf("a refused stream left %d files in the outbox", len(entries))
		}
	}

	// A closed channel: the relay's sentence, which names the time in UTC,
	// and the time it carries as data said beside it in local form.
	opens := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	bob.run("channel", "create", "cfp", "--not-before", opens.Format(time.RFC3339))
	closed := `channel "cfp" is not open: opens ` + opens.Format(time.RFC3339)
	if local := opens.Local().Format(time.RFC3339); local != opens.Format(time.RFC3339) {
		closed += ` (` + local + ` here)`
	}
	refused(closed, "send", "--to", "bob", "--channel", "cfp", "--subject", "s", "x")
	refused(closed, "send", "--to", "bob", "--channel", "cfp", "--subject", "s", "--attach", big, "x")
	// The listing says the state in the same words, in the reader's zone.
	refused("bob has no channel \"nope\"; their channels are:\n  default (open)\n  bug reports: One bug per message (open)\n  cfp (opens "+opens.Local().Format(time.RFC3339)+")",
		"send", "--to", "bob", "--channel", "nope", "--subject", "s", "x")

	// default removed, and a send that names nothing.
	bob.run("channel", "delete", "default")
	refused("bob has removed their default channel; choose one with --channel:\n  bug reports: One bug per message (open)\n  cfp (opens "+opens.Local().Format(time.RFC3339)+")",
		"send", "--to", "bob", "--subject", "s", "x")

	// No directory at all, and a --channel: the one-channel sentence.
	carol := newUser(t, "carol", bob.relayURL())
	alice.run("peers", "add", carol.exportLine())
	carol.run("peers", "add", alice.exportLine())
	refused("carol's mailbox has the one channel, default; drop --channel",
		"send", "--to", "carol", "--channel", "nope", "--subject", "s", "x")

	if queuedAfter, _ := workStore.MailboxUsage(fp); queuedAfter.Messages != queuedBefore.Messages {
		t.Fatalf("a refused send queued something: %d before, %d after", queuedBefore.Messages, queuedAfter.Messages)
	}
	// A note to yourself, to a channel you never defined, is said in the
	// second person and verified under your own key.
	refused("your mailbox has the one channel, default; drop --channel",
		"send", "--to", "self", "--channel", "notes", "--subject", "s", "x")
	alice.run("channel", "create", "todo", "--description", "things to do")
	refused("you have no channel \"notes\"; your channels are:\n  default (open)\n  todo: things to do (open)",
		"send", "--to", "self", "--channel", "notes", "--subject", "s", "x")
	alice.run("channel", "delete", "default")
	refused("you have removed your default channel; choose one with --channel:\n  todo: things to do (open)",
		"send", "--to", "self", "--subject", "s", "x")

	// A name no directory could hold is refused here, before the relay.
	usageError(t, alice, `--channel "a/b": name contains "/"`, "send", "--to", "bob", "--channel", "a/b", "--subject", "s", "x")

	// A relay serving a directory for bob that does not verify under the
	// key alice holds: the refusal says so and lists nothing from it.
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	forged := &channels.Directory{V: 1, Owner: fp, Issued: time.Now().Add(time.Hour),
		Channels: []channels.Channel{{Name: "send your keys here"}}}
	doc, sig, err := channels.Sign(mallory, forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workStore.SetDirectory(fp, forged, doc, sig); err != nil {
		t.Fatal(err)
	}
	relayName := alice.defaultRelayName()
	refused(`bob has no channel "nope" on `+relayName+`, and the directory `+relayName+
		` served for bob does not verify against the key you hold; do not trust it`,
		"send", "--to", "bob", "--channel", "nope", "--subject", "s", "x")
	usageError(t, alice, `--channel "a/b": name contains "/"`, "reply", "nothing", "--channel", "a/b", "x")
}

// relayURL is the URL of a user's default relay.
func (u *user) relayURL() string {
	u.t.Helper()
	for _, r := range u.relayList() {
		if r.Default {
			return r.URL
		}
	}
	u.t.Fatal("no default relay")
	return ""
}

// A reply goes to the sender's default unless --channel says otherwise: a
// channel is the receiver's sorting, not a thread.
func TestAReplyPostsToDefaultUnlessTold(t *testing.T) {
	alice, bob, workStore := peersAndDirectory(t)
	alice.run("channel", "create", "answers", "--description", "replies go here")
	_, aliceID, _ := alice.opened()
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "q", "--json", "a bug")), &sent); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	var got inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json", "--no-fetch")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("bob has %d messages", len(got.Messages))
	}

	// Without the flag: default on the wire and on alice's row.
	var reply sentJSON
	if err := json.Unmarshal([]byte(bob.run("reply", got.Messages[0].ID, "--json", "fixed")), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Channel != "" {
		t.Fatalf("a reply without --channel names one: %+v", reply)
	}
	row, raw := storedOnRelay(t, workStore, aliceID.Fingerprint())
	if row.Channel != "default" || strings.Contains(string(raw), `"ch"`) {
		t.Fatalf("a plain reply: row %q, wire has ch: %v", row.Channel, strings.Contains(string(raw), `"ch"`))
	}
	// With it.
	if err := json.Unmarshal([]byte(bob.run("reply", got.Messages[0].ID, "--channel", "answers", "--json", "fixed, really")), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Channel != "answers" {
		t.Fatalf("a reply with --channel: %+v", reply)
	}
	row, raw = storedOnRelay(t, workStore, aliceID.Fingerprint())
	if row.Channel != "answers" || !strings.Contains(string(raw), `"ch":"answers"`) {
		t.Fatalf("a reply to a channel: row %q, wire %s", row.Channel, raw)
	}
	s, _, _ := bob.opened()
	if _, copy, err := s.Find(reply.ID); err != nil || copy.Channel != "answers" || copy.Inner.Channel != "answers" {
		t.Fatalf("the reply's sent copy: %+v %v", copy, err)
	}
}

// An interrupted stream keeps its channel in the outbox record, and the
// message it becomes is filed under it.
func TestAResumedStreamKeepsItsChannel(t *testing.T) {
	relayURL, gate := startInterruptibleRelay(t, 2, 64<<10)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "create", "logs")
	payload := make([]byte, 400<<10)
	file := filepath.Join(t.TempDir(), "interrupted.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := alice.tryRun("send", "--to", "bob", "--channel", "logs", "--subject", "the long one", "--attach", file, "here it is"); err == nil {
		t.Fatalf("the send should have failed with the relay cut off:\n%s", out)
	}
	if p := onlyPending(t, alice); p.Channel != "logs" {
		t.Fatalf("the outbox record carries %q", p.Channel)
	}
	gate.open()
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--resume", "--json")), &sent); err != nil {
		t.Fatalf("resume --json: %v", err)
	}
	if sent.Channel != "logs" {
		t.Fatalf("resume --json: %+v", sent)
	}
	bob.run("inbox")
	var got inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json", "--no-fetch")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("bob has %d messages after the resume", len(got.Messages))
	}
	s, _, _ := alice.opened()
	if _, copy, err := s.Find(sent.ID); err != nil || copy.Channel != "logs" {
		t.Fatalf("the resumed stream's sent copy: %+v %v", copy, err)
	}
}
