package auu

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// sender is a user's identity and a client on their default relay, for a
// test that seals what no command of this build would: a message with
// sections.
func sender(t *testing.T, u *user) (*identity.Identity, *client.Client) {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(s, id, r)
	if err != nil {
		t.Fatal(err)
	}
	return id, c
}

func critical(name string) []wire.Section {
	return []wire.Section{{Name: name, Critical: true, Data: json.RawMessage(`{}`)}}
}

// postSections seals an ask from one user to another with sections, as a
// newer build would, and posts it.
func postSections(t *testing.T, from, to *user, subject string, sections []wire.Section) {
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
	if _, err := c.Post(context.Background(), env, ""); err != nil {
		t.Fatal(err)
	}
}

// streamSections seals a stream from one user to another with sections and
// uploads it whole, as a newer build would.
func streamSections(t *testing.T, from, to *user, subject string, sections []wire.Section) {
	t.Helper()
	streamSectionsTo(t, from, to, "", subject, sections)
}

// streamSectionsTo is streamSections for a channel of the recipient's.
func streamSectionsTo(t *testing.T, from, to *user, channel, subject string, sections []wire.Section) {
	t.Helper()
	streamSectionsDamaged(t, from, to, channel, subject, sections, nil)
}

// streamSectionsDamaged is streamSectionsTo with the sealed bytes handed to
// damage before they are uploaded.
func streamSectionsDamaged(t *testing.T, from, to *user, channel, subject string, sections []wire.Section, damage func([]byte)) {
	t.Helper()
	id, c := sender(t, from)
	payload := []byte("the payload of a stream sealed by a newer build")
	sources := []stream.Source{{
		Name: "later.bin", Media: "application/octet-stream", Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
	}}
	messageID, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	toPub := mustParseBundle(t, mustBundle(t, to))
	m, err := stream.BuildManifestSections(id, toPub, messageID,
		stream.Body{Type: message.TypeAsk, Thread: thread, Subject: subject, Text: "streamed"},
		sources, stream.DefaultChunkSize, sections)
	if err != nil {
		t.Fatal(err)
	}
	m.Channel = channel
	var blob bytes.Buffer
	if err := stream.Seal(&blob, id, toPub, m, sources); err != nil {
		t.Fatal(err)
	}
	if damage != nil {
		damage(blob.Bytes())
	}
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, to.exportFingerprint(), channel, int64(blob.Len()), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(blob.Bytes()), int64(blob.Len())); err != nil {
		t.Fatal(err)
	}
}

// peered is two users on one relay who hold each other and have pushed
// their allow lists, and the relay's store.
func peered(t *testing.T) (alice, bob *user, st *relay.Store) {
	t.Helper()
	srv, st, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice = newUser(t, "alice", srv.URL)
	bob = newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	return alice, bob, st
}

func fetchJSON(t *testing.T, u *user) (inboxJSON, string) {
	t.Helper()
	var out string
	var runErr error
	stderr := captureStderr(t, func() { out, runErr = u.tryRun("inbox", "--json") })
	if runErr != nil {
		t.Fatalf("inbox: %v\n%s\n%s", runErr, out, stderr)
	}
	var in inboxJSON
	if err := json.Unmarshal([]byte(out), &in); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	return in, stderr
}

// D29 and R8: a message with a critical section this build does not know is
// kept under damaged/ with the cause newer and its section's name,
// acknowledged, and said to need a newer auu, naming its sender as the
// quarantine does and never asking for it again; nothing of it is in the
// inbox, and the summary counts it apart from damaged mail.
func TestAMessageThatNeedsANewerAuuIsKeptAndSaidSo(t *testing.T) {
	alice, bob, st := peered(t)
	postSections(t, alice, bob, "from a newer build", critical("must-know"))
	alice.run("send", "--to", "bob", "--subject", "the good one", "hello")
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Unreadable != 1 || in.Fetch.Kept != 1 {
		t.Fatalf("fetch: %+v, want the good one delivered and the newer one kept", in.Fetch)
	}
	if queued, err := st.List(bob.exportFingerprint(), 0, 10); err != nil || len(queued) != 1 {
		t.Fatalf("the relay holds %d (%v); want the newer one acknowledged and the good one kept by its channel", len(queued), err)
	}
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if spoolHas(t, bob, store.Inbox, "from a newer build") {
		t.Error("the message that needs a newer auu is in the inbox")
	}
	n, err := bs.DamagedNeedingNewer()
	if err != nil || n != 1 {
		t.Fatalf("damaged/ holds %d needing a newer auu (%v); want 1", n, err)
	}
	if !strings.Contains(stderr, `from alice needs a newer auu (section "must-know") and was kept as `) ||
		!strings.Contains(stderr, "update auu and open it with auu damaged reopen ") || strings.Contains(stderr, "ask the sender") {
		t.Errorf("the warning:\n%s", stderr)
	}
	out := bob.run("inbox")
	if !strings.Contains(out, "1 message(s) kept under "+bs.DamagedDir()+" need a newer auu; update auu and open them with auu damaged reopen --all") ||
		strings.Contains(out, "ask their senders") {
		t.Errorf("the summary:\n%s", out)
	}
}

// R8 for a stranger: the sentence names an unknown sender by the start of
// the fingerprint, so a key nobody admitted cannot put "update auu" before
// a person as if from a peer.
func TestAStrangersMessageThatNeedsANewerAuuIsSaidToBeAStrangers(t *testing.T) {
	srv, _, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	carol := newUser(t, "carol", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	postSections(t, carol, bob, "from a stranger", critical("must-know"))
	_, stderr := fetchJSON(t, bob)
	if !strings.Contains(stderr, "from an unknown sender, "+carol.exportFingerprint()[:16]+` needs a newer auu (section "must-know")`) {
		t.Errorf("the warning does not name a stranger as one:\n%s", stderr)
	}
}

// D42: a peer's stream with a critical section this build does not know
// waits on the relay, unacknowledged, recorded in the inbox and marked, and
// the fetch goes past it; read, reply and --json say so and show nothing of
// it; the next fetch is clean.
func TestAPeersStreamThatNeedsANewerAuuWaitsOnTheRelay(t *testing.T) {
	alice, bob, st := peered(t)
	streamSections(t, alice, bob, "a newer stream", critical("must-know"))
	alice.run("send", "--to", "bob", "--subject", "the good one", "hello")
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Unreadable != 0 || len(in.Fetch.Newer) != 1 || in.Fetch.Newer[0] != "must-know" {
		t.Fatalf("fetch: %+v, want the good one delivered and the stream waiting\n%s", in.Fetch, stderr)
	}
	if queued, err := st.List(bob.exportFingerprint(), 0, 10); err != nil || len(queued) != 2 {
		t.Fatalf("the relay holds %d (%v); want the stream left there unacknowledged", len(queued), err)
	}
	var waiting *messageJSON
	for i := range in.Messages {
		if in.Messages[i].Subject == "a newer stream" {
			waiting = &in.Messages[i]
		}
	}
	if waiting == nil || waiting.Newer != "must-know" || !waiting.PayloadOnRelay || waiting.Text != "" {
		t.Fatalf("the waiting record in --json: %+v", waiting)
	}
	if out := bob.run("inbox"); !strings.Contains(out, `needs a newer auu (section "must-know")`) ||
		!strings.Contains(out, `1 stream(s) wait on the relay for a newer auu (section "must-know"); update auu to fetch them`) {
		t.Errorf("the listing:\n%s", out)
	}
	sentence := "message " + waiting.ID[:12] + ` waits on the relay for a newer auu (section "must-know"); update auu to fetch it`
	if out := bob.run("read", waiting.ID); strings.TrimSpace(out) != sentence {
		t.Errorf("read: %q; want %q", out, sentence)
	}
	if _, err := bob.tryRun("reply", waiting.ID, "a reply"); err == nil || !strings.Contains(err.Error(), sentence) {
		t.Errorf("reply: %v; want %q", err, sentence)
	}
	if _, err := bob.tryRun("extract", waiting.ID); err == nil || !strings.Contains(err.Error(), sentence) {
		t.Errorf("extract: %v; want %q", err, sentence)
	}
	again, _ := fetchJSON(t, bob)
	if !again.Fetch.empty() || len(again.Fetch.Newer) != 0 {
		t.Errorf("the second fetch met the stream again: %+v", again.Fetch)
	}
}

// D42 for a stranger: the stream waits in the quarantine, marked, and the
// quarantine's show and trust say so and fetch nothing.
func TestAStrangersStreamThatNeedsANewerAuuWaitsInTheQuarantine(t *testing.T) {
	srv, _, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	carol := newUser(t, "carol", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	streamSections(t, carol, bob, "a stranger's newer stream", critical("must-know"))
	in, _ := fetchJSON(t, bob)
	if len(in.Fetch.Newer) != 1 || in.Fetch.Quarantined != 0 {
		t.Fatalf("fetch: %+v, want the stream waiting", in.Fetch)
	}
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	q, err := bs.List(store.Quarantine)
	if err != nil || len(q) != 1 || q[0].Newer != "must-know" || !q[0].PayloadOnRelay {
		t.Fatalf("the quarantine: %v, %v", q, err)
	}
	sentence := "message " + q[0].Inner.ID[:12] + ` waits on the relay for a newer auu (section "must-know"); update auu to fetch it`
	if out := bob.run("quarantine", "show", q[0].Inner.ID); strings.TrimSpace(out) != sentence {
		t.Errorf("quarantine show: %q", out)
	}
	if _, err := bob.tryRun("quarantine", "trust", q[0].Inner.ID); err == nil || !strings.Contains(err.Error(), sentence) {
		t.Errorf("quarantine trust: %v", err)
	}
	if peers := bob.run("peers", "ls"); strings.Contains(peers, carol.exportFingerprint()[:16]) {
		t.Error("trust added the sender although it fetched nothing")
	}
}

// D31: a section this build does not know and need not is kept with the
// message as it came, at the kept size and under, and dropped and counted
// over it; --json names what was kept and counts what was not; the message
// is read either way. This is also D35's round trip through a real relay.
func TestIgnoredSectionsAreKeptToTheKeptSize(t *testing.T) {
	alice, bob, _ := peered(t)
	at := func(n int) json.RawMessage { return json.RawMessage(`"` + strings.Repeat("a", n-2) + `"`) }
	postSections(t, alice, bob, "with sections", []wire.Section{
		{Name: "at-the-size", Data: at(wire.MaxKeptBytes)},
		{Name: "one-over", Data: at(wire.MaxKeptBytes + 1)},
		{Name: "small", Data: json.RawMessage(`{"n":1}`)},
	})
	in, _ := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 {
		t.Fatalf("fetch: %+v, want it read", in.Fetch)
	}
	var got *messageJSON
	for i := range in.Messages {
		if in.Messages[i].Subject == "with sections" {
			got = &in.Messages[i]
		}
	}
	if got == nil || strings.Join(got.IgnoredSections, ",") != "at-the-size,small" || got.DroppedSections != 1 {
		t.Fatalf("--json: %+v; want two kept and one dropped", got)
	}
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, err := bs.Load(store.Inbox, got.ID)
	if err != nil || len(m.Inner.Sections) != 2 || len(m.Inner.Sections[0].Data) != wire.MaxKeptBytes || m.DroppedSections != 1 {
		t.Fatalf("the record: %+v, %v", m, err)
	}
	if out := bob.run("read", got.ID); !strings.Contains(out, "sealed by a newer build") {
		t.Errorf("the message was not read:\n%s", out)
	}
}

// After the upgrade: a peer's stream that waited on the relay is fetched
// whole by the first fetch of a build that knows its section, delivered
// over its record without the mark, and acknowledged; S12 for streams. It
// keeps the arrival of the record that waited, set here an hour back so
// that an arrival taken at the delivery would show: it arrived when it was
// first fetched, not when its payload was.
func TestAWaitingStreamIsFetchedByABuildThatKnowsItsSection(t *testing.T) {
	alice, bob, st := peered(t)
	streamSections(t, alice, bob, "a newer stream", critical("now-known"))
	if in, _ := fetchJSON(t, bob); len(in.Fetch.Newer) != 1 {
		t.Fatalf("fetch: %+v, want the stream waiting", in.Fetch)
	}
	held := recordOf(t, bob, store.Inbox, "a newer stream")
	arrived := held.Arrived.Add(-time.Hour)
	held.Arrived = arrived
	if err := storeOf(t, bob).Save(store.Inbox, held); err != nil {
		t.Fatal(err)
	}
	// The upgrade: this build learns the section.
	t.Cleanup(wire.Register("now-known", wire.OnManifest))
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 {
		t.Fatalf("the fetch after the upgrade: %+v\n%s", in.Fetch, stderr)
	}
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := bs.List(store.Inbox)
	if err != nil || len(msgs) != 1 || msgs[0].Newer != "" || msgs[0].PayloadOnRelay {
		t.Fatalf("the inbox after the upgrade: %v, %v", msgs, err)
	}
	if files, err := os.ReadDir(bs.AttachmentDir(store.Inbox, msgs[0].Inner.ID)); err != nil || len(files) != 1 {
		t.Fatalf("the payload was not fetched: %v, %v", files, err)
	}
	if !msgs[0].Arrived.Equal(arrived) {
		t.Errorf("the delivered stream arrived %v; want the waiting record's, %v", msgs[0].Arrived, arrived)
	}
	if queued, err := st.List(bob.exportFingerprint(), 0, 10); err != nil || len(queued) != 1 {
		t.Errorf("the relay holds %d (%v); the default channel keeps, so the stream stays there", len(queued), err)
	}
}

// A waiting stream whose payload is gone from the relay before the upgrade
// is said once by the first fetch that knows its section, keeps its mark
// with the payload gone, and is never asked for again.
func TestAWaitingStreamGoneFromTheRelayIsSaidOnce(t *testing.T) {
	alice, bob, st := peered(t)
	streamSections(t, alice, bob, "a newer stream", critical("gone-later"))
	fetchJSON(t, bob)
	queued, err := st.List(bob.exportFingerprint(), 0, 10)
	if err != nil || len(queued) != 1 {
		t.Fatalf("queued %d (%v)", len(queued), err)
	}
	if _, err := st.Delete(bob.exportFingerprint(), queued[0].ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wire.Register("gone-later", wire.OnManifest))
	_, stderr := fetchJSON(t, bob)
	if !strings.Contains(stderr, "waited on ") || !strings.Contains(stderr, "is no longer there; ask the sender to send it again") {
		t.Errorf("the gone stream was not said:\n%s", stderr)
	}
	_, stderr = fetchJSON(t, bob)
	if strings.Contains(stderr, "is no longer there") {
		t.Errorf("the gone stream was said twice:\n%s", stderr)
	}
}

// Ruling 62: serve leaves a stream that waits for a newer auu pending in its
// ledger with that reason, never skipped, never answered and never counted
// as a turn; the round after the upgrade finds it delivered and answers it.
func TestServeAnswersAWaitingStreamAfterTheUpgrade(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	streamSectionsTo(t, alice, bob.user, bob.channel, "a newer ask", critical("serve-later"))
	first := bob.round(t)
	if len(first.Answered) != 0 || len(first.Skipped) != 0 || len(first.Failed) != 0 {
		t.Fatalf("the round before the upgrade: %+v; want nothing answered, skipped or failed", first)
	}
	var waiting *ledgerEntry
	var id string
	for mid, e := range bob.ledgerOf(t).Messages {
		if e.Newer != "" {
			waiting, id = e, mid
		}
	}
	if waiting == nil || waiting.Newer != "serve-later" || waiting.settled() {
		t.Fatalf("the ledger before the upgrade: %+v; want the message pending with the reason newer", waiting)
	}
	if n := bob.ledgerOf(t).answered(waiting.Thread); n != 0 {
		t.Fatalf("%d turns counted on the thread before the upgrade; want none", n)
	}
	t.Cleanup(wire.Register("serve-later", wire.OnManifest))
	second := bob.round(t)
	if len(second.Answered) != 1 {
		t.Fatalf("the round after the upgrade: %+v; want the message answered", second)
	}
	after := bob.ledgerOf(t).Messages[id]
	if after == nil || after.Handled.IsZero() || after.Newer != "" {
		t.Fatalf("the ledger after the upgrade: %+v; want it settled and the reason gone", after)
	}
	if n := bob.ledgerOf(t).answered(after.Thread); n != 1 {
		t.Errorf("%d turns counted after the answer; want one", n)
	}
}

// From the second reader on e332ec2e6313af34: a waiting stream must not
// make serve's first start take itself for a later round. Saving the
// stream's reason wrote the ledger, a written ledger exists, and the first
// round then answered every old ask instead of leaving them alone.
func TestAWaitingStreamDoesNotTurnOffTheFirstStart(t *testing.T) {
	alice, bob := newExpertCold(t, modeReadOnly)
	alice.ask(t, bob.channel, "an old ask", "one")
	alice.ask(t, bob.channel, "another old ask", "two")
	streamSectionsTo(t, alice, bob.user, bob.channel, "a newer ask", critical("first-start"))
	out := bob.round(t)
	if len(out.Answered) != 0 || len(out.Skipped) != 2 {
		t.Fatalf("the first round: answered %d, skipped %d; want the two old asks left alone", len(out.Answered), len(out.Skipped))
	}
}

// From the second reader on e332ec2e6313af34: a waiting stream that will
// never open, met after the upgrade, is kept under damaged/ and
// acknowledged, and its record goes, as the fetch does for any stream it
// meets that way; it never stops every later fetch of the mailbox.
func TestADamagedWaitingStreamDoesNotStopTheFetchAfterTheUpgrade(t *testing.T) {
	alice, bob, _ := peered(t)
	streamSectionsDamaged(t, alice, bob, "", "a newer stream", critical("damaged-later"), func(b []byte) {
		b[len(b)-1] ^= 1
	})
	fetchJSON(t, bob)
	t.Cleanup(wire.Register("damaged-later", wire.OnManifest))
	alice.run("send", "--to", "bob", "--subject", "the good one", "hello")
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Unreadable != 1 {
		t.Fatalf("the fetch after the upgrade: %+v; want the good one delivered and the stream kept as unreadable\n%s", in.Fetch, stderr)
	}
	if !spoolHas(t, bob, store.Inbox, "the good one") {
		t.Error("the good message is not in the inbox")
	}
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mustList(t, bs, store.Inbox) {
		if m.Newer != "" {
			t.Errorf("the waiting record is still there: %+v", m)
		}
	}
	again, _ := fetchJSON(t, bob)
	if !again.Fetch.empty() {
		t.Errorf("the next fetch met the stream again: %+v", again.Fetch)
	}
}

// From the second reader on e332ec2e6313af34: 'auu rm --remote-only' on a
// waiting stream leaves a record that still reads, with its payload gone,
// rather than one the store refuses for a mark without a payload.
func TestRemovingAWaitingStreamFromTheRelayLeavesARecordThatReads(t *testing.T) {
	alice, bob, _ := peered(t)
	streamSections(t, alice, bob, "a newer stream", critical("removed-later"))
	fetchJSON(t, bob)
	bs, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	msgs := mustList(t, bs, store.Inbox)
	if len(msgs) != 1 {
		t.Fatalf("the inbox holds %d", len(msgs))
	}
	bob.run("rm", "--remote-only", msgs[0].Inner.ID)
	m, err := bs.Load(store.Inbox, msgs[0].Inner.ID)
	if err != nil || m.Newer != "removed-later" || !m.PayloadGone {
		t.Fatalf("after rm --remote-only: %+v, %v; want it read, its payload gone", m, err)
	}
}

func mustList(t *testing.T, s *store.Store, box store.Box) []*store.Stored {
	t.Helper()
	msgs, err := s.List(box)
	if err != nil {
		t.Fatal(err)
	}
	return msgs
}

// From the re-read of the fixes: on a first start, recording a waiting
// stream's reason writes nothing to disk. A ledger written before the first
// start's record of the backlog would make the next start, after a crash or
// a failed write between the two, take itself for a later one and answer
// the old mail; the reason is written by the backlog's own save.
func TestAFirstStartWritesNoLedgerBeforeItsBacklog(t *testing.T) {
	alice, bob := newExpertCold(t, modeReadOnly)
	streamSectionsTo(t, alice, bob.user, bob.channel, "a newer ask", critical("first-write"))
	fetchJSON(t, bob.user)
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadServeConfig(bob.path)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(bob.home, "serve")
	path := filepath.Join(root, ledgerFile)
	led, err := loadLedger(path)
	if err != nil || led.existed {
		t.Fatalf("a ledger before the first start: %v, existed %v", err, led.existed)
	}
	run := &serveRun{s: s, cfg: cfg, led: led, root: root}
	if _, err := run.pending(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pending wrote the ledger on a first start: %v", err)
	}
	var reason string
	for _, e := range led.Messages {
		reason = e.Newer
	}
	if reason != "first-write" {
		t.Fatalf("the reason held in memory is %q", reason)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := run.recordBacklog(false); err != nil {
		t.Fatal(err)
	}
	written, err := loadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range written.Messages {
		if e.Newer != "first-write" || e.Skipped {
			t.Errorf("the backlog's save wrote %+v; want the reason, not skipped", e)
		}
	}
}

// The count of streams that wait for a newer auu reads the quarantine on
// every inbox run, and says nothing of a record there that will not read:
// the warning says the record "is not listed", which is the quarantine's own
// listing to say, once, when a person asks for it. Without a fetch, the
// count is the only thing that reads the quarantine.
func TestTheCountOfWaitingStreamsIsQuiet(t *testing.T) {
	_, bob, _ := peered(t)
	dir := filepath.Join(bob.home, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, strings.Repeat("e", 32)+".json")
	if err := os.WriteFile(stray, []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The record does not parse, so Load calls it damaged and the warning
	// is "<path> will not read (...): <advice>; it is not listed". The
	// inbox is held to never naming the file at all, which is stricter
	// than either sentence.
	stderr := captureStderr(t, func() { bob.tryRun("inbox", "--no-fetch") })
	if strings.Contains(stderr, stray) || strings.Contains(stderr, "will not read") || strings.Contains(stderr, "could not be read") {
		t.Errorf("auu inbox warned about a quarantine record it does not list:\n%s", stderr)
	}
	stderr = captureStderr(t, func() { bob.tryRun("quarantine", "ls") })
	if !strings.Contains(stderr, "warning: "+stray+" will not read (") ||
		!strings.Contains(stderr, "fix it, or move it out of the box; the rest of the box reads without it; it is not listed\n") {
		t.Errorf("quarantine ls did not warn about its own record:\n%s", stderr)
	}
}
