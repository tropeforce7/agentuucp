package auu

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A quarantined stream that is trusted is delivered over its record with
// the record's arrival: it arrived when it was fetched into the quarantine,
// not when the person trusted it. The quarantined record's arrival is set
// an hour back, so that one taken at the trust would show.
func TestATrustedStreamKeepsItsQuarantinedArrival(t *testing.T) {
	_, _, bob, rec, payload := strangersStream(t)
	arrived := rec.Arrived.Add(-time.Hour)
	rec.Arrived = arrived
	if err := storeOf(t, bob).Save(store.Quarantine, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID); err != nil {
		t.Fatalf("trust: %v", err)
	}
	trusted(t, bob, rec.Inner.ID, "mallory", payload)
	m, err := storeOf(t, bob).Load(store.Inbox, rec.Inner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Arrived.Equal(arrived) || !m.Received.Equal(rec.Received) {
		t.Errorf("the trusted stream arrived %v, received %v; want the quarantined record's %v and %v",
			m.Arrived, m.Received, arrived, rec.Received)
	}
}

// 'auu inbox --json' carries each message's arrival here beside the
// relay's received: the key is there, and it is the record's Arrived.
func TestTheInboxJSONCarriesArrived(t *testing.T) {
	alice, bob, _ := peered(t)
	alice.run("send", "--to", "bob", "--subject", "arriving", "hello")
	out := bob.run("inbox", "--json")
	var raw struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Messages) != 1 {
		t.Fatalf("inbox --json lists %d messages, want 1:\n%s", len(raw.Messages), out)
	}
	key, ok := raw.Messages[0]["arrived"]
	if !ok {
		t.Fatalf("inbox --json has no arrived key:\n%s", out)
	}
	var arrived time.Time
	if err := json.Unmarshal(key, &arrived); err != nil {
		t.Fatalf("arrived %s: %v", key, err)
	}
	m := recordOf(t, bob, store.Inbox, "arriving")
	if arrived.IsZero() || !arrived.Equal(m.Arrived) {
		t.Errorf("inbox --json says arrived %v; want the record's, %v", arrived, m.Arrived)
	}
}

// A thread's opener is decided by arrival here, not by the relay's
// received. Alice's ask on a new thread arrives at bob first, and carol's
// on the same thread after it, but the relay stamped carol's received five
// minutes before alice's, as a relay with its clock behind, or one that
// lies, would. Both are pending in one round: alice's is answered and
// opens the thread, carol's is left alone and said once, no handler runs
// for it, nothing is written for it, and alice's ledger entry holds her
// record's arrival. Ordered by the relay's received, carol's would have
// come first and taken the thread.
func TestAnEarlierReceivedDoesNotTakeAThreadFromAnEarlierArrival(t *testing.T) {
	alice, carol, bob, st, dbPath := newExpertAndCarolOnDisk(t)
	b := bob.user

	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "stamped before")

	// The relay's received for carol's row, five minutes before alice's.
	rows, err := st.List(b.exportFingerprint(), 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("the relay holds %d rows for bob (%v); want alice's and carol's", len(rows), err)
	}
	setReceived(t, dbPath, rows[1].ID, rows[0].Received.Add(-5*time.Minute))

	// Fetched, not yet served, alice's a minute before carol's.
	bob.run("inbox", "--json")
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := s.Load(store.Inbox, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	hers, err := s.Load(store.Inbox, hijack.ID)
	if err != nil {
		t.Fatal(err)
	}
	mine.Arrived = time.Now().UTC().Add(-2 * time.Minute)
	hers.Arrived = mine.Arrived.Add(time.Minute)
	for _, m := range []*store.Stored{mine, hers} {
		if err := s.Save(store.Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	if !hers.Received.Before(mine.Received) || hers.RelayID != rows[1].ID {
		t.Fatalf("carol's ask is received %v (relay id %d) beside alice's %v, so the test proves nothing",
			hers.Received, hers.RelayID, mine.Received)
	}

	report, stderr := bob.roundSaid(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID || len(report.Failed) != 0 {
		t.Fatalf("want alice's ask, the first to arrive, answered and nothing else: %+v\nstderr:\n%s", report, stderr)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("the handler ran other than once, for alice:\n%s", runs)
	}
	led := bob.ledgerOf(t)
	if o := led.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice", o)
	}
	arrivalIs(t, bob, led, sent.ID)
	if e := led.Messages[sent.ID]; e != nil && !e.Arrived.Equal(mine.Arrived) {
		t.Errorf("alice's entry has arrived %v; want her record's, %v", e.Arrived, mine.Arrived)
	}
	if e, ok := led.Messages[hijack.ID]; ok {
		t.Errorf("carol's message was written into the ledger: %+v", e)
	}
	nothingFromBob(t, carol, bob)
	unreadAtBob(t, bob, hijack.ID)
}

// newExpertAndCarolOnDisk is newExpertAndCarol on a relay whose store and
// database file the test can reach, for a test that sets the relay's
// received on a row as a relay with its clock elsewhere would.
func newExpertAndCarolOnDisk(t *testing.T) (alice, carol *user, bob *expert, st *relay.Store, dbPath string) {
	t.Helper()
	srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice = newUser(t, "alice", srv.URL)
	b := newUser(t, "bob", srv.URL)
	carol = newUser(t, "carol", srv.URL)
	for _, u := range []*user{alice, carol} {
		u.run("peers", "add", b.exportLine())
		b.run("peers", "add", u.exportLine())
	}
	b.run("channel", "create", "jostle")
	t.Setenv(handlerScript, "echo:the expert has spoken")
	bob = &expert{user: b, dir: repo(t), channel: "jostle"}
	bob.row = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: modeReadOnly}
	bob.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": bob.row}}
	bob.path = filepath.Join(b.home, serveFile)
	bob.write(t)
	bob.serve(t) // the first start, which answers nothing
	return alice, carol, bob, st, filepath.Join(filepath.Dir(messages), "relay.db")
}

// setReceived writes the relay's received for one of its rows.
func setReceived(t *testing.T, dbPath string, id int64, at time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE messages SET received = ? WHERE id = ?`, at.UTC().Format(time.RFC3339), id)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("set received on row %d: %d rows, %v", id, n, err)
	}
}

// channelFor decides whether a message may open a thread that a held
// stream's entry, with no try, already names another sender on, by the
// message's arrival here against the entry's: the one that arrived here
// first opens the thread, whatever the relays' received say. Alice asks on
// a new thread T, and carol sends a stream on T that is held for a newer
// auu. Alice's ask arrived here a minute before carol's stream, but the
// relay stamped it received two minutes ahead of this clock, after carol's
// stream and after the stream's arrival here, so the two orders disagree.
// In the round, the held stream's entry names carol with no try, and
// alice's ask, compared by its arrival, is answered and opens the thread;
// compared by its received it would have been left alone as being on
// carol's thread.
func TestTheFirstToArriveHereOpensAThreadWhateverTheRelaySays(t *testing.T) {
	alice, carol, bob, st, dbPath := newExpertAndCarolOnDisk(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	streamOnThread(t, carol, bob.user, bob.channel, sent.Thread, "a newer ask", critical("later"))

	rows, err := st.List(bob.exportFingerprint(), 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("the relay holds %d rows for bob (%v); want alice's ask and carol's stream", len(rows), err)
	}
	now := time.Now().UTC()
	setReceived(t, dbPath, rows[0].ID, now.Add(2*time.Minute))

	// Fetched, not yet served: alice's ask arrived two minutes back, and
	// carol's held stream a minute after it.
	bob.run("inbox", "--json")
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := s.Load(store.Inbox, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	var hers *store.Stored
	msgs, err := s.List(store.Inbox)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Newer == "later" && m.Inner.Body.Thread == sent.Thread {
			hers = m
		}
	}
	if hers == nil {
		t.Fatalf("carol's stream is not held in the inbox: %+v", msgs)
	}
	mine.Arrived = now.Add(-2 * time.Minute)
	hers.Arrived = now.Add(-time.Minute)
	for _, m := range []*store.Stored{mine, hers} {
		if err := s.Save(store.Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	// The orders disagree: by arrival alice's first, by received carol's,
	// and alice's received is after the arrival the held entry will hold.
	if !mine.Arrived.Before(hers.Arrived) || !hers.Received.Before(mine.Received) || !mine.Received.After(hers.Arrived) {
		t.Fatalf("alice's ask arrived %v received %v, carol's stream arrived %v received %v: the orders agree, so the test proves nothing",
			mine.Arrived, mine.Received, hers.Arrived, hers.Received)
	}

	report, stderr := bob.roundSaid(t)
	led := bob.ledgerOf(t)
	e := led.Messages[hers.Inner.ID]
	if e == nil || e.From != carol.fingerprint() || !e.Tried.IsZero() || !e.Handled.IsZero() || !e.Arrived.Equal(hers.Arrived) {
		t.Fatalf("carol's held stream wrote %+v; want her sender, no try, and her record's arrival %v\nstderr:\n%s", e, hers.Arrived, stderr)
	}
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID || len(report.Failed) != 0 {
		t.Fatalf("alice's ask, the first to arrive here, was not answered: %+v\nstderr:\n%s", report, stderr)
	}
	if strings.Contains(stderr, "left alone") {
		t.Errorf("a message was left alone:\n%s", stderr)
	}
	if runs := readFile(t, marker); !strings.Contains(runs, sent.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("the handler ran other than once, for alice:\n%s", runs)
	}
	if o := led.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice; carol is %s", o, carol.fingerprint())
	}
	arrivalIs(t, bob, led, sent.ID)
	alice.replyOn(t, sent.Thread)
}
