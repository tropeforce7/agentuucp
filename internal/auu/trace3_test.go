package auu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The third adversarial trace, at v0.17.0: who a thread on an expert host
// belongs to. Its tests are here as the
// regression tests, each renamed for what it proves.

// newExpertAndCarol is newExpert with a third user: alice and carol, each
// on bob's peer list and he on theirs, and bob serving one channel in the
// given mode with serve having run once already. Carol is any peer who has
// learned a thread id of alice's, as every co-recipient of a message to
// several does.
func newExpertAndCarol(t *testing.T, mode string) (alice, carol *user, bob *expert) {
	t.Helper()
	alice, carol, bob = newExpertAndCarolCold(t, mode)
	bob.serve(t) // the first start, which answers nothing
	return alice, carol, bob
}

// newExpertAndCarolCold is the same without that round, for the tests
// about what a first start does.
func newExpertAndCarolCold(t *testing.T, mode string) (alice, carol *user, bob *expert) {
	t.Helper()
	relayURL := startRelay(t)
	alice = newUser(t, "alice", relayURL)
	b := newUser(t, "bob", relayURL)
	carol = newUser(t, "carol", relayURL)
	for _, u := range []*user{alice, carol} {
		u.run("peers", "add", b.exportLine())
		b.run("peers", "add", u.exportLine())
	}
	b.run("channel", "create", "jostle")
	t.Setenv(handlerScript, "echo:the expert has spoken")
	bob = &expert{user: b, dir: repo(t), channel: "jostle"}
	bob.row = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: mode}
	bob.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": bob.row}}
	bob.path = filepath.Join(b.home, serveFile)
	bob.write(t)
	return alice, carol, bob
}

// askOn sends one ask to bob's served channel on a thread the sender names,
// which is what 'auu send --thread' lets any peer do.
func (u *user) askOn(t *testing.T, channel, thread, subject, text string) sentJSON {
	t.Helper()
	var sent sentJSON
	out := u.run("send", "--to", "bob", "--channel", channel, "--thread", thread, "--subject", subject, "--json", text)
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Thread != thread {
		t.Fatalf("the ask is on thread %s, not %s", sent.Thread, thread)
	}
	return sent
}

// roundSaid runs one round and gives its report and what it said on
// standard error.
func (e *expert) roundSaid(t *testing.T) (roundJSON, string) {
	t.Helper()
	var out string
	var err error
	stderr := captureStderr(t, func() { out, err = e.tryRun("serve", "--once", "--json") })
	if err != nil {
		t.Fatalf("serve --once: %v\nstdout: %s\nstderr: %s", err, out, stderr)
	}
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return report, stderr
}

// leftAlone is the line serve says for a message on another peer's thread.
func leftAlone(m sentJSON, name, opener string) string {
	return fmt.Sprintf("auu: %s from %s is on thread %s, which %s opened; left alone",
		shortID(m.ID), name, shortID(m.Thread), opener[:16])
}

// nothingFromBob fails the test if u has been sent anything by bob.
func nothingFromBob(t *testing.T, u *user, bob *expert) {
	t.Helper()
	var in inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	fp := bob.fingerprint()
	for _, m := range in.Messages {
		if m.From == fp || m.Type == "reply" {
			t.Errorf("bob sent %s (%s on thread %s): %+v", m.ID[:12], m.Type, m.Thread[:12], m)
		}
	}
}

// unreadAtBob fails the test unless the message is in bob's inbox unread.
func unreadAtBob(t *testing.T, bob *expert, id string) {
	t.Helper()
	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.ID == id {
			if m.Read {
				t.Errorf("%s was marked read", id[:12])
			}
			return
		}
	}
	t.Errorf("%s is not in bob's inbox: %+v", id[:12], in.Messages)
}

// tree is every path under dir, relative to it, or nothing for a dir that
// is not there.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out = append(out, rel)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// arrivalIs fails the test unless a message's ledger entry records when
// and in what order it arrived exactly as bob's stored copy does: Received
// and RelayID, neither of them zero.
func arrivalIs(t *testing.T, bob *expert, led *ledger, id string) {
	t.Helper()
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Load(store.Inbox, id)
	if err != nil {
		t.Fatal(err)
	}
	e := led.Messages[id]
	if e == nil {
		t.Fatalf("no ledger entry for %s", id[:12])
	}
	if e.Arrived.IsZero() || e.RelayID == 0 || !e.Arrived.Equal(m.Received) || e.RelayID != m.RelayID {
		t.Errorf("%s's entry has arrived %v and relay_id %d; want the stored record's %v and %d, neither zero",
			id[:12], e.Arrived, e.RelayID, m.Received, m.RelayID)
	}
}

// Any peer may name any thread id with 'auu send --thread', and every
// co-recipient of a message to several knows the thread it opened. The
// trace had carol ask on alice's side-copy thread: the handler ran in
// alice's worktree with alice's thread directory, counted it as alice's
// next turn, and sent carol the patch of all alice's work. Now a thread
// belongs to the peer who opened it: carol's message is not answered, not
// counted, runs no handler and is given no directory of alice's, is said
// once in each run that meets it, and stays unread in bob's inbox for him
// to see; and alice's next turn on her thread is answered as her second.
func TestAThreadIsAnsweredForThePeerWhoOpenedIt(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeSideCopy)
	marker := filepath.Join(t.TempDir(), "runs")

	// Alice's thread: the handler writes something in her worktree.
	t.Setenv(handlerScript, "append:"+marker+";write:secret.txt=alice's private work;echo:done")
	sent := alice.ask(t, "jostle", "alice's question", "please work on this")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)
	arrivalIs(t, bob, bob.ledgerOf(t), sent.ID)
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	before := tree(t, threadDir)

	// Carol, another peer who knows the thread id, asks on it.
	t.Setenv(handlerScript, "append:"+marker+";env")
	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	want := leftAlone(hijack, "carol", alice.fingerprint())
	for round := 1; round <= 2; round++ {
		report, stderr := bob.roundSaid(t)
		if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
			t.Fatalf("round %d: carol's message on alice's thread was taken as work: %+v", round, report)
		}
		if n := strings.Count(stderr, want); n != 1 {
			t.Errorf("round %d said it %d times, want once:\n%s\nstderr:\n%s", round, n, want, stderr)
		}
	}
	nothingFromBob(t, carol, bob)
	led := bob.ledgerOf(t)
	if n := led.answered(sent.Thread); n != 1 {
		t.Errorf("alice's thread has %d turns answered after carol's message, want 1", n)
	}
	if e, ok := led.Messages[hijack.ID]; ok {
		t.Errorf("carol's message was written into the ledger: %+v", e)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's message:\n%s", runs)
	}
	if after := tree(t, threadDir); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Errorf("alice's thread directory changed under carol's message:\nbefore %q\nafter  %q", before, after)
	}
	unreadAtBob(t, bob, hijack.ID)

	// Alice's next turn on her own thread is answered, as her second.
	alice.run("reply", first.ID[:12], "and one more thing")
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].Thread != sent.Thread {
		t.Fatalf("alice's follow-up was not answered: %+v", report)
	}
	if line := "handler " + report.Answered[0].ID + " 2\n"; !strings.Contains(readFile(t, marker), line) {
		t.Errorf("alice's follow-up was not her turn 2; the handler ran:\n%s", readFile(t, marker))
	}
	if n := bob.ledgerOf(t).answered(sent.Thread); n != 2 {
		t.Errorf("alice's thread has %d turns answered, want 2", n)
	}
}

// rewriteAsOlder writes bob's ledger as v0.17.0 wrote it, in exactly its
// keys: no entry names a sender.
func rewriteAsOlder(t *testing.T, bob *expert) {
	t.Helper()
	type olderEntry struct {
		Thread   string    `json:"thread"`
		Channel  string    `json:"channel"`
		Handled  time.Time `json:"handled"`
		Tried    time.Time `json:"tried"`
		Reply    string    `json:"reply"`
		Failures int       `json:"failures"`
	}
	older := struct {
		V        int                    `json:"v"`
		Messages map[string]*olderEntry `json:"messages"`
	}{V: 1, Messages: map[string]*olderEntry{}}
	for id, e := range bob.ledgerOf(t).Messages {
		older.Messages[id] = &olderEntry{e.Thread, e.Channel, e.Handled, e.Tried, e.Reply, e.Failures}
	}
	data, err := json.Marshal(older)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"from"`) {
		t.Fatalf("the older ledger names a sender: %s", data)
	}
	if err := os.WriteFile(filepath.Join(bob.home, "serve", ledgerFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for id, e := range bob.ledgerOf(t).Messages {
		if e.From != "" || !e.Arrived.IsZero() || e.RelayID != 0 {
			t.Fatalf("the older ledger's entry %s reads with sender or arrival: %+v", id[:12], e)
		}
	}
}

// A ledger written by v0.17.0 names no sender on any entry. Where the
// message is still in the inbox, serve reads its sender from there at the
// start of a run (TestAnOlderLedgerTakesItsOpenersFromTheInbox); this is
// the other case, a thread whose messages the owner has removed, which has
// no opener until it is written again. The first turn on it after the
// upgrade is the one that names one: alice's follow-up is answered as her
// second turn and its entry carries her fingerprint, while her removed
// ask's entry still names nobody, and carol's ask on the same thread after
// that is left alone.
func TestAThreadFromAnOlderLedgerTakesItsNextSenderAsOpener(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)

	rewriteAsOlder(t, bob)
	bob.run("rm", sent.ID)
	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.ID == sent.ID {
			t.Fatalf("alice's ask is still in bob's inbox after auu rm: %+v", m)
		}
	}

	alice.run("reply", first.ID[:12], "and one more thing")
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].Thread != sent.Thread {
		t.Fatalf("alice's follow-up on the older ledger's thread was not answered: %+v", report)
	}
	followUp := report.Answered[0].ID
	if !strings.Contains(readFile(t, marker), "handler "+followUp+" 2\n") {
		t.Errorf("alice's follow-up was not her turn 2; the handler ran:\n%s", readFile(t, marker))
	}
	led := bob.ledgerOf(t)
	if e := led.Messages[followUp]; e == nil || e.From != alice.fingerprint() {
		t.Fatalf("alice's follow-up's entry names sender %+v, want %s", e, alice.fingerprint())
	}
	if e := led.Messages[sent.ID]; e == nil || e.From != "" {
		t.Errorf("alice's removed ask's entry is %+v; want it kept with no sender, so that the follow-up is what named one", e)
	}

	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	after, stderr := bob.roundSaid(t)
	if len(after.Answered)+len(after.Failed) != 0 {
		t.Errorf("carol's ask on a thread alice took up after the upgrade was taken: %+v", after)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	nothingFromBob(t, carol, bob)
	if n := bob.ledgerOf(t).answered(sent.Thread); n != 2 {
		t.Errorf("the thread has %d turns answered, want 2", n)
	}
}

// A ledger written by v0.17.0 names no sender, but serve leaves what
// it answered in the inbox, marked read, and at the start of a run gives
// each entry without a sender the verified sender of its message there,
// and writes the ledger when it gave any. So a thread carried over the
// upgrade has its true opener from the first round: carol's ask on alice's
// thread is left alone at once, before alice has come back, with no
// handler run and nothing sent, and alice's entry on disk names her after
// that round though it answered nothing. The opener then outlives the
// message: bob removes alice's ask, and carol asking again is still left
// alone, where a sender held only in memory would have let her take the
// thread as its next sender. Alice's follow-up is answered as her second
// turn.
func TestAnOlderLedgerTakesItsOpenersFromTheInbox(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)
	rewriteAsOlder(t, bob)

	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("carol's ask on alice's thread from an older ledger was taken: %+v", report)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's message:\n%s", runs)
	}
	nothingFromBob(t, carol, bob)
	unreadAtBob(t, bob, hijack.ID)
	led := bob.ledgerOf(t)
	if e := led.Messages[sent.ID]; e == nil || e.From != alice.fingerprint() {
		t.Errorf("after a round that answered nothing, alice's ask's entry on disk is %+v; want her fingerprint, read from the inbox", e)
	}
	arrivalIs(t, bob, led, sent.ID)
	if e, ok := led.Messages[hijack.ID]; ok {
		t.Errorf("carol's message was written into the ledger: %+v", e)
	}

	// The owner removes alice's ask; the opener is on disk, not only in
	// the message.
	bob.run("rm", sent.ID)
	again := carol.askOn(t, "jostle", sent.Thread, "carol again", "and now?")
	report, stderr = bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("with alice's ask removed, carol's ask on her thread was taken: %+v", report)
	}
	if want := leftAlone(again, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, again.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's second message:\n%s", runs)
	}
	nothingFromBob(t, carol, bob)
	if o := bob.ledgerOf(t).opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("after alice's ask was removed the thread's opener is %q, want alice", o)
	}

	alice.run("reply", first.ID[:12], "and one more thing")
	after := bob.round(t)
	if len(after.Answered) != 1 || after.Answered[0].Thread != sent.Thread {
		t.Fatalf("alice's follow-up was not answered: %+v", after)
	}
	if line := "handler " + after.Answered[0].ID + " 2\n"; !strings.Contains(readFile(t, marker), line) {
		t.Errorf("alice's follow-up was not her turn 2; the handler ran:\n%s", readFile(t, marker))
	}
}

// A thread's opener is the sender of its first message to arrive, answered
// or not: alice's ask on a new thread fails and is given up on, with her
// fingerprint on its entry, and carol's ask on that thread after it is left
// alone though nothing on it was ever answered and the handler would now
// succeed. The order is the order of arrival and not of the map nor of the
// ids: a second sender's entry with a try that arrived an hour after
// alice's, written here by hand, does not take the thread from alice, whose next ask on it is answered; its id is the
// least there is, so that an order by id alone would put it first.
func TestTheOpenerIsTheFirstToArrive(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	bob.row.Retries = 1
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:the handler could not;exit:3")
	sent := alice.ask(t, "jostle", "a question", "the first")
	if _, err := bob.tryRun("serve", "--once"); err == nil {
		t.Fatal("a handler that exits 3 was not a failure")
	}
	e := bob.ledgerOf(t).Messages[sent.ID]
	if e == nil || e.From != alice.fingerprint() || e.Failures != 1 || !e.GaveUp || !e.Handled.IsZero() {
		t.Fatalf("alice's failed ask wrote %+v, want her fingerprint and one failure", e)
	}

	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed) != 0 {
		t.Errorf("carol's ask on alice's unanswered thread was taken: %+v", report)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) {
		t.Errorf("a handler ran for carol's message:\n%s", runs)
	}
	nothingFromBob(t, carol, bob)

	// An entry from carol on the thread that arrived an hour after
	// alice's, written by hand, under the least id there is.
	led := bob.ledgerOf(t)
	mine := led.Messages[sent.ID]
	if mine.Arrived.IsZero() {
		t.Fatalf("alice's entry has no arrival: %+v", mine)
	}
	led.Messages[strings.Repeat("0", 32)] = &ledgerEntry{
		Thread: sent.Thread, Channel: "jostle", Failures: 1,
		Arrived: mine.Arrived.Add(time.Hour), Tried: mine.Tried.Add(time.Hour), From: carol.fingerprint(),
	}
	if err := led.save(); err != nil {
		t.Fatal(err)
	}
	again := alice.askOn(t, "jostle", sent.Thread, "again", "a second try")
	report = bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != again.ID {
		t.Errorf("alice's ask on her own thread was not answered beside a later entry of carol's: %+v", report)
	}
}

// Two asks on one new thread can both be pending in one round, since the
// round decides what is pending before it answers anything. The first by
// arrival, alice's, is answered and opens the thread; carol's, asked again
// when its turn comes, is then on alice's thread and is left alone and
// said, with no handler run and nothing sent to carol.
func TestTwoAsksOnOneNewThreadInOneRoundAnswerOnlyTheFirst(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "me too")

	report, stderr := bob.roundSaid(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID || len(report.Failed) != 0 {
		t.Fatalf("want alice's ask answered and nothing else: %+v", report)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("the handler ran other than once, for alice:\n%s", runs)
	}
	led := bob.ledgerOf(t)
	if e, ok := led.Messages[hijack.ID]; ok {
		t.Errorf("carol's message was written into the ledger: %+v", e)
	}
	if o := led.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice", o)
	}
	nothingFromBob(t, carol, bob)
	alice.replyOn(t, sent.Thread)
	unreadAtBob(t, bob, hijack.ID)
}

// An entry skipped as a first start's backlog opens nothing: serve never
// answered that message, never ran a handler for it and never will, so the
// thread is not a conversation with its sender here. Alice's ask on T was
// in the inbox when serve first started and was left; carol's ask on T
// after it is a new thread to serve, and is answered with carol as its
// opener. Counting the skipped entry would hold T for alice, who was never
// served on it.
func TestASkippedBacklogEntryOpensNothing(t *testing.T) {
	alice, carol, bob := newExpertAndCarolCold(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "before serve ever ran")
	bob.serve(t) // the first start, which leaves alice's ask
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || !e.Skipped {
		t.Fatalf("the first start wrote %+v for alice's ask; want it skipped", e)
	}

	ask := carol.askOn(t, "jostle", sent.Thread, "carol's question", "on the same thread")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != ask.ID {
		t.Fatalf("carol's ask on a thread serve never answered was not answered: %+v\nstderr:\n%s", report, stderr)
	}
	if strings.Contains(stderr, "left alone") {
		t.Errorf("a message was left alone for another's thread:\n%s", stderr)
	}
	if o := bob.ledgerOf(t).opener(sent.Thread); o != carol.fingerprint() {
		t.Errorf("the thread's opener is %q, want carol", o)
	}
	if runs := readFile(t, marker); strings.Contains(runs, sent.ID) || !strings.Contains(runs, ask.ID) {
		t.Errorf("the handler ran other than for carol alone:\n%s", runs)
	}
	carol.replyOn(t, sent.Thread)
}

// The line for a message on another peer's thread is said once per message
// per run, as the renamed follow-up's is: a run meets a pending message in
// pending, in handle and in every round of a long run, and a log that says
// it each time hides everything else. A run asked three times about one
// message of carol's on alice's thread says it once, and leaves it each
// time; asked about a second message of carol's, it says that one once
// too; asked about alice's own, it gives the channel and says nothing; and
// a new run says the first again.
func TestTheOtherPartyLineIsSaidOncePerMessagePerRun(t *testing.T) {
	aliceFP, carolFP := strings.Repeat("a", 64), strings.Repeat("c", 64)
	thread := strings.Repeat("1", 32)
	now := time.Now().UTC().Truncate(time.Second)
	led := &ledger{V: ledgerV, Messages: map[string]*ledgerEntry{
		strings.Repeat("2", 32): {Thread: thread, Channel: "jostle", Handled: now, Tried: now, From: aliceFP},
	}}
	cfg := &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": {Mode: modeReadOnly}}}
	stored := func(id, from, name string) *store.Stored {
		return &store.Stored{Channel: "jostle", SenderName: name, Inner: &envelope.Inner{
			ID: id, From: from,
			Body: message.Body{Type: message.TypeAsk, Thread: thread, Subject: "on the thread"},
		}}
	}
	first := stored(strings.Repeat("3", 32), carolFP, "carol")
	second := stored(strings.Repeat("4", 32), carolFP, "carol")
	own := stored(strings.Repeat("5", 32), aliceFP, "alice")
	line := func(m *store.Stored) string {
		return fmt.Sprintf("auu: %s from carol is on thread %s, which %s opened; left alone\n",
			m.Inner.ID[:12], thread[:12], aliceFP[:16])
	}

	r := &serveRun{cfg: cfg, led: led}
	stderr := captureStderr(t, func() {
		for i := 1; i <= 3; i++ {
			if ch := r.channelFor(first); ch != nil {
				t.Errorf("ask %d: carol's message on alice's thread was given a channel", i)
			}
		}
		for i := 1; i <= 2; i++ {
			if ch := r.channelFor(second); ch != nil {
				t.Errorf("ask %d: carol's second message was given a channel", i)
			}
		}
		if ch := r.channelFor(own); ch == nil {
			t.Error("alice's own message on her thread was given no channel")
		}
	})
	if strings.Count(stderr, "left alone") != 2 || strings.Count(stderr, line(first)) != 1 || strings.Count(stderr, line(second)) != 1 {
		t.Errorf("one run said:\n%s\nwant once each:\n%s%s", stderr, line(first), line(second))
	}

	again := &serveRun{cfg: cfg, led: led}
	stderr = captureStderr(t, func() { again.channelFor(first) })
	if stderr != line(first) {
		t.Errorf("a new run said:\n%q\nwant:\n%q", stderr, line(first))
	}
}

// The reply route is held too. A follow-up is taken for a channel because
// its in_reply_to names a reply serve sent, and the reply alice was sent is
// one anybody she shows it to can name: carol answers bob's reply to alice
// on alice's thread, which is what a forwarded reply makes possible, and is
// left alone, said once, with no handler run and nothing sent to her.
func TestAReplyToAnotherPeersAnswerIsNotAnswered(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	reply := alice.replyOn(t, sent.Thread)

	t.Setenv("AUU_HOME", carol.home)
	s, id, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := selectRelay(s, "")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{
		Type: message.TypeReply, Subject: "re: a question", Thread: sent.Thread,
		InReplyTo: reply.ID, Text: "and what about me?",
	}
	followUp, _, err := sendSealed(s, id, r, recipient, body, nil, sendMode{})
	if err != nil {
		t.Fatal(err)
	}

	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("carol's reply to bob's answer to alice was taken: %+v", report)
	}
	want := leftAlone(sentJSON{ID: followUp.ID, Thread: sent.Thread}, "carol", alice.fingerprint())
	if strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, followUp.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's reply:\n%s", runs)
	}
	led := bob.ledgerOf(t)
	if e, ok := led.Messages[followUp.ID]; ok {
		t.Errorf("carol's reply was written into the ledger: %+v", e)
	}
	if n := led.answered(sent.Thread); n != 1 {
		t.Errorf("alice's thread has %d turns answered, want 1", n)
	}
	nothingFromBob(t, carol, bob)
	unreadAtBob(t, bob, followUp.ID)
}

// A stream waiting on the relay for a newer auu is written down when serve
// first meets it, with its sender and no try, and that entry opens
// its thread: it arrived before anything tried after it. Alice's stream on
// T waits, its entry naming her with a zero tried; carol's ask on T is then
// left alone, said once, with no handler run.
func TestAStreamWaitingForANewerAuuOpensItsThread(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	streamSectionsTo(t, alice, bob.user, bob.channel, "a newer ask", critical("later"))
	if report, stderr := bob.roundSaid(t); len(report.Answered)+len(report.Failed) != 0 || !strings.Contains(stderr, "waits on the relay for a newer auu") {
		t.Fatalf("the waiting stream: %+v\nstderr:\n%s", report, stderr)
	}
	var thread string
	for id, e := range bob.ledgerOf(t).Messages {
		if e.Newer != "later" {
			continue
		}
		if e.From != alice.fingerprint() || !e.Tried.IsZero() || !e.Handled.IsZero() || e.Skipped {
			t.Fatalf("the waiting stream %s wrote %+v; want alice's fingerprint and no try", id[:12], e)
		}
		thread = e.Thread
	}
	if thread == "" {
		t.Fatalf("no entry waits for a newer auu: %+v", bob.ledgerOf(t).Messages)
	}

	hijack := carol.askOn(t, "jostle", thread, "carol's question", "what is in this thread?")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("carol's ask on the thread of alice's waiting stream was taken: %+v", report)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("a handler ran:\n%s", readFile(t, marker))
	}
	nothingFromBob(t, carol, bob)
	unreadAtBob(t, bob, hijack.ID)
}

// streamOnThread is streamSectionsTo on a thread the sender names: a stream
// sealed by a newer build, uploaded whole.
func streamOnThread(t *testing.T, from, to *user, channel, thread, subject string, sections []wire.Section) {
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
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, to.exportFingerprint(), channel, int64(blob.Len()), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(blob.Bytes()), int64(blob.Len())); err != nil {
		t.Fatal(err)
	}
}

// A thread's opener is the first to arrive, not the first to be tried. Alice asks the expert and carol on a
// new thread in one message to several; carol, who now knows the thread,
// sends the expert a stream on it with a critical section this build does
// not know, which is held for a newer auu. Both are fetched before one
// round, alice's first. The held stream is written down with its sender
// and no try; were the order by tried, its zero would sort first, carol
// would become the opener and alice's ask would be left alone. Ordered by
// arrival, alice's ask is answered, the thread is hers, and carol's
// ordinary ask on it afterwards is left alone.
func TestAHeldStreamDoesNotOpenAThreadWhoseAskArrivedFirst(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	carol.run("peers", "add", alice.exportLine())
	alice.run("peers", "add", carol.exportLine())
	carol.run("channel", "create", "jostle")
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	var many sentManyJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob,carol", "--channel", "jostle",
		"--subject", "a question for two", "--json", "what do you both think?")), &many); err != nil {
		t.Fatal(err)
	}
	thread := many.Thread
	streamOnThread(t, carol, bob.user, bob.channel, thread, "a newer ask", critical("later"))

	report, stderr := bob.roundSaid(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != many.ID {
		t.Fatalf("alice's ask, which arrived first, was not answered: %+v\nstderr:\n%s", report, stderr)
	}
	if !strings.Contains(stderr, "waits on the relay for a newer auu") {
		t.Errorf("carol's stream was not held:\n%s", stderr)
	}
	led := bob.ledgerOf(t)
	if o := led.opener(thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice; carol is %s", o, carol.fingerprint())
	}
	held := false
	for _, e := range led.Messages {
		if e.Newer == "later" && e.Thread == thread {
			held = e.From == carol.fingerprint() && e.Tried.IsZero()
		}
	}
	if !held {
		t.Errorf("no held entry of carol's with no try on the thread: %+v", led.Messages)
	}

	hijack := carol.askOn(t, "jostle", thread, "carol's question", "and mine?")
	after, stderr := bob.roundSaid(t)
	if len(after.Answered)+len(after.Failed) != 0 {
		t.Errorf("carol's ask on alice's thread was taken: %+v", after)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) {
		t.Errorf("a handler ran for carol's ask:\n%s", runs)
	}
}

// A retry does not move a thread. Tried is the last attempt, so an order by
// tried would give the thread to whoever had been tried least recently:
// alice's ask on T fails, carol's entry on T, which arrived after alice's,
// was tried after alice's first attempt, and alice's retry, answered, would
// make her own entry the latest tried and carol the opener. By arrival, alice is the opener before her retry and after
// it, and the retry is answered. Carol's entry is written by hand, and
// alice's attempt moved two hours back so that carol's try falls between
// alice's two.
func TestARetryDoesNotMoveTheOpener(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:not yet;exit:3")
	sent := alice.ask(t, "jostle", "a question", "the first")
	if _, err := bob.tryRun("serve", "--once"); err == nil {
		t.Fatal("a handler that exits 3 was not a failure")
	}
	led := bob.ledgerOf(t)
	mine := led.Messages[sent.ID]
	if mine == nil || mine.Failures != 1 || mine.GaveUp || mine.From != alice.fingerprint() || mine.Arrived.IsZero() {
		t.Fatalf("alice's failed ask wrote %+v, want one failure, still pending, with her sender and arrival", mine)
	}
	firstTry := mine.Tried.Add(-2 * time.Hour)
	mine.Tried = firstTry
	mine.Arrived = mine.Arrived.Add(-2 * time.Hour)
	led.Messages[strings.Repeat("0", 32)] = &ledgerEntry{
		Thread: sent.Thread, Channel: "jostle", Failures: 1,
		Arrived: mine.Arrived.Add(time.Hour), Tried: firstTry.Add(time.Hour), From: carol.fingerprint(),
	}
	if err := led.save(); err != nil {
		t.Fatal(err)
	}
	if o := bob.ledgerOf(t).opener(sent.Thread); o != alice.fingerprint() {
		t.Fatalf("before the retry the opener is %q, want alice", o)
	}

	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("alice's retry was not answered: %+v", report)
	}
	after := bob.ledgerOf(t)
	if e := after.Messages[sent.ID]; !e.Tried.After(after.Messages[strings.Repeat("0", 32)].Tried) {
		t.Fatalf("the retry's try %v is not after carol's %v, so the test proves nothing", e.Tried, after.Messages[strings.Repeat("0", 32)].Tried)
	}
	if o := after.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("after alice's retry the opener is %q, want alice", o)
	}
	alice.replyOn(t, sent.Thread)
}

// A message's arrival is the relay's listing stamp, and a relay that is
// behind, or dishonest, can stamp a co-recipient's message before the
// opener's. So a message from somebody other than the opener competes on
// its own arrival only while the opener's message has not been taken up,
// a held stream's entry with no try and no answer; against a thread serve
// has answered, an earlier stamp wins nothing. Alice's ask on T is
// answered, and her entry's arrival is set to an hour from now, so that carol's
// ask on T, fetched after it, carries the earlier stamp: carol is left
// alone and said once, no handler runs for her, alice stays the opener,
// and alice's next turn is answered.
func TestAnEarlierStampCannotTakeAnAnsweredThread(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)

	led := bob.ledgerOf(t)
	mine := led.Messages[sent.ID]
	if mine == nil || mine.Handled.IsZero() || mine.Arrived.IsZero() {
		t.Fatalf("alice's answered ask wrote %+v", mine)
	}
	mine.Arrived = time.Now().UTC().Add(time.Hour)
	if err := led.save(); err != nil {
		t.Fatal(err)
	}

	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "stamped first")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("carol's ask with the earlier stamp took alice's answered thread: %+v", report)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Load(store.Inbox, hijack.ID)
	if err != nil {
		t.Fatal(err)
	}
	after := bob.ledgerOf(t)
	if !m.Received.Before(after.Messages[sent.ID].Arrived) {
		t.Fatalf("carol's ask was received %v, not before alice's arrival %v, so the test proves nothing",
			m.Received, after.Messages[sent.ID].Arrived)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's ask:\n%s", runs)
	}
	if o := after.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice", o)
	}
	if e, ok := after.Messages[hijack.ID]; ok {
		t.Errorf("carol's ask was written into the ledger: %+v", e)
	}
	nothingFromBob(t, carol, bob)
	unreadAtBob(t, bob, hijack.ID)

	alice.run("reply", first.ID[:12], "and one more thing")
	next := bob.round(t)
	if len(next.Answered) != 1 || next.Answered[0].Thread != sent.Thread {
		t.Fatalf("alice's next turn was not answered: %+v", next)
	}
	if line := "handler " + next.Answered[0].ID + " 2\n"; !strings.Contains(readFile(t, marker), line) {
		t.Errorf("alice's next turn was not her turn 2; the handler ran:\n%s", readFile(t, marker))
	}
}

// The opener's own held stream does not reopen a thread serve has answered.
// A message from somebody other than the opener competes on its arrival
// only while nothing on the thread has been tried or answered, and not
// merely while the opener's earliest entry is untaken. Alice sends a stream
// on T that is held for a newer auu, its entry the thread's earliest and
// untaken, and then a plain ask on T, which is answered. Both her entries'
// arrivals are then set an hour and more from now, the stream's still the
// earlier, so that carol's ask on T, fetched after them, carries a stamp
// before both. Carol is left alone, said once, with no handler run, and
// alice stays the opener.
func TestTheOpenersHeldStreamDoesNotReopenAnAnsweredThread(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	streamOnThread(t, alice, bob.user, bob.channel, thread, "a newer ask", critical("later"))
	ask := alice.askOn(t, "jostle", thread, "a plain ask", "and the question itself")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != ask.ID {
		t.Fatalf("alice's plain ask was not answered: %+v\nstderr:\n%s", report, stderr)
	}
	led := bob.ledgerOf(t)
	var held string
	for id, e := range led.Messages {
		if e.Newer == "later" && e.Thread == thread {
			held = id
		}
	}
	if held == "" {
		t.Fatalf("alice's stream was not held: %+v", led.Messages)
	}
	if e := led.Messages[held]; e.From != alice.fingerprint() || !e.Tried.IsZero() || !e.Handled.IsZero() {
		t.Fatalf("alice's held stream wrote %+v; want her sender, untaken", e)
	}
	now := time.Now().UTC()
	led.Messages[held].Arrived = now.Add(time.Hour)
	led.Messages[ask.ID].Arrived = now.Add(2 * time.Hour)
	if err := led.save(); err != nil {
		t.Fatal(err)
	}

	hijack := carol.askOn(t, "jostle", thread, "carol's question", "stamped first")
	after, stderr := bob.roundSaid(t)
	if len(after.Answered)+len(after.Failed)+len(after.Skipped) != 0 {
		t.Errorf("carol's ask with an earlier stamp took alice's answered thread past her held stream: %+v", after)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Load(store.Inbox, hijack.ID)
	if err != nil {
		t.Fatal(err)
	}
	led = bob.ledgerOf(t)
	if !m.Received.Before(led.Messages[held].Arrived) {
		t.Fatalf("carol's ask was received %v, not before alice's stream %v, so the test proves nothing",
			m.Received, led.Messages[held].Arrived)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's ask:\n%s", runs)
	}
	if o := led.opener(thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice", o)
	}
	if e, ok := led.Messages[hijack.ID]; ok {
		t.Errorf("carol's ask was written into the ledger: %+v", e)
	}
	nothingFromBob(t, carol, bob)
}

// A thread whose only attempts have failed has been taken up all the same:
// its opener's ask was tried, and an earlier stamp on another's message
// wins nothing against it, as against an answered thread. Alice's ask on T
// fails once and is not given up on; her entry's arrival is then set to an
// hour from now, so that carol's ask on T, fetched after it, carries the
// earlier stamp. The round that meets carol's ask retries alice's, which
// fails again, so that the thread has still only failed when carol's ask
// is decided: an answer to alice earlier in the same round would close the
// thread whatever counted as tried. Carol is left alone and said once, with
// no handler run, nothing sent to her and nothing written for her; the next
// round answers alice's retry as her first turn, and alice stays the
// opener throughout.
func TestAFailingOpenersThreadIsNotTakenByAnEarlierStamp(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	bob.row.Retries = 3
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";say:not yet;exit:3")
	sent := alice.ask(t, "jostle", "a question", "the first")
	if _, err := bob.tryRun("serve", "--once"); err == nil {
		t.Fatal("a handler that exits 3 was not a failure")
	}
	led := bob.ledgerOf(t)
	mine := led.Messages[sent.ID]
	if mine == nil || mine.Failures != 1 || mine.GaveUp || mine.Tried.IsZero() || !mine.Handled.IsZero() ||
		mine.From != alice.fingerprint() || mine.Arrived.IsZero() {
		t.Fatalf("alice's failed ask wrote %+v; want one failure, tried, not answered, not given up, with her sender and arrival", mine)
	}
	mine.Arrived = time.Now().UTC().Add(time.Hour)
	if err := led.save(); err != nil {
		t.Fatal(err)
	}

	// The round with carol's ask, alice's retry failing again.
	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "stamped first")
	var out string
	var runErr error
	stderr := captureStderr(t, func() { out, runErr = bob.tryRun("serve", "--once", "--json") })
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v (%v)\n%s\nstderr:\n%s", err, runErr, out, stderr)
	}
	if len(report.Answered) != 0 || len(report.Failed) != 1 || report.Failed[0].ID != sent.ID {
		t.Errorf("want alice's retry failed and carol's ask not taken: %+v\nstderr:\n%s", report, stderr)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Load(store.Inbox, hijack.ID)
	if err != nil {
		t.Fatal(err)
	}
	led = bob.ledgerOf(t)
	if !m.Received.Before(led.Messages[sent.ID].Arrived) {
		t.Fatalf("carol's ask was received %v, not before alice's arrival %v, so the test proves nothing",
			m.Received, led.Messages[sent.ID].Arrived)
	}
	if e := led.Messages[sent.ID]; e.Failures != 2 || !e.Handled.IsZero() {
		t.Fatalf("alice's entry is %+v; want two failures and no answer, so the thread had only failed", e)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	if e, ok := led.Messages[hijack.ID]; ok {
		t.Errorf("carol's ask was written into the ledger: %+v", e)
	}
	if o := led.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("the thread's opener is %q, want alice", o)
	}

	// Alice's retry answered, as her first turn.
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	after, stderr := bob.roundSaid(t)
	if len(after.Answered) != 1 || after.Answered[0].ID != sent.ID || len(after.Failed)+len(after.Skipped) != 0 {
		t.Errorf("want alice's retry answered and nothing else: %+v\nstderr:\n%s", after, stderr)
	}
	runs := readFile(t, marker)
	if strings.Contains(runs, hijack.ID) {
		t.Errorf("a handler ran for carol's ask:\n%s", runs)
	}
	if strings.Count(runs, "handler "+sent.ID+" 1\n") != 3 || strings.Count(runs, "\n") != 3 {
		t.Errorf("want alice's ask run three times, each as turn 1, and nothing else:\n%s", runs)
	}
	led = bob.ledgerOf(t)
	if n := led.answered(sent.Thread); n != 1 {
		t.Errorf("the thread has %d turns answered, want 1", n)
	}
	if o := led.opener(sent.Thread); o != alice.fingerprint() {
		t.Errorf("after the retry the thread's opener is %q, want alice", o)
	}
	nothingFromBob(t, carol, bob)
	unreadAtBob(t, bob, hijack.ID)
	alice.replyOn(t, sent.Thread)
}
