package auu

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The third adversarial trace, at v0.17.0: who a thread on an expert host
// belongs to, what a fetch does with an answer that is not the range it
// asked for, and what 'quarantine trust' fetches and when it writes the
// peer. Its tests are here as the regression tests, each renamed for what
// it proves.

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
// and in what order it arrived exactly as bob's stored copy does: Arrived,
// this machine's clock when the record was first saved, not the relay's
// Received, and RelayID, neither of them zero.
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
	if e.Arrived.IsZero() || e.RelayID == 0 || !e.Arrived.Equal(m.Arrived) || e.RelayID != m.RelayID {
		t.Errorf("%s's entry has arrived %v and relay_id %d; want the stored record's %v and %d, neither zero",
			id[:12], e.Arrived, e.RelayID, m.Arrived, m.RelayID)
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

// A message's arrival is the record's Arrived, this machine's clock when it
// was first saved; an entry an earlier release wrote holds the relay's
// received in its place, which a relay that is behind, or dishonest, can
// stamp before the opener's, and this machine's clock may be set back. So a
// message from somebody other than the opener competes on its own arrival
// only while the opener's message has not been taken up, a held stream's
// entry with no try and no answer; against a thread serve has answered, an
// earlier arrival wins nothing. Alice's ask on T is answered, and her
// entry's arrival is set to an hour from now, so that carol's ask on T,
// fetched after it, carries the earlier arrival: carol is left alone and
// said once, no handler runs for her, alice stays the opener, and alice's
// next turn is answered.
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
	if !m.Arrived.Before(after.Messages[sent.ID].Arrived) {
		t.Fatalf("carol's ask arrived %v, not before alice's arrival %v, so the test proves nothing",
			m.Arrived, after.Messages[sent.ID].Arrived)
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
	if !m.Arrived.Before(led.Messages[held].Arrived) {
		t.Fatalf("carol's ask arrived %v, not before alice's stream %v, so the test proves nothing",
			m.Arrived, led.Messages[held].Arrived)
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
	if !m.Arrived.Before(led.Messages[sent.ID].Arrived) {
		t.Fatalf("carol's ask arrived %v, not before alice's arrival %v, so the test proves nothing",
			m.Arrived, led.Messages[sent.ID].Arrived)
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

// repointRelay makes a home's default relay answer from another URL, as a
// proxy in front of the real one would, and hands back the relay's name.
func repointRelay(t *testing.T, u *user, to string) string {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	r.URL = to
	if err := s.SaveRelay(r); err != nil {
		t.Fatal(err)
	}
	return r.Name
}

// The trace's reverse proxy in front of an honest relay, dropping Range from
// every request as a proxy or a cache may: the relay answers each range with
// the whole blob as a 200. That used to read as the range, the manifest did
// not open, and the fetch kept the stream as damaged and acknowledged it,
// deleting the sender's message from the relay. Now the answer is a
// malformed one and the fetch's failure a transport failure: the inbox
// exits 2 naming the range, keeps nothing under damaged/, delivers nothing
// and acknowledges nothing, so the stream is still in bob's mailbox on the
// relay; and the next fetch, straight to the relay, delivers it whole.
func TestAnIntermediaryIgnoringRangeLeavesTheStreamOnTheRelay(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	target, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	var stripped atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(target)
	direct := proxy.Director
	proxy.Director = func(r *http.Request) {
		direct(r)
		if r.Header.Get("Range") != "" {
			stripped.Add(1)
		}
		r.Header.Del("Range")
	}
	front := httptest.NewServer(proxy)
	defer front.Close()
	relayName := repointRelay(t, bob, front.URL)

	const text = "a message that travels as a stream"
	alice.run("send", "--to", "bob", "--stream", text)
	out, err := bob.tryRun("inbox", "--json")
	t.Logf("bob's fetch through the Range-stripping proxy: %v; stdout %q", err, out)
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("the fetch through the proxy: %v; want a transport failure, exit %d", err, exitTransport)
	}
	if !errors.Is(err, client.ErrMalformedAnswer) || !strings.Contains(err.Error(), "range") ||
		!strings.Contains(err.Error(), front.URL) {
		t.Errorf("the failure %q is not a malformed answer from %s naming the range", err, front.URL)
	}
	if stripped.Load() == 0 {
		t.Fatal("the proxy saw no range request: the test did not reach the stream's body")
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if kept, err := os.ReadDir(s.DamagedDir()); err == nil && len(kept) > 0 {
		t.Errorf("the fetch through the proxy kept %d entries under damaged/; want none", len(kept))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if got := bob.inboxJSON("--no-fetch"); len(got.Messages) != 0 {
		t.Errorf("the failed fetch delivered %d messages", len(got.Messages))
	}

	// The relay still holds it: bob's own client, straight to the relay. (A
	// damaged stream is acknowledged whatever the channel's keep setting,
	// so the row being there is the failed fetch having let it be.)
	repointRelay(t, bob, relayURL)
	bs, id, relays := bob.opened()
	c, err := dial(bs, id, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	listing, err := c.List(ctx(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Messages) != 1 || !listing.Messages[0].IsStream() {
		t.Fatalf("after the fetch through the proxy the relay %s holds %+v; want the one stream, unacknowledged", relayName, listing.Messages)
	}

	got := bob.inboxJSON()
	if got.Fetch.Delivered != 1 || got.Fetch.Unreadable != 0 || got.Fetch.Kept != 0 || len(got.Messages) != 1 {
		t.Fatalf("the fetch straight to the relay: %+v, %d messages; want the stream delivered whole", got.Fetch, len(got.Messages))
	}
	if read := bob.run("read", got.Messages[0].ID); !strings.Contains(read, text) {
		t.Errorf("the delivered stream reads %q; want it to carry %q", read, text)
	}
}

// The same on the resume path: the payload download is cut part-way, and
// the resume's open-ended N- request reaches the relay with its Range
// dropped, as a proxy may, so the relay answers 200 with the whole blob.
// That is not the remainder: the fetch fails as a transport failure, keeps
// nothing under damaged/ and acknowledges nothing, the stream is still on
// the relay, and the next fetch, straight to the relay, delivers it whole.
func TestAResumeAnsweredWholeLeavesTheStreamOnTheRelay(t *testing.T) {
	relayURL, gate := startDroppingRelay(t, 1, 100<<10)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	payload := downloadPayload()

	target, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	var openEnded, stripped atomic.Int64
	var resumes []string
	var mu sync.Mutex
	proxy := httputil.NewSingleHostReverseProxy(target)
	direct := proxy.Director
	proxy.Director = func(r *http.Request) {
		direct(r)
		rng := r.Header.Get("Range")
		// The first open-ended range is the download, cut by the dropper;
		// every one after it is a resume, and loses its Range here.
		if strings.HasSuffix(rng, "-") && openEnded.Add(1) > 1 {
			mu.Lock()
			resumes = append(resumes, rng)
			mu.Unlock()
			stripped.Add(1)
			r.Header.Del("Range")
		}
	}
	// The cut download is the proxy's to read short; that is the test.
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	front := httptest.NewServer(proxy)
	defer front.Close()
	repointRelay(t, bob, front.URL)
	sendOneStream(t, alice, bob, payload, "long.bin")

	out, err := bob.tryRun("inbox", "--json")
	t.Logf("bob's fetch with the resume answered whole: %v; stdout %q; resumes sent %q", err, out, resumes)
	if _, cut := gate.counts(); cut != 1 {
		t.Fatalf("the harness cut %d downloads, want 1", cut)
	}
	if stripped.Load() == 0 {
		t.Fatal("no resume was asked for after the cut: the test did not reach the resume")
	}
	mu.Lock()
	first := resumes[0]
	mu.Unlock()
	from := strings.TrimSuffix(strings.TrimPrefix(first, "bytes="), "-")
	if from == "" || from == "0" {
		t.Fatalf("the resume asked for %q; want an open-ended range from past the start", first)
	}
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("the fetch with the resume answered whole: %v; want a transport failure, exit %d", err, exitTransport)
	}
	if !errors.Is(err, client.ErrMalformedAnswer) || !strings.Contains(err.Error(), "bytes "+from+"-") {
		t.Errorf("the failure %q is not a malformed answer naming the range bytes %s-", err, from)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if kept, err := os.ReadDir(s.DamagedDir()); err == nil && len(kept) > 0 {
		t.Errorf("the fetch kept %d entries under damaged/; want none", len(kept))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if got := bob.inboxJSON("--no-fetch"); len(got.Messages) != 0 {
		t.Errorf("the failed fetch delivered %d messages", len(got.Messages))
	}

	// Still on the relay, unacknowledged.
	repointRelay(t, bob, relayURL)
	bs, id, relays := bob.opened()
	c, err := dial(bs, id, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	listing, err := c.List(ctx(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Messages) != 1 || !listing.Messages[0].IsStream() {
		t.Fatalf("after the failed resume the relay holds %+v; want the one stream", listing.Messages)
	}

	got := bob.inboxJSON()
	if got.Fetch.Delivered != 1 || got.Fetch.Unreadable != 0 || len(got.Messages) != 1 {
		t.Fatalf("the fetch straight to the relay: %+v; want the stream delivered", got.Fetch)
	}
	dir := t.TempDir()
	bob.run("extract", got.Messages[0].ID, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "long.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("the stream delivered after the failed resume differs: %d bytes back, %d sent", len(back), len(payload))
	}
}

// uploadShortStream seals a stream from u for toFP whose manifest declares
// four body chunks, and uploads only the header, the manifest and the
// first body chunk, as the trace test does. It returns the manifest, the
// sealed manifest length and the bytes uploaded.
func uploadShortStream(t *testing.T, u *user, to *store.Store, toFP string, subject string) (*stream.Manifest, int, []byte) {
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
	toID, err := to.Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := toID.Public()
	payload := make([]byte, 200<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sources := []stream.Source{{
		Name: "big.bin", Media: "application/octet-stream", Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
	}}
	messageID, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	m, err := stream.BuildManifest(id, pub, messageID,
		stream.Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: subject, Text: "streamed"},
		sources, stream.DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, id, pub, m, sources); err != nil {
		t.Fatal(err)
	}
	full := blob.Bytes()
	n := int(binary.BigEndian.Uint32(full[stream.EncSize:stream.HeaderSize]))
	short := full[:stream.HeaderSize+n+stream.DefaultChunkSize+stream.TagSize]
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, toFP, "", int64(len(short)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(short), int64(len(short))); err != nil {
		t.Fatal(err)
	}
	return m, n, short
}

// peersOf is a user's peer list as 'peers ls --json' says it.
func peersOf(t *testing.T, u *user) []peerJSON {
	t.Helper()
	var peers []peerJSON
	if err := json.Unmarshal([]byte(u.run("peers", "ls", "--json")), &peers); err != nil {
		t.Fatal(err)
	}
	return peers
}

// rowIDs is what a relay holds in a mailbox, by row id.
func rowIDs(t *testing.T, st *relay.Store, fp string) []int64 {
	t.Helper()
	rows, err := st.List(fp, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// stillQuarantined fails unless the message is in quarantine with its
// payload on the relay, no name given its sender, and nothing in its
// attachment spool: a trust that failed left it as it was.
func stillQuarantined(t *testing.T, u *user, id string) *store.Stored {
	t.Helper()
	s, _, _ := u.opened()
	box, rec, err := s.Find(id)
	if err != nil {
		t.Fatal(err)
	}
	if box != store.Quarantine || !rec.PayloadOnRelay || rec.SenderName != "" {
		t.Fatalf("%s is in %s with payload_on_relay=%v and sender name %q; want it in quarantine as it was",
			id[:12], box, rec.PayloadOnRelay, rec.SenderName)
	}
	if entries, err := os.ReadDir(s.AttachmentDir(store.Quarantine, id)); err == nil && len(entries) > 0 {
		t.Fatalf("%s's payload was fetched into the quarantine spool: %d files", id[:12], len(entries))
	}
	return rec
}

// The trace: a stranger's stream whose signed manifest declares more than
// was uploaded was quarantined from its manifest alone, since the fetch
// compared the two sizes only for a sender on the peer list, and 'quarantine
// trust' then fetched the payload into the end of the blob, failed as a
// transport failure after writing the stranger to the peer list, and did
// the same at every later trust. The size is compared now before anybody is
// asked whether the sender is admitted: the stream is kept under damaged/
// with the two numbers and acknowledged, nothing is quarantined, nobody is
// added, and there is nothing to trust.
func TestAStrangersOverstatedStreamIsKeptAsDamagedNotQuarantined(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	bobStore, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, n, short := uploadShortStream(t, stranger, bobStore, bob.exportFingerprint(), "unasked")
	rows := rowIDs(t, st, bob.exportFingerprint())
	if len(rows) != 1 {
		t.Fatalf("the relay holds %d rows for bob, want the short stream", len(rows))
	}

	out := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Fetch.Quarantined != 0 || got.Fetch.Unreadable != 1 || got.Fetch.Kept != 1 || got.Fetch.Delivered != 0 {
		t.Fatalf("fetch: %+v; want the stream kept as damaged and nothing quarantined", got.Fetch)
	}
	var q []messageJSON
	if err := json.Unmarshal([]byte(bob.run("quarantine", "ls", "--json")), &q); err != nil {
		t.Fatal(err)
	}
	if len(q) != 0 {
		t.Fatalf("quarantine: %+v; want it empty", q)
	}
	rec := damagedRecord(t, bobStore, bob.defaultRelayName(), rows[0])
	if want := sizeCause(stream.Size(n, m.PayloadBytes, m.ChunkSize), int64(len(short))); rec.Cause != want {
		t.Fatalf("the kept record's cause is %q, want %q", rec.Cause, want)
	}
	if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("the relay still holds %v; the damaged stream was not acknowledged", left)
	}
	if peers := peersOf(t, bob); len(peers) != 0 {
		t.Fatalf("the stranger was added to the peer list: %+v", peers)
	}

	// Nothing to trust: the message is in no box, and trust says so as
	// the person's error, not as the relay's.
	_, trustErr := bob.answer("mallory", "quarantine", "trust", m.ID)
	var e *exitError
	if trustErr == nil || !asExit(trustErr, &e) || e.code != exitUsage {
		t.Fatalf("trust of the damaged stream's id: %v; want a usage refusal", trustErr)
	}
	if peers := peersOf(t, bob); len(peers) != 0 {
		t.Fatalf("the refused trust added a peer: %+v", peers)
	}
}

// The trace: 'quarantine trust' fetched the manifest again under the
// record's relay id and held only its sender to the record, so a relay
// that put another stream of the same sender under the row made trust
// deliver that other stream: its payload under the other message's id, and
// the record that was shown moved to the inbox with its payload still on
// the relay. The manifest's sender, id and channel are held to the record
// now, before a byte of payload is asked for: trust refuses, nothing of the
// payload is fetched and nothing acknowledged, nobody is added, and both
// records are as they were.
func TestTrustDeliversOnlyTheStreamThatWasQuarantined(t *testing.T) {
	srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	bobFP := bob.exportFingerprint()

	// Two streams of the same size and shape, so the swap on disk is byte
	// for byte the same length: the subjects, the names and the payload
	// sizes are equal, and only the bytes differ.
	dir := t.TempDir()
	files := map[string][]byte{}
	for i, name := range []string{"a.bin", "b.bin"} {
		payload := make([]byte, 300<<10)
		for j := range payload {
			payload[j] = byte(j*(i+3) + i)
		}
		files[name] = payload
		if err := os.WriteFile(filepath.Join(dir, name), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stranger.run("send", "--to", bobFP, "--subject", "first", "--attach", filepath.Join(dir, "a.bin"), "x")
	stranger.run("send", "--to", bobFP, "--subject", "secnd", "--attach", filepath.Join(dir, "b.bin"), "x")

	rows, err := st.List(bobFP, 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %d (%v), want 2", len(rows), err)
	}
	if rows[0].Size != rows[1].Size {
		t.Fatalf("the two streams are %d and %d bytes; the test needs them equal", rows[0].Size, rows[1].Size)
	}

	out := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Fetch.Quarantined != 2 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	var q []messageJSON
	if err := json.Unmarshal([]byte(bob.run("quarantine", "ls", "--json")), &q); err != nil {
		t.Fatal(err)
	}
	if len(q) != 2 {
		t.Fatalf("quarantine: %+v", q)
	}
	var first, second messageJSON
	for _, m := range q {
		switch m.Subject {
		case "first":
			first = m
		case "secnd":
			second = m
		}
	}
	if first.ID == "" || second.ID == "" {
		t.Fatalf("quarantine: %+v", q)
	}

	// The relay re-arranges what it stores: the second stream's bytes now
	// stand under the first stream's row.
	firstPath := filepath.Join(messages, bobFP[:2], bobFP, strconv.FormatInt(rows[0].ID, 10))
	secondPath := filepath.Join(messages, bobFP[:2], bobFP, strconv.FormatInt(rows[1].ID, 10))
	swapped, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstPath, swapped, 0o600); err != nil {
		t.Fatal(err)
	}

	// Bob was shown "first" and trusts it, and is refused.
	trustOut, trustErr := bob.answer("mallory", "quarantine", "trust", first.ID)
	if trustErr == nil {
		t.Fatalf("trust of \"first\" delivered what the relay served under its row:\n%s", trustOut)
	}
	if want := first.ID[:12] + ": the stream on the relay is not the one that was quarantined"; !strings.Contains(trustErr.Error(), want) {
		t.Fatalf("trust: %v; want %q", trustErr, want)
	}
	stillQuarantined(t, bob, first.ID)
	stillQuarantined(t, bob, second.ID)
	if peers := peersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a refused trust added the stranger to the peer list: %+v", peers)
	}
	if left := rowIDs(t, st, bobFP); len(left) != 2 {
		t.Fatalf("the relay holds %v after the refused trust; want both rows unacknowledged", left)
	}
}

// strangersStream is a relay, bob, and one ordinary stream of 300 KiB from
// a stranger to him, fetched and so quarantined with its payload on the
// relay. It hands back the record.
func strangersStream(t *testing.T) (srv *httptest.Server, st *relay.Store, bob *user, rec *store.Stored, payload []byte) {
	t.Helper()
	srv, st = startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob = newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	payload = make([]byte, 300<<10)
	for i := range payload {
		payload[i] = byte(i * 13)
	}
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	stranger.run("send", "--to", bob.exportFingerprint(), "--subject", "unasked", "--attach", file, "x")
	if got := bob.inboxJSON(); got.Fetch.Quarantined != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	rec = recordOf(t, bob, store.Quarantine, "unasked")
	if !rec.PayloadOnRelay || rec.RelaySize == 0 {
		t.Fatalf("the quarantined stream: %+v", rec)
	}
	return srv, st, bob, rec, payload
}

// trusted fails unless the message was delivered whole: in the inbox, its
// attachment the payload sent, and its sender on the peer list under name.
func trusted(t *testing.T, u *user, id, name string, payload []byte) {
	t.Helper()
	s, _, _ := u.opened()
	box, rec, err := s.Find(id)
	if err != nil {
		t.Fatal(err)
	}
	if box != store.Inbox || rec.PayloadOnRelay || rec.SenderName != name {
		t.Fatalf("after trust %s is in %s with payload_on_relay=%v and sender name %q", id[:12], box, rec.PayloadOnRelay, rec.SenderName)
	}
	dir := t.TempDir()
	u.run("extract", id, "--out", dir)
	if back, err := os.ReadFile(filepath.Join(dir, "big.bin")); err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("the trusted payload did not arrive whole: %v", err)
	}
	if names := u.peerNames(); len(names) != 1 || names[0] != name {
		t.Fatalf("after trust the peer list is %v, want [%s]", names, name)
	}
}

// A trust whose fetch fails at the relay writes nothing: the peer list is
// as it was and the record is still in quarantine with its payload on the
// relay, so the person can try again; with the relay back, the same trust
// delivers the stream and only then names the peer.
func TestATrustThatCannotReachTheRelayAddsNobody(t *testing.T) {
	srv, st, bob, rec, payload := strangersStream(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	repointRelay(t, bob, deadURL)

	_, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID)
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("trust with the relay unreachable: %v; want exit %d", err, exitTransport)
	}
	stillQuarantined(t, bob, rec.Inner.ID)
	if peers := peersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a trust that delivered nothing added the stranger: %+v", peers)
	}
	if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v, want the stream unacknowledged", left)
	}

	repointRelay(t, bob, srv.URL)
	if _, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID); err != nil {
		t.Fatalf("trust with the relay back: %v", err)
	}
	trusted(t, bob, rec.Inner.ID, "mallory", payload)
}

// A trust whose payload cannot be fetched, the manifest having been fetched
// and held to the record, writes nothing: a proxy in front of the relay
// passes the manifest's two ranges and fails every range past them with a
// 503, trust exits with the transport code, nobody is added, the record is
// still in quarantine with its payload on the relay and the row is still
// there; straight to the relay, the same trust delivers and names the peer.
func TestATrustWhosePayloadFailsAddsNobody(t *testing.T) {
	srv, st, bob, rec, payload := strangersStream(t)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var failed atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var from, to int64
		if n, _ := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &from, &to); n >= 1 && from > stream.HeaderSize {
			failed.Add(1)
			http.Error(w, "the payload is not served here", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()
	repointRelay(t, bob, front.URL)

	_, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID)
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("trust with the payload failing: %v; want exit %d", err, exitTransport)
	}
	if failed.Load() == 0 {
		t.Fatal("the proxy failed no payload range: the test did not reach the payload")
	}
	stillQuarantined(t, bob, rec.Inner.ID)
	if peers := peersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a trust whose payload never arrived added the stranger: %+v", peers)
	}
	if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v, want the stream unacknowledged", left)
	}

	repointRelay(t, bob, srv.URL)
	if _, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID); err != nil {
		t.Fatalf("trust straight to the relay: %v", err)
	}
	trusted(t, bob, rec.Inner.ID, "mallory", payload)
}

// recordJSON is a stored record as its bytes, for saying it is unchanged.
func recordJSON(t *testing.T, u *user, id string) string {
	t.Helper()
	s, _, _ := u.opened()
	m, err := s.Load(store.Quarantine, id)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A trust whose body is gone from the relay, found so at the fetch or known
// so already, says so at the transport exit and writes nothing: the record
// is as it was and nobody is added to the peer list.
func TestATrustWhoseBodyIsGoneAddsNobody(t *testing.T) {
	gone := func(t *testing.T, bob *user, rec *store.Stored, before string) {
		t.Helper()
		_, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID)
		var e *exitError
		if !asExit(err, &e) || e.code != exitTransport ||
			err.Error() != rec.Inner.ID[:12]+": its body is no longer on the relay; ask the sender to send it again" {
			t.Fatalf("trust with the body gone: %v", err)
		}
		if after := recordJSON(t, bob, rec.Inner.ID); after != before {
			t.Fatalf("the record changed:\n%s\nwas\n%s", after, before)
		}
		if peers := peersOf(t, bob); len(peers) != 0 {
			t.Fatalf("a trust that delivered nothing added the stranger: %+v", peers)
		}
	}
	t.Run("a 404 at the fetch", func(t *testing.T) {
		_, st, bob, rec, _ := strangersStream(t)
		if ok, err := st.Delete(bob.exportFingerprint(), rec.RelayID); err != nil || !ok {
			t.Fatalf("delete on the relay: %v %v", ok, err)
		}
		gone(t, bob, rec, recordJSON(t, bob, rec.Inner.ID))
	})
	t.Run("payload gone on the record", func(t *testing.T) {
		_, _, bob, rec, _ := strangersStream(t)
		s, _, _ := bob.opened()
		m, err := s.Load(store.Quarantine, rec.Inner.ID)
		if err != nil {
			t.Fatal(err)
		}
		m.PayloadGone = true
		if err := s.Save(store.Quarantine, m); err != nil {
			t.Fatal(err)
		}
		gone(t, bob, rec, recordJSON(t, bob, rec.Inner.ID))
	})
}

// Trust holds what the relay serves to the record it was shown: a record
// whose sender, id or channel the stream on the relay does not have is
// refused by name with nothing of the payload fetched, nothing acknowledged
// or added and the record as it was; one whose size the stream's signed
// manifest disagrees with is the sender's fault, kept as damaged,
// acknowledged and taken out of the quarantine with nobody added; and a
// record from before the relay's size was kept, which has 0, has its size
// alone unchecked and is delivered.
func TestTrustHoldsTheStreamToItsRecord(t *testing.T) {
	srv, st, bob, rec, payload := strangersStream(t)
	s, _, _ := bob.opened()
	edit := func(change func(*store.Stored)) {
		t.Helper()
		m, err := s.Load(store.Quarantine, rec.Inner.ID)
		if err != nil {
			t.Fatal(err)
		}
		change(m)
		if err := s.Save(store.Quarantine, m); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(what, id string) {
		t.Helper()
		before := recordJSON(t, bob, id)
		_, err := bob.answer("mallory", "quarantine", "trust", id)
		if want := id[:12] + ": the stream on the relay is not the one that was quarantined; " +
			"nothing was delivered and the record is as it was"; err == nil || err.Error() != want {
			t.Fatalf("trust of a record with %s: %v; want %q", what, err, want)
		}
		stillQuarantined(t, bob, id)
		if after := recordJSON(t, bob, id); after != before {
			t.Fatalf("a refused trust (%s) changed the record:\n%s\nwas\n%s", what, after, before)
		}
		if peers := peersOf(t, bob); len(peers) != 0 {
			t.Fatalf("a refused trust (%s) added a peer: %+v", what, peers)
		}
		if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 1 {
			t.Fatalf("a refused trust (%s) left the relay holding %v", what, left)
		}
	}

	edit(func(m *store.Stored) { m.Channel = "elsewhere" })
	refused("another channel", rec.Inner.ID)
	edit(func(m *store.Stored) { m.Channel = rec.Channel })

	// A record whose sender is a third party, consistently: its bundle and
	// its fingerprint agree, so trust's own check of the record passes, and
	// only the stream on the relay, still the stranger's, says otherwise.
	third := newUser(t, "third", srv.URL)
	edit(func(m *store.Stored) {
		m.Inner.From, m.Inner.FromBundle = third.exportFingerprint(), mustBundle(t, third)
	})
	refused("another sender", rec.Inner.ID)
	edit(func(m *store.Stored) { m.Inner.From, m.Inner.FromBundle = rec.Inner.From, rec.Inner.FromBundle })

	// The same record under another id, the row still the stream's.
	other, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	moved, err := s.Load(store.Quarantine, rec.Inner.ID)
	if err != nil {
		t.Fatal(err)
	}
	original := recordJSON(t, bob, rec.Inner.ID)
	if err := s.Remove(store.Quarantine, rec.Inner.ID); err != nil {
		t.Fatal(err)
	}
	moved.Inner.ID = other
	if err := s.Save(store.Quarantine, moved); err != nil {
		t.Fatal(err)
	}
	refused("another id", other)
	if err := s.Remove(store.Quarantine, other); err != nil {
		t.Fatal(err)
	}
	moved.Inner.ID = rec.Inner.ID
	if err := s.Save(store.Quarantine, moved); err != nil {
		t.Fatal(err)
	}
	if back := recordJSON(t, bob, rec.Inner.ID); back != original {
		t.Fatalf("the record did not come back as it was:\n%s\nwas\n%s", back, original)
	}

	edit(func(m *store.Stored) { m.RelaySize = 0 })
	if _, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID); err != nil {
		t.Fatalf("trust of a record with no size kept: %v", err)
	}
	trusted(t, bob, rec.Inner.ID, "mallory", payload)
}

// overstatedAtTrust fails unless trust of id found the manifest weighing
// manifest bytes and the record listed, kept the stream as damaged with the
// two numbers, acknowledged it, took it out of the quarantine and added
// nobody.
func overstatedAtTrust(t *testing.T, bob *user, st *relay.Store, id string, relayID, manifest, listed int64) {
	t.Helper()
	_, err := bob.answer("mallory", "quarantine", "trust", id)
	var e *exitError
	want := fmt.Sprintf("%s: its manifest says the stream is %d bytes on the wire and the relay listed %d; "+
		"it was kept as damaged and acknowledged, and nobody was added", id[:12], manifest, listed)
	if !asExit(err, &e) || e.code != exitTransport || err.Error() != want {
		t.Fatalf("trust of a stream whose manifest overstates it: %v; want exit %d and %q", err, exitTransport, want)
	}
	s, _, _ := bob.opened()
	if box, _, err := s.Find(id); err == nil {
		t.Fatalf("after trust the message is still in %s", box)
	}
	if rec := damagedRecord(t, s, bob.defaultRelayName(), relayID); rec.Cause != sizeCause(manifest, listed) {
		t.Fatalf("the damaged record's cause is %q, want %q", rec.Cause, sizeCause(manifest, listed))
	}
	if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("the relay still holds %v; the stream was not acknowledged", left)
	}
	if peers := peersOf(t, bob); len(peers) != 0 {
		t.Fatalf("trust of a stream kept as damaged added a peer: %+v", peers)
	}
}

// A record whose size the stream's signed manifest disagrees with, the
// sender, id and channel all the record's: trust keeps it as damaged with
// the manifest's number and the record's, acknowledges it, takes it out of
// the quarantine and adds nobody.
func TestATrustWhoseRecordSizeDisagreesKeepsItAsDamaged(t *testing.T) {
	_, st, bob, rec, _ := strangersStream(t)
	s, _, _ := bob.opened()
	m, err := s.Load(store.Quarantine, rec.Inner.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.RelaySize = rec.RelaySize + 1
	if err := s.Save(store.Quarantine, m); err != nil {
		t.Fatal(err)
	}
	overstatedAtTrust(t, bob, st, rec.Inner.ID, rec.RelayID, rec.RelaySize, rec.RelaySize+1)
}

// A stranger's overstated stream as v0.14.0 to v0.17.0 left it: quarantined
// from its manifest alone, with the size the relay listed, which the
// manifest overstates. Trusting it now does what the fetch does with such a
// stream: kept as damaged with the two numbers, acknowledged, out of the
// quarantine and in no box, and nobody added.
func TestATrustOfAnOverstatedStreamQuarantinedBeforeTheCheckIsKeptAsDamaged(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	bobStore, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	m, n, short := uploadShortStream(t, stranger, bobStore, bob.exportFingerprint(), "unasked")
	rows, err := st.List(bob.exportFingerprint(), 0, 10)
	if err != nil || len(rows) != 1 || rows[0].Size != int64(len(short)) {
		t.Fatalf("the relay's rows for bob: %+v (%v); want the short stream", rows, err)
	}

	// Quarantined as those builds did it, and not by a fetch, which now
	// keeps such a stream as damaged itself.
	s, id, relays := bob.opened()
	c, err := dial(s, id, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	opened, _, err := fetchManifest(ctx(), c, id, rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := quarantineStream(s, relays[0], relayCopy{rows[0].ID, rows[0].Received, rows[0].Size}, opened); err != nil {
		t.Fatal(err)
	}
	rec := stillQuarantined(t, bob, m.ID)
	if rec.RelaySize != int64(len(short)) {
		t.Fatalf("the record keeps the size %d, want the relay's %d", rec.RelaySize, len(short))
	}

	overstatedAtTrust(t, bob, st, m.ID, rows[0].ID, stream.Size(n, m.PayloadBytes, m.ChunkSize), int64(len(short)))
}

// A name the peer list already uses is refused before anything is fetched:
// for a stream, the payload stays on the relay unacknowledged and the record
// as it was; for an envelope, the record is as it was; the peer list is
// unchanged either way, and a free name then trusts the envelope.
func TestATakenNameIsRefusedBeforeTrustFetches(t *testing.T) {
	srv, st, bob, rec, _ := strangersStream(t)
	mallory := newUser(t, "mallory", srv.URL)
	bob.run("peers", "add", mallory.exportLine())
	before := bob.peerNames()

	_, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID)
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), `peer name "mallory" is already used by`) {
		t.Fatalf("trust under a taken name: %v", err)
	}
	stillQuarantined(t, bob, rec.Inner.ID)
	if after := bob.peerNames(); !slices.Equal(after, before) {
		t.Fatalf("the peer list went from %v to %v", before, after)
	}
	if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 1 {
		t.Fatalf("the relay holds %v after the refusal; want the stream unacknowledged", left)
	}

	// An envelope from another stranger, under the same name.
	other := newUser(t, "other", srv.URL)
	other.run("peers", "add", bob.exportLine())
	other.run("send", "--to", bob.exportFingerprint(), "--subject", "small", "hello")
	if got := bob.inboxJSON(); got.Fetch.Quarantined != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	env := recordOf(t, bob, store.Quarantine, "small")
	_, err = bob.answer("mallory", "quarantine", "trust", env.Inner.ID)
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), `peer name "mallory" is already used by`) {
		t.Fatalf("trust of an envelope under a taken name: %v", err)
	}
	s, _, _ := bob.opened()
	box, held, err := s.Find(env.Inner.ID)
	if err != nil || box != store.Quarantine || held.SenderName != "" {
		t.Fatalf("after the refusal the envelope is in %s with sender name %q (%v)", box, held.SenderName, err)
	}
	if after := bob.peerNames(); !slices.Equal(after, before) {
		t.Fatalf("the peer list went from %v to %v", before, after)
	}

	if _, err := bob.answer("other", "quarantine", "trust", env.Inner.ID); err != nil {
		t.Fatalf("trust of the envelope under a free name: %v", err)
	}
	box, held, err = s.Find(env.Inner.ID)
	if err != nil || box != store.Inbox || held.SenderName != "other" {
		t.Fatalf("after trust the envelope is in %s with sender name %q (%v)", box, held.SenderName, err)
	}
	if after := bob.peerNames(); !slices.Equal(after, append(before, "other")) {
		t.Fatalf("after trust the peer list is %v", after)
	}
}

// uploadSealed seals an honest stream of 200 KiB from u to to, its manifest
// carrying channel, and uploads it with extra bytes of zeros after its end,
// the upload's size counting them. It returns the manifest, the sealed
// manifest length, the bytes uploaded and the payload.
func uploadSealed(t *testing.T, u, to *user, channel string, extra int) (*stream.Manifest, int, []byte, []byte) {
	t.Helper()
	id, c := sender(t, u)
	payload := make([]byte, 200<<10)
	for i := range payload {
		payload[i] = byte(i * 5)
	}
	sources := []stream.Source{{
		Name: "big.bin", Media: "application/octet-stream", Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
	}}
	messageID, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	toPub := mustParseBundle(t, mustBundle(t, to))
	m, err := stream.BuildManifest(id, toPub, messageID,
		stream.Body{Type: message.TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Subject: "sealed", Text: "streamed"},
		sources, stream.DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	m.Channel = channel
	var blob bytes.Buffer
	if err := stream.Seal(&blob, id, toPub, m, sources); err != nil {
		t.Fatal(err)
	}
	full := blob.Bytes()
	n := int(binary.BigEndian.Uint32(full[stream.EncSize:stream.HeaderSize]))
	long := append(append([]byte{}, full...), make([]byte, extra)...)
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, to.exportFingerprint(), "", int64(len(long)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(long), int64(len(long))); err != nil {
		t.Fatal(err)
	}
	return m, n, long, payload
}

// The mirror of the overstated stream: a relay copy longer than its signed
// manifest says, which is as much a disagreement as a shorter one. From a
// stranger and from a peer alike it is kept under damaged/ with the two
// numbers and acknowledged before anybody is asked whether its sender is
// admitted: nothing is delivered, nothing quarantined, nobody added.
func TestAStreamWhoseRelayCopyIsLongerThanItsManifestIsKeptAsDamaged(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		name := "a stranger"
		if admitted {
			name = "a peer"
		}
		t.Run(name, func(t *testing.T) {
			srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
			bob := newUser(t, "bob", srv.URL)
			alice := newUser(t, "alice", srv.URL)
			alice.run("peers", "add", bob.exportLine())
			if admitted {
				bob.run("peers", "add", alice.exportLine())
			}
			peersBefore := bob.peerNames()
			m, n, long, _ := uploadSealed(t, alice, bob, "", 1000)
			rows := rowIDs(t, st, bob.exportFingerprint())
			if len(rows) != 1 {
				t.Fatalf("the relay holds %v for bob, want the long stream", rows)
			}

			got := bob.inboxJSON()
			if got.Fetch.Delivered != 0 || got.Fetch.Quarantined != 0 || got.Fetch.Unreadable != 1 || got.Fetch.Kept != 1 {
				t.Fatalf("fetch: %+v; want the stream kept as damaged and nothing else", got.Fetch)
			}
			s, _, _ := bob.opened()
			want := sizeCause(stream.Size(n, m.PayloadBytes, m.ChunkSize), int64(len(long)))
			if rec := damagedRecord(t, s, bob.defaultRelayName(), rows[0]); rec.Cause != want {
				t.Fatalf("the kept record's cause is %q, want %q", rec.Cause, want)
			}
			if left := rowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
				t.Fatalf("the relay still holds %v; the stream was not acknowledged", left)
			}
			if _, _, err := s.Find(m.ID); err == nil {
				t.Fatal("the stream is in a box")
			}
			if after := bob.peerNames(); !slices.Equal(after, peersBefore) {
				t.Fatalf("the peer list went from %v to %v", peersBefore, after)
			}
		})
	}
}

// A manifest may name the default channel by its name, which the fetch
// files as the default and the quarantine records as "". Trust holds the
// record to the stream by the name the record keeps, so such a stream is
// the one that was quarantined and is delivered to the default channel.
func TestATrustOfAStreamNamingTheDefaultChannelDelivers(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	m, _, _, payload := uploadSealed(t, stranger, bob, channels.Default, 0)
	if rows := rowIDs(t, st, bob.exportFingerprint()); len(rows) != 1 {
		t.Fatalf("the relay holds %v for bob", rows)
	}
	if got := bob.inboxJSON(); got.Fetch.Quarantined != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	if rec := stillQuarantined(t, bob, m.ID); rec.Channel != "" {
		t.Fatalf("the quarantine record's channel is %q, want the default's \"\"", rec.Channel)
	}
	if _, err := bob.answer("mallory", "quarantine", "trust", m.ID); err != nil {
		t.Fatalf("trust of a stream naming the default channel: %v", err)
	}
	trusted(t, bob, m.ID, "mallory", payload)
	if rec := recordOf(t, bob, store.Inbox, "sealed"); rec.Channel != "" {
		t.Fatalf("the delivered record's channel is %q, want the default's", rec.Channel)
	}
}
