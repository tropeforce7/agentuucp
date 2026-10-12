package auu

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A sender-less entry, from a v0.17.0 ledger, is filled at serve's start
// only from its own message (R9, R9a): a record under its id on its
// thread; on a thread tried or answered, only a record v0.17.0 wrote,
// whose arrival Load lent from the relay's received, and only when that
// is no later than the thread's last attempt and the relay's skew. A
// record this build fetched has an arrival of its own and fills nothing
// on such a thread.

// asOlderRecord rewrites a record in bob's inbox as v0.17.0 kept it: the
// same keys and values, with no arrived key, so that Load lends it the
// relay's received. The received must be no later than the thread's last
// attempt and the skew, as the message's was when serve tried it.
func asOlderRecord(t *testing.T, bob *expert, id string) {
	t.Helper()
	path := filepath.Join(bob.home, "inbox", id+".json")
	var record map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &record); err != nil {
		t.Fatal(err)
	}
	if _, ok := record["arrived"]; !ok {
		t.Fatalf("the record %s has no arrived key to drop", id[:12])
	}
	delete(record, "arrived")
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := storeOf(t, bob.user).Load(store.Inbox, id)
	if err != nil {
		t.Fatal(err)
	}
	led := bob.ledgerOf(t)
	e := led.Messages[id]
	if e == nil {
		t.Fatalf("no ledger entry for %s", id[:12])
	}
	if !m.Arrived.Equal(m.Received) || m.Received.After(led.lastTried(e.Thread).Add(relayapi.MaxSkew)) {
		t.Fatalf("the older record %s loads arrived %v, received %v; want its received lent, within the skew of the thread's attempt %v",
			id[:12], m.Arrived, m.Received, led.lastTried(e.Thread))
	}
}

// postByHand posts a hand-sealed envelope from u to bob's mailbox under
// channel.
func postByHand(t *testing.T, u *user, env *envelope.Envelope, channel string) int64 {
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
	relayID, err := c.Post(t.Context(), env, channel)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return relayID
}

// decodeJSON decodes a command's JSON output into v.
func decodeJSON(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
}

// notItsMessageLine is the line serve says at a start for a record under
// a carried-over entry's id that is not the entry's message. Written out
// here rather than taken from serve, since a person reads it.
func notItsMessageLine(id, thread, name string) string {
	return fmt.Sprintf("auu: %s from %s has the id of a message serve carried over from before the upgrade on thread %s, "+
		"and is not that message; the thread takes no sender from it", id[:12], name, thread[:12])
}

// notItsMessage is the part of that line every instance of it has.
const notItsMessage = "has the id of a message serve carried over from before the upgrade"

// worktreesOf lists the worktrees bob's serve has made.
func worktreesOf(t *testing.T, bob *expert) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(bob.home, "serve", "worktrees"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A thread a v0.17.0 ledger carried over, answered before the upgrade,
// whose message the owner removed, is nobody's (D81). A message id is the
// sender's to choose, so carol, a co-recipient who saw alice's id and
// thread, plants a note under alice's message id once alice's message is
// gone. At the next start the plant is in the inbox under the id of
// alice's sender-less entry, on her thread, but it was fetched by this
// build after the upgrade, so it is not her message: the entry takes no
// sender from it, the start says so once, and the thread stays nobody's.
// Carol's ask on it is then left alone: no answer, no turn in alice's
// side-copy worktree, no patch of alice's work, no worktree made and no
// ledger entry. Before the guard carol became the thread's opener and was
// answered as alice's turn 2 with alice's work as the patch. The plant is
// fetched by this build and keeps an arrival of its own, which on a thread
// tried before the upgrade fills nothing at any time (R9a).
func TestAPlantedIDDoesNotAdoptANobodysThread(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeSideCopy)
	t.Setenv(handlerScript, "write:secret.txt=alice's private work;echo:done")
	sent := alice.ask(t, "jostle", "alice's question", "please work on this")
	bob.serve(t)
	alice.replyOn(t, sent.Thread)

	// The upgrade from v0.17.0, with alice's message removed by the owner:
	// D81's precondition, a thread that is nobody's.
	rewriteAsOlder(t, bob)
	bob.run("rm", sent.ID)

	// Carol plants a note under alice's message id. It is not an ask, so
	// nothing answers it; it only needs to be in the inbox at a start.
	env := sealByHand(t, carol, bob.user, &envelope.Inner{V: envelope.Version,
		ID: sent.ID, Time: time.Now().UTC().Truncate(time.Second),
		Body:    message.Body{Type: message.TypeNote, Thread: sent.Thread, Subject: "fyi", Text: "nothing to see"},
		Channel: "jostle",
	})
	postByHand(t, carol, env, "jostle")
	stderr := captureStderr(t, func() {
		for i := 0; i < 2; i++ { // the first fetches the plant, the second's start meets it
			if out, err := bob.tryRun("serve", "--once"); err != nil {
				t.Errorf("serve --once: %v\n%s", err, out)
			}
		}
	})
	if want := notItsMessageLine(sent.ID, sent.Thread, "carol"); strings.Count(stderr, want) != 1 || strings.Count(stderr, notItsMessage) != 1 {
		t.Errorf("two starts said:\n%s\nwant once:\n%s", stderr, want)
	}

	if e := bob.ledgerOf(t).Messages[sent.ID]; e != nil && e.From == carol.fingerprint() {
		t.Errorf("alice's answered entry %s now names carol as its sender: %+v", sent.ID[:12], e)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.From != "" {
		t.Errorf("alice's answered entry %s is %+v; want it kept with no sender", sent.ID[:12], e)
	}
	if o := bob.ledgerOf(t).opener(sent.Thread); o != "" {
		t.Errorf("alice's thread has opener %q; want nobody", o)
	}

	worktrees := worktreesOf(t, bob)
	t.Setenv(handlerScript, "env")
	ask := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	bob.serve(t)

	var in inboxJSON
	decodeJSON(t, carol.run("inbox", "--json"), &in)
	for _, m := range in.Messages {
		if m.Type != "reply" || m.Thread != sent.Thread {
			continue
		}
		var full messageJSON
		decodeJSON(t, carol.run("read", m.ID, "--json"), &full)
		vars := envOf(t, full.Text)
		t.Errorf("carol was answered on alice's nobody's thread as turn %s in worktree %s", vars["AUU_TURN"], vars["AUU_WORKTREE"])
		for _, a := range full.Attachments {
			if a.Name == patchName(sent.Thread) {
				if p := readFile(t, patchOf(t, carol, full)); strings.Contains(p, "alice's private work") {
					t.Errorf("carol was sent alice's work as %s", a.Name)
				}
			}
		}
	}
	nothingFromBob(t, carol, bob)
	if after := worktreesOf(t, bob); !slices.Equal(after, worktrees) {
		t.Errorf("carol's ask made a worktree: before %v, after %v", worktrees, after)
	}
	if e, ok := bob.ledgerOf(t).Messages[ask.ID]; ok {
		t.Errorf("carol's ask was written into the ledger: %+v", e)
	}
}

// The honest case of the same upgrade: alice's message is still in bob's
// inbox, where serve left it answered, so it arrived before the thread's
// attempt. The first start after the upgrade gives alice's entry her
// fingerprint and says nothing about it, and her follow-up is answered as
// the thread's turn 2. Its record is rewritten in v0.17.0's keys, as the
// release that answered it kept it, so its arrival is lent from its
// received.
func TestACarriedOverThreadTakesItsOpenerFromItsOwnMessage(t *testing.T) {
	alice, _, bob := newExpertAndCarol(t, modeSideCopy)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)
	rewriteAsOlder(t, bob)
	asOlderRecord(t, bob, sent.ID)

	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("a round with nothing new took something: %+v", report)
	}
	if strings.Contains(stderr, notItsMessage) {
		t.Errorf("alice's own message was refused:\n%s", stderr)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.From != alice.fingerprint() || e.Arrived.IsZero() {
		t.Errorf("alice's carried-over entry is %+v; want it to name her, with her message's arrival", e)
	}

	alice.run("reply", first.ID[:12], "and one more thing")
	after, stderr := bob.roundSaid(t)
	if len(after.Answered) != 1 || after.Answered[0].Thread != sent.Thread {
		t.Fatalf("alice's follow-up was not answered: %+v\n%s", after, stderr)
	}
	if strings.Contains(stderr, notItsMessage) {
		t.Errorf("the follow-up's start refused a message:\n%s", stderr)
	}
	if line := "handler " + after.Answered[0].ID + " 2\n"; !strings.Contains(readFile(t, marker), line) {
		t.Errorf("alice's follow-up was not her turn 2; the handler ran:\n%s", readFile(t, marker))
	}
	if n := bob.ledgerOf(t).answered(sent.Thread); n != 2 {
		t.Errorf("alice's thread has %d turns answered, want 2", n)
	}
}

// A home a v0.17.0 serve kept its ledger in, whose mail this build has
// fetched: alice's message is still in the inbox, but its record has an
// arrival of its own, which on a thread tried before the upgrade says
// nothing about whether it was there when serve tried it (R9a). Each start
// says once that it is not taken and leaves the entry with no sender, so
// the thread is nobody's (D81): alice's follow-up is left alone, said once
// in each run, with no handler run and nothing sent.
func TestARecordThisReleaseFetchedDoesNotFillACarriedOverThread(t *testing.T) {
	alice, _, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)
	rewriteAsOlder(t, bob)
	m, err := storeOf(t, bob.user).Load(store.Inbox, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Arrived.Equal(m.Received) {
		t.Fatalf("alice's record reads its arrival as lent (%v); the case needs one of its own", m.Arrived)
	}

	notTaken := notItsMessageLine(sent.ID, sent.Thread, "alice")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("a round with nothing new took something: %+v", report)
	}
	if strings.Count(stderr, notTaken) != 1 || strings.Count(stderr, notItsMessage) != 1 {
		t.Errorf("the first start said:\n%s\nwant once:\n%s", stderr, notTaken)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.From != "" || !e.Arrived.IsZero() || e.RelayID != 0 {
		t.Errorf("alice's carried-over entry is %+v; want it kept with no sender", e)
	}
	if o := bob.ledgerOf(t).opener(sent.Thread); o != "" {
		t.Errorf("the thread has opener %q; want nobody", o)
	}

	var follow sentJSON
	decodeJSON(t, alice.run("reply", first.ID[:12], "--json", "and one more thing"), &follow)
	leftAlone := noOpenerLine(follow.ID, sent.Thread, "alice")
	for round := 1; round <= 2; round++ {
		report, stderr := bob.roundSaid(t)
		if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
			t.Errorf("round %d: alice's follow-up on a nobody's thread was taken: %+v", round, report)
		}
		if strings.Count(stderr, leftAlone) != 1 {
			t.Errorf("round %d said:\n%s\nwant once:\n%s", round, stderr, leftAlone)
		}
		if strings.Count(stderr, notTaken) != 1 {
			t.Errorf("round %d's start said:\n%s\nwant once:\n%s", round, stderr, notTaken)
		}
	}
	unreadAtBob(t, bob, follow.ID)
	if runs := readFile(t, marker); strings.Count(runs, "\n") != 1 || strings.Contains(runs, follow.ID) {
		t.Errorf("a handler ran for the follow-up:\n%s", runs)
	}
	led := bob.ledgerOf(t)
	if n := led.answered(sent.Thread); n != 1 {
		t.Errorf("the thread has %d turns answered, want 1", n)
	}
	if e, ok := led.Messages[follow.ID]; ok {
		t.Errorf("the follow-up was written into the ledger: %+v", e)
	}
	var in inboxJSON
	decodeJSON(t, alice.run("inbox", "--json"), &in)
	for _, m := range in.Messages {
		if m.ID != first.ID && m.From == bob.fingerprint() {
			t.Errorf("bob sent alice %s past her first answer: %+v", m.ID[:12], m)
		}
	}
}

// The edges of ownMessage, through fillSenders on a ledger and a store
// built here. The thread's last attempt is T, in whole seconds as serve
// writes it. A record this release saved has an arrival of its own, and on
// a thread tried or answered it is never the entry's message, even one
// that arrived before the attempt (R9a). A record v0.17.0 wrote has no
// arrival and Load lends its received, which is the relay's clock, judged
// by its second and allowed the skew: T + MaxSkew + 0.9s is taken, a
// second past T + MaxSkew is not. A record on another thread is never the
// entry's message, lent on a tried thread or saved on an untried one. The
// last attempt is the thread's, not the entry's: an entry with no attempt
// of its own, the kind a stream waiting for a newer auu leaves, on a
// thread answered at T does not take a lent record past T and the skew.
// And on a thread nothing was tried on, any record on it is taken whatever
// its arrival. Where a record is refused the line is said once and nothing
// is written; where it is taken nothing is said and the ledger on disk
// names its sender.
func TestOwnMessageEdges(t *testing.T) {
	T := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	thread := strings.Repeat("1", 32)
	other := strings.Repeat("9", 32)
	id := strings.Repeat("2", 32)
	answered := strings.Repeat("3", 32)
	carolFP := strings.Repeat("c", 64)
	bobFP := strings.Repeat("b", 64)

	// saved is a record this release saves: its own arrival, and a
	// received a minute before it, so the two are never equal.
	saved := func(onThread string, arrived time.Time) func(*testing.T, string, *store.Store) {
		return func(t *testing.T, _ string, s *store.Store) {
			t.Helper()
			m := &store.Stored{RelayID: 7, Relay: "relay", Received: arrived.Add(-time.Minute), Arrived: arrived,
				SenderName: "carol", Channel: "jostle", Inner: &envelope.Inner{
					V: envelope.Version, From: carolFP, To: bobFP, ID: id, Time: T.Add(-time.Hour),
					Body: message.Body{Type: message.TypeAsk, Thread: onThread, Subject: "a question", Text: "on the thread"},
				}}
			if err := s.Save(store.Inbox, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	// older is a record in v0.17.0's keys, with no arrived key, so that
	// Load lends it the received.
	older := func(onThread string, received time.Time) func(*testing.T, string, *store.Store) {
		return func(t *testing.T, root string, _ *store.Store) {
			t.Helper()
			record := `{
  "relay_id": 7,
  "relay": "relay",
  "received": "` + received.Format(time.RFC3339Nano) + `",
  "read": true,
  "inner": {
    "v": 1,
    "from": "` + carolFP + `",
    "from_bundle": null,
    "to": "` + bobFP + `",
    "id": "` + id + `",
    "time": "2026-01-01T00:00:00Z",
    "body": {"type": "ask", "thread": "` + onThread + `", "text": "from v0.17.0"}
  },
  "sender_name": "carol",
  "channel": "jostle"
}
`
			if strings.Contains(record, `"arrived"`) {
				t.Fatal("the older record has an arrived key")
			}
			if err := os.WriteFile(filepath.Join(root, "inbox", id+".json"), []byte(record), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	tried := func() map[string]*ledgerEntry {
		return map[string]*ledgerEntry{id: {Thread: thread, Channel: "jostle", Handled: T, Tried: T}}
	}
	untried := func() map[string]*ledgerEntry {
		return map[string]*ledgerEntry{id: {Thread: thread, Channel: "jostle", Failures: 0}}
	}
	// newer is a thread answered at T by another entry, whose own record
	// is gone, beside the entry under test with no attempt of its own.
	newer := func() map[string]*ledgerEntry {
		return map[string]*ledgerEntry{
			answered: {Thread: thread, Channel: "jostle", Handled: T, Tried: T},
			id:       {Thread: thread, Channel: "jostle", Newer: "x-made-up"},
		}
	}
	// handledLater is a thread whose entry was answered an hour after its
	// recorded attempt: the thread's last attempt is the answer, which
	// lastTried reads beside Tried, as tried does.
	handledLater := func() map[string]*ledgerEntry {
		return map[string]*ledgerEntry{id: {Thread: thread, Channel: "jostle", Handled: T.Add(time.Hour), Tried: T}}
	}
	for _, c := range []struct {
		name    string
		entries func() map[string]*ledgerEntry
		put     func(*testing.T, string, *store.Store)
		filled  bool
	}{
		{"saved an hour before the attempt", tried, saved(thread, T.Add(-time.Hour)), false},
		{"saved a second before the attempt", tried, saved(thread, T.Add(-time.Second)), false},
		{"saved in the attempt's second", tried, saved(thread, T.Add(900*time.Millisecond)), false},
		{"saved a second after the attempt", tried, saved(thread, T.Add(time.Second)), false},
		{"lent before the attempt", tried, older(thread, T.Add(-time.Second)), true},
		{"lent at the attempt", tried, older(thread, T), true},
		{"lent at the attempt and the skew", tried, older(thread, T.Add(relayapi.MaxSkew)), true},
		{"lent in the second of the attempt and the skew", tried, older(thread, T.Add(relayapi.MaxSkew+900*time.Millisecond)), true},
		{"lent a second past the skew", tried, older(thread, T.Add(relayapi.MaxSkew+time.Second)), false},
		{"lent on another thread, tried", tried, older(other, T.Add(-time.Hour)), false},
		{"saved on another thread, untried", untried, saved(other, T.Add(-time.Hour)), false},
		{"no attempt of its own, lent within the thread's", newer, older(thread, T.Add(relayapi.MaxSkew)), true},
		{"no attempt of its own, lent past the thread's", newer, older(thread, T.Add(relayapi.MaxSkew+time.Second)), false},
		{"answered after its attempt, lent within the answer and the skew", handledLater, older(thread, T.Add(time.Hour+relayapi.MaxSkew)), true},
		{"answered after its attempt, lent past the answer and the skew", handledLater, older(thread, T.Add(time.Hour+relayapi.MaxSkew+time.Second)), false},
		{"untried, a year ago", untried, saved(thread, T.AddDate(-1, 0, 0)), true},
		{"untried, a year ahead", untried, saved(thread, T.AddDate(1, 0, 0)), true},
		{"untried, lent a year ahead", untried, older(thread, T.AddDate(1, 0, 0)), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			s, err := store.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			c.put(t, root, s)
			m, err := s.Load(store.Inbox, id)
			if err != nil {
				t.Fatal(err)
			}
			ledgerPath := filepath.Join(t.TempDir(), ledgerFile)
			led := &ledger{V: ledgerV, Messages: c.entries(), path: ledgerPath}
			stderr := captureStderr(t, func() { err = fillSenders(s, led) })
			if err != nil {
				t.Fatal(err)
			}
			e := led.Messages[id]
			if !c.filled {
				if want := notItsMessageLine(id, e.Thread, "carol") + "\n"; stderr != want {
					t.Errorf("said:\n%q\nwant once:\n%q", stderr, want)
				}
				if e.From != "" || !e.Arrived.IsZero() || e.RelayID != 0 {
					t.Errorf("a record that is not the entry's message filled it: %+v", e)
				}
				if _, err := os.Stat(ledgerPath); !os.IsNotExist(err) {
					t.Errorf("the ledger was written for a refused record: %v", err)
				}
				return
			}
			if stderr != "" {
				t.Errorf("the entry's own message was said about:\n%s", stderr)
			}
			if e.From != carolFP || !e.Arrived.Equal(m.Arrived) || e.RelayID != 7 {
				t.Errorf("the entry is %+v; want it filled from its record arriving %v", e, m.Arrived)
			}
			disk, err := loadLedger(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if d := disk.Messages[id]; d == nil || d.From != carolFP {
				t.Errorf("the ledger on disk has %+v; want the sender written", d)
			}
		})
	}
}
