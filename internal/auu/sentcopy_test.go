package auu

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// An answered entry a v0.17.0 ledger carried over takes its asker from the
// copy of the reply serve sent, which this home wrote (R21, R21a), and the
// entries carried over open their thread in tiers on serve's own clock.

// olderInboxRecord writes a record into an inbox in v0.17.0's keys, with no
// arrived key, so that Load lends it the received.
func olderInboxRecord(t *testing.T, root, id, thread, from, to string, received time.Time) {
	t.Helper()
	record := `{
  "relay_id": 7,
  "relay": "relay",
  "received": "` + received.Format(time.RFC3339Nano) + `",
  "read": true,
  "inner": {
    "v": 1,
    "from": "` + from + `",
    "from_bundle": null,
    "to": "` + to + `",
    "id": "` + id + `",
    "time": "2026-01-01T00:00:00Z",
    "body": {"type": "ask", "thread": "` + thread + `", "text": "from v0.17.0"}
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

// The answered case of the upgrade with the asker's message gone: the
// owner removed alice's ask from the inbox, but the sent copy of serve's
// reply to her stands, and it names her. The first start gives her entry
// her fingerprint from it, marks it carried, takes the answer as its
// arrival and the reply's counter as its relay id, and says nothing; her
// follow-up is answered as the thread's turn 2.
func TestAnAnsweredCarriedOverThreadTakesItsAskerFromTheSentCopy(t *testing.T) {
	alice, _, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)
	reply, err := storeOf(t, bob.user).Load(store.Sent, replyOf(t, bob, sent.ID))
	if err != nil {
		t.Fatal(err)
	}
	if reply.RelayID == 0 {
		t.Fatalf("the sent copy has no relay id: %+v", reply)
	}
	rewriteAsOlder(t, bob)
	handled := bob.ledgerOf(t).Messages[sent.ID].Handled
	bob.run("rm", sent.ID)

	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("a round with nothing new took something: %+v", report)
	}
	if strings.Contains(stderr, notItsMessage) {
		t.Errorf("the start refused a record:\n%s", stderr)
	}
	e := bob.ledgerOf(t).Messages[sent.ID]
	if e == nil || e.From != alice.fingerprint() || !e.Carried || !e.Arrived.Equal(handled) || e.RelayID != reply.RelayID {
		t.Errorf("alice's carried-over entry is %+v; want her, carried, arriving at its answer %v, relay id %d", e, handled, reply.RelayID)
	}

	alice.run("reply", first.ID[:12], "and one more thing")
	after, stderr := bob.roundSaid(t)
	if len(after.Answered) != 1 || after.Answered[0].Thread != sent.Thread {
		t.Fatalf("alice's follow-up was not answered: %+v\n%s", after, stderr)
	}
	if strings.Contains(stderr, notItsMessage) {
		t.Errorf("the follow-up's start refused a record:\n%s", stderr)
	}
	if line := "handler " + after.Answered[0].ID + " 2\n"; !strings.Contains(readFile(t, marker), line) {
		t.Errorf("alice's follow-up was not her turn 2; the handler ran:\n%s", readFile(t, marker))
	}
}

// The residual 3dabff9 stated, closed (section 3a): carol's note under
// alice's id, fetched by v0.17.0 before the upgrade, so its arrival is
// lent from a received inside the thread's last attempt and the skew, on
// alice's answered thread, with alice's own message removed. Under the
// inbox rule alone it would fill alice's entry with carol. The sent copy
// of serve's reply names alice and is read first, so the entry is hers;
// carol's ask on the thread is left alone as another party's, and alice's
// follow-up is answered as turn 2.
func TestAPlantFetchedBeforeTheUpgradeDoesNotTakeAnAnsweredThread(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)
	replyOf(t, bob, sent.ID)
	rewriteAsOlder(t, bob)
	bob.run("rm", sent.ID)

	env := sealByHand(t, carol, bob.user, &envelope.Inner{V: envelope.Version,
		ID: sent.ID, Time: time.Now().UTC().Truncate(time.Second),
		Body:    message.Body{Type: message.TypeNote, Thread: sent.Thread, Subject: "fyi", Text: "nothing to see"},
		Channel: "jostle",
	})
	postByHand(t, carol, env, "jostle")
	bob.run("inbox", "--json") // the fetch, as v0.17.0 made it
	asOlderRecord(t, bob, sent.ID)
	if m, err := storeOf(t, bob.user).Load(store.Inbox, sent.ID); err != nil || m.Inner.From != carol.fingerprint() {
		t.Fatalf("the planted record is %+v (%v); want carol's", m, err)
	}

	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("a round with nothing new took something: %+v", report)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.From != alice.fingerprint() || !e.Carried {
		t.Errorf("alice's answered entry is %+v; want alice from the sent copy, carried, and not carol (%s)", e, carol.fingerprint()[:16])
	}
	if strings.Contains(stderr, notItsMessage) {
		t.Errorf("the start said:\n%s", stderr)
	}

	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	report, stderr = bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("carol's ask on alice's thread was taken: %+v", report)
	}
	if want := leftAlone(hijack, "carol", alice.fingerprint()); strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	nothingFromBob(t, carol, bob)
	if runs := readFile(t, marker); strings.Contains(runs, hijack.ID) || strings.Count(runs, "\n") != 1 {
		t.Errorf("a handler ran for carol's message:\n%s", runs)
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

// fromSentCopy takes Inner.To as the asker because serve resolves the
// message's verified sender alone and sends it one copy (R21a). This pins
// that on both ways serve sends: an inline reply, and a reply whose patch
// is over the stream threshold and goes as a stream. Each sent record has
// no Copies and is addressed to the asker.
func TestServesSentCopyHasNoCopies(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	for _, c := range []struct {
		name, script string
		streamed     bool
	}{
		{"inline", "echo:the answer", false},
		{"a patch as a stream", "write:big.txt=" + strings.Repeat("x", 80<<10) + ";echo:the change is attached", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(handlerScript, c.script)
			sent := alice.ask(t, "jostle", c.name, "please")
			report := bob.round(t)
			if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
				t.Fatalf("not answered: %+v", report)
			}
			m, err := storeOf(t, bob.user).Load(store.Sent, replyOf(t, bob, sent.ID))
			if err != nil {
				t.Fatal(err)
			}
			if m.Streamed != c.streamed {
				t.Fatalf("the reply went streamed=%v; the case needs %v", m.Streamed, c.streamed)
			}
			if len(m.Copies) != 0 || m.Inner.To != alice.fingerprint() {
				t.Errorf("serve's sent copy has %d copies and is to %s; want none, to alice %s", len(m.Copies), m.Inner.To, alice.fingerprint())
			}
		})
	}
}

// A sent copy that does not read as one of serve's fills nothing, and the
// entry falls to its inbox record (R21): one gone, one with Copies (a
// message to several, which serve never sends), and one whose to is not a
// fingerprint, which does not load. A sent copy that does read fills the
// entry with its to, the answer as its arrival and its own relay id, and
// the inbox record under the id is not read. The inbox record here is
// carol's, lent and within the attempt and the skew, so the inbox rule
// takes it, with serve's clock as its arrival.
func TestASentCopyThatIsNotServesFallsToTheInbox(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	var many sentManyJSON
	decodeJSON(t, bob.run("send", "--to", "alice,carol", "--json", "to several"), &many)
	if m, err := storeOf(t, bob.user).Load(store.Sent, many.ID); err != nil || len(m.Copies) != 2 {
		t.Fatalf("the message to several is %+v (%v); the case needs its copies", m, err)
	}

	T := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	thread := strings.Repeat("1", 32)
	id := strings.Repeat("2", 32)
	notTo := strings.Repeat("3", 32)
	single := strings.Repeat("4", 32)
	gone := strings.Repeat("5", 32)
	s := storeOf(t, bob.user)
	badTo := `{
  "relay_id": 9,
  "relay": "relay",
  "received": "` + T.Format(time.RFC3339) + `",
  "arrived": "` + T.Format(time.RFC3339) + `",
  "read": true,
  "inner": {
    "v": 1,
    "from": "` + bob.fingerprint() + `",
    "from_bundle": null,
    "to": "not a fingerprint",
    "id": "` + notTo + `",
    "time": "` + T.Format(time.RFC3339) + `",
    "body": {"type": "reply", "thread": "` + thread + `", "in_reply_to": "` + id + `", "text": "an answer"}
  },
  "sender_name": "alice",
  "channel": "jostle"
}
`
	if err := os.WriteFile(filepath.Join(bob.home, "sent", notTo+".json"), []byte(badTo), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(store.Sent, notTo); err == nil {
		t.Fatal("a sent record to no fingerprint loads; the case needs one that does not")
	}
	if err := s.Save(store.Sent, &store.Stored{RelayID: 42, Relay: "relay", Received: T, Read: true, SenderName: "alice",
		Channel: "jostle", Inner: &envelope.Inner{V: envelope.Version, From: bob.fingerprint(), To: alice.fingerprint(),
			ID: single, Time: T, Body: message.Body{Type: message.TypeReply, Thread: thread, InReplyTo: id, Text: "an answer"}}}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, reply string
		from        string
		relayID     int64
	}{
		{"gone", gone, carol.fingerprint(), 7},
		{"to several", many.ID, carol.fingerprint(), 7},
		{"to no fingerprint", notTo, carol.fingerprint(), 7},
		{"serve's", single, alice.fingerprint(), 42},
	} {
		t.Run(c.name, func(t *testing.T) {
			olderInboxRecord(t, bob.home, id, thread, carol.fingerprint(), bob.fingerprint(), T.Add(relayapi.MaxSkew))
			led := &ledger{V: ledgerV, path: filepath.Join(t.TempDir(), ledgerFile), Messages: map[string]*ledgerEntry{
				id: {Thread: thread, Channel: "jostle", Handled: T, Tried: T, Reply: c.reply},
			}}
			var err error
			stderr := captureStderr(t, func() { err = fillSenders(s, led) })
			if err != nil {
				t.Fatal(err)
			}
			if stderr != "" {
				t.Errorf("said:\n%s", stderr)
			}
			if e := led.Messages[id]; e.From != c.from || !e.Carried || !e.Arrived.Equal(T) || e.RelayID != c.relayID {
				t.Errorf("the entry is %+v; want from %s, carried, arriving %v, relay id %d", e, c.from[:16], T, c.relayID)
			}
		})
	}
}

// The tiers openerEntry reads a thread's opener in (R21). Times are
// serve's clock for a carried entry it tried, which fillSenders wrote as
// its Arrived; a carried pending entry keeps its record's arrival. A
// carried tier that names two senders says who opened the thread only
// when no carried tried entry on it failed (R21b) and no two tier entries
// share a second (R21c); otherwise the thread has no opener. A tier of one
// sender is that sender's whatever its failures or ties. Among entries
// this release wrote, the relay id still breaks a tie of arrival.
func TestTheCarriedOverOpenerIsReadInTiers(t *testing.T) {
	day := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return day.Add(time.Duration(h) * time.Hour) }
	thread := strings.Repeat("1", 32)
	alice, carol := strings.Repeat("a", 64), strings.Repeat("c", 64)
	answered := func(from string, h int, relayID int64) *ledgerEntry {
		return &ledgerEntry{Thread: thread, Channel: "jostle", Handled: at(h), Tried: at(h), From: from,
			Arrived: at(h), RelayID: relayID, Carried: true}
	}
	// answeredAt is a carried answered entry at a given time, with the
	// failures it took before its answer.
	answeredAt := func(from string, when time.Time, relayID int64, failures int) *ledgerEntry {
		return &ledgerEntry{Thread: thread, Channel: "jostle", Handled: when, Tried: when, From: from,
			Arrived: when, RelayID: relayID, Carried: true, Failures: failures}
	}
	// ours is an entry this release wrote: not carried, its real arrival.
	ours := func(from string, when time.Time, relayID int64) *ledgerEntry {
		return &ledgerEntry{Thread: thread, Channel: "jostle", Handled: when, Tried: when, From: from,
			Arrived: when, RelayID: relayID}
	}
	tenPast := func(m, sec int) time.Time {
		return at(10).Add(time.Duration(m)*time.Minute + time.Duration(sec)*time.Second)
	}
	pending := func(from string, h int) *ledgerEntry {
		return &ledgerEntry{Thread: thread, Channel: "jostle", From: from, Arrived: at(h), RelayID: 3, Carried: true}
	}
	// Ids chosen so that the id string, the last tie-break, would pick the
	// other entry wherever it is the one under test.
	idA, idC := strings.Repeat("f", 32), strings.Repeat("0", 32)
	for _, c := range []struct {
		name    string
		entries map[string]*ledgerEntry
		want    string // the opener's fingerprint, "" for none
	}{
		{"an answered entry before a pending one that arrived earlier",
			map[string]*ledgerEntry{idA: answered(alice, 12, 9), idC: pending(carol, 11)}, alice},
		{"two answered, by serve's clock",
			map[string]*ledgerEntry{idA: answered(carol, 10, 9), idC: answered(alice, 12, 1)}, carol},
		{"R21c: two senders answered in one second, the stranger first by relay id and id",
			map[string]*ledgerEntry{idA: answered(alice, 12, 6), idC: answered(carol, 12, 5)}, ""},
		{"R21c: one sender answered twice in one second",
			map[string]*ledgerEntry{idA: answered(alice, 12, 6), idC: answered(alice, 12, 5)}, alice},
		{"R21c: two senders a second apart",
			map[string]*ledgerEntry{idA: answered(alice, 12, 6), idC: answeredAt(carol, at(12).Add(time.Second), 5, 0)}, alice},
		{"R21b a: the later sender's entry failed first",
			map[string]*ledgerEntry{idA: answeredAt(alice, tenPast(5, 0), 9, 1), idC: answeredAt(carol, tenPast(0, 30), 1, 0)}, ""},
		{"R21b b: no failure, alice first",
			map[string]*ledgerEntry{idA: answeredAt(alice, tenPast(0, 0), 9, 0), idC: answeredAt(carol, tenPast(5, 0), 1, 0)}, alice},
		{"R21b c: one sender, one of her entries failed",
			map[string]*ledgerEntry{idA: answeredAt(alice, tenPast(0, 0), 9, 2), idC: answeredAt(alice, tenPast(5, 0), 1, 0)}, alice},
		{"R21b d: two senders, the failure on carol's",
			map[string]*ledgerEntry{idA: answeredAt(alice, tenPast(0, 0), 9, 0), idC: answeredAt(carol, tenPast(5, 0), 1, 2)}, ""},
		// R21b reads the failures of every carried tried entry, filled or
		// not: an unfilled one, its sent copy and record both gone, whose
		// attempt failed loses the tier's order whoever sent it.
		{"R21b: two senders in order, and an unfilled carried entry that failed",
			map[string]*ledgerEntry{
				idA:                     answeredAt(alice, tenPast(0, 0), 9, 0),
				idC:                     answeredAt(carol, tenPast(5, 0), 1, 0),
				strings.Repeat("5", 32): {Thread: thread, Channel: "jostle", Handled: tenPast(7, 0), Tried: tenPast(7, 0), Failures: 1},
			}, ""},
		{"R21b: two senders in order, and an unfilled carried entry that did not fail",
			map[string]*ledgerEntry{
				idA:                     answeredAt(alice, tenPast(0, 0), 9, 0),
				idC:                     answeredAt(carol, tenPast(5, 0), 1, 0),
				strings.Repeat("5", 32): {Thread: thread, Channel: "jostle", Handled: tenPast(7, 0), Tried: tenPast(7, 0)},
			}, alice},
		{"this release's entries in one arrival, by relay id",
			map[string]*ledgerEntry{idA: ours(alice, at(12), 5), idC: ours(carol, at(12), 6)}, alice},
		{"an unfilled answered entry beside a pending one",
			map[string]*ledgerEntry{idA: {Thread: thread, Channel: "jostle", Tried: at(12)}, idC: pending(carol, 11)}, ""},
		{"nothing carried and tried: the earliest arrival",
			map[string]*ledgerEntry{
				idA: {Thread: thread, Channel: "jostle", Handled: at(12), Tried: at(12), From: alice, Arrived: at(12), RelayID: 1},
				idC: pending(carol, 11),
			}, carol},
		{"this release's tried entry after a carried tried one",
			map[string]*ledgerEntry{
				idC: {Thread: thread, Channel: "jostle", Handled: at(13), Tried: at(13), From: alice, Arrived: at(9), RelayID: 1},
				idA: answered(carol, 12, 9),
			}, carol},
	} {
		t.Run(c.name, func(t *testing.T) {
			led := &ledger{V: ledgerV, Messages: c.entries}
			_, e := led.openerEntry(thread)
			got := ""
			if e != nil {
				got = e.From
			}
			if got != c.want {
				t.Errorf("the opener is %q; want %q", got, c.want)
			}
			if o := led.opener(thread); o != c.want {
				t.Errorf("opener says %q; want %q", o, c.want)
			}
		})
	}
}

// twoSendersCarried builds, through real serve runs, a thread a v0.17.0
// ledger carried over with two senders answered on it: carol asks on a
// thread of her own and is answered first, then alice asks and is answered,
// after one failed attempt when failAlice is set. No build answers two
// senders on one thread, which is what v0.17.0 did, so carol's entry is
// then moved onto alice's thread in the ledger and answered carolBefore
// alice's answer; the sent copies of both replies stay, so the next start
// fills both entries from them. It gives alice's thread.
func twoSendersCarried(t *testing.T, failAlice bool, carolBefore time.Duration) (alice, carol *user, bob *expert, thread, marker string) {
	t.Helper()
	alice, carol, bob = newExpertAndCarol(t, modeSideCopy)
	marker = filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	cs := carol.ask(t, "jostle", "carol's question", "on a thread of her own")
	if r := bob.round(t); len(r.Answered) != 1 {
		t.Fatalf("carol's ask was not answered: %+v", r)
	}
	as := alice.ask(t, "jostle", "alice's question", "the first")
	if failAlice {
		t.Setenv(handlerScript, "append:"+marker+";say:not now;exit:1")
		out, err := bob.tryRun("serve", "--once", "--json")
		var r roundJSON
		decodeJSON(t, out, &r)
		if err == nil || len(r.Failed) != 1 || r.Failed[0].ID != as.ID {
			t.Fatalf("alice's first attempt did not fail: %v %+v", err, r)
		}
		t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	}
	if r := bob.round(t); len(r.Answered) != 1 || r.Answered[0].ID != as.ID {
		t.Fatalf("alice's ask was not answered: %+v", r)
	}
	replyOf(t, bob, cs.ID)
	replyOf(t, bob, as.ID)
	led := bob.ledgerOf(t)
	a, c := led.Messages[as.ID], led.Messages[cs.ID]
	if want := map[bool]int{true: 1, false: 0}[failAlice]; a.Failures != want || c.Failures != 0 {
		t.Fatalf("alice's entry has %d failures and carol's %d; want %d and 0", a.Failures, c.Failures, want)
	}
	c.Thread = a.Thread
	c.Handled = a.Handled.Add(-carolBefore)
	c.Tried = c.Handled
	if err := led.save(); err != nil {
		t.Fatal(err)
	}
	rewriteAsOlder(t, bob)
	return alice, carol, bob, a.Thread, marker
}

// worktreeTimes is each worktree's name and modification time.
func worktreeTimes(t *testing.T, bob *expert) map[string]time.Time {
	t.Helper()
	dir := filepath.Join(bob.home, "serve", "worktrees")
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out := map[string]time.Time{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = info.ModTime()
	}
	return out
}

// fromBob counts what u holds from bob.
func fromBob(t *testing.T, u *user, bob *expert) int {
	t.Helper()
	var in inboxJSON
	decodeJSON(t, u.run("inbox", "--json"), &in)
	n := 0
	for _, m := range in.Messages {
		if m.From == bob.fingerprint() {
			n++
		}
	}
	return n
}

// carriedThreadIsNobodys asks on the thread as alice and as carol and
// fails the test unless the next start fills both carried entries from
// their sent copies, gives the thread no opener, and leaves both asks
// alone with D81's line once each: no handler run, no worktree touched,
// nothing sent and no ledger entry.
func carriedThreadIsNobodys(t *testing.T, alice, carol *user, bob *expert, thread, marker string) {
	t.Helper()
	runs := readFile(t, marker)
	worktrees := worktreeTimes(t, bob)
	toAlice, toCarol := fromBob(t, alice, bob), fromBob(t, carol, bob)
	af := alice.askOn(t, "jostle", thread, "alice again", "and one more thing")
	cf := carol.askOn(t, "jostle", thread, "carol again", "and me?")

	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Errorf("an ask on a thread of unknown order was taken: %+v", report)
	}
	for _, c := range []struct {
		m    sentJSON
		name string
	}{{af, "alice"}, {cf, "carol"}} {
		if want := noOpenerLine(c.m.ID, thread, c.name); strings.Count(stderr, want) != 1 {
			t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
		}
	}
	led := bob.ledgerOf(t)
	senders := map[string]bool{}
	for _, e := range led.Messages {
		if e.Thread == thread && e.Carried {
			senders[e.From] = true
		}
	}
	if !senders[alice.fingerprint()] || !senders[carol.fingerprint()] || len(senders) != 2 {
		t.Errorf("the carried entries on the thread name %v; want alice and carol, filled from their sent copies", senders)
	}
	if o := led.opener(thread); o != "" {
		t.Errorf("the thread has opener %q; want nobody", o)
	}
	for _, id := range []string{af.ID, cf.ID} {
		if e, ok := led.Messages[id]; ok {
			t.Errorf("%s was written into the ledger: %+v", id[:12], e)
		}
	}
	if after := readFile(t, marker); after != runs {
		t.Errorf("a handler ran:\n%s", after)
	}
	if after := worktreeTimes(t, bob); !maps.Equal(after, worktrees) {
		t.Errorf("a worktree was touched: before %v, after %v", worktrees, after)
	}
	if a, c := fromBob(t, alice, bob), fromBob(t, carol, bob); a != toAlice || c != toCarol {
		t.Errorf("bob sent alice %d and carol %d more", a-toAlice, c-toCarol)
	}
}

// R21b end to end: alice's ask failed once before it was answered, and
// carol's, on the same thread, was answered four and a half minutes before
// alice's answer at the first attempt. Under v0.17.0 alice's ask may have
// arrived first and waited out its failure while carol's was answered, so
// serve's clock does not say who opened the thread: it has no opener, and
// both senders' follow-ups are left alone. The failure is driven through
// real serve runs; carol's entry is moved onto the thread in the ledger.
func TestACarriedThreadWithAFailureAndTwoSendersIsNobodys(t *testing.T) {
	alice, carol, bob, thread, marker := twoSendersCarried(t, true, 4*time.Minute+30*time.Second)
	carriedThreadIsNobodys(t, alice, carol, bob, thread, marker)
}

// R21c end to end: carol's and alice's entries on one thread were answered
// in the same second, carol's first, so her reply's relay id, the next
// tie-break, sorts first. A second does not say who asked first: the
// thread has no opener, and both senders' follow-ups are left alone.
func TestACarriedThreadWithTwoSendersInOneSecondIsNobodys(t *testing.T) {
	alice, carol, bob, thread, marker := twoSendersCarried(t, false, 0)
	carriedThreadIsNobodys(t, alice, carol, bob, thread, marker)
}
