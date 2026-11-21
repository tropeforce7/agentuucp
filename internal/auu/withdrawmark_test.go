package auu

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// sealedNote is a withdrawal note from one identity to another, sealed by
// envelope.SealWithdrawal as auu withdraw seals one, naming the message id
// on its thread.
func sealedNote(t *testing.T, from *identity.Identity, to *identity.Public, thread, id, reason string) (raw []byte, noteID string) {
	t.Helper()
	env, inner, err := envelope.SealWithdrawal(from, to, "", thread, id, reason)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw, inner.ID
}

// identityOf is a user's own identity, from their home.
func identityOf(u *user) *identity.Identity {
	_, id, _ := u.opened()
	return id
}

// deliver puts a sealed envelope straight into a mailbox on the relay, as
// a post that passed every rule would leave it.
func deliver(t *testing.T, st *relay.Store, to *user, raw []byte) {
	t.Helper()
	if _, err := st.Put(to.exportFingerprint(), "default", relayapi.KindEnvelope, "", "", raw, relay.Quotas{}, relay.Forwarded{}); err != nil {
		t.Fatal(err)
	}
}

// withStderr runs a command for a user and answers its standard output and
// what it wrote to standard error.
func withStderr(u *user, args ...string) (stdout, stderr string) {
	u.t.Helper()
	real := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		u.t.Fatal(err)
	}
	read := make(chan []byte)
	go func() {
		data, _ := io.ReadAll(r)
		read <- data
	}()
	os.Stderr = w
	stdout = u.run(args...)
	w.Close()
	os.Stderr = real
	return stdout, string(<-read)
}

// The mark, in the two cases where the recipient has the message: fetched
// and kept on the relay, and fetched and acknowledged away. The note from
// the message's own sender marks it: this machine's time, the note's id and
// the reason, and nothing else about it changes, its text, read, on_relay
// and an acknowledgement owed among them. The note is filed as a note. The
// inbox line says withdrawn, read says so above the message with the
// reason, and --json carries the three keys. A second note for the same
// message changes nothing (R146 P5).
func TestAWithdrawalNoteMarksItsMessage(t *testing.T) {
	for _, keep := range []bool{true, false} {
		name := "kept"
		if !keep {
			name = "acknowledged"
		}
		t.Run(name, func(t *testing.T) {
			r := startResettable(t)
			alice, bob := watchers(t, r.url)
			if !keep {
				bob.run("channel", "keep", "default", "off")
			}
			alice.run("send", "--to", "bob", "--subject", "oops", "the wrong text")
			bob.run("inbox")
			orig := recordOf(t, bob, store.Inbox, "oops")
			bob.run("read", orig.Inner.ID[:12])
			before := bob.stored(store.Inbox, orig.Inner.ID)

			raw, noteID := sealedNote(t, identityOf(alice), identityOf(bob).Public(), orig.Inner.Body.Thread, orig.Inner.ID, "sent to the wrong person")
			deliver(t, r.st, bob, raw)
			out := bob.run("inbox")

			m := bob.stored(store.Inbox, orig.Inner.ID)
			if m.Withdrawn.IsZero() || m.WithdrawnBy != noteID || m.WithdrawnReason != "sent to the wrong person" {
				t.Fatalf("the original after the note: withdrawn %v by %q reason %q", m.Withdrawn, m.WithdrawnBy, m.WithdrawnReason)
			}
			if time.Since(m.Withdrawn) > time.Minute || m.Withdrawn.After(time.Now()) {
				t.Errorf("the mark's time %v is not this machine's now", m.Withdrawn)
			}
			if m.Inner.Body.Text != before.Inner.Body.Text || m.Read != before.Read || m.OnRelay != before.OnRelay ||
				m.AckOwed != before.AckOwed || !m.Arrived.Equal(before.Arrived) {
				t.Errorf("the mark changed more than the mark: before %+v after %+v", before, m)
			}
			note := bob.stored(store.Inbox, noteID)
			if note.Inner.Body.Type != message.TypeNote || note.Inner.Body.InReplyTo != orig.Inner.ID {
				t.Errorf("the note was filed as %+v", note.Inner.Body)
			}
			// The mark is the line's last word; the note's own subject is
			// "withdrawn", in its subject column, and it is not marked.
			line := firstLineWith(out, orig.Inner.ID[:12])
			if !strings.HasSuffix(line, "  withdrawn") {
				t.Errorf("the inbox line %q does not end saying withdrawn", line)
			}
			if strings.HasSuffix(firstLineWith(out, noteID[:12]), "  withdrawn") {
				t.Errorf("the note's own line ends saying withdrawn")
			}
			read := bob.run("read", orig.Inner.ID[:12])
			if first := strings.SplitN(read, "\n", 2)[0]; !strings.HasPrefix(first, "!! WITHDRAWN by its sender on ") ||
				!strings.HasSuffix(first, ": sent to the wrong person") {
				t.Errorf("read begins %q; want the withdrawal and its reason", first)
			}
			var js messageJSON
			if err := json.Unmarshal([]byte(bob.run("read", orig.Inner.ID[:12], "--json")), &js); err != nil {
				t.Fatal(err)
			}
			if js.Withdrawn.IsZero() || js.WithdrawnBy != noteID || js.WithdrawnReason != "sent to the wrong person" {
				t.Errorf("read --json: %+v", js)
			}

			// A second note for it, from the same sender, changes nothing.
			again, _ := sealedNote(t, identityOf(alice), identityOf(bob).Public(), orig.Inner.Body.Thread, orig.Inner.ID, "and again")
			deliver(t, r.st, bob, again)
			bob.run("inbox")
			if after := bob.stored(store.Inbox, orig.Inner.ID); !after.Withdrawn.Equal(m.Withdrawn) || after.WithdrawnBy != noteID ||
				after.WithdrawnReason != "sent to the wrong person" {
				t.Errorf("a second note changed the mark: %+v", after)
			}
		})
	}
}

// firstLineWith is the first line of out that holds s.
func firstLineWith(out, s string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, s) {
			return l
		}
	}
	return ""
}

// A message never fetched is never seen: its note arrives alone and is
// filed as any note, marking nothing. And --json leaves the three keys out
// of a message nobody withdrew.
func TestANoteForAMessageNotHeldMarksNothing(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	missing := strings.Repeat("7", 32)
	raw, noteID := sealedNote(t, identityOf(alice), identityOf(bob).Public(), strings.Repeat("8", 32), missing, "")
	deliver(t, r.st, bob, raw)
	out := bob.run("inbox", "--json")
	if strings.Contains(out, `"withdrawn":`) || strings.Contains(out, `"withdrawn_by"`) || strings.Contains(out, `"withdrawn_reason"`) {
		t.Errorf("the inbox's JSON names a withdrawal: %s", out)
	}
	if note := bob.stored(store.Inbox, noteID); note.Inner.Body.Type != message.TypeNote {
		t.Fatalf("the note was not filed: %+v", note)
	}
	s, _, _ := bob.opened()
	if m, err := s.Holding(store.Inbox, missing); err != nil || m != nil {
		t.Fatalf("a record for the missing message: %+v %v", m, err)
	}
}

// A note naming a message somebody else sent marks nothing and is said once,
// naming the note and never its reason: carol, another of bob's peers,
// sends a note for alice's message. A note naming a message bob sent and
// did not receive marks nothing either, even bob's own, the sent box not
// being looked in.
func TestANoteFromAnotherSenderMarksNothing(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	carol := newUser(t, "carol", r.url)
	bob.run("peers", "add", carol.exportLine())
	carol.run("peers", "add", bob.exportLine())
	alice.run("send", "--to", "bob", "--subject", "alice's", "x")
	bob.run("inbox")
	orig := recordOf(t, bob, store.Inbox, "alice's")

	raw, noteID := sealedNote(t, identityOf(carol), identityOf(bob).Public(), orig.Inner.Body.Thread, orig.Inner.ID, "a secret reason")
	deliver(t, r.st, bob, raw)
	_, stderr := withStderr(bob, "inbox")
	if m := bob.stored(store.Inbox, orig.Inner.ID); !m.Withdrawn.IsZero() {
		t.Fatalf("carol's note marked alice's message: %+v", m)
	}
	if n := strings.Count(stderr, noteID[:12]+": a withdrawal note names a message it was not signed by the sender of; nothing was marked"); n != 1 {
		t.Errorf("the note was said %d times; want once:\n%s", n, stderr)
	}
	if strings.Contains(stderr, "a secret reason") {
		t.Errorf("the refusal shows the note's reason:\n%s", stderr)
	}

	// Bob's own note, sealed to himself, naming a message he sent alice:
	// the sender is the message's own, and still nothing is marked, the
	// sent box being the withdrawal command's and never the mark's.
	bob.run("send", "--to", "alice", "--subject", "bob's", "y")
	sent := recordOf(t, bob, store.Sent, "bob's")
	raw, _ = sealedNote(t, identityOf(bob), identityOf(bob).Public(), sent.Inner.Body.Thread, sent.Inner.ID, "")
	deliver(t, r.st, bob, raw)
	bob.run("inbox")
	if m := bob.stored(store.Sent, sent.Inner.ID); !m.Withdrawn.IsZero() {
		t.Fatalf("a note marked a message bob sent: %+v", m)
	}
}

// The original in the quarantine: a stranger's message and the stranger's
// own note for it, both quarantined, the original marked; and listed so.
func TestAWithdrawalNoteMarksAQuarantinedMessage(t *testing.T) {
	r := startResettable(t)
	_, bob := watchers(t, r.url)
	mallory := newUser(t, "mallory", r.url)
	m := identityOf(mallory)
	bobPub := identityOf(bob).Public()
	body := message.Body{Type: message.TypeAsk, Subject: "hello", Thread: strings.Repeat("9", 32), Text: "x"}
	env, inner, err := envelope.Seal(m, bobPub, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, r.st, bob, raw)
	bob.run("inbox")
	note, noteID := sealedNote(t, m, bobPub, body.Thread, inner.ID, "")
	deliver(t, r.st, bob, note)
	bob.run("inbox")
	got := bob.stored(store.Quarantine, inner.ID)
	if got.Withdrawn.IsZero() || got.WithdrawnBy != noteID {
		t.Fatalf("the quarantined original: %+v", got)
	}
	if line := firstLineWith(bob.run("quarantine", "ls"), inner.ID[:12]); !strings.HasSuffix(line, "  withdrawn") {
		t.Errorf("the quarantine line %q does not say withdrawn", line)
	}
}

// The sender removed from the peers between the message and its note: the
// mark is admitted by the original's verified sender, not by the peer list,
// so the note, now a stranger's and quarantined, still marks the message in
// the inbox that sender signed, which is the mark handle and serve read
// (withdrawjobs_test.go holds them to it). A withdrawal only ever takes an
// ask away from the one who sent it.
func TestANoteFromASenderNoLongerAPeerStillMarksTheirMessage(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	alice.run("send", "--to", "bob", "--subject", "oops", "the wrong text")
	bob.run("inbox")
	orig := recordOf(t, bob, store.Inbox, "oops")
	bob.run("peers", "rm", "alice")

	raw, noteID := sealedNote(t, identityOf(alice), identityOf(bob).Public(), orig.Inner.Body.Thread, orig.Inner.ID, "")
	deliver(t, r.st, bob, raw)
	bob.run("inbox")
	if note := bob.stored(store.Quarantine, noteID); note == nil {
		t.Fatal("the note from a sender no longer a peer was not quarantined")
	}
	if m := bob.stored(store.Inbox, orig.Inner.ID); m.Withdrawn.IsZero() || m.WithdrawnBy != noteID {
		t.Fatalf("the original after its sender's note: withdrawn %v by %q", m.Withdrawn, m.WithdrawnBy)
	}
}

// What the mark acts on, beyond what a fetch shows: nothing for a note on a
// stream's record, nothing for a record whose section breaks the rule (as a
// release before v0.22.0 could have kept one, R150), nothing for a record
// with no section; and it marks the message once.
func TestTheMarkActsOnlyOnANoteThatPassesItsRule(t *testing.T) {
	home := t.TempDir()
	s, err := store.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	from := strings.Repeat("a", 64)
	orig := &store.Stored{Relay: "relay", Received: time.Now().UTC().Truncate(time.Second), Inner: &envelope.Inner{
		ID: strings.Repeat("1", 32), From: from, To: strings.Repeat("b", 64),
		Body: message.Body{Type: message.TypeAsk, Thread: strings.Repeat("3", 32), Text: "x"}}}
	if err := s.Save(store.Inbox, orig); err != nil {
		t.Fatal(err)
	}
	noteOf := func(sections []wire.Section, body message.Body, streamed bool) *store.Stored {
		return &store.Stored{Relay: "relay", Streamed: streamed, Inner: &envelope.Inner{
			ID: strings.Repeat("2", 32), From: from, To: strings.Repeat("b", 64), Body: body, Sections: sections}}
	}
	good, err := withdraw.Section(orig.Inner.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	body := withdraw.NoteBody(orig.Inner.Body.Thread, orig.Inner.ID, "")
	ask := body
	ask.Type = message.TypeAsk
	for _, c := range []struct {
		name string
		note *store.Stored
	}{
		{"a stream's record", noteOf([]wire.Section{good}, body, true)},
		{"a section on an ask", noteOf([]wire.Section{good}, ask, false)},
		{"a section with foreign data", noteOf([]wire.Section{{Name: withdraw.SectionName, Data: json.RawMessage(`{"x":1}`)}}, body, false)},
		{"no section", noteOf(nil, body, false)},
	} {
		if err := markWithdrawn(s, c.note); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if m, err := s.Load(store.Inbox, orig.Inner.ID); err != nil || !m.Withdrawn.IsZero() {
			t.Fatalf("%s marked the message: %+v %v", c.name, m, err)
		}
	}
	if err := markWithdrawn(s, noteOf([]wire.Section{good}, body, false)); err != nil {
		t.Fatal(err)
	}
	if m, err := s.Load(store.Inbox, orig.Inner.ID); err != nil || m.WithdrawnBy != strings.Repeat("2", 32) {
		t.Fatalf("a good note: %+v %v", m, err)
	}
}

// A record rebuilt from the wire keeps the mark the record it replaces
// carries (R146 P11): a quarantined stream marked withdrawn and then saved
// again by waitingStream, as a fetch that meets it again saves it, keeps its
// mark.
func TestARebuiltStreamRecordKeepsItsMark(t *testing.T) {
	home := t.TempDir()
	s, err := store.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	from, to := strings.Repeat("a", 64), strings.Repeat("b", 64)
	id := strings.Repeat("4", 32)
	mf := &stream.Manifest{V: stream.Version, ID: id, From: from, To: to, Time: time.Now().UTC().Truncate(time.Second),
		Body: stream.Body{Type: message.TypeAsk, Thread: strings.Repeat("5", 32), Text: "x"}}
	r := &store.Relay{Name: "relay"}
	listed := relayCopy{ID: 7, Received: time.Now().UTC().Truncate(time.Second), Size: 100}
	if err := waitingStream(s, store.Quarantine, r, listed, &stream.Opened{Manifest: mf}, ""); err != nil {
		t.Fatal(err)
	}
	m, err := s.Load(store.Quarantine, id)
	if err != nil {
		t.Fatal(err)
	}
	m.Withdrawn, m.WithdrawnBy, m.WithdrawnReason = time.Now().UTC().Truncate(time.Second), strings.Repeat("6", 32), "gone"
	if err := s.Save(store.Quarantine, m); err != nil {
		t.Fatal(err)
	}
	if err := waitingStream(s, store.Quarantine, r, listed, &stream.Opened{Manifest: mf}, ""); err != nil {
		t.Fatal(err)
	}
	again, err := s.Load(store.Quarantine, id)
	if err != nil || !again.Withdrawn.Equal(m.Withdrawn) || again.WithdrawnBy != m.WithdrawnBy || again.WithdrawnReason != "gone" {
		t.Fatalf("the record saved again: %+v %v; want its mark kept", again, err)
	}
}

// A reason saved by hand with an escape in it reaches no terminal: Load
// refuses the record by name, so the inbox and the quarantine leave it out
// with a warning and read refuses it, none of them printing the byte.
func TestAReasonWrittenByHandReachesNoTerminal(t *testing.T) {
	r := startResettable(t)
	_, bob := watchers(t, r.url)
	s, _, _ := bob.opened()
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		id := strings.Repeat("c", 31) + string("12"[len(box)%2])
		m := &store.Stored{Relay: bob.defaultRelayName(), Received: time.Now().UTC().Truncate(time.Second), Inner: &envelope.Inner{
			ID: id, From: strings.Repeat("a", 64), To: bob.exportFingerprint(),
			Body: message.Body{Type: message.TypeAsk, Thread: strings.Repeat("d", 32), Text: "x"}},
			Withdrawn: time.Now().UTC().Truncate(time.Second), WithdrawnBy: strings.Repeat("e", 32), WithdrawnReason: "a\x1b[2Jb"}
		if err := s.Save(box, m); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"inbox"}, {"quarantine", "ls"}} {
			out, stderr := withStderr(bob, args...)
			if strings.Contains(out+stderr, "\x1b") {
				t.Errorf("%s: an escape reached the terminal", strings.Join(args, " "))
			}
		}
		out, err := bob.tryRun("read", id)
		if err == nil || strings.Contains(out, "\x1b") || strings.Contains(err.Error(), "\x1b") {
			t.Errorf("read of the %s record: %v; want it refused without the escape", box, err)
		}
		if err := s.Remove(box, id); err != nil {
			t.Fatal(err)
		}
	}
}

// Trusting a quarantined stream whose sender withdrew it while its body
// waited on the relay: its body is not fetched, the relay is not asked and
// nobody is asked for a name; the command says so and nobody is added.
func TestTrustingAWithdrawnStreamAddsNobody(t *testing.T) {
	r := startResettable(t)
	_, bob := watchers(t, r.url)
	mallory := identityOf(newUser(t, "mallory", r.url))
	s, _, _ := bob.opened()
	id := strings.Repeat("f", 32)
	when := time.Date(2026, 11, 21, 9, 30, 0, 0, time.UTC)
	if err := s.Save(store.Quarantine, &store.Stored{RelayID: 3, Relay: bob.defaultRelayName(), Received: when,
		Streamed: true, PayloadOnRelay: true, Inner: &envelope.Inner{
			ID: id, From: mallory.Fingerprint(), FromBundle: mallory.Public().Bundle(), To: bob.exportFingerprint(),
			Body: message.Body{Type: message.TypeAsk, Thread: strings.Repeat("d", 32), Text: "x"}},
		Withdrawn: when, WithdrawnBy: strings.Repeat("e", 32)}); err != nil {
		t.Fatal(err)
	}
	before := bob.peerNames()
	_, err := bob.tryRun("quarantine", "trust", id[:12])
	want := id[:12] + ": its sender withdrew it on " + when.Local().Format("2006-01-02 15:04") + "; its body is not fetched, and nobody was added"
	if err == nil || err.Error() != want {
		t.Fatalf("trust: %v; want %q", err, want)
	}
	if after := bob.peerNames(); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("the peers were %v and are %v", before, after)
	}
	if m := bob.stored(store.Quarantine, id); m == nil {
		t.Fatal("the quarantined record went")
	}
}

// A note kept as needing a newer auu, and reopened once this build knows
// what it carries, marks its message as a fetched note does: damaged
// reopen files a note through the same mark.
func TestAReopenedNoteMarksItsMessage(t *testing.T) {
	srv, st, _ := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice, bob := watchers(t, srv.URL)
	alice.run("send", "--to", "bob", "--subject", "oops", "x")
	bob.run("inbox")
	orig := recordOf(t, bob, store.Inbox, "oops")

	sec, err := withdraw.Section(orig.Inner.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	env, inner, err := envelope.SealSections(identityOf(alice), identityOf(bob).Public(), "",
		withdraw.NoteBody(orig.Inner.Body.Thread, orig.Inner.ID, ""), append([]wire.Section{sec}, critical("note-later")...))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, st, bob, raw)
	id := keptNewer(t, bob, 1)[0]
	if m := bob.stored(store.Inbox, orig.Inner.ID); !m.Withdrawn.IsZero() {
		t.Fatal("a note kept as newer marked its message")
	}
	t.Cleanup(wire.Register("note-later", wire.OnMessage))
	bob.run("damaged", "reopen", bob.defaultRelayName(), strconv.FormatInt(id, 10))
	if m := bob.stored(store.Inbox, orig.Inner.ID); m.WithdrawnBy != inner.ID {
		t.Fatalf("after the reopen the message is %+v; want it marked by the note", m)
	}
}

// A stream waiting on the relay for a newer auu, marked withdrawn by its
// sender's note, keeps the mark when a build that knows its section fetches
// it whole: deliverStream rebuilds the record and carries the mark over.
func TestAStreamFetchedWholeKeepsItsMark(t *testing.T) {
	alice, bob, st := peered(t)
	streamSections(t, alice, bob, "a newer stream", critical("mark-later"))
	fetchJSON(t, bob)
	waiting := recordOf(t, bob, store.Inbox, "a newer stream")
	if !waiting.PayloadOnRelay || waiting.Newer != "mark-later" {
		t.Fatalf("the stream does not wait: %+v", waiting)
	}
	raw, noteID := sealedNote(t, identityOf(alice), identityOf(bob).Public(), waiting.Inner.Body.Thread, waiting.Inner.ID, "")
	deliver(t, st, bob, raw)
	bob.run("inbox")
	if m := bob.stored(store.Inbox, waiting.Inner.ID); m.WithdrawnBy != noteID {
		t.Fatalf("the waiting stream after its note: %+v", m)
	}
	t.Cleanup(wire.Register("mark-later", wire.OnManifest))
	bob.run("inbox")
	m := bob.stored(store.Inbox, waiting.Inner.ID)
	if m.PayloadOnRelay || m.Newer != "" {
		t.Fatalf("the stream was not fetched whole: %+v", m)
	}
	if m.WithdrawnBy != noteID {
		t.Fatalf("the stream fetched whole lost its mark: %+v", m)
	}
}

// The same message from its sender, arriving through a second relay after
// its note had marked it, is saved afresh over the record held from the
// first, and keeps the mark.
func TestAMessageMetThroughAnotherRelayKeepsItsMark(t *testing.T) {
	r := startResettable(t)
	other, otherSt := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits(), Streams: true})
	alice, bob := watchers(t, r.url)
	bob.run("relay", "add", other, "--name", "other")
	bob.run("register", "--relay", "other")
	bobPub := identityOf(bob).Public()
	body := message.Body{Type: message.TypeAsk, Subject: "twice", Thread: strings.Repeat("9", 32), Text: "x"}
	env, inner, err := envelope.Seal(identityOf(alice), bobPub, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, r.st, bob, raw)
	bob.run("inbox")
	note, noteID := sealedNote(t, identityOf(alice), bobPub, body.Thread, inner.ID, "")
	deliver(t, r.st, bob, note)
	bob.run("inbox")
	if m := bob.stored(store.Inbox, inner.ID); m.WithdrawnBy != noteID {
		t.Fatalf("the message after its note: %+v", m)
	}
	deliver(t, otherSt, bob, raw)
	bob.run("inbox")
	if m := bob.stored(store.Inbox, inner.ID); m.WithdrawnBy != noteID {
		t.Fatalf("the message met again through another relay lost its mark: %+v", m)
	}
}

// The mark is saved before the note (R146 P10): with the note's own record
// unwritable, the fetch stops at the note's save, and the original is
// already marked; once the way is clear the next fetch files the note.
func TestTheMarkIsSavedBeforeTheNote(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	bob.run("channel", "keep", "default", "off")
	alice.run("send", "--to", "bob", "--subject", "oops", "x")
	bob.run("inbox")
	orig := recordOf(t, bob, store.Inbox, "oops")
	raw, noteID := sealedNote(t, identityOf(alice), identityOf(bob).Public(), orig.Inner.Body.Thread, orig.Inner.ID, "")
	deliver(t, r.st, bob, raw)
	// A directory where the note's record goes, with something in it, so
	// the record's atomic rename onto it fails.
	block := filepath.Join(bob.home, "inbox", noteID+".json")
	if err := os.MkdirAll(filepath.Join(block, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.tryRun("inbox"); err == nil {
		t.Fatal("the fetch saved the note over a directory")
	}
	if m := bob.stored(store.Inbox, orig.Inner.ID); m.WithdrawnBy != noteID {
		t.Fatalf("the original after the note's save failed: %+v; want it marked first", m)
	}
	if err := os.RemoveAll(block); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	if note := bob.stored(store.Inbox, noteID); note.Inner.Body.Type != message.TypeNote {
		t.Fatalf("the note was not filed on the next fetch: %+v", note)
	}
}

// A note met again marks its original again: a writer racing the first
// mark, such as a read marking the original read, could save over it, and
// nothing else would ever mark it. Here the mark is taken off by hand, as
// that race would leave it, and a fetch that meets the kept note again
// puts it back.
func TestANoteMetAgainPutsBackALostMark(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	alice.run("send", "--to", "bob", "--subject", "oops", "x")
	bob.run("inbox")
	orig := recordOf(t, bob, store.Inbox, "oops")
	raw, noteID := sealedNote(t, identityOf(alice), identityOf(bob).Public(), orig.Inner.Body.Thread, orig.Inner.ID, "")
	deliver(t, r.st, bob, raw)
	bob.run("inbox")
	s, _, _ := bob.opened()
	m := bob.stored(store.Inbox, orig.Inner.ID)
	m.Withdrawn, m.WithdrawnBy, m.WithdrawnReason = time.Time{}, "", ""
	if err := s.Save(store.Inbox, m); err != nil {
		t.Fatal(err)
	}
	bob.setCursor(bob.defaultRelayName(), "0\n")
	bob.run("inbox")
	if m := bob.stored(store.Inbox, orig.Inner.ID); m.WithdrawnBy != noteID {
		t.Fatalf("the note met again did not put the mark back: %+v", m)
	}
}
