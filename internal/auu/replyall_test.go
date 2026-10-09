package auu

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A message to several as each recipient sees it, and reply --all (D50,
// D51): who it went to, answering everyone, and a copy that arrives twice.

// putBack writes files saved from the outbox back into it, which is the
// outbox as it stood when a post's answer was lost: the copy is on the
// relay and still waits here, so --resume posts it again (R5).
func putBack(t *testing.T, u *user, saved map[string][]byte) {
	t.Helper()
	for name, data := range saved {
		if err := os.WriteFile(filepath.Join(u.home, "outbox", name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// saveOutbox reads every file in the outbox.
func saveOutbox(t *testing.T, u *user) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(u.home, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	saved := map[string][]byte{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(u.home, "outbox", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		saved[e.Name()] = data
	}
	return saved
}

// A copy posted a second time, as --resume does after a lost answer, is
// one message here. Where the channel keeps its mail, the relay still lists
// the record's own row, so the second is acknowledged, counted as already
// held, and the record stays on its first row. Where it does not, the
// record's row is gone, and the second row is what a message served again
// is (ruling 53): the record moves to it and it is acknowledged, nothing
// counted. Either way a reset of the cursor afterwards delivers nothing
// twice.
func TestACopyPostedTwiceIsHeldOnce(t *testing.T) {
	for _, keep := range []string{"on", "off"} {
		t.Run("keep "+keep, func(t *testing.T) {
			r := startResettable(t)
			us := peersOn(t, r.url, "alice", "bob", "carol")
			alice, bob := us[0], us[1]
			bob.run("channel", "keep", "default", keep)
			id, _ := sealCopies(t, alice, "bob", "carol")
			saved := saveOutbox(t, alice)
			alice.run("send", "--resume")
			putBack(t, alice, saved)
			alice.run("send", "--resume")
			rows := queuedOn(t, r.st, bob.exportFingerprint())
			if len(rows) != 2 {
				t.Fatalf("the relay holds %d rows for bob, want the copy twice", len(rows))
			}

			in, _ := fetchSaying(t, bob)
			duplicate, row, want := 1, rows[0], rows[:1]
			if keep == "off" {
				duplicate, row, want = 0, rows[1], nil
			}
			if in.Fetch.Delivered != 1 || in.Fetch.Duplicate != duplicate {
				t.Fatalf("the fetch: %+v; want one delivered and %d already held", in.Fetch, duplicate)
			}
			if n := spoolFiles(t, bob, store.Inbox); n != 1 {
				t.Fatalf("the inbox holds %d records, want 1", n)
			}
			if m := bob.stored(store.Inbox, id); m.RelayID != row {
				t.Errorf("the record is on row %d, want %d", m.RelayID, row)
			}
			if left := queuedOn(t, r.st, bob.exportFingerprint()); len(left) != len(want) || (len(want) == 1 && left[0] != want[0]) {
				t.Errorf("the relay holds %v after the fetch, want %v", left, want)
			}

			// The plain line says so, where it is counted.
			putBack(t, alice, saved)
			alice.run("send", "--resume")
			out := bob.run("inbox")
			if keep == "on" && !strings.Contains(out, "fetched 0 new message(s), 1 already held") ||
				keep == "off" && strings.Contains(out, "fetched") {
				t.Errorf("the fetch of a third posting says:\n%s", out)
			}

			// A reset of the cursor meets the record's own row, or nothing,
			// and delivers nothing twice.
			bob.setCursor(bob.defaultRelayName(), "0\n")
			if in, _ := fetchSaying(t, bob); in.Fetch.Delivered != 0 || in.Fetch.Duplicate != 0 {
				t.Errorf("the fetch after a reset: %+v; want nothing", in.Fetch)
			}
			if n := spoolFiles(t, bob, store.Inbox); n != 1 {
				t.Errorf("after the reset the inbox holds %d records, want 1", n)
			}
		})
	}
}

// A message to several says who it went to: the listing how many, read
// each by the name this machine has for them, the reader as you and
// somebody unknown by short fingerprint, --json each with a name where one
// is known; a message to one says nothing of the kind.
func TestAMessageToSeveralSaysWhoItWentTo(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	dave := newUser(t, "dave", relayURL)
	for _, v := range []*user{bob, carol, dave} {
		alice.run("peers", "add", v.exportLine())
	}
	bob.run("peers", "add", alice.exportLine())
	bob.run("peers", "add", carol.exportLine())
	bob.run("allow", "push")

	got := sentMany(t, alice.run("send", "--to", "carol,bob,dave", "--subject", "plans", "--json", "for all three"))
	single := sentJSON{}
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--json", "for bob alone")), &single); err != nil {
		t.Fatal(err)
	}

	listing := bob.run("inbox")
	var severalLine, singleLine string
	for _, line := range strings.Split(listing, "\n") {
		switch {
		case strings.Contains(line, got.ID[:12]):
			severalLine = line
		case strings.Contains(line, single.ID[:12]):
			singleLine = line
		}
	}
	if !strings.Contains(severalLine, "(to 3)") || strings.Contains(singleLine, "(to ") {
		t.Errorf("the listing:\n%s", listing)
	}

	read := bob.run("read", got.ID)
	if !strings.Contains(read, "to:      carol, you, <"+dave.exportFingerprint()[:16]+">\n") {
		t.Errorf("read says:\n%s", read)
	}
	if strings.Contains(bob.run("read", single.ID), "to:") {
		t.Errorf("read of a message to one says who it went to")
	}

	var asJSON messageJSON
	if err := json.Unmarshal([]byte(bob.run("read", got.ID, "--json")), &asJSON); err != nil {
		t.Fatal(err)
	}
	want := []recipientNameJSON{
		{Fingerprint: carol.exportFingerprint(), Name: "carol"},
		{Fingerprint: bob.exportFingerprint(), Name: "bob"},
		{Fingerprint: dave.exportFingerprint()},
	}
	if len(asJSON.Recipients) != 3 {
		t.Fatalf("read --json recipients: %+v", asJSON.Recipients)
	}
	for i := range want {
		if asJSON.Recipients[i] != want[i] {
			t.Errorf("recipient %d is %+v, want %+v", i, asJSON.Recipients[i], want[i])
		}
	}
	if raw := bob.run("read", single.ID, "--json"); strings.Contains(raw, `"recipients"`) {
		t.Errorf("read --json of a message to one carries recipients:\n%s", raw)
	}
}

// A record whose list breaks its rule, here one that no longer names its
// own recipient, is refused when it is loaded, and so is never shown as a
// message to several, or at all.
func TestARecordWhoseListFailsIsNotShown(t *testing.T) {
	alice, bob, _ := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "hello"))
	bob.run("inbox")
	path := filepath.Join(bob.home, "inbox", got.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The list no longer names bob, its copy's own recipient.
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	sections, _ := rec["inner"].(map[string]any)["sections"].([]any)
	if len(sections) != 1 || sections[0].(map[string]any)["name"] != recipients.Name {
		t.Fatalf("the record's sections: %v", sections)
	}
	list := sections[0].(map[string]any)["data"].(map[string]any)["to"].([]any)
	if list[0] != bob.exportFingerprint() {
		t.Fatalf("the list begins %v", list[0])
	}
	list[0] = strings.Repeat("e", 64)
	if data, err = json.Marshal(rec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out string
	said := captureStderr(t, func() { out, _ = bob.tryRun("inbox") })
	if strings.Contains(out, got.ID[:12]) {
		t.Errorf("the listing shows a record whose list fails:\n%s", out)
	}
	if !strings.Contains(said, "does not name "+bob.exportFingerprint()[:16]+", whose copy this is) and is not listed") {
		t.Errorf("the listing does not say why the record is left out:\n%s", said)
	}
	if _, err := bob.tryRun("read", got.ID); err == nil {
		t.Errorf("read of a record whose list fails went through")
	}
}

// reply --all from a recipient: the sender and every other recipient get
// one message to several, which names them all and not the replier twice,
// on the thread.
func TestReplyAllAnswersEveryone(t *testing.T) {
	alice, bob, carol := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--subject", "plans", "--json", "hello"))
	bob.run("inbox")
	reply := sentMany(t, bob.run("reply", got.ID, "--all", "--json", "to you both"))
	if len(reply.Recipients) != 2 || reply.Recipients[0].Name != "alice" || reply.Recipients[1].Name != "carol" {
		t.Fatalf("reply --all went to %+v; want alice and carol", reply.Recipients)
	}
	for _, u := range []*user{alice, carol} {
		u.run("inbox")
		m := u.stored(store.Inbox, reply.ID)
		if m.Inner.Body.Thread != got.Thread || m.Inner.Body.InReplyTo != got.ID {
			t.Errorf("the reply is not on the thread: %+v", m.Inner.Body)
		}
		list := recipientsOf(m)
		if len(list) != 2 || list[0] != alice.exportFingerprint() || list[1] != carol.exportFingerprint() {
			t.Errorf("the reply's list is %v", list)
		}
	}

	// From the sender of a message to several, by its thread: everybody it
	// went to.
	follow := sentMany(t, alice.run("reply", got.Thread, "--all", "--json", "and again"))
	if len(follow.Recipients) != 2 {
		t.Fatalf("alice's reply --all on her own latest: %+v", follow.Recipients)
	}
}

// reply --all is refused whole, naming whoever is not on the peer list and
// what to do, with nothing sealed, written or sent.
func TestReplyAllIsRefusedForSomebodyOffThePeerList(t *testing.T) {
	relayURL := startRelay(t)
	us := peersOn(t, relayURL, "alice", "bob")
	alice, bob := us[0], us[1]
	carol := newUser(t, "carol", relayURL)
	alice.run("peers", "add", carol.exportLine())
	carol.run("peers", "add", alice.exportLine())
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "hello"))
	bob.run("inbox")
	before := len(sentBox(t, bob))
	_, err := bob.tryRun("reply", got.ID, "--all", "to you all")
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage ||
		!strings.Contains(err.Error(), "cannot answer everyone: "+carol.exportFingerprint()[:16]+" is not on your peer list") ||
		!strings.Contains(err.Error(), "'auu vouch'") || !strings.Contains(err.Error(), "'auu peers add'") ||
		!strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("reply --all with carol unknown: %v", err)
	}
	if waiting, _ := outboxOf(t, bob); len(waiting) != 0 || len(sentBox(t, bob)) != before {
		t.Errorf("a refused reply --all wrote something")
	}
	if out := alice.run("inbox"); strings.Contains(out, "fetched") {
		t.Errorf("alice got a refused reply:\n%s", out)
	}
}

// A recipient registered on another relay than the one the message came by
// is a copy refused there: it waits in the outbox, and the sentence says how
// to reach them, which a send to several that is not reply --all does not.
func TestReplyAllSaysHowToReachSomebodyElsewhere(t *testing.T) {
	relayURL := startRelay(t)
	us := peersOn(t, relayURL, "alice", "bob")
	alice, bob := us[0], us[1]
	dave := newUser(t, "dave", startRelay(t))
	for _, u := range []*user{alice, bob} {
		u.run("peers", "add", dave.exportLine())
	}
	// Alice's own copy to dave is refused on her relay too; bob's arrives.
	out, _ := alice.tryRun("send", "--to", "bob,dave", "--json", "hello")
	got := sentMany(t, out)
	bob.run("inbox")
	_, err := bob.tryRun("reply", got.ID, "--all", "to you both")
	var e *exitError
	if !asExit(err, &e) || e.code == exitUsage ||
		!strings.Contains(err.Error(), "1 of 2 copies were not sent and wait in the outbox") ||
		!strings.Contains(err.Error(), "somebody not registered there is reached by a new message with --to 'RELAY!NAME', "+
			"or by a new message to a room, which carries an address for each person") ||
		strings.Contains(err.Error(), "a reply goes back the way the message came") {
		t.Fatalf("reply --all to somebody elsewhere: %v", err)
	}
	waiting, _ := outboxOf(t, bob)
	if len(waiting) != 1 || waiting[0].To != dave.exportFingerprint() {
		t.Errorf("waiting: %+v; want dave's copy", waiting)
	}
	if !strings.Contains(alice.run("inbox"), "fetched 1 new message(s)") {
		t.Errorf("alice did not get bob's reply")
	}
	if _, err := alice.tryRun("send", "--to", "bob,dave", "again"); err == nil || strings.Contains(err.Error(), "RELAY!NAME") {
		t.Errorf("a plain send to several: %v; want the copy left without the reply --all sentence", err)
	}
}

// reply --all to a message to one, or to a message to several whose other
// recipient is the replier alone, is an ordinary reply with no list.
func TestReplyAllToOneIsAnOrdinaryReply(t *testing.T) {
	alice, bob, _ := threePeers(t)
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--json", "hello")), &sent); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	var reply sentJSON
	if err := json.Unmarshal([]byte(bob.run("reply", sent.ID, "--all", "--json", "hi")), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.ToName != "alice" {
		t.Fatalf("reply --all to a message to one went to %+v", reply)
	}
	alice.run("inbox")
	if m := alice.stored(store.Inbox, reply.ID); len(m.Inner.Sections) != 0 {
		t.Errorf("the reply carries sections: %+v", m.Inner.Sections)
	}

	// Alice's own message to bob alone, answered by its thread: bob.
	var again sentJSON
	if err := json.Unmarshal([]byte(alice.run("reply", reply.ID, "--all", "--json", "and back")), &again); err != nil {
		t.Fatal(err)
	}
	if again.ToName != "bob" {
		t.Errorf("alice's reply --all went to %+v", again)
	}
}

// --all takes no --to and no --via, and says why.
func TestReplyAllTakesNoAddress(t *testing.T) {
	alice, bob, _ := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "hello"))
	bob.run("inbox")
	for _, extra := range [][]string{{"--to", "alice"}, {"--via", "somewhere"}} {
		_, err := bob.tryRun(append([]string{"reply", got.ID, "--all"}, append(extra, "x")...)...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "--all answers everyone through the relay "+
			"the message came by, and takes no --to or --via; to reach somebody by other relays, send a new message to them "+
			"or to a room, which carries an address for each person") {
			t.Errorf("--all %v: %v", extra, err)
		}
	}
}

// A follow-up to your own message to several names --all beside --to, and
// --all on it goes to everybody it went to.
func TestAFollowUpToSeveralOffersAll(t *testing.T) {
	alice, bob, carol := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "hello"))
	_, err := alice.tryRun("reply", got.Thread, "more")
	if err == nil || !strings.Contains(err.Error(), "as --to PEER, or answer everyone with --all") {
		t.Errorf("a plain follow-up: %v", err)
	}
	follow := sentMany(t, alice.run("reply", got.Thread, "--all", "--json", "more for you both"))
	if len(follow.Recipients) != 2 || follow.Recipients[0].Name != "bob" || follow.Recipients[1].Name != "carol" {
		t.Fatalf("the follow-up to everyone went to %+v", follow.Recipients)
	}
	for _, u := range []*user{bob, carol} {
		u.run("inbox")
		if m := u.stored(store.Inbox, follow.ID); m.Inner.Body.InReplyTo != got.ID {
			t.Errorf("the follow-up answers %s, want %s", m.Inner.Body.InReplyTo, got.ID)
		}
	}
}

// serve hands a handler the list a message to several went to, in its
// sender's order, and an empty one for a message to one; the expert's
// answer goes to the sender alone.
func TestServeHandsTheHandlerTheRecipients(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	b := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	for _, u := range []*user{b, carol} {
		alice.run("peers", "add", u.exportLine())
		u.run("peers", "add", alice.exportLine())
		u.run("channel", "create", "jostle")
	}
	t.Setenv(handlerScript, "env")
	bob := &expert{user: b, dir: repo(t), channel: "jostle"}
	bob.row = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: modeSideCopy}
	bob.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": bob.row}}
	bob.path = filepath.Join(b.home, serveFile)
	bob.write(t)
	bob.serve(t)

	seen := func(thread string) (string, bool) {
		for _, line := range strings.Split(alice.replyOn(t, thread).Text, "\n") {
			if v, ok := strings.CutPrefix(line, "AUU_RECIPIENTS="); ok {
				return v, true
			}
		}
		return "", false
	}
	single := alice.ask(t, "jostle", "one", "for bob")
	bob.serve(t)
	if v, ok := seen(single.Thread); !ok || v != "" {
		t.Errorf("for a message to one AUU_RECIPIENTS is %q, set %v; want set and empty", v, ok)
	}

	several := sentMany(t, alice.run("send", "--to", "carol,bob", "--channel", "jostle", "--subject", "two", "--json", "for both"))
	bob.serve(t)
	want := carol.exportFingerprint() + " " + bob.exportFingerprint()
	if v, _ := seen(several.Thread); v != want {
		t.Errorf("for a message to several AUU_RECIPIENTS is %q, want %q", v, want)
	}
	var in inboxJSON
	if err := json.Unmarshal([]byte(carol.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.Type == "reply" {
			t.Errorf("carol got the expert's reply: %+v", m)
		}
	}
}

// A stream posted a second time is one message here, as an envelope is:
// the relay holds its manifest twice when a resume's answer is lost, and
// the second is acknowledged, counted as already held and not delivered.
func TestAStreamPostedTwiceIsHeldOnce(t *testing.T) {
	relayURL, gate := startInterruptibleRelay(t, 2, 64<<10)
	us := peersOn(t, relayURL, "alice", "bob")
	alice, bob := us[0], us[1]
	file := filepath.Join(t.TempDir(), "long.bin")
	if err := os.WriteFile(file, make([]byte, 400<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.tryRun("send", "--to", "bob", "--attach", file, "long"); err == nil {
		t.Fatal("the send went through with the relay cut off part way")
	}
	saved := saveOutbox(t, alice)
	gate.open()
	alice.run("send", "--resume")
	putBack(t, alice, saved)
	alice.run("send", "--resume")
	in, _ := fetchSaying(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Duplicate != 1 {
		t.Fatalf("the fetch: %+v; want one delivered and one already held", in.Fetch)
	}
	if n := spoolFiles(t, bob, store.Inbox); n != 1 {
		t.Fatalf("the inbox holds %d records, want 1", n)
	}
}

// A stream that waits for a newer build, posted a second time, is one
// record here too: the second row is acknowledged and counted, and the
// first still waits.
func TestAWaitingStreamPostedTwiceIsHeldOnce(t *testing.T) {
	r := startResettable(t)
	us := peersOn(t, r.url, "alice", "bob")
	alice, bob := us[0], us[1]
	var sealed []byte
	streamSectionsDamaged(t, alice, bob, "", "from later", critical("later-feature"), func(b []byte) {
		sealed = bytes.Clone(b)
	})
	_, c := sender(t, alice)
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, bob.exportFingerprint(), "", int64(len(sealed)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(sealed), int64(len(sealed))); err != nil {
		t.Fatal(err)
	}
	rows := queuedOn(t, r.st, bob.exportFingerprint())
	if len(rows) != 2 {
		t.Fatalf("the relay holds %d rows for bob, want the stream twice", len(rows))
	}
	in, _ := fetchSaying(t, bob)
	if in.Fetch.Duplicate != 1 || len(in.Fetch.Newer) != 1 {
		t.Fatalf("the fetch: %+v; want one waiting and one already held", in.Fetch)
	}
	if n := spoolFiles(t, bob, store.Inbox); n != 1 {
		t.Fatalf("the inbox holds %d records, want 1", n)
	}
	if left := queuedOn(t, r.st, bob.exportFingerprint()); len(left) != 1 || left[0] != rows[0] {
		t.Errorf("the relay holds %v after the fetch, want the first row alone, %d", left, rows[0])
	}
}

// Kept mail the relay holds again under a new id, after its numbering began
// again, with its old id now another message's, is that mail moved and not
// a second copy: the record names the new row, which stays on the relay as
// the channel keeps it, and removing the record later removes it and not
// the other message that has the old id now.
func TestKeptMailUnderANewNumberingIsNotACopy(t *testing.T) {
	r := startResettable(t)
	alice, bob := watchers(t, r.url)
	fp := bob.exportFingerprint()
	rowsNow := func() []relay.Row {
		t.Helper()
		rows, err := r.st.List(fp, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	alice.run("send", "--to", "bob", "--subject", "kept", "x")
	kept := rowsNow()[0]
	bob.run("inbox")
	alice.run("send", "--to", "bob", "--subject", "other", "a longer text than the kept one has")
	other := rowsNow()[1]
	if kept.Received.Equal(other.Received) && len(kept.Envelope) == len(other.Envelope) {
		t.Fatal("the two rows cannot be told apart")
	}
	r.renumber(t, fp)
	otherID, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", other.Envelope, relay.Quotas{}, relay.Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	keptID, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", kept.Envelope, relay.Quotas{}, relay.Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	if otherID != kept.ID {
		t.Fatalf("the other message is row %d, want the kept one's old %d", otherID, kept.ID)
	}

	bob.setCursor(bob.defaultRelayName(), "0\n")
	in, _ := fetchSaying(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Duplicate != 0 {
		t.Fatalf("the fetch: %+v; want the other message delivered and the kept one not a second copy", in.Fetch)
	}
	m := recordOf(t, bob, store.Inbox, "kept")
	if m.RelayID != keptID || !m.OnRelay {
		t.Fatalf("the kept record names row %d, on the relay %v; want %d, on it", m.RelayID, m.OnRelay, keptID)
	}
	if got := queuedOn(t, r.st, fp); len(got) != 2 {
		t.Fatalf("the relay holds %v, want both", got)
	}
	bob.run("rm", m.Inner.ID[:12])
	if got := queuedOn(t, r.st, fp); len(got) != 1 || got[0] != otherID {
		t.Fatalf("after removing the kept record the relay holds %v, want the other message alone, %d", got, otherID)
	}
}

// A message removed here alone, left on the relay, that is posted again is
// that message a second time and not a move: the second row is
// acknowledged, the entry that says the first was left stays on it, and no
// fetch says mail is waiting behind the cursor, before a reset or after.
func TestACopyPostedAgainAfterItWasRemovedHereAlone(t *testing.T) {
	r := startResettable(t)
	us := peersOn(t, r.url, "alice", "bob", "carol")
	alice, bob := us[0], us[1]
	fp := bob.exportFingerprint()
	id, _ := sealCopies(t, alice, "bob", "carol")
	saved := saveOutbox(t, alice)
	alice.run("send", "--resume")
	bob.run("inbox")
	first := queuedOn(t, r.st, fp)
	if len(first) != 1 {
		t.Fatalf("the relay holds %v for bob, want one row", first)
	}
	bob.run("rm", "--local-only", id[:12])
	putBack(t, alice, saved)
	alice.run("send", "--resume")
	if rows := queuedOn(t, r.st, fp); len(rows) != 2 {
		t.Fatalf("the relay holds %v, want the copy twice", rows)
	}

	entryOn := func() int64 {
		t.Helper()
		s, _, _ := bob.opened()
		entries, err := s.LeftBehind(bob.defaultRelayName())
		if err != nil || len(entries) != 1 || entries[0].ID != id {
			t.Fatalf("the left-behind entries: %+v, %v", entries, err)
		}
		return entries[0].RelayID
	}
	for _, when := range []string{"a fetch", "a fetch after a cursor reset"} {
		if when != "a fetch" {
			bob.setCursor(bob.defaultRelayName(), "0\n")
		}
		in, said := fetchSaying(t, bob)
		if in.Fetch.Delivered != 0 || said != "" {
			t.Fatalf("%s: %+v, said %q", when, in.Fetch, said)
		}
		if got := queuedOn(t, r.st, fp); len(got) != 1 || got[0] != first[0] {
			t.Fatalf("after %s the relay holds %v, want the first row alone, %d", when, got, first[0])
		}
		if got := entryOn(); got != first[0] {
			t.Fatalf("after %s the entry is on row %d, want %d", when, got, first[0])
		}
	}
	if n := spoolFiles(t, bob, store.Inbox); n != 0 {
		t.Errorf("the inbox holds %d records, want none", n)
	}
}

// An entry for mail removed here alone whose row was lost when the relay's
// numbering began again, and whose message the relay then holds twice, as
// a restore and a resend leave it: the first row met moves the entry, and
// the second is checked against where it moved, so it is acknowledged and
// the entry and the relay agree on one row.
func TestALeftEntryMovedThenMetAgain(t *testing.T) {
	r := startResettable(t)
	us := peersOn(t, r.url, "alice", "bob", "carol")
	alice, bob := us[0], us[1]
	fp := bob.exportFingerprint()
	id, _ := sealCopies(t, alice, "bob", "carol")
	alice.run("send", "--resume")
	bob.run("inbox")
	rows, err := r.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the relay holds %d (%v)", len(rows), err)
	}
	bob.run("rm", "--local-only", id[:12])
	r.renumber(t, fp)
	// Somebody else's mail takes the entry's old id.
	if _, err := r.st.Put(alice.exportFingerprint(), "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{}); err != nil {
		t.Fatal(err)
	}
	var restored []int64
	for range 2 {
		n, err := r.st.Put(fp, "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{})
		if err != nil {
			t.Fatal(err)
		}
		restored = append(restored, n)
	}
	in, said := fetchSaying(t, bob)
	if in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch: %+v, said %q", in.Fetch, said)
	}
	if got := queuedOn(t, r.st, fp); len(got) != 1 || got[0] != restored[0] {
		t.Fatalf("the relay holds %v, want the first restored row alone, %d", got, restored[0])
	}
	s, _, _ := bob.opened()
	entries, err := s.LeftBehind(bob.defaultRelayName())
	if err != nil || len(entries) != 1 || entries[0].RelayID != restored[0] {
		t.Fatalf("the entry: %+v, %v; want it on row %d", entries, err, restored[0])
	}
	if in, said := fetchSaying(t, bob); in.Fetch.Delivered != 0 || said != "" {
		t.Fatalf("the fetch after: %+v, said %q", in.Fetch, said)
	}
}
