package auu

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// sentOne sends a message to one and answers what --json said.
func sentOne(t *testing.T, u *user, args ...string) sentJSON {
	t.Helper()
	out := u.run(append([]string{"send", "--json"}, args...)...)
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return sent
}

// sentRecord is a user's sent record of a message.
func sentRecord(t *testing.T, u *user, id string) *store.Stored {
	t.Helper()
	m, err := storeOf(t, u).Load(store.Sent, id)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// relayRows is what a relay holds in a user's mailbox.
func relayRows(t *testing.T, st *relay.Store, u *user) []relay.Row {
	t.Helper()
	rows, err := st.List(u.exportFingerprint(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// withdrawn runs auu withdraw --json and answers what it said, the error
// and what it wrote to standard error.
func withdrawn(t *testing.T, u *user, args ...string) (withdrawnJSON, string, error) {
	t.Helper()
	stdout, stderr, err := tryWithStderr(u, append([]string{"withdraw", "--json"}, args...)...)
	var out withdrawnJSON
	if stdout != "" {
		if jerr := json.Unmarshal([]byte(stdout), &out); jerr != nil {
			t.Fatalf("withdraw --json: %v\n%s", jerr, stdout)
		}
	}
	return out, stderr, err
}

// tryWithStderr is withStderr for a command that may fail.
func tryWithStderr(u *user, args ...string) (stdout, stderr string, err error) {
	u.t.Helper()
	real := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		u.t.Fatal(perr)
	}
	read := make(chan []byte)
	go func() {
		data, _ := io.ReadAll(r)
		read <- data
	}()
	os.Stderr = w
	stdout, err = u.tryRun(args...)
	w.Close()
	os.Stderr = real
	return stdout, string(<-read), err
}

// outboxListed is what a user's outbox --json lists.
func outboxListed(t *testing.T, u *user) []outboxJSON {
	t.Helper()
	var out []outboxJSON
	if err := json.Unmarshal([]byte(u.run("outbox", "--json")), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// sentAndOutbox is every file under a user's sent box and outbox, by its path
// and bytes, for a test that a refusal changed nothing.
func sentAndOutbox(t *testing.T, u *user) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, dir := range []string{"sent", "outbox"} {
		root := filepath.Join(u.home, dir)
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				data, _ := os.ReadFile(path)
				files[path] = string(data)
			}
			return nil
		})
	}
	return files
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The whole of a withdrawal through a real relay, a message to one by the
// withdrawal route. The sent record keeps the key the relay keeps the
// stored form of, the one withdraw.EnvelopeKey makes of the envelope the
// relay holds. The withdrawal takes the message's place on the relay with
// the note, on the same channel; the sent record is marked with the note
// and the reason, and the note has its own sent record, with its section
// and no key of its own; the outbox is empty. The recipient's fetch marks
// the copy they hold. read says the sender withdrew it, and the key reaches
// no output.
func TestAWithdrawnMessageIsReplacedOnTheRelay(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	both := peersOn(t, relayURL, "alice", "bob")
	alice, bob := both[0], both[1]
	sent := sentOne(t, alice, "--to", "bob", "--subject", "figures", "the wrong figures")
	bob.run("inbox")

	rec := sentRecord(t, alice, sent.ID)
	rows := relayRows(t, st, bob)
	if len(rows) != 1 {
		t.Fatalf("bob's mailbox holds %d rows, want the one message", len(rows))
	}
	var env envelope.Envelope
	if err := json.Unmarshal(rows[0].Envelope, &env); err != nil {
		t.Fatal(err)
	}
	if rec.WithdrawKey == "" || rec.WithdrawKey != withdraw.EnvelopeKey(env.To, env.CT) {
		t.Fatalf("the sent record's key %q is not the key of what the relay holds", rec.WithdrawKey)
	}

	out, _, err := withdrawn(t, alice, sent.ID[:12], "--reason", "the figures were last year's", "--yes")
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if out.ID != sent.ID || len(out.Copies) != 1 {
		t.Fatalf("withdraw --json said %+v", out)
	}
	c := out.Copies[0]
	if !c.Replaced || c.Said != "replaced on the relay" || c.Note == "" || c.Withdrawn.IsZero() || c.Error != "" ||
		c.Fingerprint != bob.exportFingerprint() || c.Name != "bob" {
		t.Fatalf("the copy: %+v", c)
	}
	rows = relayRows(t, st, bob)
	if len(rows) != 1 || rows[0].ID != c.RelayID || rows[0].ID == sent.RelayID || rows[0].Channel != "default" {
		t.Fatalf("after the withdrawal bob's mailbox holds %+v; want the note alone, in the message's place", rows)
	}
	if bytes.Equal(rows[0].Envelope, mustMarshal(t, &env)) {
		t.Fatal("the relay still holds the message")
	}

	rec = sentRecord(t, alice, sent.ID)
	if !rec.Withdrawn.Equal(c.Withdrawn) || rec.WithdrawnBy != c.Note || rec.WithdrawnReason != "the figures were last year's" {
		t.Errorf("the sent record's mark: %v %q %q", rec.Withdrawn, rec.WithdrawnBy, rec.WithdrawnReason)
	}
	note := sentRecord(t, alice, c.Note)
	w, err := withdraw.CheckSections(note.Inner.Sections, note.Inner.Body)
	if err != nil || w == nil || w.ID != sent.ID || w.Reason != "the figures were last year's" {
		t.Errorf("the note's sent record carries %+v, %v", w, err)
	}
	if note.WithdrawKey != "" || note.RelayID != c.RelayID || note.Inner.To != bob.exportFingerprint() {
		t.Errorf("the note's sent record: key %q, relay id %d, to %s", note.WithdrawKey, note.RelayID, note.Inner.To)
	}
	if left := outboxListed(t, alice); len(left) != 0 {
		t.Errorf("the outbox holds %+v after the note was placed", left)
	}

	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	held := recordOf(t, bob, store.Inbox, "figures")
	if held.Withdrawn.IsZero() || held.WithdrawnBy != c.Note || held.WithdrawnReason != "the figures were last year's" {
		t.Errorf("bob's copy is not marked: %+v", held)
	}

	text := alice.run("read", sent.ID[:12])
	if !strings.HasPrefix(text, "!! WITHDRAWN by you on ") || !strings.Contains(firstLineWith(text, "WITHDRAWN"), "the figures were last year's") {
		t.Errorf("read of the sent message:\n%s", text)
	}
	var full messageJSON
	asJSON := alice.run("read", sent.ID[:12], "--json")
	if err := json.Unmarshal([]byte(asJSON), &full); err != nil || full.Withdrawn.IsZero() || full.WithdrawnBy != c.Note {
		t.Errorf("read --json of the sent message: %v\n%s", err, asJSON)
	}
	// The key is a credential: no output carries it.
	for name, said := range map[string]string{
		"withdraw --json": mustJSON(t, out), "read": text, "read --json": asJSON,
		"outbox --json": alice.run("outbox", "--json"), "read of the note": alice.run("read", c.Note[:12], "--json"),
	} {
		if strings.Contains(said, rec.WithdrawKey) {
			t.Errorf("%s says the withdrawal key", name)
		}
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t *testing.T, v any) string { return string(mustMarshal(t, v)) }

// A stream's key is the relay's too, as the first send of one keeps it
// (finishStream) and as each copy of a message to several keeps its own,
// an envelope and a stream alike (landCopy): each is withdrawn by the
// withdrawal route, and the relay takes the note in its place only for
// the key that is its own.
func TestEveryPlacementKeepsTheRelaysKey(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	users := peersOn(t, relayURL, "alice", "bob", "carol")
	alice, bob, carol := users[0], users[1], users[2]

	stream := sentOne(t, alice, "--to", "bob", "--stream", "--subject", "a stream", "a stream to one")
	if stream.Kind != "stream" {
		t.Fatalf("sent as %s", stream.Kind)
	}
	if rec := sentRecord(t, alice, stream.ID); !withdraw.Valid(rec.WithdrawKey) {
		t.Fatalf("a stream's sent record keeps the key %q", rec.WithdrawKey)
	}
	for _, args := range [][]string{
		{"--to", "bob", "--to", "carol", "--subject", "envelopes", "to both"},
		{"--to", "bob", "--to", "carol", "--stream", "--subject", "streams", "to both"},
	} {
		out := alice.run(append([]string{"send", "--json"}, args...)...)
		var many sentManyJSON
		if err := json.Unmarshal([]byte(out), &many); err != nil {
			t.Fatal(err)
		}
		rec := sentRecord(t, alice, many.ID)
		if rec.WithdrawKey != "" {
			t.Errorf("%s: a message to several keeps a key at its top", many.ID[:12])
		}
		for _, c := range rec.Copies {
			if !withdraw.Valid(c.WithdrawKey) {
				t.Errorf("%s: the copy to %s keeps the key %q", many.ID[:12], c.Name, c.WithdrawKey)
			}
		}
		res, _, err := withdrawn(t, alice, many.ID, "--yes")
		if err != nil || len(res.Copies) != 2 || !res.Copies[0].Replaced || !res.Copies[1].Replaced {
			t.Errorf("%s: withdraw %+v, %v; want both copies replaced on the relay", many.ID[:12], res, err)
		}
	}
	res, _, err := withdrawn(t, alice, stream.ID, "--yes")
	if err != nil || len(res.Copies) != 1 || !res.Copies[0].Replaced {
		t.Fatalf("the stream to one: %+v, %v", res, err)
	}
	// Each mailbox holds the notes alone: three for bob, two for carol.
	for _, tc := range []struct {
		u    *user
		want int
	}{{bob, 3}, {carol, 2}} {
		rows := relayRows(t, st, tc.u)
		if len(rows) != tc.want {
			t.Errorf("%d rows; want %d notes", len(rows), tc.want)
		}
		for _, r := range rows {
			if r.Kind != relayapi.KindEnvelope {
				t.Errorf("a %s row is left in the mailbox", r.Kind)
			}
		}
	}
	rec := sentRecord(t, alice, stream.ID)
	if rec.Withdrawn.IsZero() {
		t.Error("the stream's sent record is not marked")
	}
}

// After a 404 not-withdrawable, and on that alone, the note goes by the
// ordinary route: the recipient had removed the message from the relay,
// so the note is posted after it, the copy is marked, and the line says
// so.
func TestANoteGoesAfterAMessageTheRelayNoLongerHolds(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	both := peersOn(t, relayURL, "alice", "bob")
	alice, bob := both[0], both[1]
	sent := sentOne(t, alice, "--to", "bob", "--subject", "gone", "read and removed")
	bob.run("inbox")
	bob.run("rm", sent.ID[:12])

	out, _, err := withdrawn(t, alice, sent.ID[:12], "--yes")
	if err != nil || len(out.Copies) != 1 {
		t.Fatalf("withdraw: %+v, %v", out, err)
	}
	c := out.Copies[0]
	if c.Replaced || c.Said != "no longer on the relay, or not withdrawable there: the note was sent after it" || c.Withdrawn.IsZero() {
		t.Fatalf("the copy: %+v", c)
	}
	if rows := relayRows(t, st, bob); len(rows) != 1 || rows[0].ID != c.RelayID {
		t.Errorf("bob's mailbox: %+v; want the note posted", rows)
	}
	if rec := sentRecord(t, alice, sent.ID); rec.WithdrawnBy != c.Note {
		t.Errorf("the sent record is not marked: %+v", rec)
	}
}

// A copy with no key, a message sent before auu kept one, and a copy on a
// relay below wire level 3, are each sent the note by the ordinary route,
// and the line says why the relay's copy stays: it does, beside the note.
func TestACopyTheRelayCannotTakeBackIsSentTheNote(t *testing.T) {
	t.Run("no key", func(t *testing.T) {
		relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
		both := peersOn(t, relayURL, "alice", "bob")
		alice, bob := both[0], both[1]
		sent := sentOne(t, alice, "--to", "bob", "from before")
		s := storeOf(t, alice)
		rec := sentRecord(t, alice, sent.ID)
		rec.WithdrawKey = ""
		if err := s.Save(store.Sent, rec); err != nil {
			t.Fatal(err)
		}
		out, _, err := withdrawn(t, alice, sent.ID, "--yes")
		if err != nil || len(out.Copies) != 1 || out.Copies[0].Replaced ||
			!strings.Contains(out.Copies[0].Said, "the relay's copy stays, since it was sent before auu kept the key") {
			t.Fatalf("withdraw: %+v, %v", out, err)
		}
		if rows := relayRows(t, st, bob); len(rows) != 2 {
			t.Errorf("bob's mailbox holds %d rows; want the message and the note", len(rows))
		}
	})
	t.Run("a relay below level 3", func(t *testing.T) {
		srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
		target, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		// The health answer at level 2, as a v0.21 relay gives it.
		proxy.ModifyResponse = func(resp *http.Response) error {
			if resp.Request.URL.Path != "/v1/health" {
				return nil
			}
			var h map[string]any
			dec := json.NewDecoder(resp.Body)
			dec.UseNumber()
			if err := dec.Decode(&h); err != nil {
				return err
			}
			resp.Body.Close()
			h["wire_level"] = 2
			raw, err := json.Marshal(h)
			if err != nil {
				return err
			}
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			resp.ContentLength = int64(len(raw))
			resp.Header.Del("Content-Length")
			return nil
		}
		var withdrawals int
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/withdraw/") {
				withdrawals++
			}
			proxy.ServeHTTP(w, r)
		}))
		defer front.Close()
		both := peersOn(t, front.URL, "alice", "bob")
		alice, bob := both[0], both[1]
		sent := sentOne(t, alice, "--to", "bob", "to an older relay")
		out, _, err := withdrawn(t, alice, sent.ID, "--yes")
		if err != nil || len(out.Copies) != 1 || out.Copies[0].Replaced ||
			!strings.Contains(out.Copies[0].Said, "does not take a message back (its wire level is 2, and 3 does)") {
			t.Fatalf("withdraw: %+v, %v", out, err)
		}
		if withdrawals != 0 {
			t.Errorf("the withdrawal route was asked %d times of a relay at level 2", withdrawals)
		}
		if rows := relayRows(t, st, bob); len(rows) != 2 {
			t.Errorf("bob's mailbox holds %d rows; want the message and the note", len(rows))
		}
	})
}

// A copy sent by a path is sent its note by the same path: the first relay
// queues it for the neighbour, as it queued the message, and the line says
// only the first relay could have been asked to take the message back.
func TestACopyByAPathIsSentItsNoteByThePath(t *testing.T) {
	relayURL, st := forwarding(t, "bar")
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	sent := sentOne(t, alice, "--to", "bar!bob", "over there")
	out, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if err != nil || len(out.Copies) != 1 || out.Copies[0].Replaced ||
		out.Copies[0].Said != "the note went by bar; only the first relay could have been asked to take the message back, and it was not" {
		t.Fatalf("withdraw: %+v, %v", out, err)
	}
	queued, err := st.OutboundFor(alice.exportFingerprint(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 2 {
		t.Fatalf("the first hop queues %d rows from alice; want the message and the note", len(queued))
	}
	if rec := sentRecord(t, alice, out.Copies[0].Note); rec.Path != "bar" {
		t.Errorf("the note's sent record says path %q", rec.Path)
	}
}

// What is refused before anything is sealed, each at exit 1 by its own
// sentence, with the sent box and the outbox as they were: no such sent
// message, a message this home received, a withdrawal note, a message no
// relay took a copy of, a knock, and a message already withdrawn.
func TestWithdrawRefusesBeforeSealing(t *testing.T) {
	relayURL := startRelay(t)
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	received := sentOne(t, bob, "--to", "alice", "from bob")
	alice.run("inbox")
	sent := sentOne(t, alice, "--to", "bob", "withdrawn first")
	first, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	when := sentRecord(t, alice, sent.ID).Withdrawn.Local().Format("Mon, 02 Jan 2006 15:04:05 MST")

	// A message to two who both refuse alice: both copies wait.
	dave := newUser(t, "dave", relayURL)
	erin := newUser(t, "erin", relayURL)
	dave.run("peers", "add", erin.exportLine())
	erin.run("peers", "add", dave.exportLine())
	for _, u := range []*user{dave, erin} {
		alice.run("peers", "add", u.exportLine())
		u.run("allow", "push")
	}
	_, werr := alice.tryRun("send", "--to", "dave", "--to", "erin", "nobody took this")
	if werr == nil {
		t.Fatal("a message to two who refuse alice was sent")
	}
	var waiting string
	for _, p := range outboxListed(t, alice) {
		waiting = p.ID
	}
	// A knock, to a stranger whose card takes knocks.
	frank := newUser(t, "frank", relayURL)
	frank.run("card", "push", "--knocks")
	answerWith(t, "frank\n")
	alice.run("knock", frank.exportFingerprint(), "--yes")
	var knock string
	msgs, err := storeOf(t, alice).List(store.Sent)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Inner.Body.Type == "knock" {
			knock = m.Inner.ID
		}
	}
	if knock == "" || waiting == "" {
		t.Fatalf("the knock %q or the waiting message %q is missing", knock, waiting)
	}

	before := sentAndOutbox(t, alice)
	if _, err := alice.tryRun("withdraw", sent.ID[:12], "--reason", "two\nlines", "--yes"); exitCodeOf(err) != exitUsage ||
		!strings.HasPrefix(err.Error(), "--reason: ") {
		t.Errorf("a reason of two lines: exit %d %v; want the reason's rule at exit 1", exitCodeOf(err), err)
	}
	for _, tc := range []struct{ id, want string }{
		{"abcdabcdabcd", "no message you sent has an id beginning abcdabcdabcd; only a message in your sent box can be withdrawn"},
		{received.ID[:12], "no message you sent has an id beginning " + received.ID[:12] + "; only a message in your sent box can be withdrawn"},
		{first.Copies[0].Note[:12], first.Copies[0].Note[:12] + " is a withdrawal note, which is not withdrawn in its turn"},
		{waiting[:12], "no copy of " + waiting[:12] + " was taken by a relay, so there is nothing to withdraw; " +
			"what waits in the outbox is given up with 'auu outbox drop " + waiting[:12] + "'"},
		{knock[:12], knock[:12] + " is a knock, which cannot be withdrawn"},
		{sent.ID[:12], sent.ID[:12] + " was withdrawn on " + when + ", from everybody a relay took it for"},
	} {
		_, err := alice.tryRun("withdraw", tc.id, "--yes")
		if exitCodeOf(err) != exitUsage || err.Error() != tc.want {
			t.Errorf("withdraw %s: exit %d %v; want exit 1 %q", tc.id, exitCodeOf(err), err, tc.want)
		}
	}
	if !sameFiles(before, sentAndOutbox(t, alice)) {
		t.Error("a refused withdrawal changed the sent box or the outbox")
	}
}

// A message to several with one copy refused: the other is replaced, the
// refused copy's note waits in the outbox with the relay's words, exit 2,
// and send --resume leaves it for auu withdraw. Once the recipient admits
// the sender again, the second run takes up that copy alone and posts the
// note the first sealed, under the same id, sealing no other.
func TestASecondRunTakesUpTheCopyThatFailed(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	users := peersOn(t, relayURL, "alice", "bob", "carol")
	alice, bob, carol := users[0], users[1], users[2]
	out := alice.run("send", "--json", "--to", "bob", "--to", "carol", "to both")
	var many sentManyJSON
	if err := json.Unmarshal([]byte(out), &many); err != nil {
		t.Fatal(err)
	}
	carol.run("peers", "rm", "alice")
	carol.run("allow", "push")

	first, _, err := withdrawn(t, alice, many.ID, "--yes")
	if exitCodeOf(err) != exitTransport || len(first.Copies) != 2 {
		t.Fatalf("the first run: exit %d %v, %+v", exitCodeOf(err), err, first)
	}
	if !first.Copies[0].Replaced || first.Copies[1].Error == "" || !first.Copies[1].Withdrawn.IsZero() {
		t.Fatalf("the first run's copies: %+v", first.Copies)
	}
	waiting := outboxListed(t, alice)
	if len(waiting) != 1 || waiting[0].Kind != "note" || waiting[0].Withdraws != many.ID ||
		waiting[0].ID != first.Copies[1].Note || waiting[0].Refused == "" {
		t.Fatalf("the outbox: %+v", waiting)
	}
	carolRows := len(relayRows(t, st, carol))
	_, stderr, err := tryWithStderr(alice, "send", "--resume")
	if err != nil || !strings.Contains(stderr, "a withdrawal note to carol waits; 'auu withdraw "+many.ID[:12]+"' sends it") {
		t.Errorf("send --resume: %v\n%s", err, stderr)
	}
	if len(relayRows(t, st, carol)) != carolRows || len(outboxListed(t, alice)) != 1 {
		t.Error("send --resume sent the note")
	}
	rec := sentRecord(t, alice, many.ID)
	if rec.WithdrawnBy != first.Copies[0].Note || rec.Copies[0].Withdrawn.IsZero() || !rec.Copies[1].Withdrawn.IsZero() {
		t.Fatalf("the sent record after the first run: %+v", rec)
	}

	// A note left for bob's copy, which is withdrawn, by a run that
	// stopped after the mark: the next run takes it out, carol's copy
	// still refused beside it, and sends bob nothing.
	s, id, _ := alice.opened()
	bobPub, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	env, inner, err := envelope.SealWithdrawal(id, bobPub, "", rec.Inner.Body.Thread, many.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeNote(s, withdrawTarget{fp: bob.exportFingerprint(), name: "bob", relay: "relay"}, "", env, inner, ""); err != nil {
		t.Fatal(err)
	}
	bobRows := len(relayRows(t, st, bob))
	if _, _, err := withdrawn(t, alice, many.ID, "--yes"); exitCodeOf(err) != exitTransport {
		t.Fatalf("a run with carol still refusing: %v", err)
	}
	if left := outboxListed(t, alice); len(left) != 1 || left[0].To != carol.exportFingerprint() || len(relayRows(t, st, bob)) != bobRows {
		t.Fatalf("the note left for bob's withdrawn copy: outbox %+v", left)
	}

	carol.run("peers", "add", alice.exportLine())
	carol.run("allow", "push")
	second, _, err := withdrawn(t, alice, many.ID, "--yes")
	if err != nil || len(second.Copies) != 2 {
		t.Fatalf("the second run: %v, %+v", err, second)
	}
	if second.Copies[0].Said != "withdrawn already" || !second.Copies[0].Withdrawn.Equal(first.Copies[0].Withdrawn) {
		t.Errorf("bob's copy on the second run: %+v", second.Copies[0])
	}
	if !second.Copies[1].Replaced || second.Copies[1].Note != first.Copies[1].Note {
		t.Errorf("carol's copy on the second run: %+v; want the note the first run sealed, %s", second.Copies[1], first.Copies[1].Note)
	}
	if len(outboxListed(t, alice)) != 0 {
		t.Error("the outbox is not empty after the second run")
	}
	if rows := relayRows(t, st, carol); len(rows) != 1 {
		t.Errorf("carol's mailbox holds %d rows; want the note alone", len(rows))
	}
	rec = sentRecord(t, alice, many.ID)
	if rec.Copies[1].Withdrawn.IsZero() || rec.WithdrawnBy != first.Copies[0].Note {
		t.Errorf("the sent record after the second run: %+v", rec)
	}
	_ = bob
}

// A note is sealed only to a peer (F5): a recipient no longer on the peer
// list is said by name at exit 1, and nothing is sealed.
func TestANoteIsSealedOnlyToAPeer(t *testing.T) {
	relayURL := startRelay(t)
	users := peersOn(t, relayURL, "alice", "bob")
	alice := users[0]
	sent := sentOne(t, alice, "--to", "bob", "to somebody since removed")
	alice.run("peers", "rm", "bob")
	out, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if exitCodeOf(err) != exitUsage || len(out.Copies) != 1 || !strings.Contains(out.Copies[0].Error, "is no longer on your peer list") {
		t.Fatalf("withdraw: exit %d %v, %+v", exitCodeOf(err), err, out)
	}
	if left := outboxListed(t, alice); len(left) != 0 {
		t.Errorf("a note was sealed: %+v", left)
	}
}

// The question, declined, writes nothing; asked of a pipe that says yes,
// and with a flag after the id, the message is withdrawn.
func TestTheWithdrawalAsksFirst(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	sent := sentOne(t, alice, "--to", "bob", "--subject", "asked", "think twice")
	before := sentAndOutbox(t, alice)
	answerWith(t, "n\n")
	stdout, err := alice.tryRun("withdraw", sent.ID[:12])
	if exitCodeOf(err) != exitUsage || !strings.Contains(stdout, "withdraw "+sent.ID[:12]+" (asked) from bob?") {
		t.Fatalf("declined: exit %d %v\n%s", exitCodeOf(err), err, stdout)
	}
	if !sameFiles(before, sentAndOutbox(t, alice)) || len(relayRows(t, st, bob)) != 1 {
		t.Fatal("a declined withdrawal changed something")
	}
	answerWith(t, "y\n")
	if out := alice.run("withdraw", sent.ID[:12], "--reason", "second thoughts"); !strings.Contains(out, "bob: replaced on the relay") {
		t.Fatalf("accepted:\n%s", out)
	}
	if rec := sentRecord(t, alice, sent.ID); rec.WithdrawnReason != "second thoughts" {
		t.Errorf("the flag after the id was not read: %+v", rec)
	}
}

// With the keys unlocked only to receive the command exits 4 with the
// agent's sentence, and nothing is sealed.
func TestWithdrawNeedsTheKeysToSend(t *testing.T) {
	relayURL := startRelay(t)
	agentEnv(t)
	users := peersOn(t, relayURL, "alice", "bob")
	alice := users[0]
	sent := sentOne(t, alice, "--to", "bob", "a send before the lock")
	alice.encrypt()
	before := sentAndOutbox(t, alice)
	_, err := alice.tryRun("withdraw", sent.ID, "--yes")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Fatalf("withdraw in receive scope: %v", err)
	}
	if !sameFiles(before, sentAndOutbox(t, alice)) {
		t.Error("a withdrawal refused for the keys changed the sent box or the outbox")
	}
}

// D196: after the 404, a note into a channel closed since is refused as
// any post there is. The copy is not marked, the command says why, at exit
// 2, and the note waits in the outbox with the relay's words.
func TestANoteIntoAChannelClosedSinceIsRefused(t *testing.T) {
	relayURL := startRelay(t)
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	bob.run("channel", "create", "cfp")
	sent := sentOne(t, alice, "--to", "bob", "--channel", "cfp", "a talk")
	bob.run("inbox")
	bob.run("rm", sent.ID[:12])
	bob.run("channel", "close", "cfp")

	out, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if exitCodeOf(err) != exitTransport || len(out.Copies) != 1 {
		t.Fatalf("withdraw: exit %d %v, %+v", exitCodeOf(err), err, out)
	}
	c := out.Copies[0]
	if c.Code != relayapi.CodeChannelClosed || !strings.Contains(c.Error, `channel "cfp" is not open: closed `) || !c.Withdrawn.IsZero() {
		t.Errorf("the copy: %+v", c)
	}
	if rec := sentRecord(t, alice, sent.ID); !rec.Withdrawn.IsZero() {
		t.Error("the copy was marked")
	}
	if left := outboxListed(t, alice); len(left) != 1 || left[0].RefusedCode != relayapi.CodeChannelClosed {
		t.Errorf("the outbox: %+v", left)
	}

	// A channel deleted since: the relay refuses the note there whether or
	// not it still holds the message, and the line says the channel is
	// gone from the recipient's directory.
	bob.run("channel", "create", "talks")
	gone := sentOne(t, alice, "--to", "bob", "--channel", "talks", "another talk")
	bob.run("channel", "delete", "talks")
	out, _, err = withdrawn(t, alice, gone.ID, "--yes")
	want := "the channel talks the message went to is no longer in bob's directory, and a note goes on the message's channel alone"
	if exitCodeOf(err) != exitTransport || len(out.Copies) != 1 || out.Copies[0].Error != want ||
		out.Copies[0].Code != relayapi.CodeNoSuchChannel || !out.Copies[0].Withdrawn.IsZero() {
		t.Errorf("a deleted channel: exit %d %v, %+v", exitCodeOf(err), err, out)
	}
}

// D198: on a closed channel, a note with a reason too large to take the
// message's place is refused note-too-large. The command says the channel
// is closed and that the same withdrawal without --reason fits, at exit 1,
// and does not try that itself; the note is taken out of the outbox, so
// the run without the reason seals one, which takes the message's place.
func TestANoteTooLargeForAClosedChannelSaysToLeaveTheReasonOut(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	bob.run("channel", "create", "cfp")
	sent := sentOne(t, alice, "--to", "bob", "--channel", "cfp", "hi")
	bob.run("channel", "close", "cfp")

	out, _, err := withdrawn(t, alice, sent.ID, "--reason", strings.Repeat("<", withdraw.MaxReasonBytes), "--yes")
	want := `the channel cfp is closed, and the note with this reason is too large to take the message's place there; ` +
		"'auu withdraw " + sent.ID[:12] + "' again without --reason fits"
	if exitCodeOf(err) != exitUsage || len(out.Copies) != 1 || out.Copies[0].Error != want || out.Copies[0].Code != relayapi.CodeNoteTooLarge {
		t.Fatalf("withdraw: exit %d %v, %+v", exitCodeOf(err), err, out)
	}
	if left := outboxListed(t, alice); len(left) != 0 {
		t.Errorf("the refused note waits: %+v", left)
	}
	if rows := relayRows(t, st, bob); len(rows) != 1 || rows[0].ID != sent.RelayID {
		t.Errorf("bob's mailbox: %+v; want the message, untouched, and no note sent without the reason", rows)
	}
	if rec := sentRecord(t, alice, sent.ID); !rec.Withdrawn.IsZero() {
		t.Error("the copy was marked")
	}
	again, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if err != nil || !again.Copies[0].Replaced {
		t.Fatalf("without the reason: %+v, %v", again, err)
	}
}

// A message this home sent itself is withdrawn as any other: the note is
// sealed to this identity, and the inbox copy is marked when it is fetched.
func TestAMessageToSelfIsWithdrawn(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	sent := sentOne(t, alice, "--to", "self", "--subject", "a note to self", "remember")
	alice.run("inbox")
	out, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if err != nil || len(out.Copies) != 1 || !out.Copies[0].Replaced {
		t.Fatalf("withdraw: %+v, %v", out, err)
	}
	alice.run("inbox")
	if held := recordOf(t, alice, store.Inbox, "a note to self"); held.WithdrawnBy != out.Copies[0].Note {
		t.Errorf("the inbox copy is not marked: %+v", held)
	}
}

// A note an earlier run placed and saw marked, still in the outbox because
// the run stopped before the outbox let it go, is taken out by the next
// run, which sends nothing more.
func TestANoteLeftAfterTheMarkIsCleared(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	sent := sentOne(t, alice, "--to", "bob", "--subject", "left", "a note left behind")
	if _, _, err := withdrawn(t, alice, sent.ID, "--yes"); err != nil {
		t.Fatal(err)
	}
	s, id, _ := alice.opened()
	pubs, err := s.Peers()
	if err != nil {
		t.Fatal(err)
	}
	env, inner, err := envelope.SealWithdrawal(id, pubs[0], "", sentRecord(t, alice, sent.ID).Inner.Body.Thread, sent.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeNote(s, withdrawTarget{fp: bob.exportFingerprint(), name: "bob", relay: "relay"}, "", env, inner, ""); err != nil {
		t.Fatal(err)
	}
	if left := outboxListed(t, alice); len(left) != 1 {
		t.Fatalf("the note was not left: %+v", left)
	}
	rows := len(relayRows(t, st, bob))
	if _, err := alice.tryRun("withdraw", sent.ID, "--yes"); exitCodeOf(err) != exitUsage {
		t.Fatalf("withdraw again: %v", err)
	}
	if left := outboxListed(t, alice); len(left) != 0 || len(relayRows(t, st, bob)) != rows {
		t.Errorf("the outbox: %+v; the relay rows changed", left)
	}
}

// TestLimitANoteRecordIsHeldToTheNote: a note's outbox record whose body
// is not the note its record names, or whose message id is not one, is not
// one auu withdraw wrote, and is listed as broken, never posted.
func TestLimitANoteRecordIsHeldToTheNote(t *testing.T) {
	relayURL := startRelay(t)
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	sent := sentOne(t, alice, "--to", "bob", "kept")
	s, id, _ := alice.opened()
	pubs, err := s.Peers()
	if err != nil {
		t.Fatal(err)
	}
	env, inner, err := envelope.SealWithdrawal(id, pubs[0], "", sentRecord(t, alice, sent.ID).Inner.Body.Thread, sent.ID, "why")
	if err != nil {
		t.Fatal(err)
	}
	p, err := writeNote(s, withdrawTarget{fp: bob.exportFingerprint(), name: "bob", relay: "relay"}, "", env, inner, "why")
	if err != nil {
		t.Fatal(err)
	}
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 1 || len(broken) != 0 {
		t.Fatalf("the note as written: %v %v %v", waiting, broken, err)
	}
	for name, change := range map[string]func(*pending){
		"another reason": func(p *pending) { p.Reason = "another" },
		"another text":   func(p *pending) { p.Body.Text += "!" },
		"no message":     func(p *pending) { p.Withdraws = "" },
		"an id one short": func(p *pending) {
			p.Withdraws = p.Withdraws[:31]
			p.Body = withdraw.NoteBody(p.Body.Thread, p.Withdraws, p.Reason)
		},
		"a bad reason": func(p *pending) {
			p.Reason = "two\nlines"
			p.Body = withdraw.NoteBody(p.Body.Thread, p.Withdraws, p.Reason)
		},
		"an ask":                 func(p *pending) { p.Body.Type = "ask" },
		"several":                func(p *pending) { p.RecipientCount = 2 },
		"a path with ESC":        func(p *pending) { p.Path = "\x1b[31mevil" },
		"a refusal of two lines": func(p *pending) { p.Refused = "a\nb" },
	} {
		q := *p
		change(&q)
		if err := q.save(s); err != nil {
			t.Fatal(err)
		}
		if waiting, broken, _ := listPending(s); len(waiting) != 0 || len(broken) != 1 {
			t.Errorf("%s: listed as %d waiting and %d broken; want it broken", name, len(waiting), len(broken))
		}
	}
}

// relayBehind is a relay behind a proxy that passes everything through
// but what refuse says to answer itself.
func relayBehind(t *testing.T, refuse func(w http.ResponseWriter, r *http.Request, proxy http.Handler) bool) (string, *relay.Store) {
	t.Helper()
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse != nil && refuse(w, r, proxy) {
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	return front.URL, st
}

// Condition 1 end to end: the withdrawal route refusing for any reason but
// not-withdrawable, here a 403 the ordinary post would not give, posts
// nothing by the ordinary route. The copy is not marked, the exit is 2,
// and the note waits.
func TestNoRefusalButNotWithdrawableSendsTheNoteAfter(t *testing.T) {
	var on bool
	relayURL, st := relayBehind(t, func(w http.ResponseWriter, r *http.Request, _ http.Handler) bool {
		if on && strings.Contains(r.URL.Path, "/withdraw/") {
			http.Error(w, "not today", http.StatusForbidden)
			return true
		}
		return false
	})
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	sent := sentOne(t, alice, "--to", "bob", "kept")
	on = true
	out, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if exitCodeOf(err) != exitTransport || len(out.Copies) != 1 || out.Copies[0].Error == "" || !out.Copies[0].Withdrawn.IsZero() {
		t.Fatalf("withdraw: exit %d %v, %+v", exitCodeOf(err), err, out)
	}
	if rows := relayRows(t, st, bob); len(rows) != 1 || rows[0].ID != sent.RelayID {
		t.Errorf("bob's mailbox: %+v; want the message alone, no note posted", rows)
	}
	if rec := sentRecord(t, alice, sent.ID); !rec.Withdrawn.IsZero() {
		t.Error("the copy was marked")
	}
	if left := outboxListed(t, alice); len(left) != 1 {
		t.Errorf("the note does not wait: %+v", left)
	}
}

// A note posted by the ordinary route after not-withdrawable, whose answer
// was lost, is posted the same way by the next run: the relay answers the
// repeat, and the line says the note went after the message, never that
// the relay replaced it.
func TestANotePostedAfterIsPostedAfterAgain(t *testing.T) {
	var lose bool
	var bobFP string
	relayURL, st := relayBehind(t, func(w http.ResponseWriter, r *http.Request, proxy http.Handler) bool {
		if lose && r.Method == http.MethodPost && r.URL.Path == "/v1/mailbox/"+bobFP {
			proxy.ServeHTTP(httptest.NewRecorder(), r)
			http.Error(w, "the answer was lost", http.StatusBadGateway)
			return true
		}
		return false
	})
	users := peersOn(t, relayURL, "alice", "bob")
	alice, bob := users[0], users[1]
	bobFP = bob.exportFingerprint()
	sent := sentOne(t, alice, "--to", "bob", "--subject", "lost", "removed")
	bob.run("inbox")
	bob.run("rm", sent.ID[:12])
	lose = true
	first, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if exitCodeOf(err) != exitTransport || first.Copies[0].Error == "" {
		t.Fatalf("the run whose answer was lost: exit %d %v, %+v", exitCodeOf(err), err, first)
	}
	if rows := relayRows(t, st, bob); len(rows) != 1 {
		t.Fatalf("the note was not posted: %+v", rows)
	}
	lose = false
	second, _, err := withdrawn(t, alice, sent.ID, "--yes")
	if err != nil || len(second.Copies) != 1 || second.Copies[0].Replaced ||
		second.Copies[0].Said != afterSaid || second.Copies[0].Note != first.Copies[0].Note {
		t.Fatalf("the next run: %v, %+v", err, second)
	}
	if rows := relayRows(t, st, bob); len(rows) != 1 {
		t.Errorf("bob's mailbox holds %d rows; want the one note", len(rows))
	}
}

// A copy of a message to several that no relay took still waits to be
// sent, so it is a copy not withdrawn: said with the drop that gives it up,
// in --json, at exit 1, beside the copy that is withdrawn; and once every
// copy a relay took is withdrawn, the refusal says the waiting one is
// still there.
func TestACopyNoRelayTookIsNotWithdrawn(t *testing.T) {
	relayURL := startRelay(t)
	users := peersOn(t, relayURL, "alice", "bob")
	alice := users[0]
	dave, erin := newUser(t, "dave", relayURL), newUser(t, "erin", relayURL)
	dave.run("peers", "add", erin.exportLine())
	dave.run("allow", "push")
	alice.run("peers", "add", dave.exportLine())
	out, _ := alice.tryRun("send", "--json", "--to", "bob", "--to", "dave", "half")
	var many sentManyJSON
	if err := json.Unmarshal([]byte(out), &many); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	res, _, err := withdrawn(t, alice, many.ID, "--yes")
	if exitCodeOf(err) != exitUsage || len(res.Copies) != 2 || !res.Copies[0].Replaced ||
		!strings.Contains(res.Copies[1].Error, "no relay took this copy, which still waits to be sent; 'auu outbox drop "+many.ID[:12]+" ") {
		t.Fatalf("withdraw: exit %d %v, %+v", exitCodeOf(err), err, res)
	}
	_, err = alice.tryRun("withdraw", many.ID, "--yes")
	if exitCodeOf(err) != exitUsage || !strings.HasSuffix(err.Error(),
		"from everybody a relay took it for; 1 copy no relay took still waiting in the outbox, which 'auu outbox drop "+many.ID[:12]+" PEER' gives up") {
		t.Errorf("again: %v", err)
	}
}
