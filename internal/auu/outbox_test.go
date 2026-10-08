package auu

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// sealCopies seals one message for several of u's peers with SealMany and
// writes every copy to u's outbox, as a send to several does: the copies
// waiting and nothing posted.
func sealCopies(t *testing.T, u *user, peers ...string) (string, []*pending) {
	t.Helper()
	t.Setenv("AUU_HOME", u.home)
	s, id, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var to []*identity.Public
	for _, name := range peers {
		p, err := s.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		to = append(to, p)
	}
	thread, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	envs, inners, err := envelope.SealMany(id, to, "", message.Body{
		Type: message.TypeAsk, Thread: thread, Subject: "to several", Text: "one message, several copies",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var copies []sealedCopy
	for i := range envs {
		copies = append(copies, sealedCopy{env: envs[i], inner: inners[i], toName: to[i].Name})
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	written, err := writeCopies(s, r, "", copies)
	if err != nil {
		t.Fatal(err)
	}
	return inners[0].ID, written
}

func outboxOf(t *testing.T, u *user) ([]*pending, []string) {
	t.Helper()
	t.Setenv("AUU_HOME", u.home)
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	waiting, broken, err := listPending(s)
	if err != nil {
		t.Fatal(err)
	}
	return waiting, broken
}

func sentBox(t *testing.T, u *user) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(u.home, "sent"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return entries
}

// Three people who know one another, each admitting the other two.
func threePeers(t *testing.T) (alice, bob, carol *user) {
	t.Helper()
	relayURL := startRelay(t)
	alice = newUser(t, "alice", relayURL)
	bob = newUser(t, "bob", relayURL)
	carol = newUser(t, "carol", relayURL)
	for _, u := range []*user{alice, bob, carol} {
		for _, v := range []*user{alice, bob, carol} {
			if u != v {
				u.run("peers", "add", v.exportLine())
			}
		}
		u.run("allow", "push")
	}
	return alice, bob, carol
}

// A copy of a message to several is written to the outbox under the id and
// its recipient's short fingerprint, told from a stream by the sealed file
// beside it; --resume posts every copy, each recipient gets the message,
// and the outbox is empty after. Nothing is written to sent/ here: the
// sent record of a message to several is the sending command's, and
// resuming a copy updates it from commit 4 on.
func TestACopyIsWrittenThenPostedByResume(t *testing.T) {
	alice, bob, carol := threePeers(t)
	id, written := sealCopies(t, alice, "bob", "carol")
	if len(written) != 2 {
		t.Fatalf("%d copies written; want 2", len(written))
	}
	waiting, broken := outboxOf(t, alice)
	if len(waiting) != 2 || len(broken) != 0 {
		t.Fatalf("waiting %d, broken %v; want two copies", len(waiting), broken)
	}
	for _, p := range waiting {
		if p.kind != kindEnvelope || p.stem != copyStem(id, p.To) || p.RecipientCount != 2 {
			t.Errorf("a copy reads as kind %q, stem %q, count %d", p.kind, p.stem, p.RecipientCount)
		}
		if _, err := os.Stat(filepath.Join(alice.home, "outbox", p.stem+".env")); err != nil {
			t.Errorf("no sealed copy beside the record: %v", err)
		}
	}
	before := len(sentBox(t, alice))

	alice.run("send", "--resume")
	if waiting, broken := outboxOf(t, alice); len(waiting) != 0 || len(broken) != 0 {
		t.Fatalf("after --resume: waiting %d, broken %v; want the outbox empty", len(waiting), broken)
	}
	entries, err := os.ReadDir(filepath.Join(alice.home, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the outbox still holds %d files", len(entries))
	}
	if after := len(sentBox(t, alice)); after != before {
		t.Errorf("sent/ went from %d records to %d; resuming a copy writes nothing there in this commit", before, after)
	}
	for _, u := range []*user{bob, carol} {
		if out := u.run("inbox", "--json"); !strings.Contains(out, id) {
			t.Errorf("a recipient's inbox does not hold %s:\n%s", id[:12], out)
		}
	}
}

// A copy the relay refuses stays, with the relay's code and sentence, and
// the rest are posted; the outbox says why it waits; once the recipient
// admits the sender, --resume posts it and it is gone.
func TestARefusedCopyStaysWithTheRelaysWords(t *testing.T) {
	alice, bob, carol := threePeers(t)
	// Carol stops admitting alice.
	carol.run("peers", "rm", "alice")
	carol.run("allow", "push")
	id, _ := sealCopies(t, alice, "bob", "carol")

	// A refused copy is a transport failure to the skill, exit 2, as
	// every final refusal from a relay is.
	_, err := alice.tryRun("send", "--resume")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("--resume with a copy refused: %v; want exit %d", err, exitTransport)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || !strings.HasPrefix(waiting[0].To, carol.exportFingerprint()[:16]) {
		t.Fatalf("waiting %d; want carol's copy alone", len(waiting))
	}
	if waiting[0].Refused == "" {
		t.Errorf("the refused copy kept no sentence")
	}
	if out := bob.run("inbox", "--json"); !strings.Contains(out, id) {
		t.Errorf("bob's copy was not posted beside carol's refusal")
	}
	listing := alice.run("outbox")
	if !strings.Contains(listing, "copy") || !strings.Contains(listing, "refused") || !strings.Contains(listing, waiting[0].Refused) {
		t.Errorf("the outbox does not say why the copy waits:\n%s", listing)
	}
	var asJSON []outboxJSON
	if err := json.Unmarshal([]byte(alice.run("outbox", "--json")), &asJSON); err != nil || len(asJSON) != 1 ||
		asJSON[0].Kind != kindEnvelope || asJSON[0].Refused == "" {
		t.Errorf("outbox --json: %+v, %v", asJSON, err)
	}

	carol.run("peers", "add", alice.exportLine())
	carol.run("allow", "push")
	alice.run("send", "--resume")
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 {
		t.Fatalf("after carol admits alice: %d still waiting", len(waiting))
	}
	if out := carol.run("inbox", "--json"); !strings.Contains(out, id) {
		t.Errorf("carol's copy did not arrive on the resume")
	}
}

// outbox drop: one copy by its id and peer, by the peer's fingerprint, an
// id that matches nothing, an id with several copies and no peer, and a
// prefix too short to be one.
func TestOutboxDropGivesOneUp(t *testing.T) {
	alice, _, carol := threePeers(t)
	id, _ := sealCopies(t, alice, "bob", "carol")

	_, err := alice.tryRun("outbox", "drop", id[:8])
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "has 2 copies waiting, for ") ||
		!strings.Contains(err.Error(), "bob") || !strings.Contains(err.Error(), "carol") {
		t.Fatalf("an id with two copies and no peer: %v; want the usage error naming them", err)
	}
	for _, args := range [][]string{{"outbox", "drop", "abc"}, {"outbox", "drop", "zzzz"}} {
		if _, err := alice.tryRun(args...); !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "four to thirty-two hex characters") {
			t.Errorf("%v: %v; want the id's shape refused", args, err)
		}
	}
	if _, err := alice.tryRun("outbox", "drop", "ffffffff"); !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "nothing in the outbox has an id beginning ffffffff") {
		t.Errorf("an id that matches nothing: %v", err)
	}
	if _, err := alice.tryRun("outbox", "drop", id[:8], "dave"); !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "is for dave") {
		t.Errorf("a peer with no copy: %v", err)
	}

	// The flag after the positional arguments, as every command takes it.
	out := alice.run("outbox", "drop", id[:8], "bob", "--json")
	var dropped outboxJSON
	if err := json.Unmarshal([]byte(out), &dropped); err != nil || dropped.ToName != "bob" || dropped.ID != id {
		t.Fatalf("drop --json: %s, %v", out, err)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || waiting[0].ToName != "carol" {
		t.Fatalf("after dropping bob's copy: %d waiting", len(waiting))
	}
	out = alice.run("outbox", "drop", id, carol.exportFingerprint()[:10])
	if !strings.Contains(out, "dropped the copy of "+id[:12]+" to carol") {
		t.Errorf("drop by fingerprint said %q", out)
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 {
		t.Errorf("%d still waiting after both were dropped", len(waiting))
	}
	entries, _ := os.ReadDir(filepath.Join(alice.home, "outbox"))
	if len(entries) != 0 {
		t.Errorf("drop left %d files in the outbox", len(entries))
	}
}

// Every command that sends says what waits, in one sentence, a kind with
// none left out of it.
func TestWarnPendingCountsEachKind(t *testing.T) {
	alice, _, _ := threePeers(t)
	t.Setenv("AUU_HOME", alice.home)
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	sealCopies(t, alice, "bob", "carol")
	if got := captureStderr(t, func() { warnPending(s) }); !strings.Contains(got,
		"warning: 2 unfinished messages in the outbox (2 copies); finish with 'auu send --resume' or give one up with 'auu outbox drop ID'") {
		t.Errorf("two copies: %q", got)
	}
	writeStreamRecord(t, s, strings.Repeat("b", 32), strings.Repeat("c", 64))
	if got := captureStderr(t, func() { warnPending(s) }); !strings.Contains(got,
		"warning: 3 unfinished messages in the outbox (1 stream, 2 copies);") {
		t.Errorf("a stream and two copies: %q", got)
	}
}

// writeStreamRecord is a stream's record and a sealed file as v0.15.0
// wrote them: the record in v0.15.0's exact keys, none of the new ones.
func writeStreamRecord(t *testing.T, s *store.Store, id, to string) {
	t.Helper()
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(streamPath(s, id), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	record := `{
  "message_id": "` + id + `",
  "to": "` + to + `",
  "to_name": "bob",
  "relay": "default",
  "upload": "` + strings.Repeat("d", 32) + `",
  "started": "2026-10-07T10:00:00Z",
  "time": "2026-10-07T10:00:00Z",
  "body": {"type": "ask", "thread": "` + strings.Repeat("e", 32) + `", "subject": "a big one", "text": "please look"},
  "bytes": 70000,
  "chunks": 2,
  "chunk_size": ` + strconv.Itoa(stream.DefaultChunkSize) + `
}
`
	if err := os.WriteFile(pendingPath(s, id), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A record v0.15.0 wrote reads under this build as the stream it was: no
// required key was added, and the kind is the sealed file beside it.
func TestARecordV0150WroteIsStillAStream(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	writeStreamRecord(t, s, id, strings.Repeat("c", 64))
	waiting, broken, err := listPending(s)
	if err != nil || len(broken) != 0 || len(waiting) != 1 {
		t.Fatalf("waiting %d, broken %v, %v; want v0.15.0's record read", len(waiting), broken, err)
	}
	if p := waiting[0]; p.kind != kindStream || p.name() != id || p.Upload != strings.Repeat("d", 32) {
		t.Errorf("read as kind %q, name %q, upload %q", p.kind, p.name(), p.Upload)
	}
}

// The sealed file is made exclusively: two recipients whose fingerprints
// begin alike would make one file of two copies, and the send is refused by
// name, nothing of it left in the outbox, rather than one copy written over
// another. Real fingerprints cannot be made to collide in a test, so the
// second copy's file is put there first.
func TestTwoCopiesThatWouldShareAFileAreRefused(t *testing.T) {
	alice, _, carol := threePeers(t)
	t.Setenv("AUU_HOME", alice.home)
	s, id, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobPub, _ := s.Resolve("bob")
	carolPub, _ := s.Resolve("carol")
	envs, inners, err := envelope.SealMany(id, []*identity.Public{bobPub, carolPub}, "", message.Body{
		Type: message.TypeAsk, Thread: strings.Repeat("e", 32), Text: "x",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	stand := envPath(s, copyStem(inners[1].ID, carol.exportFingerprint()))
	if err := os.WriteFile(stand, []byte("already here"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, _ := s.DefaultRelay()
	_, err = writeCopies(s, r, "", []sealedCopy{
		{env: envs[0], inner: inners[0], toName: "bob"},
		{env: envs[1], inner: inners[1], toName: "carol"},
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprints begin with "+carol.exportFingerprint()[:16]) {
		t.Fatalf("got %v; want the refusal naming the shared beginning", err)
	}
	entries, _ := os.ReadDir(outboxDir(s))
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the outbox holds %v; want only the file that was there, bob's copy taken back", names)
	}
	if data, _ := os.ReadFile(stand); string(data) != "already here" {
		t.Errorf("the file that stood there was written over")
	}
}

// A kept sentence with ESC in it is not one this program writes: the record
// is broken, never listed, and no 0x1b reaches standard output from
// `auu outbox`; the sentence this program does keep is the relay's
// escaped, cut to relayapi.MaxSaid on a rune boundary.
func TestAKeptRefusalNeverDrivesTheTerminal(t *testing.T) {
	alice, _, _ := threePeers(t)
	sealCopies(t, alice, "bob", "carol")
	waiting, _ := outboxOf(t, alice)
	waiting[0].Refused = "the relay said \x1b]0;owned\x07"
	t.Setenv("AUU_HOME", alice.home)
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := waiting[0].save(s); err != nil {
		t.Fatal(err)
	}
	out := alice.run("outbox")
	if strings.Contains(out, "\x1b") {
		t.Errorf("an ESC reached standard output:\n%q", out)
	}
	if strings.Count(out, "copy ") != 1 {
		t.Errorf("the record with the ESC was listed:\n%s", out)
	}
	if got := keptSentence(&client.HTTPError{Message: "a\x1bb"}); strings.Contains(got, "\x1b") {
		t.Errorf("keptSentence kept an ESC: %q", got)
	}
	// A peer's name read back from a record is held to the name rule, so
	// one with an ESC in it is a record this program did not write: broken,
	// never listed, and never printed, by `auu outbox` or by --resume.
	waiting, _ = outboxOf(t, alice)
	for _, p := range waiting {
		p.ToName = "b\x1b[2Job"
		if err := p.save(s); err != nil {
			t.Fatal(err)
		}
	}
	if waiting, broken := outboxOf(t, alice); len(waiting) != 0 || len(broken) != 2 {
		t.Errorf("records naming their recipient with an ESC: waiting %d, broken %v; want both broken", len(waiting), broken)
	}
	if out := alice.run("outbox"); strings.Contains(out, "\x1b") {
		t.Errorf("a name with an ESC in it reached standard output:\n%q", out)
	}
	// A relay's sentence with a tab in it is kept as a record that reads
	// back: the tab is a space, since a kept sentence is a line.
	if got := keptSentence(&client.HTTPError{Message: "no\tway"}); got != "no way" || message.ValidOneLine("refused", got) != nil {
		t.Errorf("keptSentence of a tab: %q", got)
	}
	long := strings.Repeat("é", relayapi.MaxSaid)
	if got := keptSentence(&client.HTTPError{Message: long}); len(got) > relayapi.MaxSaid || message.ValidOneLine("refused", got) != nil {
		t.Errorf("keptSentence of %d bytes kept %d, or a broken rune", len(long), len(got))
	}
}

// A copy that goes by a path says on its forward how many the message went
// to, for the first relay to hold; a message to one says nothing, and its
// forward is the bytes it always was.
func TestACopysForwardCarriesTheCount(t *testing.T) {
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"error":"stop here","code":""}`))
	}))
	t.Cleanup(srv.Close)
	me, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(srv.URL, me, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &envelope.Envelope{V: envelope.Version, To: strings.Repeat("c", 64), CT: []byte("sealed")}
	for _, n := range []int{0, 3} {
		_, _ = postOrForward(c, env, sendMode{path: []string{"bar"}, recipients: n})
	}
	if len(bodies) != 2 {
		t.Fatalf("%d requests; want 2", len(bodies))
	}
	var one, three relayapi.ForwardRequest
	if err := json.Unmarshal(bodies[0], &one); err != nil || len(one.Sections.Sections) != 0 || strings.Contains(string(bodies[0]), "sections") {
		t.Errorf("a forward to one: %s; want no sections, the bytes it always was", bodies[0])
	}
	if err := json.Unmarshal(bodies[1], &three); err != nil {
		t.Fatal(err)
	}
	data, ok := recipients.Find(three.Sections.Sections, recipients.CountName)
	if n, err := recipients.CheckCount(data); !ok || err != nil || n != 3 {
		t.Errorf("a copy of a message to three: count %d, %v, %v", n, ok, err)
	}
}
