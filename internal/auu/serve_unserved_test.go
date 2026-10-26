package auu

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// An ask on a channel serve does not serve is told which channels it does
// (D178). An ask that arrived on the expert's default, which serve.json did
// not name, sat unread with no word to anybody, and its sender took the
// expert for gone.

// askDefault sends bob an ask with no --channel, which lands on his
// default.
func (u *user) askDefault(t *testing.T, subject, text string) sentJSON {
	t.Helper()
	var sent sentJSON
	if err := json.Unmarshal([]byte(u.run("send", "--to", "bob", "--subject", subject, "--json", text)), &sent); err != nil {
		t.Fatal(err)
	}
	return sent
}

// repliesOn is the ids of every reply alice holds on a thread.
func (u *user) repliesOn(thread string) []string {
	var ids []string
	for _, m := range u.inboxJSON().Messages {
		if m.Type == "reply" && m.Thread == thread {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// unservedSays is the reply's text for an ask on default to an expert
// serving alpha and jostle, with handle's sentence when it has one.
func unservedSays(handled string) string {
	text := `This expert does not answer on channel "default". It answers on these channels: alpha, jostle.`
	if handled != "" {
		text += " It takes jobs on these channels: " + handled + "."
	}
	return text + " Send the ask again on one of them, with --channel NAME. " +
		"This message was not answered and nothing of it was read by the expert."
}

// withAlpha gives bob a second served channel, so that the list is two
// names and its order shows.
func (e *expert) withAlpha(t *testing.T) {
	t.Helper()
	e.config.Channels["alpha"] = &serveChannel{Dir: e.dir, Exec: e.row.Exec, Mode: modeReadOnly}
	e.write(t)
}

// writeHandle puts a handle.json in bob's home whose routes take the given
// channels.
func (e *expert) writeHandle(t *testing.T, channels ...string) {
	t.Helper()
	routes := map[string]any{}
	for _, ch := range channels {
		routes["r-"+ch] = map[string]any{"channel": ch, "command": []string{"true"}}
	}
	data, err := json.Marshal(map[string]any{"v": 1, "routes": routes})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.home, handleFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A peer's ask on a channel no serve.json entry names gets exactly one
// reply, on its thread, naming the served channels sorted; the ask is read,
// its entry says unserved and is on no thread, nothing is made for it, and
// it is nobody's turn. A second round and a restart send nothing more, and
// the console says what was done.
func TestServeTellsAnAskOnAnUnservedChannelWhichChannelsItAnswersOn(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.withAlpha(t)
	marker := filepath.Join(t.TempDir(), "handler-runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:never")
	sent := alice.askDefault(t, "where is it", "the question")

	report := bob.round(t)
	if len(report.Unserved) != 1 || report.Unserved[0] != (handledJSON{ID: sent.ID, Channel: "default", Thread: sent.Thread}) {
		t.Fatalf("the round told %+v; want the ask under default", report.Unserved)
	}
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Fatalf("the round also reported %+v", report)
	}
	replies := alice.repliesOn(sent.Thread)
	if len(replies) != 1 {
		t.Fatalf("alice holds %d replies, want 1", len(replies))
	}
	reply := alice.replyOn(t, sent.Thread)
	if reply.Text != unservedSays("") {
		t.Fatalf("the reply says:\n%s\nwant:\n%s", reply.Text, unservedSays(""))
	}
	if reply.Subject != "where is it" || len(reply.Attachments) != 0 {
		t.Fatalf("the reply is %+v", reply)
	}
	led := bob.ledgerOf(t)
	e := led.Messages[sent.ID]
	if e == nil || e.Unserved != "default" || e.Thread != "" || e.Channel != "" || e.Reply != replies[0] ||
		e.Handled.IsZero() || e.Tried.IsZero() || e.From == "" {
		t.Fatalf("the entry is %+v", e)
	}
	if n := led.answered(sent.Thread); n != 0 {
		t.Fatalf("the ask counts as %d turns on its thread", n)
	}
	if led.tried(sent.Thread) || led.opener(sent.Thread) != "" {
		t.Fatal("the ask opened its thread")
	}
	for _, dir := range []string{
		filepath.Join("serve", "threads", sent.Thread), filepath.Join("serve", "worktrees", sent.Thread),
		filepath.Join("serve", "kept", sent.Thread), filepath.Join("serve", unservedDir, sent.ID),
	} {
		if _, err := os.Lstat(filepath.Join(bob.home, dir)); !os.IsNotExist(err) {
			t.Errorf("%s is there (%v)", dir, err)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("a handler ran for the ask")
	}
	for _, m := range bob.inboxJSON().Messages {
		if m.ID == sent.ID && !m.Read {
			t.Fatal("the ask was left unread")
		}
	}

	if again := bob.round(t); len(again.Unserved)+len(again.Answered)+len(again.Failed) != 0 {
		t.Fatalf("a second round did %+v", again)
	}
	if out := bob.serve(t); out != "nothing to answer\n" {
		t.Fatalf("a restart said %q", out)
	}
	if n := len(alice.repliesOn(sent.Thread)); n != 1 {
		t.Fatalf("alice holds %d replies after two more rounds", n)
	}

	// Without --json the round says it, in one line.
	second := alice.askDefault(t, "and this", "another")
	out := bob.serve(t)
	want := `auu: ` + shortID(second.ID) + ` from alice asked on channel "default", which this expert does not answer on; told it the channels it does (reply `
	if !strings.HasPrefix(out, want) || strings.Count(out, "\n") != 1 {
		t.Fatalf("the round said %q; want a line starting %q", out, want)
	}
}

// With handle.json in the home its routes' channels are named in a second
// sentence (D179), and an ask on one of them is handle's and left alone.
func TestServeNamesHandlesChannelsAndLeavesTheirAsksAlone(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.withAlpha(t)
	bob.writeHandle(t, "delta", "beta", "delta")
	bob.run("channel", "create", "delta")
	sent := alice.askDefault(t, "where is it", "the question")
	handles := alice.ask(t, "delta", "a job", "for handle")

	report := bob.round(t)
	if len(report.Unserved) != 1 || report.Unserved[0].ID != sent.ID {
		t.Fatalf("the round told %+v", report.Unserved)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != unservedSays("beta, delta") {
		t.Fatalf("the reply says:\n%s", reply.Text)
	}
	if bob.ledgerOf(t).Messages[handles.ID] != nil {
		t.Fatal("serve wrote down an ask on a channel handle routes")
	}
	if n := len(alice.repliesOn(handles.Thread)); n != 0 {
		t.Fatalf("an ask on handle's channel was told %d times", n)
	}
}

// handle.json is read every round. While it will not read, nothing can say
// which asks are handle's, so none is told, and that is said once; when it
// reads again the telling resumes.
func TestServeTellsNothingWhileHandleJSONWillNotRead(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.withAlpha(t)
	sent := alice.askDefault(t, "where is it", "the question")
	bob.run("inbox")

	s, id, _ := bob.opened()
	cfg, err := loadServeConfig(bob.path)
	if err != nil {
		t.Fatal(err)
	}
	led, err := loadLedger(filepath.Join(bob.home, "serve", ledgerFile))
	if err != nil {
		t.Fatal(err)
	}
	r := &serveRun{s: s, id: id, cfg: cfg, led: led, root: s.ServeDir(), telling: true}
	if err := os.WriteFile(filepath.Join(bob.home, handleFile), []byte(`{"v":1,"routes":`), 0o600); err != nil {
		t.Fatal(err)
	}
	var pending int
	said := captureStderr(t, func() {
		for range 3 {
			r.handleRead = false
			p, err := r.pending()
			if err != nil {
				t.Error(err)
			}
			pending += len(p)
		}
	})
	if pending != 0 {
		t.Fatalf("%d asks were to be told while handle.json would not read", pending)
	}
	if n := strings.Count(said, "will not read, so an ask on a channel this expert does not answer on is left alone until it does"); n != 1 {
		t.Fatalf("it was said %d times over three rounds:\n%s", n, said)
	}

	bob.writeHandle(t, "beta")
	r.handleRead = false
	if p, err := r.pending(); err != nil || len(p) != 1 || p[0].Inner.ID != sent.ID {
		t.Fatalf("with handle.json read again, pending is %v (%v)", p, err)
	}
	if report := bob.round(t); len(report.Unserved) != 1 {
		t.Fatalf("the round told %+v", report.Unserved)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != unservedSays("beta") {
		t.Fatalf("the reply says:\n%s", reply.Text)
	}
}

// A message that is not a peer's ask is left alone exactly as before: a
// stranger's, which here is a peer removed since it arrived; the owner's
// own, which several agents under one identity send one another (S85); a
// note; a reply serve did not send; and a vouch.
func TestServeTellsOnlyAPeersAsk(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	alice.run("peers", "add", carol.exportLine())

	stranger := carol.askDefault(t, "from somebody", "who is not a peer by the round")
	bob.run("inbox")
	bob.run("peers", "rm", "carol")

	var own sentJSON
	if err := json.Unmarshal([]byte(bob.run("send", "--to", "self", "--subject", "to myself", "--json", "an agent of mine")), &own); err != nil {
		t.Fatal(err)
	}
	var note sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--type", "note", "--subject", "fyi", "--json", "no answer wanted")), &note); err != nil {
		t.Fatal(err)
	}
	var byHand sentJSON
	if err := json.Unmarshal([]byte(bob.run("send", "--to", "alice", "--subject", "by hand", "--json", "mine")), &byHand); err != nil {
		t.Fatal(err)
	}
	alice.run("inbox")
	alice.run("reply", byHand.ID[:12], "answering you, not it")
	alice.run("vouch", "carol", "--to", "bob")

	report, said := bob.roundSaid(t)
	if len(report.Unserved)+len(report.Answered)+len(report.Failed) != 0 {
		t.Fatalf("the round did %+v\n%s", report, said)
	}
	held := map[string]bool{}
	for _, m := range bob.inboxJSON().Messages {
		held[m.ID] = true
	}
	for name, id := range map[string]string{"the stranger's ask": stranger.ID, "the owner's own ask": own.ID, "the note": note.ID} {
		if !held[id] {
			t.Fatalf("%s is not in bob's inbox, so the test proves nothing", name)
		}
	}
	led := bob.ledgerOf(t)
	for name, id := range map[string]string{"the stranger's ask": stranger.ID, "the owner's own ask": own.ID, "the note": note.ID} {
		if led.Messages[id] != nil {
			t.Errorf("%s was written down", name)
		}
	}
	for _, e := range led.Messages {
		if e.Unserved != "" {
			t.Errorf("an entry says unserved: %+v", e)
		}
	}
	if n := len(alice.repliesOn(note.Thread)); n != 0 {
		t.Fatalf("the note was told %d times", n)
	}
}

// A reply to the telling is none of serve's business and said nowhere, so
// two serves pointed at each other exchange one message each way at most
// and stop: here alice is an expert too, on a channel bob does not serve.
func TestServeLeavesAReplyToItsTellingAloneAndSaysNothing(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.withAlpha(t)
	aliceExpert := &expert{user: alice, dir: repo(t), channel: "kestrel"}
	aliceExpert.row = &serveChannel{Dir: aliceExpert.dir, Exec: bob.row.Exec, Mode: modeReadOnly}
	aliceExpert.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"kestrel": aliceExpert.row}}
	aliceExpert.path = filepath.Join(alice.home, serveFile)
	aliceExpert.write(t)
	aliceExpert.serve(t) // her first start

	sent := alice.askDefault(t, "where is it", "the question")
	if r := bob.round(t); len(r.Unserved) != 1 {
		t.Fatalf("bob told %+v", r.Unserved)
	}
	told := alice.replyOn(t, sent.Thread)

	// Her serve takes the telling for what it is, a reply, and leaves it.
	if r, said := aliceExpert.roundSaid(t); len(r.Unserved)+len(r.Answered)+len(r.Failed) != 0 ||
		strings.Contains(said, shortID(told.ID)) || strings.Contains(said, "left alone") {
		t.Fatalf("alice's serve did %+v and said:\n%s", r, said)
	}
	// A follow-up to the telling, by hand, is left alone and said nowhere.
	var follow sentJSON
	if err := json.Unmarshal([]byte(alice.run("reply", told.ID[:12], "--json", "but I meant it")), &follow); err != nil {
		t.Fatal(err)
	}
	r, said := bob.roundSaid(t)
	if len(r.Unserved)+len(r.Answered)+len(r.Failed) != 0 {
		t.Fatalf("the follow-up was taken: %+v", r)
	}
	if strings.Contains(said, shortID(follow.ID)) || strings.Contains(said, "left alone") {
		t.Fatalf("the follow-up was said:\n%s", said)
	}
	if bob.ledgerOf(t).Messages[follow.ID] != nil {
		t.Fatal("the follow-up was written down")
	}
	if n := len(alice.repliesOn(sent.Thread)); n != 1 {
		t.Fatalf("alice holds %d replies on the thread, want the one telling", n)
	}
	if r := bob.round(t); len(r.Unserved)+len(r.Answered) != 0 {
		t.Fatalf("bob's next round did %+v", r)
	}
}

// A first start leaves an ask on an unserved channel alone with the rest of
// the old mail; with --backlog it is told like any other ask in it.
func TestServeTellsTheBacklogOnlyWhenAsked(t *testing.T) {
	for _, backlog := range []bool{false, true} {
		t.Run(map[bool]string{false: "first start", true: "backlog"}[backlog], func(t *testing.T) {
			alice, bob := newExpertCold(t, modeReadOnly)
			bob.withAlpha(t)
			sent := alice.askDefault(t, "old mail", "from before")
			args := []string{}
			if backlog {
				args = append(args, "--backlog")
			}
			var report roundJSON
			captureStderr(t, func() { report = bob.round(t, args...) })
			told := len(report.Unserved)
			if backlog && told != 1 || !backlog && told != 0 {
				t.Fatalf("the round told %+v", report.Unserved)
			}
			e := bob.ledgerOf(t).Messages[sent.ID]
			if backlog && (e == nil || e.Unserved != "default") || !backlog && (e == nil || !e.Skipped || e.Unserved != "") {
				t.Fatalf("the entry is %+v", e)
			}
			if n := len(alice.repliesOn(sent.Thread)); n != told {
				t.Fatalf("alice holds %d replies", n)
			}
		})
	}
}

// A post that fails is the ask's failure, and the next round posts the
// envelope it was sealed as, under the same id (sealOnce, G41, R57), with
// the words it was sealed with though serve.json has gained a channel
// since: words made afresh would be another answer, sealed again.
func TestServeTellsAgainFromTheSameEnvelope(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.withAlpha(t)
	sent := alice.askDefault(t, "where is it", "the question")
	bob.run("inbox")
	_, _, relays := bob.opened()
	target, err := url.Parse(relays[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			http.Error(w, "not now", http.StatusBadRequest)
			return
		}
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	defer refusing.Close()
	repointRelay(t, bob.user, refusing.URL)
	var out string
	said := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once", "--json") })
	if err == nil {
		t.Fatalf("a round whose telling failed exited 0:\n%s", out)
	}
	if !strings.Contains(said, "could not be told so") || !strings.Contains(said, "(attempt 1 of 3)") {
		t.Fatalf("the failure was said as:\n%s", said)
	}
	sealed := filepath.Join(bob.home, "serve", unservedDir, sent.ID, "sealed.json")
	var k keptSeal
	if err := json.Unmarshal([]byte(readFile(t, sealed)), &k); err != nil || k.Inner == nil {
		t.Fatalf("no envelope was kept: %v", err)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.Failures != 1 || e.settled() || e.Unserved != "default" {
		t.Fatalf("the entry after the failure is %+v", e)
	}

	repointRelay(t, bob.user, target.String())
	bob.config.Channels["zeta"] = &serveChannel{Dir: bob.dir, Exec: bob.row.Exec, Mode: modeReadOnly}
	bob.write(t)
	if r := bob.round(t); len(r.Unserved) != 1 {
		t.Fatalf("the retry told %+v", r)
	}
	replies := alice.repliesOn(sent.Thread)
	if len(replies) != 1 || replies[0] != k.Inner.ID {
		t.Fatalf("alice holds %v; want the kept envelope's %s alone", replies, k.Inner.ID)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != unservedSays("") {
		t.Fatalf("the retry says:\n%s", reply.Text)
	}
	if _, err := os.Lstat(filepath.Dir(sealed)); !os.IsNotExist(err) {
		t.Fatalf("the envelope's directory outlived the telling (%v)", err)
	}
}

// The ledger takes the new key and a ledger without it, and holds the key
// to its rules: a channel's name, on no thread or channel of serve's.
func TestALedgerWithAnUnservedEntryIsHeldToItsRules(t *testing.T) {
	id := strings.Repeat("a", 32)
	thread := strings.Repeat("b", 32)
	entry := func(fields string) string {
		return `{"v":1,"messages":{"` + id + `":{` + fields + `}}}`
	}
	for _, tc := range []struct {
		name, text, refused string
	}{
		{"a v0.20.0 entry", entry(`"thread":"` + thread + `","channel":"jostle","handled":"2026-10-20T10:00:00Z","tried":"2026-10-20T10:00:00Z","reply":"` + thread + `","failures":0`), ""},
		{"an unserved entry", entry(`"thread":"","channel":"","handled":"2026-10-26T10:00:00Z","tried":"2026-10-26T10:00:00Z","reply":"` + thread + `","failures":0,"unserved":"default"`), ""},
		{"an unserved name that is no name", entry(`"thread":"","channel":"","tried":"2026-10-26T10:00:00Z","reply":"","failures":0,"unserved":"a\u0001b"`), "which is not a channel's name"},
		{"an unserved entry on a thread", entry(`"thread":"` + thread + `","channel":"","tried":"2026-10-26T10:00:00Z","reply":"","failures":0,"unserved":"default"`), "on a thread or channel of serve's as well"},
		{"an unserved entry on a channel", entry(`"thread":"","channel":"jostle","tried":"2026-10-26T10:00:00Z","reply":"","failures":0,"unserved":"default"`), "on a thread or channel of serve's as well"},
		{"the key in another case", entry(`"thread":"","channel":"","tried":"2026-10-26T10:00:00Z","reply":"","failures":0,"Unserved":"default"`), "only by case"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ledgerFile)
			if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadLedger(path)
			switch {
			case tc.refused == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
				t.Fatalf("%v; want it refused with %q", err, tc.refused)
			}
		})
	}
}

// A home whose serve ran before this release has asks on unserved
// channels in its inbox that nobody was told about. The first round after
// the upgrade writes them down as skipped and says how many, rather than
// telling months of them at once; an ask after it is told. The mark is the
// unserved directory, so the ledger stays one a v0.20.0 serve reads.
func TestServeLeavesTheOldAsksOfAnUpgradedHomeAlone(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.withAlpha(t)
	mark := filepath.Join(bob.home, "serve", unservedDir)
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("a first start made no mark: %v", err)
	}
	// The home as v0.20.0 left it: a ledger, an old ask, and no mark.
	if err := os.Remove(mark); err != nil {
		t.Fatal(err)
	}
	old := alice.askDefault(t, "months ago", "anyone there?")
	report, said := bob.roundSaid(t)
	if len(report.Unserved)+len(report.Answered)+len(report.Failed) != 0 {
		t.Fatalf("the upgrade's round did %+v", report)
	}
	if !strings.Contains(said, "1 ask on channels this expert does not answer on already in the inbox, left alone") {
		t.Fatalf("the upgrade said:\n%s", said)
	}
	if e := bob.ledgerOf(t).Messages[old.ID]; e == nil || !e.Skipped || e.Unserved != "" {
		t.Fatalf("the old ask's entry is %+v", e)
	}
	if n := len(alice.repliesOn(old.Thread)); n != 0 {
		t.Fatalf("the old ask was told %d times", n)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("the upgrade made no mark: %v", err)
	}
	fresh := alice.askDefault(t, "now", "and now?")
	if r := bob.round(t); len(r.Unserved) != 1 || r.Unserved[0].ID != fresh.ID {
		t.Fatalf("the round after told %+v", r.Unserved)
	}
}

// A telling still pending, its post failed, is let go when the ask is not
// to be told any more: its channel served since, which answers it on its
// thread as any ask, or its sender no longer a peer, which leaves it alone.
func TestServeForgetsAPendingTellingThatNoLongerHolds(t *testing.T) {
	for _, change := range []string{"the channel is served", "the sender is not a peer"} {
		t.Run(change, func(t *testing.T) {
			alice, bob := newExpert(t, modeReadOnly)
			bob.run("channel", "create", "elsewhere")
			sent := alice.ask(t, "elsewhere", "a question", "for elsewhere")
			bob.run("inbox")
			_, _, relays := bob.opened()
			target, err := url.Parse(relays[0].URL)
			if err != nil {
				t.Fatal(err)
			}
			refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
					http.Error(w, "not now", http.StatusBadRequest)
					return
				}
				httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
			}))
			defer refusing.Close()
			repointRelay(t, bob.user, refusing.URL)
			captureStderr(t, func() { bob.tryRun("serve", "--once", "--json") })
			if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.Unserved != "elsewhere" || e.settled() {
				t.Fatalf("the failed telling wrote %+v", e)
			}
			repointRelay(t, bob.user, target.String())

			if change == "the channel is served" {
				bob.config.Channels["elsewhere"] = &serveChannel{Dir: bob.dir, Exec: bob.row.Exec, Mode: modeReadOnly}
				bob.write(t)
			} else {
				bob.run("peers", "rm", "alice")
			}
			report, said := bob.roundSaid(t)
			if !strings.Contains(said, shortID(sent.ID)+" from alice was to be told that this expert does not answer on channel \"elsewhere\", which no longer holds; not told") {
				t.Fatalf("the round said:\n%s", said)
			}
			if _, err := os.Lstat(filepath.Join(bob.home, "serve", unservedDir, sent.ID)); !os.IsNotExist(err) {
				t.Fatalf("the kept envelope's directory is still there (%v)", err)
			}
			led := bob.ledgerOf(t)
			e := led.Messages[sent.ID]
			if change == "the sender is not a peer" {
				if e != nil || len(report.Unserved)+len(report.Answered) != 0 {
					t.Fatalf("a stranger's ask: entry %+v, round %+v", e, report)
				}
				return
			}
			if len(report.Answered) != 1 || len(report.Unserved) != 0 {
				t.Fatalf("the round did %+v", report)
			}
			if e == nil || e.Unserved != "" || e.Thread != sent.Thread || e.Channel != "elsewhere" || e.Failures != 0 {
				t.Fatalf("the answered ask's entry is %+v", e)
			}
			if led.answered(sent.Thread) != 1 || led.opener(sent.Thread) != alice.fingerprint() {
				t.Fatalf("the thread counts %d turns and is opened by %q", led.answered(sent.Thread), led.opener(sent.Thread))
			}
			if reply := alice.replyOn(t, sent.Thread); reply.Text != "the expert has spoken" {
				t.Fatalf("alice was answered %q", reply.Text)
			}
		})
	}
}

// A telling is let go for its sender not being a peer only when the peer
// list read and does not hold the sender: a list that will not read says
// nothing of who is a peer, and letting the telling go would seal it
// afresh once the list reads, though a post the relay took with its
// answer lost may already be the asker's.
func TestServeKeepsAPendingTellingWhileThePeerListWillNotRead(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob := newExpert(t, modeReadOnly)
	alice.askDefault(t, "where is it", "the question")
	bob.run("inbox")
	s, id, _ := bob.opened()
	cfg, err := loadServeConfig(bob.path)
	if err != nil {
		t.Fatal(err)
	}
	led, err := loadLedger(filepath.Join(bob.home, "serve", ledgerFile))
	if err != nil {
		t.Fatal(err)
	}
	r := &serveRun{s: s, id: id, cfg: cfg, led: led, root: s.ServeDir(), telling: true}
	msgs, err := s.List(store.Inbox)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("bob's inbox: %d messages (%v)", len(msgs), err)
	}
	var m *store.Stored
	for _, rec := range msgs {
		if rec.Inner.Body.Type == "ask" {
			m = rec
		}
	}
	if m == nil {
		t.Fatal("no ask in bob's inbox")
	}
	peers := filepath.Join(bob.home, "authorized_peers")
	if err := os.Chmod(peers, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(peers, 0o600) })
	if r.untellable(m) {
		t.Fatal("a peer list that will not read let the telling go")
	}
	if err := os.Chmod(peers, 0o600); err != nil {
		t.Fatal(err)
	}
	if r.untellable(m) {
		t.Fatal("a peer list that holds the sender let the telling go")
	}
	bob.run("peers", "rm", "alice")
	if !r.untellable(m) {
		t.Fatal("a peer list without the sender kept the telling")
	}
}
