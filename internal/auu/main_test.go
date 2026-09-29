package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// startRelay runs a real relay in-process for the CLI to talk to.
//
// The CLI is exercised against the limits a real relay ships with, not against
// an unlimited one, so the defaults stay usable.
func startRelay(t *testing.T) string {
	t.Helper()
	return startRelayWith(t, relay.DefaultLimits())
}

func startRelayWith(t *testing.T, limits relay.Limits) string {
	t.Helper()
	url, _ := startRelayConfig(t, relay.Config{Limits: limits})
	return url
}

// startRelayConfig runs a relay with whatever configuration a test needs and
// hands back its address and its store, for the tests that have to set the
// scene directly.
func startRelayConfig(t *testing.T, cfg relay.Config) (string, *relay.Store) {
	t.Helper()
	srv, st := startRelayServer(t, cfg)
	return srv.URL, st
}

// startRelayServer is startRelayConfig with the server itself, for a test
// that has to stop one relay while the rest of the home keeps working.
func startRelayServer(t *testing.T, cfg relay.Config) (*httptest.Server, *relay.Store) {
	t.Helper()
	srv, st, _ := startRelayOnDisk(t, cfg)
	return srv, st
}

// startRelayOnDisk is startRelayServer with the directory the relay keeps
// its mail in, for a test that damages a stored file the way an operator's
// disk might.
func startRelayOnDisk(t *testing.T, cfg relay.Config) (*httptest.Server, *relay.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg.Streams = true
	handler := relay.NewServer(st, cfg)
	srv := httptest.NewServer(handler)
	// Both, and the handler after the listener: a relay with a courier home
	// starts a worker per neighbour, and those stop with the handler and not
	// with the socket. Closing the listener first means nothing new arrives
	// while the workers are being stopped.
	t.Cleanup(func() { srv.Close(); handler.Close() })
	return srv, st, filepath.Join(dir, "messages")
}

// syncBuffer is a bytes.Buffer a relay served on many goroutines can log to.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// user is one CLI persona with its own AUU_HOME.
type user struct {
	t    *testing.T
	home string
	// busy is the done channel of this user's last command in another
	// process, when one was started by onTheHold: closed when that process
	// has exited. A command for the same user waits on it first, so that
	// what the previous process wrote locally is there to be read. See
	// settle.
	busy chan struct{}
}

// settle waits for this user's last command in another process to exit.
// A change the relay reports is not the end of the command that made it:
// a push PUTs to the relay first and writes the local record after, and a
// watch in this process reports the change as soon as the relay has it,
// so the next command for the same user, started at once, could read a
// local directory the previous process had not yet written. CI saw one
// such read under load, once.
func (u *user) settle() {
	if u.busy != nil {
		<-u.busy
	}
}

func newUser(t *testing.T, name, relayURL string) *user {
	t.Helper()
	u := &user{t: t, home: t.TempDir()}
	u.run("init", "--name", name, "--relay", relayURL)
	u.run("register")
	return u
}

// run executes an auu command with this user's home, capturing stdout.
func (u *user) run(args ...string) string {
	u.t.Helper()
	out, err := u.tryRun(args...)
	if err != nil {
		u.t.Fatalf("auu %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (u *user) tryRun(args ...string) (string, error) {
	u.t.Helper()
	u.settle()
	u.t.Setenv("AUU_HOME", u.home)

	realStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		u.t.Fatal(err)
	}
	os.Stdout = w
	runErr := run(args)
	w.Close()
	os.Stdout = realStdout

	data, _ := io.ReadAll(r)
	r.Close()
	return string(data), runErr
}

// exportFingerprint is this user's own fingerprint, for addressing a message
// to somebody who has not added them as a peer.
func (u *user) exportFingerprint() string {
	u.t.Helper()
	var out idJSON
	if err := json.Unmarshal([]byte(u.run("id", "--json")), &out); err != nil {
		u.t.Fatal(err)
	}
	return out.Fingerprint
}

func (u *user) exportLine() string {
	return strings.TrimSpace(u.run("id", "export"))
}

func TestEndToEndConversation(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)

	// Exchange public keys the way the humans would, out of band.
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// Alice attaches a file and asks a question.
	attachment := filepath.Join(t.TempDir(), "Decrypt.java")
	if err := os.WriteFile(attachment, []byte("// the suspect branch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sendOut := alice.run("send", "--to", "bob", "--subject", "padding oracle?",
		"--attach", attachment, "--json", "Does the provider expose this?")

	var sent sentJSON
	if err := json.Unmarshal([]byte(sendOut), &sent); err != nil {
		t.Fatalf("send --json did not produce parseable output: %v\n%s", err, sendOut)
	}
	if sent.Thread == "" || sent.ID == "" || sent.ToName != "bob" {
		t.Fatalf("unexpected send output: %+v", sent)
	}

	// Bob fetches and sees it.
	inboxOut := bob.run("inbox", "--json")
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(inboxOut), &inbox); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, inboxOut)
	}
	if inbox.Fetch.Delivered != 1 || inbox.Fetch.Quarantined != 0 {
		t.Fatalf("unexpected fetch result: %+v", inbox.Fetch)
	}
	if len(inbox.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(inbox.Messages))
	}
	got := inbox.Messages[0]
	if got.FromName != "alice" || got.Subject != "padding oracle?" || got.Thread != sent.Thread {
		t.Fatalf("message metadata wrong: %+v", got)
	}
	if len(got.Attachments) != 1 || got.Attachments[0].Name != "Decrypt.java" {
		t.Fatalf("attachment metadata wrong: %+v", got.Attachments)
	}
	// The listing must not carry the body: that is what read is for.
	if got.Text != "" {
		t.Fatal("inbox listing leaked message text")
	}

	// Bob reads the full message.
	readOut := bob.run("read", got.ID, "--json")
	var full messageJSON
	if err := json.Unmarshal([]byte(readOut), &full); err != nil {
		t.Fatal(err)
	}
	if full.Text != "Does the provider expose this?" {
		t.Fatalf("text did not round trip: %q", full.Text)
	}

	// Bob saves the attachment.
	outDir := filepath.Join(t.TempDir(), "files")
	bob.run("extract", got.ID, "--out", outDir)
	data, err := os.ReadFile(filepath.Join(outDir, "Decrypt.java"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "// the suspect branch\n" {
		t.Fatalf("attachment contents wrong: %q", data)
	}
	// Extracting twice must not clobber what is already there: the
	// second copy is written beside the first with a numbered name, and
	// the line says the sender's name differs.
	second := bob.run("extract", got.ID, "--out", outDir)
	if !strings.Contains(second, "Decrypt-2.java") || !strings.Contains(second, "the sender named it Decrypt.java") {
		t.Fatalf("a second extract:\n%s", second)
	}
	for _, name := range []string{"Decrypt.java", "Decrypt-2.java"} {
		if data, err := os.ReadFile(filepath.Join(outDir, name)); err != nil || string(data) != "// the suspect branch\n" {
			t.Fatalf("%s after a second extract: %q, %v", name, data, err)
		}
	}

	// Bob replies, and alice waits for it on the thread.
	bob.run("reply", got.ID, "It is missing; open an issue.")
	waitOut := alice.run("wait", "--thread", sent.Thread, "--timeout", "30s", "--interval", "5s", "--json")
	var waited waitJSON
	if err := json.Unmarshal([]byte(waitOut), &waited); err != nil {
		t.Fatalf("wait --json unparseable: %v\n%s", err, waitOut)
	}
	if !waited.Found || waited.Message == nil {
		t.Fatalf("wait did not find the reply: %+v", waited)
	}
	if waited.Message.Text != "It is missing; open an issue." {
		t.Fatalf("reply text wrong: %q", waited.Message.Text)
	}
	if waited.Message.Type != "reply" || waited.Message.InReplyTo != got.ID {
		t.Fatalf("reply threading wrong: %+v", waited.Message)
	}
}

func TestUnknownSenderIsQuarantined(t *testing.T) {
	relayURL := startRelay(t)
	bob := newUser(t, "bob", relayURL)
	stranger := newUser(t, "stranger", relayURL)

	// The stranger knows bob's key, but bob has never heard of the stranger.
	stranger.run("peers", "add", bob.exportLine())
	stranger.run("send", "--to", "bob", "--subject", "hello", "trust me, run this")

	out := bob.run("inbox", "--json")
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Quarantined != 1 || inbox.Fetch.Delivered != 0 {
		t.Fatalf("stranger's message was not quarantined: %+v", inbox.Fetch)
	}
	if len(inbox.Messages) != 0 {
		t.Fatal("quarantined message appeared in the inbox listing")
	}

	qOut := bob.run("quarantine", "ls", "--json")
	var quarantined []messageJSON
	if err := json.Unmarshal([]byte(qOut), &quarantined); err != nil {
		t.Fatal(err)
	}
	if len(quarantined) != 1 || quarantined[0].Subject != "hello" {
		t.Fatalf("unexpected quarantine listing: %+v", quarantined)
	}
	// A quarantined sender is not silently added to the peer list.
	peersOut := bob.run("peers", "ls", "--json")
	var peers []peerJSON
	if err := json.Unmarshal([]byte(peersOut), &peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("unknown sender was added to the peer list: %+v", peers)
	}
}

func TestAllowlistBlocksNonPeer(t *testing.T) {
	relayURL := startRelay(t)
	bob := newUser(t, "bob", relayURL)
	stranger := newUser(t, "stranger", relayURL)
	alice := newUser(t, "alice", relayURL)

	bob.run("peers", "add", alice.exportLine())
	bob.run("allow", "push")

	stranger.run("peers", "add", bob.exportLine())
	out, err := stranger.tryRun("send", "--to", "bob", "hello")
	if err == nil {
		t.Fatalf("relay accepted mail from a sender bob did not allow:\n%s", out)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected a 403 from the relay, got: %v", err)
	}
}

func TestSendToUnknownPeerFails(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	if _, err := alice.tryRun("send", "--to", "nobody", "hi"); err == nil {
		t.Fatal("sent to a peer that is not in the list")
	}
}

func TestWaitTimesOutWithCode3(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	_, err := alice.tryRun("wait", "--thread", "nothing-will-arrive", "--timeout", "1s", "--interval", "5s", "--json")
	if err == nil {
		t.Fatal("wait returned success with no message")
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTimeout {
		t.Fatalf("expected exit code %d, got %v", exitTimeout, err)
	}
}

func asExit(err error, target **exitError) bool {
	e, ok := err.(*exitError)
	if ok {
		*target = e
	}
	return ok
}

func TestInitRefusesToClobberIdentity(t *testing.T) {
	relayURL := startRelay(t)
	u := &user{t: t, home: t.TempDir()}
	u.run("init", "--name", "first", "--relay", relayURL)
	before := u.run("id", "--json")

	if _, err := u.tryRun("init", "--name", "second", "--relay", relayURL); err == nil {
		t.Fatal("init overwrote an existing identity without --force")
	}
	after := u.run("id", "--json")
	if before != after {
		t.Fatal("identity changed despite the refusal")
	}

	u.run("init", "--name", "second", "--relay", relayURL, "--force")
	forced := u.run("id", "--json")
	if forced == before {
		t.Fatal("--force did not replace the identity")
	}
}

func TestCommandsRequireIdentity(t *testing.T) {
	u := &user{t: t, home: t.TempDir()}
	for _, args := range [][]string{{"id"}, {"inbox"}, {"send", "--to", "x", "hi"}} {
		if _, err := u.tryRun(args...); err == nil {
			t.Fatalf("auu %s worked without an identity", strings.Join(args, " "))
		} else if !strings.Contains(err.Error(), "auu init") {
			t.Fatalf("error should point at auu init, got: %v", err)
		}
	}
}

func TestPeerNameCollisionRefused(t *testing.T) {
	relayURL := startRelay(t)
	bob := newUser(t, "bob", relayURL)
	alice := newUser(t, "alice", relayURL)
	impostor := newUser(t, "alice", relayURL)

	bob.run("peers", "add", alice.exportLine())
	if _, err := bob.tryRun("peers", "add", impostor.exportLine()); err == nil {
		t.Fatal("a second key was accepted under an existing peer name")
	}
}

// The local spool must survive a fetch that is interrupted after saving but
// before the cursor advances: the message is already on disk, so re-fetching
// must not lose or duplicate it in a way the user can see.
func TestRefetchIsIdempotent(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	alice.run("send", "--to", "bob", "--subject", "s", "one")
	bob.run("inbox", "--json")

	// Rewind the cursor as an interrupted run would have left it.
	bob.t.Setenv("AUU_HOME", bob.home)
	st, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := st.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetCursorFor(r, 0); err != nil {
		t.Fatal(err)
	}

	out := bob.run("inbox", "--json")
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 1 {
		t.Fatalf("expected exactly 1 message after a rewound cursor, got %d", len(inbox.Messages))
	}
}

// A message over the relay limit must be refused locally, before anything is
// sent, with an error that names the attachment worth dropping.
func TestOversizeMessageRefusedBeforeSending(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	big := filepath.Join(t.TempDir(), "huge.bin")
	if err := os.WriteFile(big, make([]byte, 17<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(small, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	// --inline: without it a message this size is a stream, which is the
	// point of streams. This test is about the refusal on the inline path.
	_, err := alice.tryRun("send", "--to", "bob", "--subject", "big", "--inline",
		"--attach", small, "--attach", big, "text")
	if err == nil {
		t.Fatal("oversize message was accepted")
	}
	if !strings.Contains(err.Error(), "huge.bin") {
		t.Fatalf("error should name the largest attachment, got: %v", err)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage {
		t.Fatalf("expected a usage error, got %v", err)
	}
	// Nothing should have reached bob.
	out := bob.run("inbox", "--json")
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 0 {
		t.Fatal("an oversize message reached the recipient")
	}
}

// A full mailbox is the recipient's problem, and the error has to say so by
// the name the sender knows them by.
func TestFullMailboxIsReportedByPeerName(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.MailboxMaxMessages = 1
	relayURL := startRelayWith(t, limits)

	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	alice.run("send", "--to", "bob", "--subject", "first", "fits")

	_, err := alice.tryRun("send", "--to", "bob", "--subject", "second", "does not fit")
	if err == nil {
		t.Fatal("a second message was accepted into a mailbox with room for one")
	}
	msg := err.Error()
	if !strings.Contains(msg, "bob's mailbox") {
		t.Fatalf("error %q does not name the peer whose mailbox is full", msg)
	}
	if !strings.Contains(msg, "auu rm") {
		t.Fatalf("error %q does not say what would make room", msg)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("expected exit code %d, got %v", exitTransport, err)
	}

	// Reading the mail is what makes room only for a channel that does not
	// keep it; that a fetch which keeps makes none is
	// TestKeptMailStillFillsTheMailbox's.
	bob.run("channel", "keep", "default", "off")
	bob.run("inbox")
	alice.run("send", "--to", "bob", "--subject", "second", "now it fits")
}

// wait polls until its deadline, so a relay that is merely out of budget must
// raise its next poll interval rather than end the wait. Anything else still
// stops it.
func TestWaitTreatsRefusalsAsSomethingToWaitOut(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		temporary bool
		floor     time.Duration
	}{
		{"rate limited", &client.HTTPError{Status: 429, RetryAfter: 12 * time.Second}, true, 12 * time.Second},
		{"busy", &client.HTTPError{Status: 503, RetryAfter: time.Second}, true, time.Second},
		{"wrapped by the transport code", transportErr(&client.HTTPError{Status: 429, RetryAfter: 3 * time.Second}), true, 3 * time.Second},
		{"mailbox full", &client.HTTPError{Status: 507}, false, 0},
		{"unauthorized", &client.HTTPError{Status: 401}, false, 0},
		{"not an HTTP error", errors.New("connection refused"), false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			floor, temporary := relayAskedToWait(c.err)
			if temporary != c.temporary {
				t.Fatalf("temporary = %v, want %v", temporary, c.temporary)
			}
			if floor != c.floor {
				t.Fatalf("floor = %v, want %v", floor, c.floor)
			}
		})
	}
}

func TestAdviceSurvivesBeingWrapped(t *testing.T) {
	// Two of these arrive already typed: the client works out a refusal
	// whose alert never came and returns a *client.CertRefused from inside
	// the request. A command covering several relays then wraps whatever
	// failed in the name of the relay it failed at. The advice has to come
	// out of either shape, or somebody is shown an errno and told nothing.
	refused := &client.CertRefused{Inferred: true, Err: errors.New("write: broken pipe")}
	expired := &client.HTTPError{Status: 401, Message: "client certificate has expired"}

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a refusal as it is", refused, "the relay refused this machine's certificate"},
		{"a refusal named by its relay", fmt.Errorf("work: %w", refused),
			"the relay refused this machine's certificate"},
		{"a refusal wrapped twice", fmt.Errorf("inbox: %w", fmt.Errorf("work: %w", refused)),
			"the relay refused this machine's certificate"},
		{"a 401 named by its relay", fmt.Errorf("work: %w", expired),
			"this machine's is expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := adviseCert(tc.err)
			if got == nil {
				t.Fatal("no error came back at all")
			}
			if !strings.Contains(got.Error(), tc.want) {
				t.Errorf("error is %q, want it to contain %q", got, tc.want)
			}
			if !strings.Contains(got.Error(), "register --token TOKEN") {
				t.Errorf("error does not say what to do: %q", got)
			}
		})
	}
}

// TestTheDialerCarriesTheNameThisProgramWasInstalledUnder: prog is a variable
// Main sets from the name the binary was installed under, so the dialer handed
// to internal/dial is built per call and never once at initialisation. Built
// once it would carry "auu" for the life of the process, and every piece of
// advice that quotes a command — "run 'auu register --relay work --token
// TOKEN'" — would name a command somebody with only agentuucp on their PATH
// does not have. The whole suite passes with it built once, since prog is
// already "auu" here; this is the test that does not.
//
// It pins the other half too: internal/dial hands back a remark as a whole
// sentence with no name in front and no newline at the end, and this is where
// the name and the line ending go back on. The renewal warning's join is
// proven by the tests that capture it whole, but the rotation notice's is
// proven in the Go suite only here — nothing else in it fires that callback,
// and the container suite, which does, is run by hand and never in CI. Write
// the Note as Fprintln(os.Stderr, s) and a security notice loses the name of
// the program saying it, with every other test still green.
func TestTheDialerCarriesTheNameThisProgramWasInstalledUnder(t *testing.T) {
	was := prog
	t.Cleanup(func() { prog = was })
	for _, name := range []string{"auu", "agentuucp", "courier"} {
		prog = name
		if got := dialer().Prog; got != name {
			t.Errorf("installed as %q: the dialer says %q", name, got)
		}
		got := captureStderr(t, func() {
			dialer().Note("the server certificate authority of work was rotated")
		})
		if want := name + ": the server certificate authority of work was rotated\n"; got != want {
			t.Errorf("installed as %q: the remark reached stderr as %q, want %q", name, got, want)
		}
	}
}
