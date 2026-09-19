package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// One home, two relays. Every test here runs two real relays in-process and
// drives the CLI, because the whole feature is about which of them a command
// went to, and only a real second relay can tell that apart from nothing.

// onBothRelays makes a user registered on two relays, called work and personal, with
// work the default because it was added first.
func onBothRelays(t *testing.T, name, work, personalURL string) *user {
	t.Helper()
	u := &user{t: t, home: t.TempDir()}
	u.run("init", "--name", name, "--relay", work)
	u.run("register")
	// The default name is the URL's host, which for two relays on one machine
	// is the same host twice. Naming them is what a person does anyway.
	u.run("relay", "rename", u.defaultRelayName(), "work")
	u.run("relay", "add", personalURL, "--name", "personal")
	u.run("register", "--relay", "personal")
	return u
}

func (u *user) defaultRelayName() string {
	u.t.Helper()
	var out idJSON
	if err := json.Unmarshal([]byte(u.run("id", "--json")), &out); err != nil {
		u.t.Fatal(err)
	}
	if out.RelayName == "" {
		u.t.Fatal("this home has no default relay")
	}
	return out.RelayName
}

func (u *user) relayList() []relayJSON {
	u.t.Helper()
	var out []relayJSON
	if err := json.Unmarshal([]byte(u.run("relay", "ls", "--json")), &out); err != nil {
		u.t.Fatal(err)
	}
	return out
}

// stored reads a message straight out of the spool, for the assertions about
// which relay it came through.
func (u *user) stored(box store.Box, id string) *store.Stored {
	u.t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		u.t.Fatal(err)
	}
	m, err := s.Load(box, id)
	if err != nil {
		u.t.Fatal(err)
	}
	return m
}

func (u *user) inboxJSON(args ...string) inboxJSON {
	u.t.Helper()
	var out inboxJSON
	if err := json.Unmarshal([]byte(u.run(append([]string{"inbox", "--json"}, args...)...)), &out); err != nil {
		u.t.Fatal(err)
	}
	return out
}

func TestSelectionIsFlagThenEnvironmentThenDefault(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)

	name := func(args ...string) string {
		t.Helper()
		var out certStatusOutput
		if err := json.Unmarshal([]byte(alice.run(args...)), &out); err != nil {
			t.Fatal(err)
		}
		return out.RelayName
	}

	// The default, when nothing says otherwise.
	if got := name("cert", "status", "--json"); got != "work" {
		t.Errorf("with nothing set, the relay is %q, want work", got)
	}
	// The flag, before and after a positional argument.
	if got := name("cert", "status", "--json", "--relay", "personal"); got != "personal" {
		t.Errorf("--relay personal gave %q", got)
	}
	// The environment, when there is no flag.
	alice.t.Setenv("AUU_RELAY", "personal")
	if got := name("cert", "status", "--json"); got != "personal" {
		t.Errorf("AUU_RELAY=personal gave %q", got)
	}
	// And the flag beats the environment.
	if got := name("cert", "status", "--json", "--relay", "work"); got != "work" {
		t.Errorf("--relay work under AUU_RELAY=personal gave %q", got)
	}
	alice.t.Setenv("AUU_RELAY", "")

	// A flag after the positional argument is still a flag: parseArgs exists
	// because it once was not.
	out := alice.run("relay", "show", "personal", "--json")
	var shown relayJSON
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Name != "personal" {
		t.Errorf("relay show personal --json gave %q", shown.Name)
	}

	// A name that matches nothing says what the home has.
	_, err := alice.tryRun("cert", "status", "--relay", "nowhere")
	if err == nil {
		t.Fatal("an unknown relay name was accepted")
	}
	for _, want := range []string{"no such relay", "personal", "work"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}

	// With no default at all, the message says exactly what to do, and what
	// the choices are.
	alice.run("relay", "rm", "work", "--yes")
	_, err = alice.tryRun("cert", "status")
	if err == nil {
		t.Fatal("a home with no default relay picked one anyway")
	}
	const want = "no relay selected: pass --relay NAME, set AUU_RELAY, " +
		"or run 'auu relay default NAME'; this home has personal"
	if err.Error() != want {
		t.Errorf("error is\n %q\nwant\n %q", err, want)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage {
		t.Errorf("exit code %v, want %d", err, exitUsage)
	}
}

func TestInboxFetchesEveryRelayAndSurvivesOneBeingDown(t *testing.T) {
	workSrv, _ := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bcSrv, _ := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", workSrv.URL, bcSrv.URL)
	bob := onBothRelays(t, "bob", workSrv.URL, bcSrv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	bob.run("send", "--to", "alice", "--relay", "work", "--subject", "at work", "one")
	bob.run("send", "--to", "alice", "--relay", "personal", "--subject", "at personal", "two")

	// One command, both relays, each with its own cursor.
	got := alice.inboxJSON()
	if got.Fetch.Delivered != 2 {
		t.Fatalf("fetched %d of 2 messages: %+v", got.Fetch.Delivered, got)
	}
	if len(got.Relays) != 2 {
		t.Fatalf("--json reports %d relays, want 2", len(got.Relays))
	}
	byRelay := map[string]relayFetch{}
	for _, r := range got.Relays {
		byRelay[r.Relay] = r
	}
	if byRelay["work"].Delivered != 1 || byRelay["personal"].Delivered != 1 {
		t.Errorf("the messages are not one from each relay: %+v", got.Relays)
	}
	for _, m := range got.Messages {
		want := "work"
		if m.Subject == "at personal" {
			want = "personal"
		}
		if relay := alice.stored(store.Inbox, m.ID).Relay; relay != want {
			t.Errorf("%q was recorded as arriving through %q, want %q", m.Subject, relay, want)
		}
	}
	// Independent cursors: each relay's counter starts at one, so a shared
	// cursor would have skipped the second message.
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"work", "personal"} {
		r, err := s.Relay(name)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := s.CursorFor(r); err != nil || n == 0 {
			t.Errorf("%s's cursor is %d %v, want it to have advanced", name, n, err)
		}
	}

	// personal goes away. The mail on work still arrives, the command succeeds,
	// and stderr says which relay could not be reached.
	bcSrv.Close()
	bob.run("send", "--to", "alice", "--relay", "work", "--subject", "still working", "three")

	var after inboxJSON
	warning := captureStderr(t, func() { after = alice.inboxJSON() })
	if after.Fetch.Delivered != 1 {
		t.Errorf("with one relay down, fetched %d of 1: %+v", after.Fetch.Delivered, after)
	}
	if !strings.Contains(warning, "personal could not be reached") {
		t.Errorf("stderr does not name the relay that was down:\n%s", warning)
	}
	var down bool
	for _, r := range after.Relays {
		if r.Relay == "personal" && r.Error != "" {
			down = true
		}
	}
	if !down {
		t.Errorf("--json does not say why personal gave nothing: %+v", after.Relays)
	}

	// Narrowed to the relay that is down, a failure is the command's failure.
	_, err = alice.tryRun("inbox", "--relay", "personal")
	if err == nil {
		t.Fatal("inbox --relay on a relay that is down reported success")
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Errorf("exit code %v, want %d", err, exitTransport)
	}
}

func TestAReplyGoesBackTheWayTheMessageCame(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)
	bob := onBothRelays(t, "bob", work, personalURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	// Bob writes through personal, which is not alice's default.
	bob.run("send", "--to", "alice", "--relay", "personal", "--subject", "over here", "hello")
	first := alice.inboxJSON()
	if len(first.Messages) != 1 {
		t.Fatalf("alice has %d messages", len(first.Messages))
	}
	id := first.Messages[0].ID

	// She replies without saying where. It goes back through personal.
	alice.run("reply", id, "answering")
	if got := alice.inboxJSON("--relay", "work").Fetch.Delivered; got != 0 {
		t.Errorf("work delivered %d messages after a reply meant for personal", got)
	}
	viaPersonal := bob.inboxJSON("--relay", "personal")
	if viaPersonal.Fetch.Delivered != 1 {
		t.Fatalf("bob got %d replies on personal, want 1", viaPersonal.Fetch.Delivered)
	}
	sent := alice.stored(store.Sent, viaPersonal.Messages[0].ID)
	if sent.Relay != "personal" {
		t.Errorf("the sent copy records relay %q, want personal", sent.Relay)
	}

	// --relay overrides it: the same thread, sent the other way.
	alice.run("reply", id, "--relay", "work", "and again")
	if got := bob.inboxJSON("--relay", "work").Fetch.Delivered; got != 1 {
		t.Errorf("work delivered %d replies after --relay work, want 1", got)
	}

	// A message stored before a home could know more than one relay has no
	// relay recorded. It is taken to have come through the default, which is
	// where it did come from.
	stripRelay(t, alice, store.Inbox, id)
	alice.run("reply", id, "from the old days")
	if got := bob.inboxJSON("--relay", "work").Fetch.Delivered; got != 1 {
		t.Errorf("a message with no relay recorded did not go to the default: %d", got)
	}
}

// stripRelay rewrites a stored message as an older build would have written
// it, with no relay recorded.
func stripRelay(t *testing.T, u *user, box store.Box, id string) {
	t.Helper()
	path := filepath.Join(u.home, string(box), id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "relay")
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestASendThatMissesSaysWhereElseToLook(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)

	// Bob is on personal only.
	bob := &user{t: t, home: t.TempDir()}
	bob.run("init", "--name", "bob", "--relay", personalURL)
	bob.run("register")
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	bob.run("send", "--to", "alice", "--subject", "hello", "from personal")
	alice.inboxJSON()

	// Alice writes back with her default, where bob has no mailbox.
	_, err := alice.tryRun("send", "--to", "bob", "--relay", "work", "nothing doing")
	if err == nil {
		t.Fatal("a send to somebody with no mailbox there reported success")
	}
	const want = "bob is not registered on work; mail from bob has arrived through personal"
	if err.Error() != want {
		t.Errorf("error is\n %q\nwant\n %q", err, want)
	}
	// And with the flag it works, which is the point of saying so.
	alice.run("send", "--to", "bob", "--relay", "personal", "there you are")
}

func TestEnrolAddsTheTokensRelayAndOnlyTheFirstBecomesDefault(t *testing.T) {
	firstURL, issueFirst := tokenRelay(t)
	secondURL, issueSecond := tokenRelay(t)

	bob := &user{t: t, home: t.TempDir()}
	bob.run("enrol", "--name", "bob", "--yes", issueFirst(nil))
	if got := bob.defaultRelayName(); got == "" {
		t.Fatal("the first enrolment set no default")
	}
	firstName := bob.defaultRelayName()

	fingerprint := bob.fingerprint()
	out := bob.run("enrol", "--name", "bob", "--yes", issueSecond(nil))
	if !strings.Contains(out, "registered") {
		t.Fatalf("the second enrolment did not register:\n%s", out)
	}
	if bob.fingerprint() != fingerprint {
		t.Fatal("enrolling on a second relay made a second identity")
	}
	if got := bob.defaultRelayName(); got != firstName {
		t.Errorf("the second relay took the default: %q", got)
	}
	// It also says so, because a person who did not notice would send their
	// next message to the wrong place.
	if !strings.Contains(out, "still use "+firstName) {
		t.Errorf("the second enrolment does not say which relay stays the default:\n%s", out)
	}

	list := bob.relayList()
	if len(list) != 2 {
		t.Fatalf("the home has %d relays, want 2", len(list))
	}
	urls := map[string]bool{}
	for _, r := range list {
		urls[r.URL] = true
		if !r.Registered {
			t.Errorf("%s is not marked registered", r.Name)
		}
	}
	if !urls[firstURL] || !urls[secondURL] {
		t.Errorf("the relays are %v, want both tokens' relays", urls)
	}

	// Enrolling again on a relay the home already has is re-registering, not
	// a third relay.
	bob.run("enrol", "--name", "bob", "--yes", issueSecond(nil))
	if got := len(bob.relayList()); got != 2 {
		t.Errorf("re-enrolling made %d relays", got)
	}
}

func TestInitForceKeepsAnchorsAndDropsCertificates(t *testing.T) {
	url, bundle := startAnchoredRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("init", "--name", "alice", "--relay", url, "--anchor", bundle.AnchorSPKI)
	alice.run("register")

	before := alice.relayList()
	if len(before) != 1 || before[0].Anchor != bundle.AnchorSPKI {
		t.Fatalf("the relay was not pinned: %+v", before)
	}
	name := before[0].Name

	// A new identity in the same home. The relay and what makes it
	// verifiable are the relay's; the certificate and the cursor were the
	// old identity's and go with it.
	old := alice.fingerprint()
	alice.run("init", "--name", "alice", "--force")
	if alice.fingerprint() == old {
		t.Fatal("--force did not replace the identity")
	}
	after := alice.relayList()
	if len(after) != 1 || after[0].Name != name {
		t.Fatalf("--force lost the relay: %+v", after)
	}
	if after[0].Anchor != bundle.AnchorSPKI {
		t.Errorf("--force discarded the pinned anchor: %+v", after[0])
	}
	if after[0].CertSerial != "" {
		t.Errorf("--force kept the old identity's certificate: %+v", after[0])
	}
	if after[0].Registered {
		t.Error("--force left the home believing the new identity has a mailbox")
	}
	// And the new identity can register on it, which is the point of
	// keeping the anchor.
	alice.run("register")
}

func TestAllowPushReachesEveryRelay(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)
	bob := onBothRelays(t, "bob", work, personalURL)
	stranger := onBothRelays(t, "stranger", work, personalURL)
	alice.run("peers", "add", bob.exportLine())
	stranger.run("peers", "add", alice.exportLine())

	out := alice.run("allow", "push")
	for _, want := range []string{"work will now accept", "personal will now accept"} {
		if !strings.Contains(out, want) {
			t.Errorf("allow push does not report %q:\n%s", want, out)
		}
	}
	for _, r := range []string{"work", "personal"} {
		if _, err := stranger.tryRun("send", "--to", "alice", "--relay", r, "hello"); err == nil {
			t.Errorf("a stranger reached alice on %s after allow push", r)
		}
	}

	// --relay narrows it: personal opens again, work stays shut.
	alice.run("allow", "clear", "--relay", "personal")
	stranger.run("send", "--to", "alice", "--relay", "personal", "hello again")
	if _, err := stranger.tryRun("send", "--to", "alice", "--relay", "work", "and here"); err == nil {
		t.Error("allow clear --relay personal opened work as well")
	}
}

func TestRelayLsSaysWhatEachRelayHas(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)

	text := alice.run("relay", "ls")
	for _, want := range []string{"work", "personal", work, personalURL, "registered", "* is the default"} {
		if !strings.Contains(text, want) {
			t.Errorf("relay ls does not mention %q:\n%s", want, text)
		}
	}

	list := alice.relayList()
	if len(list) != 2 {
		t.Fatalf("relay ls --json listed %d relays", len(list))
	}
	byName := map[string]relayJSON{}
	for _, r := range list {
		byName[r.Name] = r
	}
	if !byName["work"].Default || byName["personal"].Default {
		t.Errorf("the default is wrong: %+v", list)
	}
	if !byName["work"].Registered || !byName["personal"].Registered {
		t.Errorf("registration is not reported: %+v", list)
	}
	if byName["work"].URL != work || byName["personal"].URL != personalURL {
		t.Errorf("the URLs are wrong: %+v", list)
	}

	// A relay the home has but has not registered on says so.
	third := startRelay(t)
	alice.run("relay", "add", third, "--name", "third")
	for _, r := range alice.relayList() {
		if r.Name == "third" && r.Registered {
			t.Error("a relay nobody registered on is listed as registered")
		}
	}
	if !strings.Contains(alice.run("relay", "ls"), "not registered") {
		t.Error("relay ls does not say which relays have no mailbox")
	}
}

func TestRelayRmAsksAndThenAReplyThereSaysSo(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)
	bob := onBothRelays(t, "bob", work, personalURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	bob.run("send", "--to", "alice", "--relay", "personal", "--subject", "over here", "hello")
	id := alice.inboxJSON().Messages[0].ID

	// Declining changes nothing.
	out, err := alice.answer("n", "relay", "rm", "personal")
	if err == nil {
		t.Fatalf("declining the prompt reported success:\n%s", out)
	}
	if !strings.Contains(out, "will be forgotten") {
		t.Errorf("relay rm does not say what will go:\n%s", out)
	}
	if len(alice.relayList()) != 2 {
		t.Fatal("declining the prompt removed the relay anyway")
	}

	// Accepting it does.
	if _, err := alice.answer("y", "relay", "rm", "personal"); err != nil {
		t.Fatal(err)
	}
	if len(alice.relayList()) != 1 {
		t.Fatal("the relay was not removed")
	}
	// The mail that came through it stays; replying to it says what happened
	// rather than quietly going somewhere else.
	_, err = alice.tryRun("reply", id, "are you there")
	if err == nil {
		t.Fatal("a reply to a removed relay was sent somewhere")
	}
	const want = "that message came through personal, which has been removed; pass --relay"
	if err.Error() != want {
		t.Errorf("error is\n %q\nwant\n %q", err, want)
	}
	// And with --relay it goes.
	alice.run("reply", id, "--relay", "work", "over here now")
}

func TestCommandsThatTalkToNoRelayRefuseTheFlag(t *testing.T) {
	work := startRelay(t)
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("send", "--to", "alice", "--subject", "s", "hello")
	id := alice.inboxJSON().Messages[0].ID

	// Nothing here reaches a relay, so --relay could only ever be a mistake,
	// and the usual unknown-flag error is what says so.
	for _, args := range [][]string{
		{"id"},
		{"read", id},
		{"peers", "ls"},
		{"quarantine", "ls"},
	} {
		withFlag := append(append([]string{}, args...), "--relay", "work")
		if _, err := alice.tryRun(withFlag...); err == nil {
			t.Errorf("%v accepted --relay", args)
		}
		// The command itself still works without it.
		alice.run(args...)
	}
}

// An upload cannot be finished anywhere but where it was opened: the relay
// holds a prefix of exactly these bytes under an identifier that is its own,
// and the HPKE context that sealed them cannot be rewound to make more.
func TestResumeUsesTheRelayTheUploadWasOpenedOn(t *testing.T) {
	work := startRelay(t)
	personalURL, gate := startInterruptibleRelay(t, 2, 64<<10)

	setUp := func(name string) *user {
		u := &user{t: t, home: t.TempDir()}
		u.run("init", "--name", name, "--relay", work)
		u.run("register")
		u.run("relay", "rename", u.defaultRelayName(), "work")
		u.run("relay", "add", personalURL, "--name", "personal")
		u.run("register", "--relay", "personal")
		return u
	}
	alice, bob := setUp("alice"), setUp("bob")
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	payload := make([]byte, 400<<10)
	for i := range payload {
		payload[i] = byte(i*17 + 3)
	}
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	// Sent to personal, which is not the default, and cut off part way.
	if out, err := alice.tryRun("send", "--to", "bob", "--relay", "personal",
		"--subject", "the long one", "--attach", file, "here it is"); err == nil {
		t.Fatalf("the send should have failed with personal cut off:\n%s", out)
	}
	if passed, cut := gate.counts(); passed != 0 || cut == 0 {
		t.Fatalf("the gate answered %d attempts and cut %d; the test proves nothing", passed, cut)
	}
	p := onlyPending(t, alice)
	if p.Relay != "personal" {
		t.Fatalf("the outbox record names relay %q, want personal", p.Relay)
	}
	upload := p.Upload
	if upload == "" {
		t.Fatal("the outbox record has no upload id")
	}

	gate.open()
	out := alice.run("send", "--resume")
	if !strings.Contains(out, "on personal") {
		t.Errorf("--resume does not say which relay it used:\n%s", out)
	}

	// It arrived on personal, and nothing was opened on the default.
	if got := bob.inboxJSON("--relay", "work").Fetch.Delivered; got != 0 {
		t.Errorf("work delivered %d messages; the resume went to the wrong relay", got)
	}
	viaPersonal := bob.inboxJSON("--relay", "personal")
	if viaPersonal.Fetch.Delivered != 1 {
		t.Fatalf("personal delivered %d messages, want 1", viaPersonal.Fetch.Delivered)
	}
	if entries, err := os.ReadDir(filepath.Join(alice.home, "outbox")); err == nil && len(entries) != 0 {
		t.Errorf("the outbox was not cleared: %d entries", len(entries))
	}
}
