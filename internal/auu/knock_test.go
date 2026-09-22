package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// quarantined is what this user holds in quarantine.
func (u *user) quarantined() []*store.Stored {
	u.t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(store.Quarantine)
	if err != nil {
		u.t.Fatal(err)
	}
	return msgs
}

// A knock is the one message that reaches somebody who has not admitted
// you: the target is resolved through the listing as peers fetch resolves
// it, the person is asked and asked the local name before anything
// leaves, the knock is posted to the knock route, and only then is the
// peer added. A relay whose card for the target says no refuses it with
// its sentence and exit 2, and nothing local changes. Somebody already on
// the peer list is refused before the relay is asked anything.
func TestKnockReachesSomebodyWhoHasNotAdmittedYou(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--listed")

	// While bob's card says no knocks: the relay's sentence, exit 2, and
	// the peer list as it was.
	atTerminal(t)
	_, err := alice.answer("y\nBob", "knock", "bob")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport ||
		!strings.Contains(err.Error(), "the recipient does not take knocks") ||
		!strings.Contains(err.Error(), "card push --knocks") {
		t.Fatalf("a knock to a card that says no: %v", err)
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("a refused knock added %v", names)
	}

	// Bob takes knocks. Answered n: nothing sent, nothing added.
	bob.run("card", "push", "--listed", "--knocks")
	out, err := alice.answer("n", "knock", "bob")
	if err != nil {
		t.Fatalf("a knock answered n: %v\n%s", err, out)
	}
	for _, want := range []string{
		"name on relay: bob", "fingerprint:   " + bob.exportFingerprint(),
		"registration:  open; the relay registers anyone: this identity proves nothing about who holds it, and its name is its own claim",
		"Knock on " + bob.exportFingerprint()[:16] + " as alice? [y/N]: ", "nothing sent",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the knock's look lacks %q:\n%s", want, out)
		}
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("a declined knock added %v", names)
	}
	if len(bob.quarantined()) != 0 {
		t.Fatal("a declined knock reached bob")
	}

	// Answered y, then the local name: both answers through one pipe, the
	// knock posted, the peer added under the typed name.
	out, err = alice.answer("y\nRobert", "knock", "bob", "--text", "alice here, we met at the standup")
	if err != nil {
		t.Fatalf("a knock answered y: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Local name for "+bob.exportFingerprint()[:16]+" [bob]: ") ||
		!strings.Contains(out, "knocked on "+bob.exportFingerprint()[:16]+"  Robert") {
		t.Fatalf("the second prompt and the knock:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 1 || names[0] != "Robert" {
		t.Fatalf("the peer list after the knock: %v", names)
	}

	// Bob fetches: the knock is in quarantine, with the sender's own name
	// and text, and it is not kept on the relay whatever the channel says.
	bob.run("inbox")
	held := bob.quarantined()
	if len(held) != 1 {
		t.Fatalf("%d messages in bob's quarantine, want the knock", len(held))
	}
	got := held[0]
	if got.Inner.Body.Type != message.TypeKnock || got.Inner.Body.Name != "alice" ||
		got.Inner.Body.Text != "alice here, we met at the standup" {
		t.Fatalf("the stored knock: %+v", got.Inner.Body)
	}
	if got.OnRelay {
		t.Fatal("the knock is marked kept on the relay; a knock is never kept")
	}
	if got.SenderName != "" {
		t.Fatalf("the knock's sender is named %q before anybody accepted a name", got.SenderName)
	}
	// And it is gone from the relay, so it does not hold a knock slot.
	if out := bob.run("inbox", "--json"); strings.Contains(out, `"queued": 1`) {
		t.Fatalf("the knock is still queued on the relay:\n%s", out)
	}

	// A second knock to the same person is refused at the peer-list step,
	// before the relay is asked anything.
	// By the local name: refused before the relay is asked anything, so
	// the sentence names what was typed and no look is printed.
	out, err = alice.tryRun("knock", "Robert", "--yes")
	if !errors.As(err, &e) || e.code != exitUsage ||
		err.Error() != "Robert is already a peer (Robert); use 'auu send' to write to them" {
		t.Fatalf("a knock to a peer by their local name: %v", err)
	}
	if out != "" {
		t.Fatalf("a knock to a known peer printed a look first:\n%s", out)
	}
	// By the name on their card, which this machine does not use for
	// them: the listing resolves it, and the same refusal names the short
	// id the relay gave back.
	_, err = alice.tryRun("knock", "bob", "--yes")
	if !errors.As(err, &e) || e.code != exitUsage ||
		err.Error() != bob.exportFingerprint()[:16]+" is already a peer (Robert); use 'auu send' to write to them" {
		t.Fatalf("a knock to a peer by the name on their card: %v", err)
	}
	// Yourself, by fingerprint.
	if _, err := alice.tryRun("knock", alice.exportFingerprint(), "--yes"); err == nil ||
		!strings.Contains(err.Error(), "that is you") {
		t.Fatalf("knocking on oneself: %v", err)
	}
}

// The knock's text is held to the message rule before anything is sealed:
// a text over 512 bytes, or with a line break, a tab or a character a
// terminal would obey, is refused by name with nothing sent, and the
// default names the sender.
func TestAKnocksTextIsHeldBeforeAnythingIsSealed(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--listed", "--knocks")

	for _, tc := range []struct {
		name, text, want string
	}{
		{"one over the cap", strings.Repeat("t", message.MaxKnockText+1), "a knock's text is 513 bytes; at most 512"},
		{"a line break", "two\nlines", "a knock's text is one line, without a tab"},
		{"a tab", "a\tb", "a knock's text is one line, without a tab"},
		{"an escape", "run \x1b[2K", "text contains U+001B, a control character"},
	} {
		_, err := alice.tryRun("knock", "bob", "--text", tc.text, "--yes")
		var e *exitError
		if !errors.As(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want the refusal naming it", tc.name, err)
		}
		if len(bob.quarantined()) != 0 {
			t.Fatalf("%s: a refused text was sent", tc.name)
		}
		if names := alice.peerNames(); len(names) != 0 {
			t.Fatalf("%s: a refused text added %v", tc.name, names)
		}
	}
	// And the rule runs before the person is asked anything: at a
	// terminal, a text the rule refuses is refused without the question,
	// so a refusal costs nobody a decision. Against a command that
	// checked only at the seal, the prompt comes first.
	atTerminal(t)
	out, err := alice.answer("y\nBob", "knock", "bob", "--text", "two\nlines")
	if err == nil || !strings.Contains(err.Error(), "a knock's text is one line") {
		t.Fatalf("a bad text at a terminal: %v", err)
	}
	if strings.Contains(out, "Knock on ") || strings.Contains(out, "Local name for ") {
		t.Fatalf("a refused text was asked about first:\n%s", out)
	}

	// At the cap it is taken, and the default names the sender.
	out = alice.run("knock", "bob", "--text", strings.Repeat("t", message.MaxKnockText), "--yes")
	if !strings.Contains(out, "knocked on "+bob.exportFingerprint()[:16]) {
		t.Fatalf("a text at the cap:\n%s", out)
	}
	carol := newUser(t, "carol", relayURL)
	carol.run("card", "push", "--listed", "--knocks")
	var sent knockJSON
	if err := json.Unmarshal([]byte(alice.run("knock", "carol", "--yes", "--json")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Text != "alice would like to exchange keys" || sent.ClaimedName != "carol" || sent.KnownAs != "carol" ||
		sent.RelayID == 0 || sent.Thread == "" || sent.AllowPushed {
		t.Fatalf("knock --json: %+v", sent)
	}
	// A second identity whose card claims the same name: the name is
	// taken on this peer list, so it is not offered, the sentence says
	// whose it is, and --yes takes the fallback rather than a name that
	// AddPeer would refuse.
	carol2 := newUser(t, "carol", relayURL)
	carol2.run("card", "push", "--listed", "--knocks")
	out = alice.run("knock", carol2.exportFingerprint(), "--yes")
	if !strings.Contains(out, `"carol" is already the name of `+carol.exportFingerprint()[:16]+" on your peer list, so it is not offered") ||
		!strings.Contains(out, "knocked on "+carol2.exportFingerprint()[:16]+"  peer-"+carol2.exportFingerprint()[:8]) {
		t.Fatalf("a knock whose offered name is taken:\n%s", out)
	}
}

// A knock is refused without a terminal unless --yes, since it adds a
// peer, and the connect skill says an agent never runs it. The flag after
// the positional works the same.
func TestKnockRefusesWithoutATerminal(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--listed", "--knocks")

	_, err := alice.tryRun("knock", "bob")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage ||
		!strings.Contains(err.Error(), "knocking adds a peer, which is a person's decision: run this at a terminal, or pass --yes") {
		t.Fatalf("a knock without a terminal: %v", err)
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("a refused knock added %v", names)
	}
	if len(bob.quarantined()) != 0 {
		t.Fatal("a refused knock reached bob")
	}
	// The flag after the positional.
	if out := alice.run("knock", "bob", "--yes"); !strings.Contains(out, "knocked on "+bob.exportFingerprint()[:16]) {
		t.Fatalf("a flag after the argument:\n%s", out)
	}
}

// The allow list is pushed again after a knock when this machine holds a
// marker for that relay, so the other end's reply reaches the inbox; with
// no marker nothing is pushed, since the mailbox admits every registered
// sender anyway. The relay's stored list is what the test reads.
func TestAKnockPushesTheAllowListWhenThisMachineHasPushedOne(t *testing.T) {
	relayURL, st, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	for _, u := range []*user{bob, carol} {
		u.run("card", "push", "--listed", "--knocks")
	}
	admits := func(fp string) bool {
		t.Helper()
		ok, err := st.MayPost(alice.exportFingerprint(), fp)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// No marker: nothing is pushed, and the relay still admits anyone.
	var sent knockJSON
	if err := json.Unmarshal([]byte(alice.run("knock", "bob", "--yes", "--json")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.AllowPushed {
		t.Fatal("the allow list was pushed with no marker for the relay")
	}
	if _, _, state, _, err := st.Allowlist(alice.exportFingerprint()); err != nil || state != "none" {
		t.Fatalf("the relay holds an allow list already: %q %v", state, err)
	}

	// With a marker, the push happens and the relay's list names the new
	// peer, so their reply is not refused.
	alice.run("allow", "push")
	if admits(carol.exportFingerprint()) {
		t.Fatal("a pushed list admits a stranger")
	}
	out := alice.run("knock", "carol", "--yes")
	if !strings.Contains(out, alice.relayName()+" will now accept mail for you from 2 peer(s) only") ||
		!strings.Contains(out, "your allow list went to "+alice.relayName()+" with them in it") {
		t.Fatalf("the push after the knock:\n%s", out)
	}
	// Under --json the same push happens and says nothing: one object on
	// standard output and nothing else, with allow_pushed in it.
	dave := newUser(t, "dave", relayURL)
	dave.run("card", "push", "--listed", "--knocks")
	raw := alice.run("knock", "dave", "--yes", "--json")
	if err := json.Unmarshal([]byte(raw), &sent); err != nil {
		t.Fatalf("knock --json after a push: %v\n%s", err, raw)
	}
	if !sent.AllowPushed {
		t.Fatalf("knock --json does not say the allow list went: %+v", sent)
	}
	if !admits(dave.exportFingerprint()) {
		t.Fatal("the push under --json did not reach the relay")
	}
	if !admits(carol.exportFingerprint()) {
		t.Fatal("the pushed list does not name the peer the knock added")
	}
	// And carol can now write to alice, which is the point.
	carol.run("peers", "add", alice.exportLine())
	carol.run("send", "--to", "alice", "thanks for the knock")
	alice.run("inbox")
	s, _, _ := alice.opened()
	msgs, err := s.List(store.Inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Inner.Body.Text != "thanks for the knock" {
		t.Fatalf("the reply to a knock: %d messages", len(msgs))
	}
}

// Trusting a knock offers the name its sender claimed as the default,
// takes what the person types, and then offers to push the allow list
// when this machine holds a marker for the relay the knock came through;
// answered n it prints what to run instead, and with no marker it prints
// the sentence it always printed. A name that folds to a peer's is not
// offered, and the sentence names the peer whose it is.
func TestTrustingAKnockOffersTheNameAndThePush(t *testing.T) {
	relayURL, st, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	alice.run("card", "push", "--knocks")
	atTerminal(t)

	// No marker on alice's machine: the old sentence, and no question.
	bob.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	held := alice.quarantined()
	if len(held) != 1 {
		t.Fatalf("%d in quarantine, want bob's knock", len(held))
	}
	out, err := alice.answer("", "quarantine", "trust", held[0].Inner.ID[:12])
	if err != nil {
		t.Fatalf("trusting a knock with no marker: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Local name for "+bob.exportFingerprint()[:16]+" [bob]: ") ||
		!strings.Contains(out, "run 'auu allow push' if your relay mailbox is restricted") {
		t.Fatalf("trust with no marker:\n%s", out)
	}
	if strings.Contains(out, "Push your allow list") {
		t.Fatalf("trust offered a push with no marker:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 1 || names[0] != "bob" {
		t.Fatalf("the offered name was not taken: %v", names)
	}

	// With a marker: the question, answered n, then answered y.
	alice.run("allow", "push")
	carol.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	var knock *store.Stored
	for _, m := range alice.quarantined() {
		if m.Inner.From == carol.exportFingerprint() {
			knock = m
		}
	}
	if knock == nil {
		t.Fatal("carol's knock is not in quarantine")
	}
	admits := func(fp string) bool {
		t.Helper()
		ok, err := st.MayPost(alice.exportFingerprint(), fp)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	out, err = alice.answer("Caroline\nn", "quarantine", "trust", knock.Inner.ID[:12])
	if err != nil {
		t.Fatalf("trusting a knock answered n: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Push your allow list to "+alice.relayName()+" now, so Caroline can write to you? [y/N]: ") ||
		!strings.Contains(out, "nothing pushed; run 'auu allow push --relay "+alice.relayName()+"' when you are ready") {
		t.Fatalf("the offer answered n:\n%s", out)
	}
	if admits(carol.exportFingerprint()) {
		t.Fatal("a declined push reached the relay")
	}
	// The peer is added all the same: the trust is not the push.
	if names := alice.peerNames(); len(names) != 2 {
		t.Fatalf("the peer list after a declined push: %v", names)
	}
	// Now another knocker, and the offer answered y.
	dave := newUser(t, "dave", relayURL)
	dave.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	knock = nil
	for _, m := range alice.quarantined() {
		if m.Inner.From == dave.exportFingerprint() {
			knock = m
		}
	}
	if knock == nil {
		t.Fatal("dave's knock is not in quarantine")
	}
	out, err = alice.answer("\ny", "quarantine", "trust", knock.Inner.ID[:12])
	if err != nil {
		t.Fatalf("trusting a knock answered y: %v\n%s", err, out)
	}
	if !strings.Contains(out, "will now accept mail for you from 3 peer(s) only") {
		t.Fatalf("the offer answered y:\n%s", out)
	}
	if !admits(dave.exportFingerprint()) {
		t.Fatal("the pushed list does not name the trusted knocker")
	}

	// A claimed name that folds to a peer's is not offered.
	erin := newUser(t, "BOB", relayURL)
	erin.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	knock = nil
	for _, m := range alice.quarantined() {
		if m.Inner.From == erin.exportFingerprint() {
			knock = m
		}
	}
	if knock == nil {
		t.Fatal("the fourth knock is not in quarantine")
	}
	out, err = alice.answer("\nn", "quarantine", "trust", knock.Inner.ID[:12])
	if err != nil {
		t.Fatalf("trusting a knock whose name folds to a peer's: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"BOB" is already the name of `+bob.exportFingerprint()[:16]+" on your peer list, so it is not offered") ||
		!strings.Contains(out, "Local name for "+erin.exportFingerprint()[:16]+" [peer-"+erin.exportFingerprint()[:8]+"]: ") {
		t.Fatalf("the fold case:\n%s", out)
	}
}

// What a knock's sender wrote reaches a terminal escaped, and a record
// that carries what the rule refuses is not shown at all. Two things,
// both worth pinning: Load holds a spool file to the shape, so a knock
// altered on disk to carry an escape is refused by name and left out of
// every listing; and the printers escape whatever they are given, which
// is the last line and not the rule, shown here by handing them a record
// with an escape in the name and in the text.
func TestAKnocksWordsReachTheTerminalEscaped(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--knocks")
	alice.run("knock", bob.exportFingerprint(), "--yes")
	bob.run("inbox")
	held := bob.quarantined()
	if len(held) != 1 {
		t.Fatalf("%d in quarantine, want the knock", len(held))
	}
	m := held[0]
	// What it prints says the name is the sender's own claim.
	out := bob.run("quarantine", "show", m.Inner.ID[:12])
	if !strings.Contains(out, "claims:  alice (their own claim, not a name you gave)") {
		t.Fatalf("quarantine show on a knock:\n%s", out)
	}
	if !strings.Contains(out, "type:    knock") {
		t.Fatalf("quarantine show does not say the type:\n%s", out)
	}
	if out := bob.run("quarantine", "ls"); !strings.Contains(out, "knock  from "+alice.exportFingerprint()[:16]) ||
		!strings.Contains(out, "alice") || !strings.Contains(out, "alice would like to exchange keys") {
		t.Fatalf("quarantine ls on a knock:\n%s", out)
	}
	// --json carries the claim beside the local name, which is empty.
	var shown []messageJSON
	if err := json.Unmarshal([]byte(bob.run("quarantine", "ls", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown) != 1 || shown[0].ClaimedName != "alice" || shown[0].FromName != "" || shown[0].Type != message.TypeKnock {
		t.Fatalf("quarantine ls --json on a knock: %+v", shown)
	}

	// The record altered on disk: Load refuses it by name, it is left out
	// of every listing, and no escape reaches the terminal.
	s, _, _ := bob.opened()
	m.Inner.Body.Name = "ali\x1b[2Kce"
	m.Inner.Body.Text = "let me \x1b]0;owned\x07in"
	if err := s.Save(store.Quarantine, m); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"quarantine", "ls"},
		{"quarantine", "show", m.Inner.ID[:12]},
		{"inbox"},
	} {
		var out string
		warning := captureStderr(t, func() { out, _ = bob.tryRun(args...) })
		if strings.ContainsRune(out, 0x1b) {
			t.Errorf("%v let an escape through:\n%q", args, out)
		}
		if strings.ContainsRune(warning, 0x1b) {
			t.Errorf("%v let an escape through on stderr:\n%q", args, warning)
		}
		if strings.Contains(out, "ce") && strings.Contains(out, "owned") {
			t.Errorf("%v showed a record the shape rule refuses:\n%s", args, out)
		}
	}
	if out := bob.run("quarantine", "ls"); !strings.Contains(out, "quarantine is empty") {
		t.Fatalf("a record the rule refuses is still listed:\n%s", out)
	}

	// And the printers escape what they are given, whatever it is: the
	// last line, shown by handing them a record in memory.
	hostile := &store.Stored{
		RelayID: 9, Relay: bob.relayName(), Received: m.Received,
		Inner: &envelope.Inner{
			ID: m.Inner.ID, From: m.Inner.From, FromBundle: m.Inner.FromBundle, Time: m.Inner.Time,
			Body: message.Body{Type: message.TypeKnock, Thread: m.Inner.Body.Thread,
				Name: "ali\x1b[2Kce", Text: "let me \x1b]0;owned\x07in"},
		},
	}
	printed, _ := captureStdout(t, func() error {
		printMessage(s, store.Quarantine, hostile)
		printQuarantineLine(hostile)
		printInboxLine(hostile)
		return nil
	})
	if strings.ContainsRune(printed, 0x1b) || strings.ContainsRune(printed, 0x07) {
		t.Fatalf("a printer let a control byte through:\n%q", printed)
	}
	if !strings.Contains(printed, `ali\x1b[2Kce`) {
		t.Fatalf("the escaped name is not shown as the escaper writes it:\n%s", printed)
	}
}

// The relay's word for a row and the type inside the signature must
// agree. A knock came past the allow list because the owner's card admits
// knocks, so a row listed as a knock whose sealed body is an ask, and a
// row listed as an envelope whose body is a knock, are obeyed in neither
// direction: each is kept under damaged/ as misfiled and acknowledged, so
// the mailbox is not blocked and nothing acts on it.
func TestARowWhoseKindAndSealedTypeDisagreeIsMisfiled(t *testing.T) {
	for _, tc := range []struct {
		mode, listed, sealed string
	}{
		{"asknock", "knock", message.TypeAsk},
		{"asenvelope", "envelope", message.TypeKnock},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			work, gate, workStore := startFilingRelay(t)
			alice := newUser(t, "alice", work)
			bob := newUser(t, "bob", work)
			_, bobID, _ := bob.opened()
			relayName := bob.defaultRelayName()
			if tc.sealed == message.TypeKnock {
				bob.run("card", "push", "--knocks")
				alice.run("knock", bob.exportFingerprint(), "--yes")
			} else {
				alice.run("peers", "add", bob.exportLine())
				bob.run("peers", "add", alice.exportLine())
				alice.run("send", "--to", "bob", "--subject", "a bug", "the bug")
			}
			gate.set(tc.mode)
			var out string
			warning := captureStderr(t, func() { out = bob.run("inbox", "--json") })
			var got inboxJSON
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			if got.Fetch.Delivered != 0 || got.Fetch.Quarantined != 0 || got.Fetch.Kept != 1 ||
				got.Fetch.Unreadable != 1 || len(got.Messages) != 0 {
				t.Fatalf("the fetch: %+v, %d messages", got.Fetch, len(got.Messages))
			}
			want := "warning: relay message 1 was listed as \"" + tc.listed + "\" by " + relayName +
				" but is sealed as \"" + tc.sealed + "\"; it was kept as " +
				filepath.Join(bob.home, "damaged", relayName, "1.bin") + "\n"
			if warning != want {
				t.Fatalf("the warning:\n%s\nwant:\n%s", warning, want)
			}
			if strings.Contains(warning, "ask the sender") {
				t.Fatalf("a misfiled kind blamed the sender:\n%s", warning)
			}
			s, _, _ := bob.opened()
			raw, err := os.ReadFile(strings.TrimSuffix(damagedPathOf(t, s, relayName, 1), ".bin") + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var rec store.DamagedRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Cause != "misfiled" || rec.Relay != relayName || rec.RelayID != 1 {
				t.Fatalf("the record: %+v", rec)
			}
			// Acknowledged: nothing queued, nothing in either box.
			if u, _ := workStore.MailboxUsage(bobID.Fingerprint()); u.Messages != 0 {
				t.Fatalf("%d messages still queued after a misfiled kind", u.Messages)
			}
			if len(bob.quarantined()) != 0 {
				t.Fatal("a row whose kind and type disagree reached the quarantine")
			}
			// With the gate off the same relay serves honestly again.
			gate.set("")
			warning = captureStderr(t, func() { out = bob.run("inbox", "--json") })
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			if !got.Fetch.empty() || warning != "" {
				t.Fatalf("the next fetch was not clean: %+v %q", got.Fetch, warning)
			}
		})
	}
}

// A name a person types is held to the rule the peer file's export line
// carries, before anything is written and, at a knock, before the knock
// is posted: a name with a space in it, or one that folds to a peer's,
// would make the file unreadable or be refused after the post. The
// person is asked again, three times, and the offer stands after that.
// Against a command that took what was typed, the file holds a line
// nothing can parse and every peer reads as a stranger.
func TestATypedNameIsHeldToTheRuleBeforeAnythingIsWritten(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--listed", "--knocks")
	atTerminal(t)

	// Three bad answers, then the offer: the knock is not sent until the
	// name is one the file can hold.
	out, err := alice.answer("y\nbob smith\nbob/smith\nself", "knock", "bob")
	if err != nil {
		t.Fatalf("a knock with three bad names: %v\n%s", err, out)
	}
	if strings.Count(out, "Local name for ") != 3 {
		t.Fatalf("the prompt was not repeated three times:\n%s", out)
	}
	for _, want := range []string{
		`name "bob smith": letters, digits, '.', '_' and '-' only`,
		`name "bob/smith": letters, digits`,
		`the name "self" is reserved; it means you`,
		"keeping bob", "knocked on " + bob.exportFingerprint()[:16] + "  bob",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the refusals lack %q:\n%s", want, out)
		}
	}
	// The peer list still reads, which is the point: a line the reader
	// refuses would make every peer a stranger.
	s, _, _ := alice.opened()
	peers, err := s.Peers()
	if err != nil {
		t.Fatalf("the peer list after three bad names: %v", err)
	}
	if len(peers) != 1 || peers[0].Name != "bob" {
		t.Fatalf("the peer list: %v", alice.peerNames())
	}

	// A typed name that folds to a peer's is refused before the knock is
	// posted, so nothing is sent and nothing is written.
	carol := newUser(t, "carol", relayURL)
	carol.run("card", "push", "--listed", "--knocks")
	_, err = alice.answer("y\nBOB", "knock", "carol")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage ||
		!strings.Contains(err.Error(), `peer name "BOB" is already used by `+bob.exportFingerprint()[:16]) {
		t.Fatalf("a typed name that folds to a peer's: %v", err)
	}
	if names := alice.peerNames(); len(names) != 1 {
		t.Fatalf("a refused name added a peer: %v", names)
	}
	if len(carol.quarantined()) != 0 {
		t.Fatal("a knock went out under a name the peer list would refuse")
	}
	// And the store itself refuses to write such a name, whichever
	// command asks: the file's invariant is the store's to keep.
	pub, err := identity.ParseExportLine(carol.exportLine())
	if err != nil {
		t.Fatal(err)
	}
	pub.Name = "bob smith"
	if _, err := s.AddPeer(pub); err == nil || !strings.Contains(err.Error(), "letters, digits") {
		t.Fatalf("AddPeer took a name the export line cannot carry: %v", err)
	}
}

// A knock's claimed name is offered at the local-name prompt only where
// somebody is there to accept or refuse it. Without a terminal the prompt
// takes its default at end of input, and a default from the wire would
// write a stranger's chosen name into the peer list with nobody
// answering: the machine's own peer-<fp8> is offered instead, and the
// line says why. At a terminal the claim is offered and said to be theirs.
func TestAKnocksClaimedNameIsOfferedOnlyToAPerson(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	eve := newUser(t, "carol", relayURL)
	alice.run("card", "push", "--knocks")
	eve.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	held := alice.quarantined()
	if len(held) != 1 {
		t.Fatalf("%d in quarantine, want the knock", len(held))
	}
	id := held[0].Inner.ID[:12]

	// No terminal: the claim is not offered, and an answerless run takes
	// this machine's own name for them.
	out, err := alice.answer("", "quarantine", "trust", id)
	if err != nil {
		t.Fatalf("trusting a knock without a terminal: %v\n%s", err, out)
	}
	if !strings.Contains(out, "they call themselves carol, which is their own claim; without a terminal it is not offered") ||
		!strings.Contains(out, "Local name for "+eve.exportFingerprint()[:16]+" [peer-"+eve.exportFingerprint()[:8]+"]: ") {
		t.Fatalf("the prompt without a terminal:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 1 || names[0] != "peer-"+eve.exportFingerprint()[:8] {
		t.Fatalf("a claimed name was taken with nobody answering: %v", names)
	}

	// At a terminal it is offered, and the line says whose name it is.
	bob := newUser(t, "bob", relayURL)
	bob.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	var knock *store.Stored
	for _, m := range alice.quarantined() {
		if m.Inner.From == bob.exportFingerprint() {
			knock = m
		}
	}
	if knock == nil {
		t.Fatal("bob's knock is not in quarantine")
	}
	atTerminal(t)
	out, err = alice.answer("\nn", "quarantine", "trust", knock.Inner.ID[:12])
	if err != nil {
		t.Fatalf("trusting a knock at a terminal: %v\n%s", err, out)
	}
	if !strings.Contains(out, "they call themselves bob; that is their own claim, not a name you gave") ||
		!strings.Contains(out, "Local name for "+bob.exportFingerprint()[:16]+" [bob]: ") {
		t.Fatalf("the prompt at a terminal:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 2 {
		t.Fatalf("the peer list: %v", names)
	}
}
