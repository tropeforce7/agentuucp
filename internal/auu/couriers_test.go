package auu

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// accepting starts a relay that accepts forwarded mail from the named
// neighbours, and answers their identities so a test can check fingerprints.
//
// It differs from forwarding in the half of a peering it fills: forwarding
// gives a relay a courier home, which is what it dials, while this fills the
// couriers file, which is what it accepts from and what the couriers route
// answers. A relay needs both halves in the wild and neither implies the other.
func accepting(t *testing.T, names ...string) (string, []*identity.Identity) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "courier")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("courier")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	neighbours := make([]*identity.Identity, 0, len(names))
	var b strings.Builder
	for _, n := range names {
		nid, err := identity.Generate(n)
		if err != nil {
			t.Fatal(err)
		}
		neighbours = append(neighbours, nid)
		b.WriteString(nid.Public().ExportLine() + "\n")
	}
	file := filepath.Join(t.TempDir(), "couriers")
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := relay.NewCourier(relay.CourierConfig{
		Home: root, AuthorizedFile: file, PublicURL: "https://mine.example",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	url, _ := startRelayConfig(t, relay.Config{
		Courier: c, CourierLimits: relay.DefaultCourierLimits(), Limits: relay.DefaultLimits(),
	})
	// Recorded so a test can rewrite the file, which is what an operator does
	// when a peering starts or stops.
	courierFilePath[url] = file
	t.Cleanup(func() { delete(courierFilePath, url) })
	return url, neighbours
}

// courierFilePath is the couriers file behind each relay accepting() started.
var courierFilePath = map[string]string{}

// TestRelayCouriersListsThemAndSaysWhoseNamesTheyAre: what the command prints,
// and the two things a reader needs beyond the names.
//
// That the names are the relay's own, because a name that looks like a hostname
// invites the opposite assumption and a person who took one for a global name
// would write an address that means something else at the next hop; and which
// of them this machine admits, because the list is most often read in order to
// decide what to admit.
func TestRelayCouriersListsThemAndSaysWhoseNamesTheyAre(t *testing.T) {
	url, neighbours := accepting(t, "zed", "abe")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()

	out := alice.run("relay", "couriers")
	if !strings.Contains(out, "accepts forwarded mail from 2 relays") {
		t.Fatalf("the count:\n%s", out)
	}
	// Name order, not file order.
	if i, j := strings.Index(out, "abe"), strings.Index(out, "zed"); i < 0 || j < 0 || i > j {
		t.Errorf("want abe before zed:\n%s", out)
	}
	for _, n := range neighbours {
		if !strings.Contains(out, n.Public().Fingerprint()[:16]) {
			t.Errorf("the fingerprint of %s is missing:\n%s", n.Public().Name, out)
		}
	}
	if !strings.Contains(out, "not admitted") {
		t.Errorf("want each to say this machine does not admit it:\n%s", out)
	}
	if !strings.Contains(out, "these names are "+rn+"'s own") {
		t.Errorf("want the sentence about whose names these are:\n%s", out)
	}
	if !strings.Contains(out, "allow add --courier") {
		t.Errorf("want it to say how to admit one:\n%s", out)
	}

	// Admitted, and the listing says so.
	alice.run("allow", "add", "--courier", "abe", "--relay", rn, "--yes")
	out = alice.run("relay", "couriers")
	if !strings.Contains(out, "admitted") || strings.Count(out, "not admitted") != 1 {
		t.Errorf("want abe admitted and zed not:\n%s", out)
	}

	// The JSON form carries the same three things.
	out = alice.run("relay", "couriers", "--json")
	var got []struct {
		Relay    string `json:"relay"`
		Couriers []struct {
			Name     string `json:"name"`
			FP       string `json:"fp"`
			Admitted bool   `json:"admitted"`
		} `json:"couriers"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json is not JSON: %s", out)
	}
	if len(got) != 1 || len(got[0].Couriers) != 2 {
		t.Fatalf("--json = %s", out)
	}
	if got[0].Couriers[0].Name != "abe" || !got[0].Couriers[0].Admitted {
		t.Errorf("abe: %+v", got[0].Couriers[0])
	}
	if got[0].Couriers[1].Name != "zed" || got[0].Couriers[1].Admitted {
		t.Errorf("zed: %+v", got[0].Couriers[1])
	}
}

// TestRelayCouriersOnARelayThatForwardsNothing: the answer a relay with no
// couriers gives, and what it means for the person reading it.
func TestRelayCouriersOnARelayThatForwardsNothing(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	out := alice.run("relay", "couriers")
	if !strings.Contains(out, "accepts no forwarded mail") {
		t.Fatalf("%s", out)
	}
	// And says what follows from it, which is the part a person acts on.
	if !strings.Contains(out, "nobody can address mail to you through it") {
		t.Errorf("want what it means:\n%s", out)
	}
}

// TestAllowAddCourierResolvesTheNameAgainstTheRelay: a name is never assumed.
//
// A courier the relay has not got is one no mail can arrive through, so a file
// naming it would be a quiet mistake — the person would believe they were
// reachable and would not be. Refused by name, and with the names that are
// there, since somebody who typed one wrong wants to see the right one rather
// than go and ask.
func TestAllowAddCourierResolvesTheNameAgainstTheRelay(t *testing.T) {
	url, _ := accepting(t, "bar", "baz")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()

	out, err := alice.tryRun("allow", "add", "--courier", "nope", "--relay", rn, "--yes")
	if err == nil {
		t.Fatalf("a name the relay does not list was taken:\n%s", out)
	}
	// The refusal is the error, not stdout: a name this program could not
	// resolve is a usage error and not a relay's answer.
	said := err.Error()
	if !strings.Contains(said, `no courier called "nope"`) {
		t.Errorf("want the name refused: %v", err)
	}
	if !strings.Contains(said, "bar") || !strings.Contains(said, "baz") {
		t.Errorf("want the names it does have: %v", err)
	}
	// Nothing was written.
	s, _, _ := alice.opened()
	if list, err := s.Couriers(rn); err != nil || len(list) != 0 {
		t.Errorf("Couriers = %+v, %v; want nothing written", list, err)
	}
	// A name that is not a relay name at all is a usage error before any
	// relay is dialled, since the rule is this end's too.
	if out, err := alice.tryRun("allow", "add", "--courier", "../x", "--relay", rn, "--yes"); err == nil {
		t.Errorf("a name that cannot be a relay name was taken:\n%s", out)
	}
}

// TestAllowAddCourierSaysWhatAdmittingOneMeans: the confirmation is the point
// of the command, not a formality.
//
// Admitting a courier admits everybody who can post through that relay, because
// a relay cannot open an envelope and the only sender it can prove is the
// neighbour that handed it over. That is the one place an allow list means
// something coarser than the fingerprints in it, so it is said before anything
// is written rather than documented elsewhere.
func TestAllowAddCourierSaysWhatAdmittingOneMeans(t *testing.T) {
	url, neighbours := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()
	out := alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")

	if !strings.Contains(out, neighbours[0].Public().Fingerprint()) {
		t.Errorf("want the whole fingerprint shown before admitting:\n%s", out)
	}
	if !strings.Contains(out, "not a trust anchor") {
		t.Errorf("want the registration sentence:\n%s", out)
	}
	for _, want := range []string{
		"whoever sent it",
		"cannot open an envelope",
		"admits everybody who can post through it",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the confirmation does not say %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "allow push") {
		t.Errorf("want it to say nothing changes until a push:\n%s", out)
	}
	// It is on the file now, under the relay's own name for it.
	s, _, _ := alice.opened()
	list, err := s.Couriers(rn)
	if err != nil || len(list) != 1 || list[0].Name != "bar" ||
		list[0].FP != neighbours[0].Public().Fingerprint() {
		t.Fatalf("Couriers = %+v, %v", list, err)
	}
	// And rm takes it off, saying a push is needed for that too.
	out = alice.run("allow", "rm", "--courier", "bar", "--relay", rn)
	if !strings.Contains(out, "no longer admitting") || !strings.Contains(out, "allow push") {
		t.Errorf("rm:\n%s", out)
	}
	if list, _ := s.Couriers(rn); len(list) != 0 {
		t.Errorf("after rm: %+v", list)
	}
	// Removing one that was never there is refused by name rather than
	// silently doing nothing, so a typo is not mistaken for success.
	if out, err := alice.tryRun("allow", "rm", "--courier", "bar", "--relay", rn); err == nil {
		t.Errorf("removing an unadmitted courier succeeded:\n%s", out)
	}
}

// TestAllowPushCarriesTheCouriersOfThatRelay: the document is per relay, and
// the count says both kinds.
func TestAllowPushCarriesTheCouriersOfThatRelay(t *testing.T) {
	url, neighbours := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	alice.run("peers", "add", bob.exportLine())
	rn := alice.relayName()
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")

	// The line describes the document: two senders signed, one of them the
	// courier. It counted the two sources' rows until the second reader pointed
	// out that they overlap and can shrink, so this assertion changed with the
	// rule and is not the one this test was written with.
	out := alice.run("allow", "push")
	if !strings.Contains(out, "from 2 sender(s), of which 1 forward mail to you from other relays") {
		t.Fatalf("the push line does not describe the document:\n%s", out)
	}
	// The document really names the courier, which is the whole point: a
	// count in a sentence is not evidence that the fingerprint was signed.
	out = alice.run("allow", "show")
	if !strings.Contains(out, neighbours[0].Public().Fingerprint()[:16]) {
		t.Errorf("the pushed list does not name the courier:\n%s", out)
	}
}

// TestAKnockKeepsTheCouriersInThePushedList: the defect this test exists for.
//
// pushAllowTo is the quiet helper a knock and a fetch push with, and it built
// its document from the peer list alone. So admitting a courier and then
// knocking pushed a list *without* that courier: the person's forwarded mail
// stopped arriving, nothing was said, and the cause was two commands away from
// the symptom. Anything that pushes has to push the same list as 'allow push',
// and this drives the knock to say so.
func TestAKnockKeepsTheCouriersInThePushedList(t *testing.T) {
	url, neighbours := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	alice.run("peers", "add", bob.exportLine())
	rn := alice.relayName()
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")
	alice.run("allow", "push")

	// Somebody who is not already a peer to knock at: a knock at a peer is
	// refused, since there is nothing to ask for.
	carol := newUser(t, "carol", url)
	carol.run("card", "push", "--listed", "--knocks")
	out := alice.run("knock", carol.fingerprint(), "--text", "hello", "--yes")
	if !strings.Contains(out, "forward mail to you from other relays") {
		t.Errorf("the knock's push line does not say a courier was signed:\n%s", out)
	}
	// And the list on the relay still names it. This is the assertion the
	// defect would have failed: the knock re-pushes, and a document built
	// from peers alone would have dropped the courier here.
	out = alice.run("allow", "show")
	if !strings.Contains(out, neighbours[0].Public().Fingerprint()[:16]) {
		t.Fatalf("after a knock the pushed list no longer names the courier:\n%s", out)
	}
}

// TestAdmittingACourierThatIsAlsoAPeerNamesItOnce: the signer refuses a list
// with one fingerprint twice, so the two sources are merged rather than
// concatenated.
//
// Contrived-looking and not: a person who runs a relay and is also a user of
// their own neighbour finds their own identity in the couriers list, and two
// colleagues who each run a relay may peer with one another as people too.
func TestAdmittingACourierThatIsAlsoAPeerNamesItOnce(t *testing.T) {
	url, neighbours := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()
	// The courier's own export line added as a peer, so the same fingerprint
	// reaches the document from both sources.
	alice.run("peers", "add", neighbours[0].Public().ExportLine())
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")
	out := alice.run("allow", "push")
	if strings.Contains(out, "error") || strings.Contains(out, "twice") {
		t.Fatalf("the push failed with one fingerprint from both sources:\n%s", out)
	}
	if !strings.Contains(out, "will now accept mail") {
		t.Fatalf("the push did not happen:\n%s", out)
	}
}

// TestAllowAddCourierAtATerminalTakesNoForAnAnswer: the question is a real
// question, and declining leaves the file exactly as it was.
//
// Admitting a courier admits everybody behind it, so the confirmation is the
// substance of the command rather than a formality, and a person who reads what
// it says and declines must end up with nothing written. Driven through a pipe
// with the terminal check forced, which is the only way to reach the branch:
// without a terminal and without --yes the command refuses outright, and that
// refusal is the other half of the same rule.
func TestAllowAddCourierAtATerminalTakesNoForAnAnswer(t *testing.T) {
	url, _ := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()

	wasTerminal := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = wasTerminal })

	answer := func(t *testing.T, text string) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(text); err != nil {
			t.Fatal(err)
		}
		w.Close()
		was := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = was; r.Close() })
	}

	answer(t, "n\n")
	out := alice.run("allow", "add", "--courier", "bar", "--relay", rn)
	if !strings.Contains(out, "nothing admitted") {
		t.Errorf("declining did not say so:\n%s", out)
	}
	s, _, _ := alice.opened()
	if list, err := s.Couriers(rn); err != nil || len(list) != 0 {
		t.Fatalf("declining wrote %+v, %v; want the file left as it was", list, err)
	}

	// And y admits it, so the question is what decides and not the flag alone.
	answer(t, "y\n")
	out = alice.run("allow", "add", "--courier", "bar", "--relay", rn)
	if !strings.Contains(out, "admitted") {
		t.Errorf("accepting did not admit:\n%s", out)
	}
	if list, err := s.Couriers(rn); err != nil || len(list) != 1 {
		t.Fatalf("after y: %+v, %v", list, err)
	}
}

// TestAllowAddCourierWithoutATerminalRefusesRatherThanAssuming: the other half
// of the same rule.
//
// An agent running this command is not a person reading the sentence about what
// admitting a courier means, so with no terminal and no --yes it refuses and
// says which of the two is missing. Nothing is written.
func TestAllowAddCourierWithoutATerminalRefusesRatherThanAssuming(t *testing.T) {
	url, _ := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()
	out, err := alice.tryRun("allow", "add", "--courier", "bar", "--relay", rn)
	if err == nil {
		t.Fatalf("admitted with no terminal and no --yes:\n%s", out)
	}
	if !strings.Contains(err.Error(), "a person's decision") || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("%v; want it to say why and what to pass", err)
	}
	s, _, _ := alice.opened()
	if list, _ := s.Couriers(rn); len(list) != 0 {
		t.Errorf("something was written: %+v", list)
	}
}

// TestAllowPushWithABadCouriersLineRefusesByName: a file somebody edited by
// hand is refused where it is read, and named.
//
// The failure this prevents is two steps from its cause: an unchecked
// fingerprint would reach the signed document and the relay would refuse it
// with a sentence about a list, leaving the person to work out that the cause
// was a file they had opened in an editor. So the line is refused here, with the
// path, the line number and what is wrong with it.
func TestAllowPushWithABadCouriersLineRefusesByName(t *testing.T) {
	url, _ := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")

	s, _, _ := alice.opened()
	path := filepath.Join(s.RelayDir(mustRelay(t, s, rn)), "couriers")
	if err := os.WriteFile(path, []byte("not-a-fingerprint bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := alice.tryRun("allow", "push")
	if err == nil {
		t.Fatalf("a bad line was pushed:\n%s", out)
	}
	said := err.Error()
	for _, want := range []string{"couriers", "line 1", "not a fingerprint"} {
		if !strings.Contains(said, want) {
			t.Errorf("%v; want it to say %q", err, want)
		}
	}
}

// TestThePushedDocumentHoldsThePeersAndTheCourierAndNothingElse: the document
// is exactly the union, asserted as a set rather than by a count.
//
// A count would pass if the wrong fingerprint were in it, and what this is
// really checking is that admitting a courier does not quietly admit anything
// else — the relay's other neighbours among them, which the route listed and
// this machine did not admit.
func TestThePushedDocumentHoldsThePeersAndTheCourierAndNothingElse(t *testing.T) {
	url, neighbours := accepting(t, "bar", "baz")
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	alice.run("peers", "add", bob.exportLine())
	rn := alice.relayName()
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")
	alice.run("allow", "push")

	var shown struct {
		Relays []struct {
			Senders []struct {
				Fingerprint string `json:"fingerprint"`
			} `json:"senders"`
		}
	}
	out := alice.run("allow", "show", "--json")
	if err := json.Unmarshal([]byte(out), &shown.Relays); err != nil {
		t.Fatalf("allow show --json is not JSON: %s", out)
	}
	if len(shown.Relays) != 1 {
		t.Fatalf("%d relays in the answer: %s", len(shown.Relays), out)
	}
	got := map[string]bool{}
	for _, sender := range shown.Relays[0].Senders {
		got[sender.Fingerprint] = true
	}
	want := map[string]bool{
		bob.fingerprint():                    true,
		neighbours[0].Public().Fingerprint(): true,
	}
	if len(got) != len(want) {
		t.Fatalf("the document names %d senders, want %d: %s", len(got), len(want), out)
	}
	for fp := range want {
		if !got[fp] {
			t.Errorf("the document does not name %s", fp[:16])
		}
	}
	// baz was listed by the relay and never admitted here, so it must not be
	// in the document: the route is a listing and not a grant.
	if got[neighbours[1].Public().Fingerprint()] {
		t.Error("the document names baz, which was never admitted")
	}
}

// mustRelay is the relay of that name, for a test that needs its directory.
func mustRelay(t *testing.T, s *store.Store, name string) *store.Relay {
	t.Helper()
	relays, err := s.Relays()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range relays {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no relay called %q", name)
	return nil
}

// pipeIn replaces standard input with a pipe carrying text, for a test that
// answers a prompt. Restored when the test ends.
func pipeIn(t *testing.T, text string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(text); err != nil {
		t.Fatal(err)
	}
	w.Close()
	was := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = was; r.Close() })
}

// TestADamagedCouriersFileStopsEveryPathThatPushes: the behaviour change worth
// stating, and what a person is told when it bites.
//
// Before this commit a knock and the push offered after trusting a quarantined
// sender did not read the couriers file, because there was no such file. They
// push the same list `allow push` does now, so they refuse on a file the person
// edited by hand — and the file they edited was for the allow list, not for
// either of those commands.
//
// That is the rule and not a regression: an unchecked fingerprint reaching a
// signed document would come back as the relay refusing a list, which is a
// failure two steps from its cause. What the rule owes the person is knowing
// which step tripped, so each path says that the thing they asked for happened
// and the push did not, and carries the file's own sentence — the path, the line
// and the remedy — inside it.
func TestADamagedCouriersFileStopsEveryPathThatPushes(t *testing.T) {
	url, _ := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	carol := newUser(t, "carol", url)
	rn := alice.relayName()
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")
	alice.run("allow", "push")

	s, _, _ := alice.opened()
	damage := func(t *testing.T) {
		t.Helper()
		path := filepath.Join(s.RelayDir(mustRelay(t, s, rn)), "couriers")
		if err := os.WriteFile(path, []byte("not-a-fingerprint bar\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repair := func(t *testing.T) {
		t.Helper()
		if err := s.SetCouriers(rn, nil); err != nil {
			t.Fatal(err)
		}
		alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")
	}

	// A knock: the knock is sent, the push is not, and the sentence says which.
	carol.run("card", "push", "--listed", "--knocks")
	damage(t)
	out, err := alice.tryRun("knock", carol.fingerprint(), "--text", "hello", "--yes")
	if err == nil {
		t.Fatalf("a knock pushed a damaged couriers file:\n%s", out)
	}
	for _, want := range []string{"allow push"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the knock's error %v does not say %q", err, want)
		}
	}
	repair(t)

	// The push offered after trusting a quarantined sender: the same shape.
	// It has to be a knock and not a send, which is the point of a knock:
	// alice's list is restricted, so a stranger's post is refused at the relay
	// and never reaches her quarantine. A knock is the one message that
	// crosses without an entry.
	alice.run("card", "push", "--knocks")
	dave := newUser(t, "dave", url)
	// No peers add: a knock takes a fingerprint, and adding her first would
	// make the knock refuse, since somebody already a peer is somebody to send
	// to.
	dave.run("knock", alice.fingerprint(), "--text", "let me in", "--yes")
	alice.run("inbox")
	damage(t)
	var held []messageJSON
	if uerr := json.Unmarshal([]byte(alice.run("quarantine", "ls", "--json")), &held); uerr != nil {
		t.Fatal(uerr)
	}
	if len(held) != 1 {
		t.Fatalf("%d messages in quarantine, want dave's knock", len(held))
	}
	// Two answers through one pipe: the local-name prompt, empty for the
	// offered name, then y to the push. No terminal is needed — the push is
	// offered through the same reader the name prompt uses, not gated on one.
	pipeIn(t, "\ny\n")
	out, err = alice.tryRun("quarantine", "trust", held[0].ID)
	if err == nil {
		t.Fatalf("the offered push took a damaged couriers file:\n%s", out)
	}
	// The trust itself happened, which is the part the person asked for.
	if !strings.Contains(out, "trusted") {
		t.Errorf("the trust did not happen or did not say so:\n%s", out)
	}
	if !strings.Contains(err.Error(), "allow push") {
		t.Errorf("the error %v does not point at the push", err)
	}
}

// TestADePeeredCourierStaysVisibleAndWithdrawable: a courier this machine
// admits that the relay no longer accepts from.
//
// Printing only the relay's answer joined against the local file hid exactly
// this case, and it is the one that matters: de-peering does not unregister the
// courier's mailbox, so the fingerprint keeps whatever its admission granted,
// the admission is still signed into every list pushed from here, and nothing
// can ever arrive through it. `allow show` names it only as sixty-four
// characters, a courier not being a peer, so somebody who could not see it here
// could not find out what it was.
func TestADePeeredCourierStaysVisibleAndWithdrawable(t *testing.T) {
	url, neighbours := accepting(t, "bar", "baz")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")
	alice.run("allow", "add", "--courier", "baz", "--relay", rn, "--yes")

	// The operator de-peers bar: its line leaves the relay's couriers file.
	rewriteCouriers(t, url, neighbours[1:])

	out := alice.run("relay", "couriers")
	if !strings.Contains(out, "admitted, but this relay no longer accepts from it") {
		t.Fatalf("a de-peered courier is not shown as one:\n%s", out)
	}
	if !strings.Contains(out, "bar") {
		t.Errorf("the de-peered courier is not named:\n%s", out)
	}
	if !strings.Contains(out, "allow rm --courier") {
		t.Errorf("nothing says how to withdraw it:\n%s", out)
	}
	// --json carries it as its own field, so a script can find it.
	var got []struct {
		Couriers []struct {
			Name string `json:"name"`
			Gone bool   `json:"gone"`
		} `json:"couriers"`
	}
	if err := json.Unmarshal([]byte(alice.run("relay", "couriers", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	gone := 0
	for _, c := range got[0].Couriers {
		if c.Gone {
			gone++
			if c.Name != "bar" {
				t.Errorf("the gone one is %q, want bar", c.Name)
			}
		}
	}
	if gone != 1 {
		t.Errorf("%d gone couriers, want one", gone)
	}
	// And it can be withdrawn by the name it was admitted under.
	alice.run("allow", "rm", "--courier", "bar", "--relay", rn)
	if out := alice.run("relay", "couriers"); strings.Contains(out, "no longer accepts from it") {
		t.Errorf("after withdrawing it is still shown:\n%s", out)
	}
}

// TestThePushLineCountsWhatWasSignedAndNotTheFilesRows: the sources overlap and
// can shrink, so the line is about the document.
//
// A fingerprint that is both a peer and a courier is signed once, and this
// identity's own is not signed at all. A line built from the two row counts
// would tell somebody their mailbox is open wider than it is, which is the one
// place an overstatement is least affordable.
func TestThePushLineCountsWhatWasSignedAndNotTheFilesRows(t *testing.T) {
	url, neighbours := accepting(t, "bar")
	alice := newUser(t, "alice", url)
	rn := alice.relayName()
	// The courier's own key added as a peer as well, so one fingerprint
	// reaches the document from both sources.
	alice.run("peers", "add", neighbours[0].Public().ExportLine())
	alice.run("allow", "add", "--courier", "bar", "--relay", rn, "--yes")

	out := alice.run("allow", "push")
	if !strings.Contains(out, "from 1 sender(s), of which 1 forward mail to you") {
		t.Fatalf("the line does not describe the document:\n%s", out)
	}
	// And the document really names one.
	var shown []struct {
		Senders []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"senders"`
	}
	if err := json.Unmarshal([]byte(alice.run("allow", "show", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown) != 1 || len(shown[0].Senders) != 1 {
		t.Fatalf("the document names %d senders, want one", len(shown[0].Senders))
	}
}

// rewriteCouriers replaces the relay's couriers file with these identities,
// which is what an operator does when they peer with somebody new or stop.
func rewriteCouriers(t *testing.T, relayURL string, ids []*identity.Identity) {
	t.Helper()
	path := courierFilePath[relayURL]
	if path == "" {
		t.Fatalf("no couriers file recorded for %s", relayURL)
	}
	var b strings.Builder
	for _, id := range ids {
		b.WriteString(id.Public().ExportLine() + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// A distinct modification time, so the reload does not depend on the
	// filesystem's timestamp resolution.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}
