package auu

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// peerNames is the names on this user's peer list.
func (u *user) peerNames() []string {
	u.t.Helper()
	s, _, _ := u.opened()
	peers, err := s.Peers()
	if err != nil {
		u.t.Fatal(err)
	}
	var names []string
	for _, p := range peers {
		names = append(names, p.Name)
	}
	return names
}

// atTerminal stands a terminal in for standard input for the length of
// the test, so a command that asks at a terminal asks.
func atTerminal(t *testing.T) {
	t.Helper()
	was := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = was })
}

// listed prints every listed identity, verified here, with the peer list's
// word beside the ones it knows; two entries with one name are both
// printed; an entry the relay serves that does not verify is left out and
// counted on stderr; and --json carries the same, with the relay's mode.
func TestListedShowsWhoChoseToBeListed(t *testing.T) {
	relayURL, _, db, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	bob2 := newUser(t, "bob", relayURL)
	dave := newUser(t, "dave", relayURL)
	alice.run("peers", "add", bob.exportLine())
	for _, u := range []*user{alice, bob, carol, bob2} {
		u.run("card", "push", "--listed")
	}
	dave.run("card", "push", "--knocks")
	rn := alice.relayName()

	var warning string
	var out string
	warning = captureStderr(t, func() { out = alice.run("listed") })
	if warning != "" {
		t.Fatalf("a warning with every entry verifying:\n%s", warning)
	}
	if !strings.Contains(out, rn+": 4 identities listed, all shown\n") {
		t.Fatalf("the header:\n%s", out)
	}
	for _, want := range []string{
		alice.exportFingerprint()[:16] + "  alice", "  you",
		bob.exportFingerprint()[:16] + "  bob", "  peer",
		carol.exportFingerprint()[:16] + "  carol",
		bob2.exportFingerprint()[:16] + "  bob",
		"The relay registers anyone: an identity here proves nothing about who holds it, and its name is its own claim.",
		"To add one, at a terminal: auu peers fetch NAME|SHORT-ID",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("listed lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dave") {
		t.Fatalf("a card that says no is listed:\n%s", out)
	}
	if strings.Count(out, "  bob") != 2 {
		t.Fatalf("two entries with one name are not both printed:\n%s", out)
	}

	var shown listedJSON
	if err := json.Unmarshal([]byte(alice.run("listed", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Relay != rn || shown.Registration != "open" || len(shown.Entries) != 4 || shown.Dropped != 0 {
		t.Fatalf("listed --json: %+v", shown)
	}
	byFP := map[string]listedEntryJSON{}
	for _, e := range shown.Entries {
		byFP[e.Fingerprint] = e
	}
	if e := byFP[alice.exportFingerprint()]; e.KnownAs != "self" || e.Name != "alice" || e.Short != alice.exportFingerprint()[:16] {
		t.Fatalf("alice's entry: %+v", e)
	}
	if e := byFP[bob.exportFingerprint()]; e.KnownAs != "bob" || e.Name != "bob" {
		t.Fatalf("bob's entry: %+v", e)
	}
	if e := byFP[carol.exportFingerprint()]; e.KnownAs != "" || e.Suite == "" {
		t.Fatalf("carol's entry: %+v", e)
	}

	// The host edits carol's card's name, and sets the listed column on
	// dave's card that says no: carol's row no longer verifies and dave's
	// document says no, so both are left out and counted, and the count
	// the relay gives is what it holds.
	if _, err := db.Exec(`UPDATE cards SET doc = CAST(replace(CAST(doc AS TEXT), '"name":"carol"', '"name":"mallory"') AS BLOB) WHERE fp = ?`, carol.exportFingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE cards SET listed = 1 WHERE fp = ?`, dave.exportFingerprint()); err != nil {
		t.Fatal(err)
	}
	warning = captureStderr(t, func() { out = alice.run("listed") })
	if warning != "auu: 2 entries did not verify and were left out\n" {
		t.Fatalf("the dropped count:\n%s", warning)
	}
	if strings.Contains(out, "mallory") || strings.Contains(out, "carol") || strings.Contains(out, "dave") {
		t.Fatalf("an edited row reached the listing:\n%s", out)
	}
	if !strings.Contains(out, rn+": 5 identities listed, 3 shown\n") {
		t.Fatalf("the header after the edits:\n%s", out)
	}
	if err := json.Unmarshal([]byte(alice.run("listed", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Dropped != 2 || len(shown.Entries) != 3 {
		t.Fatalf("listed --json after the edits: %+v", shown)
	}
	// Flag placement: the flag after the command works the same.
	if out := alice.run("listed", "--relay", rn, "--json"); !strings.Contains(out, `"dropped": 2`) {
		t.Fatalf("listed with flags after:\n%s", out)
	}
}

// peers fetch by name resolves through the listing and adds at a terminal
// after asking twice, once to add and once for the local name, with the
// card's name offered; refuses without a terminal and without --yes; adds
// with --yes under the offered name; refuses an ambiguous name with the
// sentence naming the short id; and lookup still adds nobody. The two
// prompts read through one reader, so both answers arrive through a pipe.
func TestPeersFetchAddsAListedPeerAtATerminal(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob2 := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	rn := alice.relayName()
	for _, u := range []*user{bob, bob2, carol} {
		u.run("card", "push", "--listed")
	}

	// No terminal, no --yes: refused, exit 1, nothing added.
	_, err := alice.tryRun("peers", "fetch", "carol")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "adding a peer is a person's decision: run this at a terminal, or pass --yes") {
		t.Fatalf("peers fetch without a terminal: %v", err)
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("a refused fetch added %v", names)
	}
	// lookup still adds nobody.
	if out := alice.run("lookup", carol.exportFingerprint()); !strings.Contains(out, "peer list:     not on yours") {
		t.Fatalf("lookup:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("lookup added %v", names)
	}

	// An ambiguous name: refused with the sentence, before anything is
	// asked.
	atTerminal(t)
	_, err = alice.tryRun("peers", "fetch", "bob")
	if !errors.As(err, &e) || e.code != exitUsage || err.Error() != `two listed identities call themselves "bob" on `+rn+`; use the short id (auu listed shows them)` {
		t.Fatalf("an ambiguous name: %v", err)
	}
	// A name nobody claims.
	if _, err := alice.tryRun("peers", "fetch", "erin"); err == nil || !strings.Contains(err.Error(), `no listed identity calls itself "erin" on `+rn) {
		t.Fatalf("a name nobody claims: %v", err)
	}
	// Not a name a card could carry.
	if _, err := alice.tryRun("peers", "fetch", "not a name"); err == nil || !strings.Contains(err.Error(), "is not a fingerprint, a short id, or a name a card could carry") {
		t.Fatalf("a bad query: %v", err)
	}

	// At a terminal: the look, the mode sentence, the question answered n
	// — nothing added, the home as it was.
	out, err := alice.answer("n", "peers", "fetch", "carol")
	if err != nil {
		t.Fatalf("peers fetch answered n: %v\n%s", err, out)
	}
	for _, want := range []string{
		"name on relay: carol", "fingerprint:   " + carol.exportFingerprint(),
		"registration:  open; the relay registers anyone: this identity proves nothing about who holds it, and its name is its own claim",
		"Add " + carol.exportFingerprint()[:16] + " as a peer? [y/N]: ", "nothing added",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("peers fetch lacks %q:\n%s", want, out)
		}
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("a declined fetch added %v", names)
	}
	// Answered y, then the local name typed at the second prompt: both
	// answers arrive through the pipe, and the peer is added under the
	// typed name, not the offered one.
	out, err = alice.answer("y\nCaroline", "peers", "fetch", "carol")
	if err != nil {
		t.Fatalf("peers fetch answered y then a name: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Local name for "+carol.exportFingerprint()[:16]+" [carol]: ") ||
		!strings.Contains(out, "added "+carol.exportFingerprint()[:16]+"  Caroline\n") {
		t.Fatalf("the second prompt and the add:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 1 || names[0] != "Caroline" {
		t.Fatalf("the peer list after the add: %v", names)
	}
	// Fetched again: already known, nothing asked.
	if out := alice.run("peers", "fetch", "carol"); !strings.Contains(out, "already known: "+carol.exportFingerprint()[:16]+"  Caroline") {
		t.Fatalf("a second fetch:\n%s", out)
	}

	// By short id through the key lookup, with --yes: added under the
	// offered name, the relay's registered name, without a question.
	stdinIsTerminal = func() bool { return false }
	out = alice.run("peers", "fetch", bob.exportFingerprint()[:16], "--yes")
	if !strings.Contains(out, "added "+bob.exportFingerprint()[:16]+"  bob\n") || strings.Contains(out, "[y/N]") {
		t.Fatalf("peers fetch by short id with --yes:\n%s", out)
	}
	// The other bob, by fingerprint: the name is taken on the peer list,
	// so the fallback is offered and taken.
	out = alice.run("peers", "fetch", bob2.exportFingerprint(), "--yes")
	if !strings.Contains(out, `"bob" is already the name of `+bob.exportFingerprint()[:16]+" on your peer list, so it is not offered") ||
		!strings.Contains(out, "added "+bob2.exportFingerprint()[:16]+"  peer-"+bob2.exportFingerprint()[:8]+"\n") {
		t.Fatalf("a fetch whose offered name is taken:\n%s", out)
	}
	// Taken is what AddPeer refuses on, a name that folds equal, and not
	// what Resolve matches: "bo" is a prefix of "bob" and free, so it is
	// offered and taken; "Bob" folds to "bob" and is not, and the
	// sentence names the peer whose it is.
	bo := newUser(t, "bo", relayURL)
	bo.run("card", "push", "--listed")
	out = alice.run("peers", "fetch", bo.exportFingerprint(), "--yes")
	if strings.Contains(out, "so it is not offered") ||
		!strings.Contains(out, "added "+bo.exportFingerprint()[:16]+"  bo\n") {
		t.Fatalf("a fetch whose offered name is a prefix of a peer's:\n%s", out)
	}
	bigBob := newUser(t, "Bob", relayURL)
	bigBob.run("card", "push", "--listed")
	out = alice.run("peers", "fetch", bigBob.exportFingerprint(), "--yes")
	if !strings.Contains(out, `"Bob" is already the name of `+bob.exportFingerprint()[:16]+" on your peer list, so it is not offered") ||
		!strings.Contains(out, "added "+bigBob.exportFingerprint()[:16]+"  peer-"+bigBob.exportFingerprint()[:8]+"\n") {
		t.Fatalf("a fetch whose offered name folds to a peer's:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 5 {
		t.Fatalf("the peer list: %v", names)
	}
	// Yourself.
	if _, err := alice.tryRun("peers", "fetch", alice.exportFingerprint(), "--yes"); err == nil || !strings.Contains(err.Error(), "that is you") {
		t.Fatalf("fetching oneself: %v", err)
	}
	// Flag placement: the flag before the positional.
	if out := alice.run("peers", "fetch", "--yes", carol.exportFingerprint()); !strings.Contains(out, "already known") {
		t.Fatalf("flag before the argument:\n%s", out)
	}
}

// On a relay that invites by token the sentence says an administrator let
// the identity in, and that its name is its own claim; a token pins a
// fingerprint and never a name.
func TestPeersFetchSaysWhatATokenRelayMeans(t *testing.T) {
	_, issue := tokenRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(nil))
	bob := &user{t: t, home: t.TempDir()}
	bob.run("enrol", "--name", "bob", "--yes", issue(nil))
	bob.run("card", "push", "--listed")
	out := alice.run("peers", "fetch", "bob", "--yes")
	if !strings.Contains(out, "registration:  token; the relay invites by token: this identity was let in by an administrator, and its name is its own claim") ||
		!strings.Contains(out, "added "+bob.exportFingerprint()[:16]+"  bob") {
		t.Fatalf("peers fetch on a token relay:\n%s", out)
	}
	if out := alice.run("listed"); !strings.Contains(out, "The relay invites by token: an identity here was let in by an administrator, and its name is its own claim.") {
		t.Fatalf("listed on a token relay:\n%s", out)
	}
}

// The prompts read standard input through one reader: two answers on one
// pipe reach two prompts. Against a reader per prompt the second prompt
// found end of file and took its fallback, which is what `docker exec -i`
// and the tests' pipe both showed.
func TestTwoPromptsReadOnePipe(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("y\nfred\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	real := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = real; r.Close() })
	if !confirm("first?") {
		t.Fatal("the first prompt did not read y")
	}
	if got := promptName(fp, "peer-abababab"); got != "fred" {
		t.Fatalf("the second prompt read %q, want fred: the first reader took the pipe", got)
	}
	// And a fresh pipe is a fresh reader: what the tests' answer helper
	// does between commands.
	r2, w2, _ := os.Pipe()
	w2.WriteString("n\n")
	w2.Close()
	os.Stdin = r2
	t.Cleanup(func() { r2.Close() })
	if confirm("again?") {
		t.Fatal("the new pipe's n was not read")
	}
}

// The relay's listing route is signed in receive scope: an agent unlocked
// to receive signs it, and listed and peers fetch both work under it;
// only the peer list, which no scope governs, is written.
func TestListedIsReceiveScope(t *testing.T) {
	relayURL := startRelay(t)
	agentEnv(t)
	bob := newUser(t, "bob", relayURL)
	bob.run("card", "push", "--listed")
	alice := newUser(t, "alice", relayURL)
	alice.encrypt()
	if st := alice.agentStatus(); st.Locked || st.Scope != "receive" {
		t.Fatalf("the agent after passphrase set: %+v", st)
	}
	if out := alice.run("listed"); !strings.Contains(out, "bob") {
		t.Fatalf("listed under receive scope:\n%s", out)
	}
	if out := alice.run("peers", "fetch", "bob", "--yes"); !strings.Contains(out, "added") {
		t.Fatalf("peers fetch under receive scope:\n%s", out)
	}
	if st := alice.agentStatus(); st.Scope != "receive" {
		t.Fatalf("the agent's scope after the two commands: %+v", st)
	}
}
