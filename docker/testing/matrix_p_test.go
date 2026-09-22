//go:build e2e

package e2e

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The card, the listing and the knock: what an owner publishes about
// themselves, what a stranger can do with it, and what the operator's
// settings bound. The relay these run against invites by token, so the
// sentence every one of these commands prints about a name found on it is
// the token one. The cycle left alice and bob peers with signed allow
// lists; every row here puts back what it changed.
var cardRows = []matrixRow{
	{"P01", "card_and_listing", "bob lets the relay list him, and carol finds and adds him", p01},
	{"P02", "edited_on_the_host", "the relay's database edited to change a listed name, then to blank a signature", p02},
	{"P03", "knock", "carol knocks on bob, who has not admitted her, and bob trusts her", p03},
	{"P04", "caps", "the operator's three knock settings, each met", p04},
}

// takesKnocks is what a mailbox that takes none says to a knocker.
const takesKnocks = "relay returned 403: the recipient does not take knocks"

// clearCard puts a card back to saying neither word, which is what no
// card means, so a row leaves the next one the state the cycle left.
func clearCard(t *testing.T, m *machine) {
	t.Helper()
	t.Cleanup(func() { m.auu("card", "clear") })
}

func p01(t *testing.T) {
	clearCard(t, bob)
	expectSays(t, bob.auu("card", "push", "--listed"), 0, relayName+": card pushed")
	r := bob.auu("card", "show")
	expectSays(t, r, 0, relayName+": signed, issued ", ", name bob; you are listed there and your mailbox takes no knocks")
	expectNot(t, r, "broken")

	// Alice, who has bob on her list, sees him as a peer and herself as
	// herself; carol, who has nobody, sees him as neither.
	r = alice.auu("listed")
	expectSays(t, r, 0, state.bobFP[:16]+"  bob", "  peer",
		"The relay invites by token: an identity here was let in by an administrator, and its name is its own claim.")
	stderrIs(t, r, "")
	carol := enrolCarol(t)
	r = carol.auu("listed")
	expectSays(t, r, 0, state.bobFP[:16]+"  bob")
	expectNot(t, r, "  peer", "  you")

	// Carol adds him from the listing, with --yes since there is no
	// terminal in a container: the look, the token sentence, the name
	// from his card taken as the local one.
	r = carol.auu("peers", "fetch", "bob", "--yes")
	expectSays(t, r, 0, "name on relay: bob", "fingerprint:   "+state.bobFP,
		"registration:  token; the relay invites by token: this identity was let in by an administrator, "+
			"and its name is its own claim",
		"added "+state.bobFP[:16]+"  bob")
	expectSays(t, carol.auu("peers", "ls"), 0, "bob")

	// lookup adds nobody, then or now.
	carol2 := enrolCarol(t)
	r = carol2.auu("lookup", state.bobFP)
	expectSays(t, r, 0, "peer list:     not on yours")
	expectNot(t, carol2.auu("peers", "ls"), "bob")
	verdict(t, "ok", "A card is the owner's own choice to be found; the listing is verified on the reader's machine, "+
		"and adding is a person's command that prints what the relay's admission is worth.")
}

func p02(t *testing.T) {
	clearCard(t, bob)
	expectSays(t, bob.auu("card", "push", "--listed"), 0, relayName+": card pushed")
	drain(bob)

	// The name in the document bob signed, changed on the host: the row
	// no longer verifies, so alice's client drops it and says how many
	// were left out rather than showing the name the editor wrote.
	sqlEdit(t, `UPDATE cards SET doc = CAST(replace(CAST(doc AS TEXT), `+
		`'"name":"bob"', '"name":"mallory"') AS BLOB) WHERE fp = '`+state.bobFP+`'`)
	r := alice.auu("listed")
	expectCode(t, r, 0)
	expectNot(t, r, "mallory")
	stderrIs(t, r, "auu: 1 entry did not verify and was left out")

	// Bob's own fetch is silent about his card once his row verifies
	// again, which his own push is.
	expectSays(t, bob.auu("card", "push", "--listed"), 0, relayName+": card pushed")
	r = bob.auu("inbox")
	expectCode(t, r, 0)
	expectNot(t, r, "card")
	stderrIs(t, r, "")

	// ...and says so when the signature is blanked, which is the state a
	// push repairs.
	m := logMark()
	sqlEdit(t, `UPDATE cards SET sig = X'' WHERE fp = '`+state.bobFP+`'`)
	r = bob.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, "auu: your card on "+relayName+" does not verify, so nobody can knock and you are not listed there; "+
		"run auu card push, and if you did not change it, tell the relay's operator")
	r = operator.admin("mailboxes", "show", state.bobFP)
	expectSays(t, r, 0, "card:        broken")
	// A knock while it is broken is refused, and the operator's journal
	// names the mailbox and nobody else.
	carol := enrolCarol(t)
	expectSays(t, carol.auu("knock", state.bobFP, "--yes"), 2, takesKnocks)
	log := waitRelayLog(t, m, "card for "+state.bobFP+
		" does not verify; refusing knocks to it until the owner pushes again", 5*time.Second)
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, "card for ") && strings.Contains(l, carolFP(t, carol)[:16]) {
			t.Errorf("the fault line names the knocker:\n%s", l)
		}
	}
	// The repair, and the listing has him again under his own name.
	expectSays(t, bob.auu("card", "push", "--listed"), 0, relayName+": card pushed")
	r = alice.auu("listed")
	expectSays(t, r, 0, state.bobFP[:16]+"  bob")
	stderrIs(t, r, "")
	verdict(t, "ok", "An edit on the host removes a name and never adds one; the owner is told at their next fetch, "+
		"the operator sees broken, and one push is the whole repair.")
}

func p03(t *testing.T) {
	clearCard(t, bob)
	drain(bob)
	carol := enrolCarol(t)
	cfp := carolFP(t, carol)

	// Bob's card says nothing yet, so carol cannot knock; and were she to
	// add him by hand his mailbox, restricted to alice, would refuse her
	// post. Neither door is open.
	before := queued(t, state.bobFP)
	expectSays(t, carol.auu("knock", state.bobFP, "--yes"), 2, takesKnocks)
	if q := queued(t, state.bobFP); len(q) != len(before) {
		t.Errorf("a refused knock queued a message: %v before, %v after", before, q)
	}
	// Her own allow list is pushed, so the knock has one to push again.
	expectSays(t, carol.auu("allow", "push"), 0, relayName+" will now accept mail for you from 0 peer(s) only")

	// Bob says he takes knocks. Now her knock is taken, and it adds him to
	// her peer list and pushes her allow list, so his reply can reach her.
	expectSays(t, bob.auu("card", "push", "--knocks"), 0, relayName+": card pushed")
	r := carol.auu("knock", state.bobFP, "--text", "carol from the Tuesday standup", "--yes")
	expectSays(t, r, 0, "knocked on "+state.bobFP[:16]+"  bob",
		relayName+" will now accept mail for you from 1 peer(s) only",
		"your allow list went to "+relayName+" with them in it")
	expectSays(t, carol.auu("peers", "ls"), 0, "bob")

	// Bob's fetch puts it in quarantine, saying who claims what, and the
	// relay no longer holds it: a knock is never kept.
	r = bob.auu("inbox")
	expectSays(t, r, 0, "1 quarantined from unknown senders")
	r = bob.auu("quarantine", "ls")
	expectSays(t, r, 0, "knock  from "+cfp[:16], "carol", "carol from the Tuesday standup")
	id := find(t, reHex12, r.stdout)
	expectSays(t, bob.auu("quarantine", "show", id), 0, "type:    knock",
		"claims:  carol (their own claim, not a name you gave)")
	if holdsKnock(t, state.bobFP) {
		t.Error("a fetched knock is still on the relay")
	}

	// Bob trusts her. There is no terminal here — a docker exec is a pipe,
	// as a script or an agent would be — so the name she chose for herself
	// is not offered: the prompt takes this machine's own peer-<fp8>, and
	// the line says why. Then the offer to push his allow list so she can
	// write to him, both answers through one pipe.
	local := "peer-" + cfp[:8]
	r = bob.auuIn("\ny\n", "quarantine", "trust", id)
	expectSays(t, r, 0,
		"they call themselves carol, which is their own claim; without a terminal it is not offered",
		"Local name for "+cfp[:16]+" ["+local+"]: ",
		"trusted "+cfp[:16]+" and moved message ",
		"Push your allow list to "+relayName+" now, so "+local+" can write to you?",
		relayName+" will now accept mail for you from 2 peer(s) only")
	// And the reply lands in her inbox, not her quarantine.
	sendJSON(t, bob, local, "--subject", "re: knock", "come in")
	r = carol.auu("inbox")
	expectSays(t, r, 0, "fetched 1 new message(s)")
	expectNot(t, r, "quarantine")

	// A second knock is refused before the relay is asked anything.
	expectSays(t, carol.auu("knock", state.bobFP, "--yes"), 1,
		"is already a peer (bob); use 'auu send' to write to them")
	verdict(t, "ok", "A knock crosses once, past the allow list, only where the owner's signed card says so; "+
		"both sides decide at a prompt, the name a knocker chose for themselves is not taken where nobody is "+
		"there to accept it, and the two allow lists are pushed for them.")
}

func p04(t *testing.T) {
	clearCard(t, bob)
	drain(bob)
	expectSays(t, bob.auu("card", "push", "--knocks"), 0, relayName+": card pushed")
	// The operator's settings for this row: one knock waiting, one an
	// hour per sender, and a cap under the size of a knock.
	// registrations_per_hour goes up with them: the rows before this one
	// have spent this address's five on their own strangers, and this row
	// needs two of its own.
	undoThenRestart(t, relay.edit(t, relaySettings, `"access_log": "minimal",`,
		`"access_log": "minimal",`+"\n"+`  "limits": {"max_knocks_waiting": 1, "knocks_per_hour": 2, `+
			`"registrations_per_hour": 100},`))
	relayRestart(t)
	// The settings the operator set, as the administrator reads them
	// back. The text view prints no limits at all today; --json is where
	// they are, and this asserts them there.
	r := operator.admin("status", "--json")
	expectSays(t, r, 0, `"max_knocks_waiting": 1`, `"knocks_per_hour": 2`, `"knock_max_bytes": 8192`)

	carol := enrolCarol(t)
	dave := enrolCarol(t)
	// Carol's knock fills the mailbox's one waiting place. Its text is
	// given, so the assertion below that it is gone is about this knock
	// and not about a string no row ever carried.
	expectSays(t, carol.auu("knock", state.bobFP, "--text", "carol, first try", "--yes"),
		0, "knocked on "+state.bobFP[:16])
	// And her second replaces it rather than meeting the cap: the cap
	// counts knockers, so one knocker holds one place however often they
	// knock. She has to forget bob first, since auu knock refuses a knock
	// to a peer — which is the client's rule, not the relay's.
	carol.auu("peers", "rm", "bob")
	expectSays(t, carol.auu("knock", state.bobFP, "--text", "carol again, about the CFP", "--yes"),
		0, "knocked on "+state.bobFP[:16])
	if n := knockRows(t, state.bobFP); n != 1 {
		t.Errorf("%d knock rows after one knocker knocked twice, want 1", n)
	}
	// Dave's meets the recipient's cap, refused by the sentence that
	// names the setting. It carries no Retry-After, so the client does
	// not wait it out: the answer comes back at once.
	began := time.Now()
	r = dave.auu("knock", state.bobFP, "--yes")
	expectSays(t, r, 2, "the recipient has as many knocks waiting as this relay allows (max_knocks_waiting)")
	if waited := time.Since(began); waited > 20*time.Second {
		t.Errorf("the knock took %s; a 429 with no Retry-After is final and is not slept on", waited)
	}
	// Carol's second, to another mailbox that takes knocks, meets her own
	// budget for the hour instead, which does carry a Retry-After. The
	// budget is across every mailbox, which is what this shows.
	clearCard(t, alice)
	expectSays(t, alice.auu("card", "push", "--knocks"), 0, relayName+": card pushed")
	r = carol.auu("knock", state.aliceFP, "--yes")
	expectSays(t, r, 2, "rate limited: knocks")
	// Bob fetches, which takes the knock off the relay and empties the
	// cap, and what reaches his quarantine is carol's second text and not
	// her first: the replacement is what he sees.
	expectSays(t, bob.auu("inbox"), 0, "quarantined from unknown senders")
	expectSays(t, bob.auu("quarantine", "ls"), 0, "carol again, about the CFP")
	expectNot(t, bob.auu("quarantine", "ls"), "carol, first try")
	expectSays(t, dave.auu("knock", state.bobFP, "--yes"), 0, "knocked on "+state.bobFP[:16])
	// The knock's own text rule, before anything is sealed and before the
	// relay is asked: one byte over is refused here, at exit 1.
	r = dave.auu("knock", state.aliceFP, "--text", strings.Repeat("x", 513), "--yes")
	expectSays(t, r, 1, "a knock's text is 513 bytes; at most 512")

	// And the route's own cap, which the operator lowers under the size
	// of a sealed knock: every knock is then refused 413 naming the
	// setting, before the envelope is read. A sealed knock at this
	// relay's suite is about 4.4 KiB, which is why 4096 closes the door;
	// the figure is the ciphersuite's, so the cap is set under it rather
	// than a knock built up to it.
	undoThenRestart(t, relay.edit(t, relaySettings, `"registrations_per_hour": 100},`,
		`"registrations_per_hour": 100, "knock_max_bytes": 4096},`))
	relayRestart(t)
	expectSays(t, operator.admin("status", "--json"), 0, `"knock_max_bytes": 4096`)
	drain(bob)
	carol3 := enrolCarol(t)
	expectSays(t, carol3.auu("knock", state.bobFP, "--yes"), 2,
		"relay returned 413: knock too large: at most 4096 bytes (knock_max_bytes)")
	if holdsKnock(t, state.bobFP) {
		t.Error("a knock refused for its size was stored")
	}
	verdict(t, "ok", "Each of the three settings is met by the sentence that names it, the recipient's cap clears "+
		"when its owner fetches, and the refusal that cannot be waited out is not waited out.")
}

// reHex12 is a message id as a listing prints it: the first twelve
// characters of one, which every command takes in place of the whole.
var reHex12 = regexp.MustCompile(`\b[0-9a-f]{12}\b`)

// knockRows is how many rows of kind knock the relay holds for a mailbox.
func knockRows(t *testing.T, fp string) int {
	t.Helper()
	out := strings.TrimSpace(relay.sql(t, "SELECT COUNT(*) FROM messages WHERE to_fp='"+fp+"' AND kind='knock'"))
	n, err := strconv.Atoi(out)
	if err != nil {
		t.Fatalf("counting knock rows: %q", out)
	}
	return n
}

// holdsKnock reports whether the relay still holds a row of kind knock
// for a mailbox.
func holdsKnock(t *testing.T, fp string) bool {
	t.Helper()
	return knockRows(t, fp) != 0
}
