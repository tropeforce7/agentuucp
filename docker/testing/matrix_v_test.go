//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// One peer vouching for another, across the stack's own people: alice and
// bob, peers since the cycle, and a fresh carol enrolled for each row. Each
// row pins the sentence the client prints today.
var vouchRows = []matrixRow{
	{"V01", "introduction", "alice introduces bob to carol, and carol adds him on alice's word", v01},
	{"V02", "question_by_hand", "carol asks alice whether she holds bob, and alice answers by hand", v02},
	{"V03", "knock_with_a_vouch", "alice gives carol a vouch to keep, and carol knocks on bob carrying it", v03},
}

// carolMeetsAlice enrols a fresh carol and makes her and alice peers, each
// with an allow list pushed naming the other, so mail between them is
// taken; the cleanup takes carol off alice's list and pushes it again,
// since every carol is called carol. Each row enrols its own carol, and the
// relay takes five registrations an hour from one address, which the rows
// before this family have spent; so, as P04 does, the row raises it and
// puts it back.
func carolMeetsAlice(t *testing.T) *machine {
	t.Helper()
	undoThenRestart(t, relay.edit(t, relaySettings, `"access_log": "minimal",`,
		`"access_log": "minimal",`+"\n"+`  "limits": {"registrations_per_hour": 100},`))
	relayRestart(t)
	carol := enrolCarol(t)
	line := strings.TrimSpace(carol.auu("id", "export").stdout)
	expectCode(t, alice.auu("peers", "add", line), 0)
	t.Cleanup(func() {
		alice.auu("peers", "rm", "carol")
		alice.auu("allow", "push")
	})
	expectCode(t, alice.auu("allow", "push"), 0)
	expectCode(t, carol.auu("peers", "add", state.aliceLine), 0)
	expectCode(t, carol.auu("allow", "push"), 0)
	return carol
}

func v01(t *testing.T) {
	carol := carolMeetsAlice(t)
	expectSays(t, alice.auu("vouch", "bob", "--to", "carol"), 0, "sent to carol")
	r := carol.auu("inbox")
	expectSays(t, r, 0, `vouches for "bob" `+state.bobFP[:16]+`… (not on your list)`)
	id := find(t, reHex12, lineWith(r.stdout, "vouches for"))
	r = carol.auu("peers", "add", "--vouched", id, "--yes")
	expectSays(t, r, 0,
		"fingerprint: "+state.bobFP,
		"alice is on your list, so this is alice's word for the key.",
		"added "+state.bobFP[:16], "on alice's word")
	expectSays(t, carol.auu("peers", "ls"), 0, "bob")
	expectSays(t, carol.root("cat "+carol.home+"/authorized_peers"), 0, "# vouched for by alice (")
	verdict(t, "ok", "An introduction crosses as an ordinary sealed message; at the other end it counts because "+
		"its sender is held and it verifies under the key held for them, and the person adds the peer at "+
		"their own word, with a comment saying whose word it was.")
}

func v02(t *testing.T) {
	carol := carolMeetsAlice(t)
	expectSays(t, carol.auu("vouch", "--ask", "alice", state.bobFP), 0, "sent to alice")
	r := alice.auu("inbox")
	expectSays(t, r, 0, `asks whether you trust `+state.bobFP[:16]+`… "bob"`)
	id := find(t, reHex12, lineWith(r.stdout, "asks whether you trust"))
	expectSays(t, alice.auu("read", id), 0, "you hold them as bob; answer with: auu vouch bob --to carol")
	expectSays(t, alice.auu("vouch", "bob", "--to", "carol"), 0, "sent to carol")
	expectSays(t, carol.auu("inbox"), 0, `vouches for "bob" `+state.bobFP[:16]+`… (not on your list)`)
	verdict(t, "ok", "The question is a message the person reads and answers with one command, or not at all; "+
		"with the setting off, nothing answers it by itself.")
}

func v03(t *testing.T) {
	clearCard(t, bob)
	drain(bob)
	carol := carolMeetsAlice(t)
	cfp := carolFP(t, carol)
	expectSays(t, bob.auu("card", "push", "--knocks"), 0, relayName+": card pushed")
	t.Cleanup(func() { clearCard(t, bob) })
	expectSays(t, alice.auu("vouch", "carol", "--to", "carol"), 0, "sent to carol")
	expectSays(t, carol.auu("inbox"), 0, "alice vouched for you; kept for your knocks")
	r := carol.auu("knock", state.bobFP, "--vouch", "alice", "--yes")
	expectSays(t, r, 0, "knocked on "+state.bobFP[:16]+"  bob")
	expectSays(t, bob.auu("inbox"), 0, "1 quarantined from unknown senders")
	r = bob.auu("quarantine", "ls")
	expectSays(t, r, 0, "vouched for by alice")
	id := find(t, reHex12, lineWith(r.stdout, "vouched for by alice"))
	r = bob.auuIn("\nn\n", "quarantine", "trust", id)
	expectSays(t, r, 0, "vouched for by alice: alice is on your list, so this is alice's word for the key")
	t.Cleanup(func() {
		bob.auu("peers", "rm", "peer-"+cfp[:8])
		bob.auu("allow", "push")
	})
	verdict(t, "ok", "A knock carries the vouch its sender keeps; the knocked person is told whose word it is, "+
		"among the people they hold, before they are asked anything, and nothing else about trust changes.")
}

// lineWith is the first line of out that contains s.
func lineWith(out, s string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, s) {
			return l
		}
	}
	return ""
}
