//go:build e2e

package e2e

import (
	"testing"
	"time"
)

// The signed allow list: what the owner pushes, what the relay enforces
// on every post, and what the owner is told when the list on the relay is
// not the one they signed. The cycle left alice and bob each admitting
// the other, signed; every row here puts that back.
var allowRows = []matrixRow{
	{"A01", "push_and_refuse", "bob pushes his list; alice's post is taken and a stranger's refused", a01},
	{"A02", "edited_on_the_host", "the relay's database is edited to admit the stranger", a02},
}

const refusedByList = "relay returned 403: sender is not on the recipient's allow list"

// sqlEdit is sqlFault without the backup, for a row whose own last step
// puts the database right: a backup's restore would wind the message
// sequence back behind bob's cursor, as dbBackup's note says, and the
// repair these rows are about is 'auu allow push'.
func sqlEdit(t *testing.T, stmt string) {
	t.Helper()
	if nofault {
		return
	}
	relay.sql(t, stmt)
}

// aStranger is carol, enrolled and with bob on her list, so that a send
// from her reaches the relay and is refused there rather than here.
func aStranger(t *testing.T) *machine {
	t.Helper()
	carol := enrolCarol(t)
	expectSays(t, carol.auu("peers", "add", state.bobLine), 0, "added")
	return carol
}

func a01(t *testing.T) {
	expectSays(t, bob.auu("allow", "push"), 0, relayName+" will now accept mail for you from 1 peer(s) only")
	r := bob.auu("allow", "show")
	expectSays(t, r, 0, relayName+": signed, issued ", ", 1 sender", "  "+state.aliceFP[:16]+"  alice")
	expectNot(t, r, "broken", "does not verify")
	// A peer's post is taken, and drained without a word about the list.
	sendJSON(t, alice, "bob", "--subject", "admitted", "from a peer")
	r = bob.auu("inbox")
	expectSays(t, r, 0, "fetched 1 new message(s)")
	stderrIs(t, r, "")
	// A stranger's is refused at the relay, with the sentence a refused
	// post always got, and nothing is queued.
	carol := aStranger(t)
	before := queued(t, state.bobFP)
	r = carol.auu("send", "--to", "bob", "--subject", "who is this", "from carol")
	expectSays(t, r, 2, refusedByList)
	if after := queued(t, state.bobFP); len(after) != len(before) {
		t.Errorf("a refused send queued a message: %v before, %v after", before, after)
	}
	// The administrator sees the count and the word, never the sender.
	r = operator.admin("mailboxes", "show", state.bobFP)
	expectSays(t, r, 0, "allowlist:   1 senders, signed")
	expectNot(t, r, state.aliceFP)
	verdict(t, "ok", "")
}

func a02(t *testing.T) {
	carol := aStranger(t)
	drain(bob)
	// The edit an intruder on the host would make: carol's fingerprint
	// written into the document bob signed.
	m := logMark()
	sqlEdit(t, `UPDATE allowlists SET doc = CAST(replace(CAST(doc AS TEXT), '"senders":[', '"senders":["`+
		carolFP(t, carol)+`",') AS BLOB), count = count + 1 WHERE fp = '`+state.bobFP+`'`)
	// The stranger the edit admitted is refused, since the document no
	// longer verifies; so is alice, whom bob did admit: the list fails
	// closed. Neither learns why.
	r := carol.auu("send", "--to", "bob", "--subject", "admitted?", "am I in")
	expectSays(t, r, 2, refusedByList)
	r = alice.auu("send", "--to", "bob", "--subject", "admitted?", "am I still in")
	expectSays(t, r, 2, refusedByList)
	// The operator's journal says which mailbox, once a minute.
	waitRelayLog(t, m, "allow list for "+state.bobFP+" does not verify; refusing every post to it until the owner pushes again", 5*time.Second)
	// Bob's next inbox says so, after the messages and on stderr, and
	// the run's own exit code stands.
	r = bob.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, "auu: your allow list on "+relayName+" does not verify, so nobody can post to you there; "+
		"run auu allow push, and if you did not change it, tell the relay's operator")
	r = bob.auu("allow", "show")
	expectSays(t, r, 1, relayName+": your allow list on "+relayName+" does not verify, so nobody can post to you there")
	r = operator.admin("mailboxes", "ls")
	expectSays(t, r, 0, "2 broken")
	// The repair.
	expectSays(t, bob.auu("allow", "push"), 0, relayName+" will now accept mail for you from 1 peer(s) only")
	sendJSON(t, alice, "bob", "--subject", "repaired", "back in")
	r = bob.auu("inbox")
	expectSays(t, r, 0, "fetched 1 new message(s)")
	stderrIs(t, r, "")
	r = carol.auu("send", "--to", "bob", "--subject", "admitted?", "and me")
	expectSays(t, r, 2, refusedByList)
	verdict(t, "ok", "The edit refuses everyone rather than admitting anyone, the owner and the operator are each "+
		"told in their own place, and the owner's push is the whole repair.")
}

// carolFP is a stranger's fingerprint, from her own id.
func carolFP(t *testing.T, carol *machine) string {
	t.Helper()
	return find(t, reHex64, carol.auu("id").stdout)
}
