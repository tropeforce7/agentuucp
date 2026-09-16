//go:build e2e

package e2e

import (
	"strconv"
	"strings"
	"testing"
)

// Mail left on the relay: a channel keeps its mail after it is fetched, so
// that a second machine of one identity reads the same mail, and auu rm is
// what takes it away. The cycle left bob's directory holding default and
// bug reports; every row leaves the relay and the spools as it found them.
var keepRows = []matrixRow{
	{"L01", "kept", "a fetch leaves the message on the relay and says so", l01},
	{"L02", "keep_off", "a channel set to off is acknowledged away as before", l02},
	{"L03", "rm_both", "auu rm takes it from the relay and from here", l03},
	{"L04", "rm_remote_only", "--remote-only keeps the local copy, unmarked", l04},
	{"L05", "rm_local_only", "--local-only frees the disk here and leaves the relay's copy", l05},
	{"L06", "second_machine", "bob's other machine reads the same mail, and one rm shows on both", l06},
	{"L07", "quota", "kept mail fills the mailbox, and rm is what makes room", l07},
}

// keptOnRelay is bob's record for a message id, and whether the listing
// marks it as still on the relay.
func keptOnRelay(t *testing.T, m *machine, id string) (bool, bool) {
	t.Helper()
	in := fetchJSON(t, m, "--no-fetch")
	for _, msg := range in.Messages {
		if strings.HasPrefix(msg.ID, id) {
			return true, msg.OnRelay
		}
	}
	return false, false
}

// queuedCount is what the relay says it holds for bob, as the inbox's own
// per-relay report says it.
func queuedCount(t *testing.T, in inboxJSON) int64 {
	t.Helper()
	for _, rep := range in.Relays {
		if rep.Relay == relayName {
			return rep.Queued
		}
	}
	t.Errorf("no report for %s in %+v", relayName, in.Relays)
	return -1
}

func l01(t *testing.T) {
	id, _ := queueOne(t, "--subject", "kept on the relay", "read it and it is still there")
	cursorBefore := bobCursor(t)
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 {
		t.Errorf("the fetch: %+v", in.Fetch)
	}
	// The relay still holds it, the record says so, and the count line
	// counts it.
	if left := queued(t, state.bobFP); len(left) != 1 || left[0] != id {
		t.Errorf("the relay holds %v after the fetch, want the message kept", left)
	}
	if n := queuedCount(t, in); n != 1 {
		t.Errorf("the inbox reports %d on the relay, want 1", n)
	}
	var found bool
	for _, msg := range in.Messages {
		if msg.Subject == "kept on the relay" {
			found = msg.OnRelay
		}
	}
	if !found {
		t.Errorf("the message is not marked as on the relay: %+v", in.Messages)
	}
	r := bob.auu("inbox")
	expectSays(t, r, 0, "  on relay", relayName+": 1 message(s) on the relay; auu rm removes them")
	// And the cursor moved, so it is not fetched twice.
	if bobCursor(t) == cursorBefore {
		t.Errorf("the cursor did not move: %s", bobCursor(t))
	}
	if again := fetchJSON(t, bob); again.Fetch.Delivered != 0 {
		t.Errorf("a second fetch delivered it again: %+v", again.Fetch)
	}
	drain(bob)
	verdict(t, "ok", "")
}

func l02(t *testing.T) {
	expectSays(t, bob.auu("channel", "keep", "default", "off"), 0,
		"default: mail is removed from the relay once it is fetched")
	defer func() {
		expectSays(t, bob.auu("channel", "keep", "default", "on"), 0,
			"default: mail is kept on the relay after it is fetched")
	}()
	queueOne(t, "--subject", "acknowledged away", "as a fetch always did")
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 {
		t.Errorf("the fetch: %+v", in.Fetch)
	}
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("the relay holds %v after a fetch that does not keep", left)
	}
	for _, msg := range in.Messages {
		if msg.Subject == "acknowledged away" && msg.OnRelay {
			t.Errorf("the message is marked as on the relay: %+v", msg)
		}
	}
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	expectNot(t, r, "on relay", "auu rm removes them")
	// The channel's setting is bob's own: the KEEP column says so, and
	// the relay was never told.
	expectSays(t, bob.auu("channel", "ls"), 0, "KEEP")
	drain(bob)
	verdict(t, "ok", "")
}

func l03(t *testing.T) {
	id, file := queueOne(t, "--subject", "removed from both", "gone from both")
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 || len(in.Messages) == 0 {
		t.Fatalf("the fetch: %+v", in.Fetch)
	}
	msgID := ""
	for _, msg := range in.Messages {
		if msg.Subject == "removed from both" {
			msgID = msg.ID
		}
	}
	if msgID == "" {
		t.Fatalf("the message is not in the inbox: %+v", in.Messages)
	}
	r := bob.auu("rm", msgID)
	expectSays(t, r, 0, msgID[:12]+": removed from "+relayName+" and here")
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("the relay holds %v after auu rm", left)
	}
	if relay.exists(file) {
		t.Errorf("the relay still has the message file %s", file)
	}
	if here, _ := keptOnRelay(t, bob, msgID); here {
		t.Errorf("the local copy is still there: %s", msgID)
	}
	_ = id
	verdict(t, "ok", "")
}

func l04(t *testing.T) {
	id, _ := queueOne(t, "--subject", "removed from the relay only", "kept here")
	in := fetchJSON(t, bob)
	msgID := ""
	for _, msg := range in.Messages {
		if msg.Subject == "removed from the relay only" {
			msgID = msg.ID
		}
	}
	if msgID == "" {
		t.Fatalf("the message is not in the inbox: %+v", in.Messages)
	}
	r := bob.auu("rm", "--remote-only", msgID)
	expectSays(t, r, 0, msgID[:12]+": removed from "+relayName)
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("the relay holds %v after --remote-only, want nothing", left)
	}
	here, marked := keptOnRelay(t, bob, msgID)
	if !here || marked {
		t.Errorf("the record after --remote-only: here=%v marked=%v", here, marked)
	}
	expectNot(t, bob.auu("inbox", "--no-fetch"), "on relay")
	// Again, with nothing on the relay: said, and exit 0.
	expectSays(t, bob.auu("rm", "--remote-only", msgID), 0, msgID[:12]+": not on the relay")
	_ = id
	// The local copy is this row's to clear.
	expectCode(t, bob.auu("rm", msgID), 0)
	verdict(t, "ok", "")
}

func l05(t *testing.T) {
	id, _ := queueOne(t, "--subject", "removed here only", "left on the relay")
	in := fetchJSON(t, bob)
	msgID := ""
	for _, msg := range in.Messages {
		if msg.Subject == "removed here only" {
			msgID = msg.ID
		}
	}
	if msgID == "" {
		t.Fatalf("the message is not in the inbox: %+v", in.Messages)
	}
	r := bob.auu("rm", "--local-only", msgID)
	expectSays(t, r, 0, msgID[:12]+": removed here; still on "+relayName+
		", and this machine will not fetch it again")
	if left := queued(t, state.bobFP); len(left) != 1 || left[0] != id {
		t.Errorf("the relay holds %v after --local-only, want the message left", left)
	}
	if here, _ := keptOnRelay(t, bob, msgID); here {
		t.Errorf("the local copy survived --local-only: %s", msgID)
	}
	// The id is remembered, so the fetch that follows is quiet: it neither
	// fetches it again nor calls this home damaged.
	if left := strings.TrimSpace(bob.read(t, bobRelayDir+"/left-behind")); left != strconv.FormatInt(id, 10) {
		t.Errorf("left-behind holds %q, want %d", left, id)
	}
	again := fetchJSON(t, bob)
	if again.Fetch.Delivered != 0 {
		t.Errorf("the fetch after --local-only delivered %+v", again.Fetch)
	}
	r = bob.auu("inbox")
	expectCode(t, r, 0)
	expectNot(t, r, "before this machine's cursor")
	// Taken off the relay by bob's other machine, which is who else would:
	// the laptop's file is pruned at its next fetch.
	desk := bob.at(bobDesktop)
	if !bob.exists(bobDesktop + "/config.json") {
		verdict(t, "gap", "bob has no second machine to take the message off the relay")
		t.Skip("no second machine")
	}
	deskIn := fetchJSON(t, desk)
	deskID := ""
	for _, msg := range deskIn.Messages {
		if msg.Subject == "removed here only" {
			deskID = msg.ID
		}
	}
	if deskID == "" {
		t.Fatalf("the desktop did not get the message: %+v", deskIn.Messages)
	}
	expectCode(t, desk.auu("rm", deskID), 0)
	fetchJSON(t, bob)
	if bob.exists(bobRelayDir + "/left-behind") {
		t.Errorf("left-behind is still there after the message went")
	}
	verdict(t, "ok", "")
}

func l06(t *testing.T) {
	desk := bob.at(bobDesktop)
	if !bob.exists(bobDesktop + "/config.json") {
		verdict(t, "gap", "bob has no second machine to read the same mail from")
		t.Skip("no second machine")
	}
	id, _ := queueOne(t, "--subject", "for both machines", "read me twice")
	// The laptop reads it and leaves it; the desktop reads the same
	// message, which is what keeping it is for.
	laptop := fetchJSON(t, bob)
	msgID := ""
	for _, msg := range laptop.Messages {
		if msg.Subject == "for both machines" {
			msgID = msg.ID
		}
	}
	if msgID == "" {
		t.Fatalf("the laptop did not get it: %+v", laptop.Messages)
	}
	deskIn := fetchJSON(t, desk)
	found := false
	for _, msg := range deskIn.Messages {
		if msg.ID == msgID {
			found = msg.OnRelay
		}
	}
	if !found {
		t.Errorf("the desktop did not get the same message, marked: %+v", deskIn.Messages)
	}
	if left := queued(t, state.bobFP); len(left) != 1 || left[0] != id {
		t.Errorf("the relay holds %v after both machines read it", left)
	}
	// The laptop removes it; the desktop's next fetch notices and keeps
	// its own copy, unmarked.
	expectSays(t, bob.auu("rm", msgID), 0, msgID[:12]+": removed from "+relayName+" and here")
	fetchJSON(t, desk)
	here, marked := keptOnRelay(t, desk, msgID)
	if !here || marked {
		t.Errorf("the desktop's record after the laptop's rm: here=%v marked=%v", here, marked)
	}
	// The desktop's copy is the desktop's to clear.
	expectCode(t, desk.auu("rm", "--local-only", msgID), 0)
	verdict(t, "ok", "")
}

func l07(t *testing.T) {
	defer extraArgs(t, "--mailbox-max-messages 2")()
	relayRestart(t)
	defer relayRestart(t)
	queueOne(t, "--subject", "one of two", "fits")
	queueOne(t, "--subject", "two of two", "fits")
	// Read, and still queued: the mailbox is full of mail bob has read.
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 2 || queuedCount(t, in) != 2 {
		t.Fatalf("the fetch: %+v %+v", in.Fetch, in.Relays)
	}
	r := alice.auu("send", "--to", "bob", "--subject", "three of two", "does not fit")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: bob's mailbox on the relay is full; they need to run 'auu rm' to make room")
	// Removing one makes room; reading again would not have.
	first := ""
	for _, msg := range in.Messages {
		if msg.Subject == "one of two" {
			first = msg.ID
		}
	}
	if first == "" {
		t.Fatalf("the first message is not in the inbox: %+v", in.Messages)
	}
	expectCode(t, bob.auu("rm", first), 0)
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "three of two", "now it fits"), 0, "sent to bob")
	drain(bob)
	verdict(t, "ok", "")
}
