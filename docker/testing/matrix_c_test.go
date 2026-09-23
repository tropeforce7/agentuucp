//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Channels: the named sub-mailboxes bob defines and alice chooses between.
// The cycle left bob's directory holding default and bug reports; every
// row here undoes its own change to it.
var channelRows = []matrixRow{
	{"C01", "sender_lists", "alice lists bob's channels, one of them with a period", c01},
	{"C02", "closed_refused", "a post to a channel whose period has ended", c02},
	{"C03", "not_yet_open", "a post to a channel whose period has not begun", c03},
	{"C04", "default_removed", "bob deletes default, and alice sends without --channel", c04},
	{"C05", "deleted_with_mail", "bob deletes a channel with a message queued under it", c05},
	{"C06", "close", "bob closes a channel, and alice posts to it", c06},
	{"C07", "directory_edited_on_the_host", "the stored directory's signature edited, and a post to a named channel and to default", c07},
}

const (
	cfpOpens  = "2026-10-01T00:00:00Z"
	cfpCloses = "2026-12-31T23:59:59Z"
)

// tableHas asserts a table printed through tabwriter has each row, the
// columns' padding collapsed to one space, so a row is written as a person
// reads it rather than as the widths of that run happened to pad it.
func tableHas(t *testing.T, r result, rows ...string) {
	t.Helper()
	var lines []string
	for _, l := range strings.Split(r.stdout, "\n") {
		lines = append(lines, strings.Join(strings.Fields(l), " "))
	}
	for _, want := range rows {
		found := false
		for _, l := range lines {
			if l == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no row %q in\n%s", want, r.stdout)
		}
	}
}

// bobChannel adds a channel to bob's directory and returns what removes it.
func bobChannel(t *testing.T, name string, args ...string) func() {
	t.Helper()
	r := bob.auu(append([]string{"channel", "create", name}, args...)...)
	if r.code != 0 {
		t.Fatalf("channel create %s: exit %d\n%s%s", name, r.code, r.stdout, r.stderr)
	}
	return func() {
		if r := bob.auu("channel", "delete", name); r.code != 0 {
			t.Errorf("channel delete %s: exit %d\n%s%s", name, r.code, r.stdout, r.stderr)
		}
	}
}

// bobRecreates is the undo for a row that deleted one of bob's channels:
// it puts the channel back afterwards.
func bobRecreates(t *testing.T, name string, args ...string) func() {
	return func() {
		if r := bob.auu(append([]string{"channel", "create", name}, args...)...); r.code != 0 {
			t.Errorf("channel create %s: exit %d\n%s%s", name, r.code, r.stdout, r.stderr)
		}
	}
}

// refusedSend asserts a send from alice to bob was refused at exit 2 with
// the sentence, and queued nothing.
func refusedSend(t *testing.T, want string, args ...string) {
	t.Helper()
	before := queued(t, state.bobFP)
	r := alice.auu(append([]string{"send", "--to", "bob", "--subject", "refused?"}, append(args, "is it?")...)...)
	expectCode(t, r, 2)
	stderrIs(t, r, want)
	if after := queued(t, state.bobFP); len(after) != len(before) {
		t.Errorf("a refused send queued a message: %v before, %v after", before, after)
	}
}

func c01(t *testing.T) {
	defer bobChannel(t, "cfp", "--description", "talks, until the deadline", "--not-before", cfpOpens, "--not-after", cfpCloses)()
	r := alice.auu("channel", "ls", "bob")
	expectSays(t, r, 0, "NAME", "DESCRIPTION", "PERIOD", "STATE", "issued ", " by bob")
	tableHas(t, r, "default - open", bugChannel+" "+bugDescription+" - open",
		"cfp talks, until the deadline "+cfpOpens+" to "+cfpCloses+" opens "+cfpOpens)
	expectNot(t, r, "QUEUED", "queued", "holds")
	var ls channelsJSON
	jsonOf(t, alice.auu("channel", "ls", "bob", "--json"), &ls)
	if ls.Peer != "bob" || !ls.Directory || len(ls.Channels) != 3 || ls.Relays != nil {
		t.Fatalf("channel ls bob --json: %+v", ls)
	}
	cfp := ls.Channels[2]
	if cfp.Name != "cfp" || cfp.Description != "talks, until the deadline" || cfp.NotBefore != cfpOpens || cfp.NotAfter != cfpCloses ||
		cfp.Open || cfp.Why != "opens "+cfpOpens {
		t.Errorf("cfp as alice sees it: %+v", cfp)
	}
	if !ls.Channels[0].Open || ls.Channels[0].Name != "default" || !ls.Channels[1].Open || ls.Channels[1].Name != bugChannel {
		t.Errorf("the open channels as alice sees them: %+v", ls.Channels[:2])
	}
	verdict(t, "ok", "")
}

func c02(t *testing.T) {
	defer bobChannel(t, "old", "--description", "was open once", "--not-after", "2020-01-01T00:00:00Z")()
	refusedSend(t, `auu: channel "old" is not open: closed 2020-01-01T00:00:00Z`, "--channel", "old")
	verdict(t, "ok", "")
}

func c03(t *testing.T) {
	defer bobChannel(t, "cfp", "--description", "talks, until the deadline", "--not-before", cfpOpens, "--not-after", cfpCloses)()
	refusedSend(t, `auu: channel "cfp" is not open: opens `+cfpOpens, "--channel", "cfp")
	verdict(t, "ok", "")
}

func c04(t *testing.T) {
	expectSays(t, bob.auu("channel", "delete", "default"), 0, relayName+": directory pushed (1 channel)")
	defer bobRecreates(t, "default")()
	refusedSend(t, "auu: bob has removed their default channel; choose one with --channel:\n  "+bugChannel+": "+bugDescription+" (open)")
	// With the channel named, the same message goes.
	sendJSON(t, alice, "bob", "--channel", bugChannel, "--subject", "named", "this one goes")
	drain(bob)
	verdict(t, "ok", "")
}

func c05(t *testing.T) {
	s := sendJSON(t, alice, "bob", "--channel", bugChannel, "--subject", "queued before the delete", "still arrives")
	expectSays(t, bob.auu("channel", "delete", bugChannel), 0, relayName+": directory pushed (1 channel)")
	defer bobRecreates(t, bugChannel, "--description", bugDescription)()
	r := bob.auu("inbox")
	expectSays(t, r, 0, "fetched 1 new message(s)", `1 message(s) arrived for channels no longer in your directory: "`+bugChannel+`"`,
		"  in \""+bugChannel+"\"")
	expectNot(t, r, "warning")
	in := fetchJSON(t, bob, "--no-fetch", "--channel", bugChannel)
	found := false
	for _, m := range in.Messages {
		if m.ID == s.ID && m.Channel == bugChannel {
			found = true
		}
	}
	if !found {
		t.Errorf("the message is not filed under %q: %+v", bugChannel, in.Messages)
	}
	// Read and left there: default keeps its mail, so the message is
	// still queued and the record says so. The row leaves nothing.
	if left := queued(t, state.bobFP); len(left) != 1 {
		t.Errorf("queued %v, want the message read and kept", left)
	}
	if !strings.Contains(bob.auu("inbox", "--no-fetch").stdout, "  on relay") {
		t.Errorf("the listing does not mark the kept message")
	}
	drain(bob)
	verdict(t, "ok", "")
}

func c06(t *testing.T) {
	expectSays(t, bob.auu("channel", "close", bugChannel), 0, relayName+": directory pushed (2 channels)")
	defer func() {
		if r := bob.auu("channel", "update", bugChannel, "--not-after", "none"); r.code != 0 {
			t.Errorf("reopening %s: exit %d\n%s%s", bugChannel, r.code, r.stdout, r.stderr)
		}
	}()
	var ls channelsJSON
	jsonOf(t, bob.auu("channel", "ls", "--json"), &ls)
	var closedAt string
	for _, ch := range ls.Channels {
		if ch.Name == bugChannel {
			closedAt = ch.NotAfter
			if ch.Open || ch.Why != "closed "+ch.NotAfter {
				t.Errorf("%s after close: %+v", bugChannel, ch)
			}
		}
	}
	if closedAt == "" {
		t.Fatalf("bob's directory after close: %+v", ls)
	}
	tableHas(t, bob.auu("channel", "ls"), bugChannel+" "+bugDescription+" until "+closedAt+" closed "+closedAt+" 0 on")
	refusedSend(t, fmt.Sprintf(`auu: channel %q is not open: closed %s`, bugChannel, closedAt), "--channel", bugChannel)
	if !strings.HasSuffix(closedAt, "Z") {
		t.Errorf("the close time is not UTC on this machine: %s", closedAt)
	}
	verdict(t, "ok", "")
}

func c07(t *testing.T) {
	// The relay verifies the directory where it routes, so an edit on the
	// host stops routing rather than routing something the owner did not
	// publish. One byte of the signature, as an intruder with the database
	// open would.
	m := logMark()
	sqlEdit(t, `UPDATE directories SET sig = X'00' || substr(sig, 2) WHERE fp = '`+state.bobFP+`'`)
	// Every name bob published is refused. The sender is told twice over,
	// which is worth having: the relay refuses the name, and the client's
	// own fetch of bob's directory — which it makes to list what he does
	// have — meets the same broken document and says so.
	refusedSend(t, `auu: bob has no channel "`+bugChannel+`" on `+relayName+
		`, and the directory `+relayName+` served for bob does not verify against the key you hold; do not trust it`,
		"--channel", bugChannel)
	// And default with it: the mailbox is closed, not fallen back to the
	// one channel a mailbox with no directory has, since falling back
	// would open a channel bob's own document might have removed.
	refusedSend(t, `auu: bob has no channel "default" on `+relayName+
		`, and the directory `+relayName+` served for bob does not verify against the key you hold; do not trust it`)
	// The operator's journal names the mailbox, once a minute.
	waitRelayLog(t, m, "channel directory for "+state.bobFP+
		" does not verify; refusing every post to it until the owner pushes again", 5*time.Second)
	// The operator sees it in the record too, beside the count of the
	// channels the push parsed: the mailbox has them and routes none.
	expectSays(t, operator.admin("mailboxes", "show", state.bobFP), 0, "directory:   broken", "channels:    2")
	// Bob's own fetch tells him, after the messages and on stderr.
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, "auu: your channel directory on "+relayName+" does not verify, so every post to you is "+
		"refused there; run auu channel push, and if you did not change it, tell the relay's operator")
	// The push is the repair, and the name routes again.
	expectSays(t, bob.auu("channel", "push"), 0, relayName+": directory pushed")
	expectSays(t, operator.admin("mailboxes", "show", state.bobFP), 0, "directory:   signed")
	sendJSON(t, alice, "bob", "--channel", bugChannel, "--subject", "after the repair", "back again")
	drain(bob)
	verdict(t, "ok", "An edit to the stored directory closes the mailbox rather than routing what the owner did "+
		"not publish: every channel is refused, default included, and the sender's own fetch of the directory "+
		"says why; the operator's journal names the mailbox and their listing says broken beside the channels "+
		"still counted, the owner is told at their next fetch, and their push is the whole repair.")
}
