//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The previous release, run as itself (D41): its real auu, auu-admin and
// auu-relay, built by run.sh from a clone at its tag and kept in prevBin,
// beside this tree's. Each row asserts the version an old program says
// before it relies on it, olive's auu first of all, since a row that quietly
// ran this tree's auu for the old party would pass and prove nothing. The old party is olive, a fresh person enrolled by
// the old auu in a home of her own on bob's machine: a later build reads an
// earlier build's files and never the reverse, so a home this tree has
// written is not one the old build was promised to read.
var olderRows = []matrixRow{
	{"O01", "old_recipient", "alice writes to bob and to olive, who runs the previous release, olive reads it with everyone it went to and answers them all", o01},
	{"O02", "old_recipient_stream", "the same as a stream, a message too large for an envelope", o02},
	{"O03", "old_relay", "alice writes to several through a relay running the previous release, by bang path and as a stream, which bob's fetch takes by range", o03},
	{"O04", "old_sender_and_tools", "olive writes to alice and to bob on this relay, and the previous release's auu-admin reads its status", o04},
	{"O05", "room_to_old_recipient", "alice saves a room of bob and olive and sends to it, and both read it, olive on the previous release", o05},
}

const (
	// prevBin is where the Dockerfile puts the previous release's programs.
	prevBin = "/opt/auu-prev/bin"
	// prevVersion is the release they are, which run.sh's prev names: the
	// two move together, each release.
	prevVersion = "v0.17.0"
	oliveHome   = "/home/bob/.auu-olive"
)

// isPrev fails the row unless the program says it is the previous release.
func isPrev(t *testing.T, r result, program string) {
	t.Helper()
	if r.code != 0 || !strings.HasPrefix(strings.TrimSpace(r.stdout), program+" "+prevVersion) {
		t.Fatalf("%s is not %s: exit %d\n%s%s", program, prevVersion, r.code, r.stdout, r.stderr)
	}
}

// oliveMeets enrols olive with the previous release's auu and makes her a
// peer of alice and of bob, each with an allow list pushed naming the
// other. As carolMeetsAlice does, it raises the relay's registrations an
// hour for the row and puts them back.
func oliveMeets(t *testing.T) *machine {
	t.Helper()
	olive := bob.at(oliveHome)
	olive.bin = prevBin
	isPrev(t, olive.auu("version"), "auu")
	undoThenRestart(t, relay.edit(t, relaySettings, `"access_log": "minimal",`,
		`"access_log": "minimal",`+"\n"+`  "limits": {"registrations_per_hour": 100},`))
	relayRestart(t)
	t.Cleanup(func() { bob.root("rm -rf " + oliveHome) })
	tok := issueToken(t, "--note", "olive")
	if r := olive.auu("enrol", "--name", "olive", "--label", "olive-box", "--yes", tok); r.code != 0 {
		t.Fatalf("olive could not enrol: %s%s", r.stdout, r.stderr)
	}
	line := strings.TrimSpace(olive.auu("id", "export").stdout)
	for _, m := range []*machine{alice, bob} {
		m := m
		expectCode(t, m.auu("peers", "add", line), 0)
		t.Cleanup(func() {
			m.auu("peers", "rm", "olive")
			m.auu("allow", "push")
		})
		expectCode(t, m.auu("allow", "push"), 0)
	}
	expectCode(t, olive.auu("peers", "add", state.aliceLine), 0)
	expectCode(t, olive.auu("peers", "add", state.bobLine), 0)
	expectCode(t, olive.auu("allow", "push"), 0)
	return olive
}

// sentToSeveral is what send --json says of a message to several.
type sentToSeveral struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Recipients []struct {
		Name    string `json:"name"`
		Path    string `json:"path"`
		RelayID int64  `json:"relay_id"`
		Code    string `json:"code"`
		Error   string `json:"error"`
		Waiting bool   `json:"waiting"`
	} `json:"recipients"`
}

// sendSeveral sends from alice to everyone in to and fails the row unless
// every copy was taken by the relay.
func sendSeveral(t *testing.T, to string, args ...string) sentToSeveral {
	t.Helper()
	var s sentToSeveral
	r := alice.auu(append([]string{"send", "--to", to, "--json"}, args...)...)
	if r.code != 0 {
		t.Fatalf("send: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	jsonOf(t, r, &s)
	if want := len(strings.Split(to, ",")); len(s.Recipients) != want {
		t.Fatalf("send: %d recipients, want %d: %+v", len(s.Recipients), want, s)
	}
	for _, c := range s.Recipients {
		if c.RelayID == 0 || c.Code != "" || c.Error != "" || c.Waiting {
			t.Fatalf("a copy was not taken: %+v", s)
		}
	}
	return s
}

// readBySubject is the machine's inbox --json and the one message in it
// with the subject, which must have nothing kept for a newer build and
// nothing unreadable in the fetch.
func readBySubject(t *testing.T, m *machine, subject string) (id string, ignored []string) {
	t.Helper()
	var in newerFetch
	r := m.auu("inbox", "--json")
	if r.code != 0 {
		t.Fatalf("%s inbox --json: exit %d\n%s%s", m, r.code, r.stdout, r.stderr)
	}
	jsonOf(t, r, &in)
	if in.Fetch.Unreadable != 0 || len(in.Fetch.Newer) != 0 {
		t.Fatalf("%s's fetch: %+v, want nothing unreadable and nothing waiting for a newer auu", m, in.Fetch)
	}
	for _, msg := range in.Messages {
		if msg.Subject != subject {
			continue
		}
		if id != "" {
			t.Fatalf("%s holds %q twice", m, subject)
		}
		if msg.Newer != "" || msg.DroppedSections != 0 {
			t.Fatalf("%s: %+v, want it read whole", m, msg)
		}
		id, ignored = msg.ID, msg.IgnoredSections
	}
	if id == "" {
		t.Fatalf("%s does not hold %q:\n%s", m, subject, r.stdout)
	}
	return id, ignored
}

// nothingDamaged fails the row if any of the homes keeps a message under
// damaged/: nothing in this family is malformed or needs a newer build.
func nothingDamaged(t *testing.T, ms ...*machine) {
	t.Helper()
	for _, m := range ms {
		r := m.exec("", "sh", "-c", "ls -A "+shq(m.home+"/damaged")+" 2>/dev/null")
		if strings.TrimSpace(r.stdout) != "" {
			t.Errorf("%s keeps something under %s/damaged:\n%s", m, m.home, r.stdout)
		}
	}
}

func o01(t *testing.T) {
	olive := oliveMeets(t)
	subject := "to bob and olive"
	sendSeveral(t, "bob,olive", "--subject", subject, "one message, two readers")

	id := oldReadsAll(t, olive, subject, "one message, two readers")

	// Her reply --all answers alice and bob, through the relay the message
	// came by.
	replied := "olive's answer to everyone"
	expectCode(t, olive.auu("reply", id, "--all", "--subject", replied, "answered by the previous release"), 0)
	for _, m := range []*machine{alice, bob} {
		rid, _ := readBySubject(t, m, replied)
		expectSays(t, m.auu("read", rid), 0, "answered by the previous release")
	}

	bid, _ := readBySubject(t, bob, subject)
	r := bob.auu("read", bid)
	expectSays(t, r, 0, "one message, two readers")
	if to := lineWith(r.stdout, "to:"); !strings.Contains(to, "you") || !strings.Contains(to, "olive") {
		t.Errorf("bob's to: line is %q, want him and olive", to)
	}
	nothingDamaged(t, alice, bob, olive)
	verdict(t, "ok", "The previous release reads a message to several whole, passing over no section, names everyone "+
		"it went to, and answers them all with reply --all.")
}

// oldReadsAll is the previous release's olive reading a message to her and
// bob: nothing passed over in --json, the text, and a to: line naming bob
// and her. It returns the message's id.
func oldReadsAll(t *testing.T, olive *machine, subject, text string) string {
	t.Helper()
	id, ignored := readBySubject(t, olive, subject)
	if len(ignored) != 0 {
		t.Errorf("olive's --json names %q in ignored_sections, want none", ignored)
	}
	r := olive.auu("read", id)
	expectSays(t, r, 0, text)
	expectNot(t, r, "newer", "malformed")
	if to := lineWith(r.stdout, "to:"); strings.TrimSpace(to) != "to:      bob, you" {
		t.Errorf("olive's to: line is %q, want bob and her", to)
	}
	return id
}

func o02(t *testing.T) {
	olive := oliveMeets(t)
	subject := "a large one to bob and olive"
	expectCode(t, alice.exec("", "sh", "-c", "head -c 102400 /dev/urandom > /home/alice/o02.bin"), 0)
	t.Cleanup(func() { alice.exec("", "rm", "-f", "/home/alice/o02.bin") })
	s := sendSeveral(t, "bob,olive", "--subject", subject, "--attach", "/home/alice/o02.bin", "large")
	if s.Kind != "stream" {
		t.Fatalf("sent as %q, want a stream", s.Kind)
	}

	id, ignored := readBySubject(t, olive, subject)
	if len(ignored) != 0 {
		t.Errorf("olive's --json names %q in ignored_sections, want none", ignored)
	}
	out := "/home/bob/o02-olive"
	t.Cleanup(func() { bob.root("rm -rf " + out) })
	expectSays(t, olive.auu("extract", id, "--out", out), 0, "wrote "+out+"/o02.bin")
	sum := func(m *machine, path string) string {
		if f := strings.Fields(m.exec("", "sha256sum", path).stdout); len(f) > 0 {
			return f[0]
		}
		return ""
	}
	if a, o := sum(alice, "/home/alice/o02.bin"), sum(bob, out+"/o02.bin"); a == "" || a != o {
		t.Errorf("olive's copy hashes %s, alice's file %s", o, a)
	}
	readBySubject(t, bob, subject)
	nothingDamaged(t, alice, bob, olive)
	verdict(t, "ok", "The previous release reads a stream to several whole, passing over no section of its manifest, "+
		"and the payload is the sender's to the byte.")
}

func o03(t *testing.T) {
	olive := oliveMeets(t)
	// The relay's own program swapped for the previous release's, and put
	// back after, checked as this tree's again before the next row. The old
	// one is copied beside it and renamed over it, since a running program
	// cannot be written to.
	relay.mustRoot(t, "cp -p /usr/local/bin/auu-relay /usr/local/bin/auu-relay.this && "+
		"cp -p "+prevBin+"/auu-relay /usr/local/bin/auu-relay.prev && "+
		"mv /usr/local/bin/auu-relay.prev /usr/local/bin/auu-relay")
	t.Cleanup(func() {
		if r := relay.root("mv /usr/local/bin/auu-relay.this /usr/local/bin/auu-relay"); r.code != 0 {
			t.Errorf("putting this tree's relay back: exit %d\n%s%s", r.code, r.stdout, r.stderr)
		}
		if r := relayAuu.exec("", "/usr/local/bin/auu-relay", "--version"); strings.HasPrefix(r.stdout, "auu-relay "+prevVersion) {
			t.Errorf("the relay's program is still %s after it was put back", prevVersion)
		}
		m := relayRestart(t)
		if strings.Contains(relayLogSince(m), "version="+prevVersion) {
			t.Errorf("the relay is still %s after it was put back", prevVersion)
		}
	})
	m := relayRestart(t)
	isPrev(t, relayAuu.exec("", "/usr/local/bin/auu-relay", "--version"), "auu-relay")
	if !strings.Contains(relayLogSince(m), "version="+prevVersion+" schema=13") {
		t.Fatalf("the relay did not start as %s at schema 13:\n%s", prevVersion, relayLogSince(m))
	}

	// An envelope to bob and, by bang path through relay-b and relay-c, to
	// dave: the copy for dave is a user's forward carrying the count, which
	// the old relay holds to its own max_recipients.
	subject := "through the previous relay"
	s := sendSeveral(t, "bob,bee!see!dave", "--subject", subject, "two copies, one forwarded")
	if s.Recipients[1].Path == "" {
		t.Errorf("dave's copy went with no path: %+v", s)
	}
	bid, _ := readBySubject(t, bob, subject)
	r := bob.auu("read", bid)
	expectSays(t, r, 0, "two copies, one forwarded")
	// dave is not on bob's list, so bob's to: line names him by his short
	// fingerprint.
	if to := lineWith(r.stdout, "to:"); !strings.Contains(to, "you") || !strings.Contains(to, "<"+state.daveFP[:16]+">") {
		t.Errorf("bob's to: line is %q, want him and dave's short fingerprint", to)
	}
	var did string
	for i := 0; i < 30 && did == ""; i++ {
		var in newerFetch
		jsonOf(t, dave.auu("inbox", "--json"), &in)
		for _, msg := range in.Messages {
			if msg.Subject == subject {
				did = msg.ID
			}
		}
		if did == "" {
			time.Sleep(time.Second)
		}
	}
	if did == "" {
		t.Fatal("dave's forwarded copy never arrived")
	}

	// A stream to bob and olive: each open carries the count, which the
	// old relay holds to its max_recipients as well.
	streamSubject := "a large one through the previous relay"
	expectCode(t, alice.exec("", "sh", "-c", "head -c 102400 /dev/urandom > /home/alice/o03.bin"), 0)
	t.Cleanup(func() { alice.exec("", "rm", "-f", "/home/alice/o03.bin") })
	if k := sendSeveral(t, "bob,olive", "--subject", streamSubject, "--attach", "/home/alice/o03.bin", "large").Kind; k != "stream" {
		t.Fatalf("sent as %q, want a stream", k)
	}
	// Bob's fetch is this release's client alone in the old relay's log:
	// every request it makes for the stream's bytes carries a Range, the
	// header, the manifest and then the payload from past them, and this
	// release takes nothing but a 206 for exactly the span it asked for, so
	// a relay that answered otherwise would leave the stream waiting and
	// readBySubject would not find it. The minimal access log names the
	// route and the status and not the header, so the 206s are the Range
	// seen from the relay's side.
	bm := logMark()
	readBySubject(t, bob, streamSubject)
	for _, line := range blobLinesSince(t, bm, 3) {
		if !strings.Contains(line, "status=206") {
			t.Errorf("the previous relay answered bob's range with %q, want 206", line)
		}
	}
	readBySubject(t, olive, streamSubject)

	expectNot(t, result{stdout: relayLogSince(m)}, "needs-newer", "too-many-recipients", "malformed")
	nothingDamaged(t, alice, bob, olive, dave)
	verdict(t, "ok", "A relay on the previous release takes every copy of a message to several, by bang path and as "+
		"a stream: the count on a stream's open and on a user's forward is one it knows and holds within its own limit, "+
		"and it answers each range this release's fetch asks of the stream 206 with the span this release holds it to.")
}

// blobLinesSince waits for at least n of the relay's access lines for a
// stream's bytes after the mark and returns every one there is. A line is
// written as its request ends, which can be a moment after the client has
// read the last byte, so the lines are waited for rather than read once.
func blobLinesSince(t *testing.T, m mark, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var lines []string
		log := relayLogSince(m)
		for _, line := range strings.Split(log, "\n") {
			if strings.Contains(line, "path=/v1/mailbox/{fp}/{id}/blob ") {
				lines = append(lines, line)
			}
		}
		if len(lines) >= n {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay logged %d fetches of a stream's bytes, want at least %d; it says:\n%s", len(lines), n, log)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func o04(t *testing.T) {
	olive := oliveMeets(t)
	for _, to := range []*machine{alice, bob} {
		subject := fmt.Sprintf("from the previous release to %s", to.user)
		expectCode(t, olive.auu("send", "--to", to.user, "--subject", subject, "sent by "+prevVersion), 0)
		id, ignored := readBySubject(t, to, subject)
		if len(ignored) != 0 {
			t.Errorf("%s ignored %q of a message that carries no section", to, ignored)
		}
		expectSays(t, to.auu("read", id), 0, "sent by "+prevVersion)
	}

	oldOperator := *operator
	oldOperator.bin = prevBin
	isPrev(t, oldOperator.admin("version"), "auu-admin")
	r := oldOperator.admin("status")
	expectCode(t, r, 0)
	stderrIs(t, r, "")
	nothingDamaged(t, alice, bob, olive)
	verdict(t, "ok", "The previous release sends to this one as it always did, and its auu-admin reads this relay's "+
		"status.")
}

func o05(t *testing.T) {
	olive := oliveMeets(t)
	// The room is alice's alone: nothing of it is posted, so olive's
	// release has nothing to know. It has rooms of its own and names one on
	// a read where a room saved on her machine holds exactly those people,
	// and she saves none, so her read names none, as bob's does not.
	expectCode(t, alice.auu("room", "create", "pair", "bob", "olive"), 0)
	t.Cleanup(func() { expectCode(t, alice.auu("room", "delete", "pair", "--yes"), 0) })

	subject := "to the room pair"
	var s sentToSeveral
	r := alice.auu("send", "--to", "pair", "--json", "--subject", subject, "one message, a room of two")
	if r.code != 0 {
		t.Fatalf("send to the room: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	jsonOf(t, r, &s)
	if len(s.Recipients) != 2 || s.Recipients[0].Name != "bob" || s.Recipients[1].Name != "olive" {
		t.Fatalf("the room went to %+v, want bob then olive", s.Recipients)
	}
	for _, c := range s.Recipients {
		if c.RelayID == 0 || c.Code != "" || c.Error != "" || c.Waiting {
			t.Fatalf("a copy was not taken: %+v", s)
		}
	}

	oid := oldReadsAll(t, olive, subject, "one message, a room of two")
	expectNot(t, olive.auu("read", oid), "room:")
	bid, _ := readBySubject(t, bob, subject)
	r = bob.auu("read", bid)
	expectSays(t, r, 0, "one message, a room of two")
	expectNot(t, r, "room:")
	expectSays(t, alice.auu("read", s.ID), 0, "room:    pair")
	nothingDamaged(t, alice, bob, olive)
	verdict(t, "ok", "A room is a message to several on the wire: the previous release reads it whole with everyone it "+
		"went to, the room's name travels nowhere, so neither olive's read nor bob's names one, and alice's own read names it.")
}
