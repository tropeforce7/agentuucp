package auu

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// roomDoc is a rooms file as a person would write it by hand: each room a
// name and its members, each member a fingerprint with an optional
// "via:" prefix ("far!near:FP").
func roomDoc(rooms ...[]string) string {
	var parts []string
	for _, r := range rooms {
		var members []string
		for _, m := range r[1:] {
			via, fp, ok := strings.Cut(m, ":")
			if !ok {
				fp, via = m, ""
			}
			if via != "" {
				members = append(members, fmt.Sprintf(`{"fp":%q,"via":%q}`, fp, via))
			} else {
				members = append(members, fmt.Sprintf(`{"fp":%q}`, fp))
			}
		}
		parts = append(parts, fmt.Sprintf(`{"name":%q,"members":[%s]}`, r[0], strings.Join(members, ",")))
	}
	return `{"v":1,"rooms":[` + strings.Join(parts, ",") + `]}`
}

// nothingWritten asserts a refused send left the outbox empty and sent/ as
// it was.
func nothingWritten(t *testing.T, u *user, sentBefore int, what string) {
	t.Helper()
	if waiting, broken := outboxOf(t, u); len(waiting) != 0 || len(broken) != 0 {
		t.Errorf("%s: the outbox holds %d (%d broken)", what, len(waiting), len(broken))
	}
	if n := len(sentBox(t, u)); n != sentBefore {
		t.Errorf("%s: sent/ holds %d, was %d", what, n, sentBefore)
	}
}

// A room's members take its place in --to in the room's order, not the
// peer list's: the sender's copies, its --json and the recipients section
// each recipient reads are in that order, and both receive the message.
func TestARoomExpandsIntoItsMembersInOrder(t *testing.T) {
	alice, bob, carol := threePeers(t)
	alice.run("room", "create", "team", "carol", "bob")

	got := sentMany(t, alice.run("send", "--to", "team", "--json", "hello, team"))
	if len(got.Recipients) != 2 || got.Recipients[0].Name != "carol" || got.Recipients[1].Name != "bob" {
		t.Fatalf("--json recipients: %+v", got.Recipients)
	}
	m := alice.stored(store.Sent, got.ID)
	if len(m.Copies) != 2 || m.Copies[0].Fingerprint != carol.exportFingerprint() ||
		m.Copies[1].Fingerprint != bob.exportFingerprint() {
		t.Fatalf("the sent record's copies are not in room order: %+v", m.Copies)
	}
	for _, u := range []*user{bob, carol} {
		u.run("inbox")
		var read messageJSON
		if err := json.Unmarshal([]byte(u.run("read", got.ID, "--json")), &read); err != nil {
			t.Fatal(err)
		}
		if len(read.Recipients) != 2 || read.Recipients[0].Fingerprint != carol.exportFingerprint() ||
			read.Recipients[1].Fingerprint != bob.exportFingerprint() {
			t.Errorf("the recipients section reads: %+v; want carol then bob", read.Recipients)
		}
	}
}

// One person reached twice, through a room and a name or through two
// rooms, is refused before anything is sealed, the sentence naming the
// person once and each source in the order given; two plain names keep
// the sentence they always had. One room named twice has a sentence of its
// own, tested below.
func TestARoomAndANameNamingOnePersonAreRefusedNamingBoth(t *testing.T) {
	alice, bob, _ := threePeers(t)
	alice.run("room", "create", "team", "bob", "carol")
	alice.run("room", "create", "pair", "bob")
	short := bob.exportFingerprint()[:16]
	for _, tc := range []struct {
		to, want string
	}{
		{"team,bob", fmt.Sprintf(`bob (%s) is in the room team and named as "bob"; name each once`, short)},
		{"bob,team", fmt.Sprintf(`bob (%s) is named as "bob" and in the room team; name each once`, short)},
		{"team,pair", fmt.Sprintf(`bob (%s) is in the room team and in the room pair; name each once`, short)},
		{"bob,bob", fmt.Sprintf(`"bob" and "bob" are the same recipient, %s; name each once`, short)},
	} {
		_, err := alice.tryRun("send", "--to", tc.to, "hello")
		refusedWith(t, "--to "+tc.to, err, exitUsage, tc.want)
		nothingWritten(t, alice, 0, "--to "+tc.to)
	}
}

// A room written by hand with somebody no longer on the peer list refuses
// the send with the room, the short fingerprint and the two remedies, and
// nothing is sealed: not the copies to the others, not a sent record.
func TestAMemberOffTheListRefusesBeforeAnythingIsSealed(t *testing.T) {
	alice, bob, _ := threePeers(t)
	stranger, err := identity.Generate("dave")
	if err != nil {
		t.Fatal(err)
	}
	fp := stranger.Public().Fingerprint()
	alice.writeRooms(roomDoc([]string{"team", bob.exportFingerprint(), fp}))
	alice.run("send", "--to", "bob", "before")
	before := len(sentBox(t, alice))

	for _, to := range []string{"team", "carol,team"} {
		_, err := alice.tryRun("send", "--to", to, "hello")
		refusedWith(t, "--to "+to, err, exitUsage, fmt.Sprintf(
			"the room team holds %s, who is not on your peer list, so nothing was sent; "+
				"remove them with auu room rm team %s, or add them again with auu peers add", fp[:16], fp[:16]))
		nothingWritten(t, alice, before, "--to "+to)
	}
}

// --via beside a room is refused, naming room rm and room add as the way
// to change a member's relays, whether the room is alone or one of several.
func TestViaBesideARoomIsRefused(t *testing.T) {
	alice, _, _ := threePeers(t)
	alice.run("room", "create", "team", "bob", "carol")
	for _, to := range []string{"team", "carol,team"} {
		_, err := alice.tryRun("send", "--to", to, "--via", "far", "hello")
		refusedWith(t, "--via with --to "+to, err, exitUsage,
			"team is a room, which carries its own addresses; send to it without --via, and change a member's relays "+
				"with auu room rm team NAME and auu room add team 'RELAY!NAME'")
		nothingWritten(t, alice, 0, "--via with --to "+to)
	}
}

// One room named twice in --to is refused on its own sentence, before the
// count of recipients and the check for somebody named twice, whatever the
// case of the second naming and whatever stands between the two; nothing
// is sealed.
func TestARoomNamedTwiceIsRefused(t *testing.T) {
	alice, _, _ := threePeers(t)
	alice.run("room", "create", "team", "bob", "carol")
	for _, to := range []string{"team,team", "team,TEAM", "team,carol,team"} {
		_, err := alice.tryRun("send", "--to", to, "hello")
		refusedWith(t, "--to "+to, err, exitUsage, "the room team is named twice; name it once")
		if strings.Contains(err.Error(), "name each once") {
			t.Errorf("--to %s: %v; want the room's sentence and not the duplicate's", to, err)
		}
		nothingWritten(t, alice, 0, "--to "+to)
	}
	// Two --to flags naming it are one list, and the same.
	_, err := alice.tryRun("send", "--to", "team", "--to", "team", "hello")
	refusedWith(t, "--to team --to team", err, exitUsage, "the room team is named twice; name it once")
	nothingWritten(t, alice, 0, "--to team --to team")
}

// A rooms file that does not read stops every send, since any name in --to
// might be a room in it: to a peer, to yourself and to a room alike, each
// exiting 5 naming the file, with the outbox and sent/ as they were. A file
// a later auu wrote stops them too, with exit 1 saying so.
func TestADamagedRoomsFileStopsEverySend(t *testing.T) {
	alice, _, _ := threePeers(t)
	alice.run("room", "create", "team", "bob", "carol")
	alice.run("send", "--to", "bob", "before")
	before := len(sentBox(t, alice))
	good := alice.roomsBytes()

	alice.writeRooms(string(good[:len(good)/2]))
	for _, to := range []string{"bob", "self", "team"} {
		_, err := alice.tryRun("send", "--to", to, "hello")
		refusedWith(t, "--to "+to+" beside a truncated rooms file", err, exitDamaged,
			alice.roomsPath()+" does not read")
		nothingWritten(t, alice, before, "--to "+to+" beside a truncated rooms file")
	}

	alice.writeRooms(`{"v":2,"rooms":[]}`)
	for _, to := range []string{"bob", "team"} {
		_, err := alice.tryRun("send", "--to", to, "hello")
		var e *exitError
		if err == nil || asExit(err, &e) ||
			!strings.Contains(err.Error(), "is version 2, and this auu reads version 1; a later auu wrote it") {
			t.Fatalf("--to %s beside a later version: %v; want a plain error, exit 1, saying the version", to, err)
		}
		nothingWritten(t, alice, before, "--to "+to+" beside a later version")
	}
}

// A room of one is a message to one: --json says to and not recipients,
// the message carries no recipients section and the reader sees no to:
// line; and a member with relays in front of them is reached by that path,
// which a stream cannot cross, said as it is for one --to RELAY!NAME.
func TestARoomOfOneIsAMessageToOne(t *testing.T) {
	alice, bob, _ := threePeers(t)
	alice.run("room", "create", "solo", "bob")
	raw := alice.run("send", "--to", "solo", "--json", "just you")
	if strings.Contains(raw, `"recipients"`) {
		t.Fatalf("a room of one sent as a message to several:\n%s", raw)
	}
	got := sentOf(t, raw)
	if got.To != bob.exportFingerprint() {
		t.Fatalf("--json to: %q, want bob's fingerprint", got.To)
	}
	bob.run("inbox")
	if m := bob.stored(store.Inbox, got.ID); len(m.Inner.Sections) != 0 {
		t.Errorf("a message to a room of one carries sections: %+v", m.Inner.Sections)
	}
	if read := bob.run("read", got.ID); strings.Contains(read, "to:") || strings.Contains(read, "room:") {
		t.Errorf("the read of a message to one says a list:\n%s", read)
	}
	if read := bob.run("read", got.ID, "--json"); strings.Contains(read, `"recipients"`) || strings.Contains(read, `"room"`) {
		t.Errorf("read --json of a message to one carries recipients or room:\n%s", read)
	}

	// The member's via is the path: without it a stream would go to bob's
	// mailbox on this relay, and with it the stream is refused before
	// anything is written.
	alice.writeRooms(roomDoc([]string{"solo", "far:" + bob.exportFingerprint()}))
	before := len(sentBox(t, alice))
	_, err := alice.tryRun("send", "--to", "solo", "--stream", "large")
	refusedWith(t, "a stream to a room of one with a via", err, exitUsage, "a large message does not cross a relay yet")
	if strings.Contains(err.Error(), "is reached by") {
		t.Errorf("a room of one refused as a message to several: %v", err)
	}
	nothingWritten(t, alice, before, "a stream to a room of one with a via")
}

// A room with a member reached by another relay cannot carry a large
// message: refused, naming the member and the path, before anything is
// read or written.
func TestARoomWithAViaMemberRefusesALargeMessage(t *testing.T) {
	alice, bob, carol := threePeers(t)
	alice.writeRooms(roomDoc([]string{"team", "far:" + bob.exportFingerprint(), carol.exportFingerprint()}))
	for _, args := range [][]string{
		{"--stream", "large"},
		{"--attach", fileOfSize(t, 96<<10), "large"},
	} {
		_, err := alice.tryRun(append([]string{"send", "--to", "team"}, args...)...)
		refusedWith(t, fmt.Sprint(args), err, exitUsage, "a large message does not cross a relay yet, and bob is reached by far")
		nothingWritten(t, alice, 0, fmt.Sprint(args))
	}
}

// The relay's max_recipients is held against the list once the room is
// expanded, and the sentence names the room it was counted from.
func TestARoomOverTheRelaysCapIsRefusedNamingTheRoom(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.MaxRecipients = 2
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol", "dave")
	alice := us[0]
	alice.run("room", "create", "team", "bob", "carol", "dave")
	relayName := alice.defaultRelayName()
	_, err := alice.tryRun("send", "--to", "team", "hello")
	refusedWith(t, "a room of three against two", err, exitUsage, fmt.Sprintf(
		"3 recipients once the room team is counted; %s takes at most 2 in one message (its max_recipients)", relayName))
	if !strings.HasPrefix(err.Error(), "3 recipients once") {
		t.Errorf("the sentence does not begin with the count: %v", err)
	}
	nothingWritten(t, alice, 0, "a room over the relay's cap")
	alice.run("room", "create", "pair", "bob", "carol")
	alice.run("room", "create", "one", "dave")
	_, err = alice.tryRun("send", "--to", "pair,one", "hello")
	refusedWith(t, "two rooms of three against two", err, exitUsage, fmt.Sprintf(
		"3 recipients once the rooms pair, one are counted; %s takes at most 2 in one message (its max_recipients)", relayName))
	nothingWritten(t, alice, 0, "two rooms over the relay's cap")
	alice.run("send", "--to", "pair", "hello")
}

// The protocol's 32 is held again after the rooms are expanded: a room of
// 32 and one name more is 33, refused naming the room, before anything is
// sealed.
func TestARoomAndOneMoreOverThirtyTwoIsRefused(t *testing.T) {
	alice, _, _ := threePeers(t)
	s, _, _ := alice.opened()
	names := []string{"self", "bob"}
	for i := range relayapi.MaxRecipients - 2 {
		id, err := identity.Generate(fmt.Sprintf("p%02d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AddPeer(id.Public()); err != nil {
			t.Fatal(err)
		}
		names = append(names, fmt.Sprintf("p%02d", i))
	}
	alice.run(append([]string{"room", "create", "big"}, names...)...)
	_, err := alice.tryRun("send", "--to", "big,carol", "hello")
	refusedWith(t, "a room of 32 and one more", err, exitUsage,
		"33 recipients once the room big is counted; a message may go to at most 32")
	nothingWritten(t, alice, 0, "a room of 32 and one more")
	alice.run("room", "create", "one", "carol")
	_, err = alice.tryRun("send", "--to", "big,one", "hello")
	refusedWith(t, "two rooms making 33", err, exitUsage,
		"33 recipients once the rooms big, one are counted; a message may go to at most 32")
	nothingWritten(t, alice, 0, "two rooms making 33")
}

// A room and a peer sharing a name, as only a hand-written file can make
// them, names nobody for certain: refused naming both and the two
// remedies, in any case.
func TestARoomWithAPeersNameIsRefusedAtTheSend(t *testing.T) {
	alice, bob, carol := threePeers(t)
	alice.writeRooms(roomDoc([]string{"Bob", carol.exportFingerprint()}))
	for _, to := range []string{"bob", "BOB", "carol,bob"} {
		_, err := alice.tryRun("send", "--to", to, "hello")
		refusedWith(t, "--to "+to, err, exitUsage, fmt.Sprintf(
			"Bob is a room's name and your peer %s's too, so it names nobody for certain; "+
				"one of the two must go: auu room delete, or auu peers rm", bob.exportFingerprint()[:16]))
		nothingWritten(t, alice, 0, "--to "+to)
	}
}

// A name with relays in front of it is an address on another relay and
// never a room, alone or among several: the room is not expanded and the
// name is resolved as a peer, which no peer is.
func TestAnAddressEndingInARoomsNameIsNotExpanded(t *testing.T) {
	alice, _, _ := threePeers(t)
	alice.run("room", "create", "team", "bob", "carol")
	for _, to := range []string{"far!team", "bob,far!team"} {
		_, err := alice.tryRun("send", "--to", to, "hello")
		var e *exitError
		if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "team") ||
			strings.Contains(err.Error(), "room") || strings.Contains(err.Error(), "same recipient") {
			t.Fatalf("--to %s: %v; want team refused as an unknown peer", to, err)
		}
		nothingWritten(t, alice, 0, "--to "+to)
	}
}

// readOf is a read of one message, as text and as --json's keys.
func readOf(t *testing.T, u *user, id string) (string, map[string]any) {
	t.Helper()
	text := u.run("read", id)
	var keys map[string]any
	if err := json.Unmarshal([]byte(u.run("read", id, "--json")), &keys); err != nil {
		t.Fatal(err)
	}
	return text, keys
}

// assertRoomLine asserts a read names room, or no room when room is empty;
// the line comes after the to: line and before type:.
func assertRoomLine(t *testing.T, what, text string, keys map[string]any, room string) {
	t.Helper()
	if room == "" {
		if strings.Contains(text, "room:") {
			t.Errorf("%s: read names a room:\n%s", what, text)
		}
		if _, ok := keys["room"]; ok {
			t.Errorf("%s: read --json has room %v", what, keys["room"])
		}
		return
	}
	line := "room:    " + room + "\n"
	at := strings.Index(text, line)
	if at < 0 {
		t.Errorf("%s: read does not say %q:\n%s", what, line, text)
		return
	}
	if to := strings.Index(text, "to:"); to < 0 || to > at || strings.Index(text, "type:") < at {
		t.Errorf("%s: the room line is not between to: and type:\n%s", what, text)
	}
	if keys["room"] != room {
		t.Errorf("%s: read --json room is %v, want %q", what, keys["room"], room)
	}
}

// A message to several names this machine's room for the people in it,
// the sender and the others with the reader taken out, and self in the
// room is taken out too; read --json carries it and inbox --json does
// not; the first room in the file's order wins a tie; and the sender's own
// sent record is matched by its copies.
func TestReadNamesTheRoomWhenTheSetMatches(t *testing.T) {
	alice, bob, carol := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "to you both"))
	bob.run("inbox")
	a, b, c := alice.exportFingerprint(), bob.exportFingerprint(), carol.exportFingerprint()

	bob.writeRooms(roomDoc([]string{"team", a, c}))
	text, keys := readOf(t, bob, got.ID)
	assertRoomLine(t, "the room of the others", text, keys, "team")
	if raw := bob.run("inbox", "--json"); strings.Contains(raw, `"room"`) {
		t.Errorf("inbox --json carries room:\n%s", raw)
	}

	bob.writeRooms(roomDoc([]string{"team", c, b, a}))
	text, keys = readOf(t, bob, got.ID)
	assertRoomLine(t, "a room with self in it", text, keys, "team")

	bob.writeRooms(roomDoc([]string{"zeta", c, a}, []string{"alpha", a, c}))
	text, keys = readOf(t, bob, got.ID)
	assertRoomLine(t, "two rooms alike", text, keys, "zeta")
	bob.writeRooms(roomDoc([]string{"alpha", a, c}, []string{"zeta", c, a}))
	text, keys = readOf(t, bob, got.ID)
	assertRoomLine(t, "two rooms alike, the other first", text, keys, "alpha")

	alice.writeRooms(roomDoc([]string{"crew", c, b}))
	text, keys = readOf(t, alice, got.ID)
	assertRoomLine(t, "the sender's sent record", text, keys, "crew")
	alice.writeRooms(roomDoc([]string{"crew", a, b, c}))
	text, keys = readOf(t, alice, got.ID)
	assertRoomLine(t, "the sender's room with self in it", text, keys, "crew")
}

// A message to yourself and one other is a message to several, and the
// one other is the set: the recipient's room of the sender alone names it,
// and so does the sender's room of the recipient alone, on the copy she
// sent. A message to one still names no room (the test below).
func TestReadNamesTheRoomOfOneOtherOnAMessageWithSelf(t *testing.T) {
	alice, bob, _ := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "self,bob", "--json", "to us"))
	bob.run("inbox")
	a, b := alice.exportFingerprint(), bob.exportFingerprint()

	bob.writeRooms(roomDoc([]string{"al", a}))
	text, keys := readOf(t, bob, got.ID)
	assertRoomLine(t, "the recipient's room of the sender alone", text, keys, "al")

	alice.writeRooms(roomDoc([]string{"solo", b}))
	text, keys = readOf(t, alice, got.ID)
	assertRoomLine(t, "the sender's room of the recipient alone", text, keys, "solo")
}

// No room is named where the set differs by one either way, where a room
// holds only self, for a message to one, or beside a rooms file that does
// not read, which read does not fail for.
func TestReadNamesTheRoomNotWhenAMemberDiffers(t *testing.T) {
	alice, bob, carol := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "to you both"))
	one := sentOf(t, alice.run("send", "--to", "bob", "--json", "to you"))
	bob.run("inbox")
	a, b, c := alice.exportFingerprint(), bob.exportFingerprint(), carol.exportFingerprint()
	dave, err := identity.Generate("dave")
	if err != nil {
		t.Fatal(err)
	}
	d := dave.Public().Fingerprint()

	for _, tc := range []struct {
		what string
		doc  string
	}{
		{"a room of the sender alone", roomDoc([]string{"team", a})},
		{"a room of the other recipient alone", roomDoc([]string{"team", c})},
		{"a room of one more", roomDoc([]string{"team", a, c, d})},
		{"a room of one other", roomDoc([]string{"team", a, d})},
		{"a room of self alone", roomDoc([]string{"team", b})},
		{"a rooms file that does not read", `{"v":1,"rooms":[`},
	} {
		bob.writeRooms(tc.doc)
		text, keys := readOf(t, bob, got.ID)
		assertRoomLine(t, tc.what, text, keys, "")
	}

	bob.writeRooms(roomDoc([]string{"solo", a}, []string{"team", a, c}))
	text, keys := readOf(t, bob, one.ID)
	assertRoomLine(t, "a message to one", text, keys, "")
	alice.writeRooms(roomDoc([]string{"solo", b}))
	text, keys = readOf(t, alice, one.ID)
	assertRoomLine(t, "the sender's message to one", text, keys, "")
}

// send's --to offers rooms beside peers and self; reply's and vouch's do
// not, since neither takes one; the room group offers rooms for its first
// word and peers and self for the members.
func TestCompleteOffersRoomsWhereARoomIsTaken(t *testing.T) {
	alice, _ := twoPeers(t)
	alice.run("room", "create", "team", "bob")

	if c := completions(t, alice, "send", "--to", ""); c["team"] != "a room of 1" || c["bob"] == "" || c["self"] == "" || len(c) != 3 {
		t.Errorf("send --to: %v", c)
	}
	if c := completions(t, alice, "send", "--to", "t"); len(c) != 1 || c["team"] == "" {
		t.Errorf("send --to t: %v", c)
	}
	for _, words := range [][]string{{"reply", "--to", ""}, {"vouch", "--to", ""}} {
		if c := completions(t, alice, words...); c["team"] != "" {
			t.Errorf("%v: %v", words, c)
		}
	}
	if c := completions(t, alice, "room", ""); len(c) != 6 || c["show"] == "" || c["delete"] == "" {
		t.Errorf("room subwords: %v", c)
	}
	for _, sub := range []string{"show", "delete", "add", "rm"} {
		if c := completions(t, alice, "room", sub, ""); len(c) != 1 || c["team"] == "" {
			t.Errorf("room %s: %v", sub, c)
		}
	}
	for _, sub := range []string{"add", "rm"} {
		if c := completions(t, alice, "room", sub, "team", ""); len(c) != 2 || c["bob"] == "" || c["self"] == "" {
			t.Errorf("room %s team: %v", sub, c)
		}
	}
	if c := completions(t, alice, "room", "create", "crew", ""); len(c) != 2 || c["bob"] == "" || c["self"] == "" {
		t.Errorf("room create crew: %v", c)
	}
	if c := completions(t, alice, "room", "create", ""); len(c) != 0 {
		t.Errorf("room create's new name: %v", c)
	}
}
