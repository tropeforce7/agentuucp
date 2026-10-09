package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// roomsPath is this user's rooms file.
func (u *user) roomsPath() string { return filepath.Join(u.home, "rooms.json") }

// roomsBytes is this user's rooms file as it stands, nil when there is none.
func (u *user) roomsBytes() []byte {
	u.t.Helper()
	data, err := os.ReadFile(u.roomsPath())
	if err != nil && !os.IsNotExist(err) {
		u.t.Fatal(err)
	}
	return data
}

// rooms is this user's rooms as the store reads them.
func (u *user) rooms() []store.Room {
	u.t.Helper()
	s, _, _ := u.opened()
	rooms, err := s.Rooms()
	if err != nil {
		u.t.Fatal(err)
	}
	return rooms
}

// writeRooms writes the rooms file by hand, as a person with an editor would.
func (u *user) writeRooms(doc string) {
	u.t.Helper()
	if err := os.WriteFile(u.roomsPath(), []byte(doc), 0o600); err != nil {
		u.t.Fatal(err)
	}
}

// refusedWith asserts err is an exit with code and a sentence holding want.
func refusedWith(t *testing.T, what string, err error, code int, want string) {
	t.Helper()
	var e *exitError
	if !asExit(err, &e) || e.code != code || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: %v; want exit %d with %q", what, err, code, want)
	}
}

// keysOf is the sorted keys of a JSON object.
func keysOf(m map[string]any) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A member must be on the peer list when a room is made or added to, with
// self the one exception, shown as "you"; a stranger by name or by
// fingerprint is refused, exit 1, and no file is written.
func TestRoomCreateRefusesSomebodyNotOnThePeerList(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	alice.run("peers", "add", bob.exportLine())

	for _, stranger := range []string{"carol", carol.exportFingerprint(), carol.exportFingerprint()[:16], "far!carol"} {
		_, err := alice.tryRun("room", "create", "team", "bob", stranger)
		refusedWith(t, "a room with "+stranger, err, exitUsage,
			"is not on your peer list, and a room holds only people this machine can seal to; add them with auu peers add first")
		if alice.roomsBytes() != nil {
			t.Fatalf("a refused create wrote rooms.json:\n%s", alice.roomsBytes())
		}
	}

	out := alice.run("room", "create", "team", "self", "bob")
	if !strings.Contains(out, "room team made with 2 member(s)") {
		t.Fatalf("create:\n%s", out)
	}
	out = alice.run("room", "show", "team")
	if !strings.Contains(out, "team, 2 member(s)") ||
		!strings.Contains(out, fmt.Sprintf("  %-20s %s", "you", alice.exportFingerprint()[:16])) ||
		!strings.Contains(out, fmt.Sprintf("  %-20s %s", "bob", bob.exportFingerprint()[:16])) {
		t.Fatalf("show:\n%s", out)
	}
	rooms := alice.rooms()
	if len(rooms) != 1 || rooms[0].Members[0].FP != alice.exportFingerprint() || rooms[0].Members[1].FP != bob.exportFingerprint() {
		t.Fatalf("the file holds %+v", rooms)
	}

	// add holds a member to the same rule, and refuses one already in.
	before := alice.roomsBytes()
	_, err := alice.tryRun("room", "add", "team", "carol")
	refusedWith(t, "add of a stranger", err, exitUsage, "carol is not on your peer list")
	_, err = alice.tryRun("room", "add", "team", "bob")
	refusedWith(t, "add of a member already in", err, exitUsage, "bob is already in team; name each once")
	_, err = alice.tryRun("room", "add", "team", bob.exportFingerprint())
	refusedWith(t, "add of a member already in, by fingerprint", err, exitUsage, "is already in team; name each once")
	_, err = alice.tryRun("room", "add", "team", "self")
	refusedWith(t, "add of self already in", err, exitUsage, "self is already in team")
	if !bytes.Equal(alice.roomsBytes(), before) {
		t.Fatal("a refused add changed rooms.json")
	}
	// A room is made once; a name is not made twice by case.
	_, err = alice.tryRun("room", "create", "TEAM", "bob")
	refusedWith(t, "a second room by case", err, exitUsage, "there is a room team already")
	// A name the name rule refuses is refused.
	_, err = alice.tryRun("room", "create", "a!b", "bob")
	refusedWith(t, "a room name with !", err, exitUsage, "letters, digits")
}

// One name means one thing: a room may not take a peer's name, in any
// case, and a peer may not take a room's, by peers add or by the name
// typed at a knock, which is refused before the knock is posted.
func TestARoomMayNotTakeAPeersNameNorAPeerARooms(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	for _, name := range []string{"bob", "BOB", "Bob"} {
		_, err := alice.tryRun("room", "create", name, "self")
		refusedWith(t, "a room named "+name, err, exitUsage,
			name+" is your peer "+bob.exportFingerprint()[:16]+"'s name, and a room and a peer may not share one")
	}
	if alice.roomsBytes() != nil {
		t.Fatal("a refused create wrote rooms.json")
	}

	alice.run("room", "create", "team", "self", "bob")
	team := newUser(t, "Team", relayURL)
	_, err := alice.tryRun("peers", "add", team.exportLine())
	refusedWith(t, "peers add under a room's name", err, exitUsage,
		`peer name "Team" is the name of the room "team", and a room and a peer may not share one; choose a different name`)
	if names := alice.peerNames(); len(names) != 1 {
		t.Fatalf("a refused peers add added: %v", names)
	}

	// A knock: the name typed at the prompt is refused before anything is
	// posted, and the relay holds nothing for the target.
	team.run("card", "push", "--listed", "--knocks")
	atTerminal(t)
	_, err = alice.answer("y\nTEAM", "knock", "Team")
	refusedWith(t, "a knock under a room's name", err, exitUsage, `peer name "TEAM" is the name of the room "team"`)
	team.run("inbox")
	if len(team.quarantined()) != 0 {
		t.Fatal("a knock was posted under a name the peer list refuses")
	}
	if names := alice.peerNames(); len(names) != 1 {
		t.Fatalf("a refused knock added: %v", names)
	}
}

// The knock's offer, through suggestedName: a target whose own name is a
// room's is not offered it, the line says the room holds it, and the
// fallback is offered and taken.
func TestAKnockDoesNotOfferARoomsName(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	team := newUser(t, "team", relayURL)
	team.run("card", "push", "--listed", "--knocks")
	alice.run("room", "create", "Team", "self")

	atTerminal(t)
	out, err := alice.answer("y\n", "knock", "team")
	if err != nil {
		t.Fatalf("a knock on somebody named as a room: %v\n%s", err, out)
	}
	fallback := "peer-" + team.exportFingerprint()[:8]
	if !strings.Contains(out, `"team" is already the name of the room Team, so it is not offered`) ||
		!strings.Contains(out, "Local name for "+team.exportFingerprint()[:16]+" ["+fallback+"]: ") {
		t.Fatalf("the knock's offer:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 1 || names[0] != fallback {
		t.Fatalf("the peer list: %v", names)
	}
	team.run("inbox")
	if len(team.quarantined()) != 1 {
		t.Fatal("the knock did not reach its target")
	}
	// The function itself, with --yes's default and nothing typed.
	s, _, _ := alice.opened()
	pub, err := identity.ParseExportLine(team.exportLine())
	if err != nil {
		t.Fatal(err)
	}
	if name, by := suggestedName(s, &listedPeer{Public: pub, Suggested: "TEAM"}); name != fallback || by != "the room Team" {
		t.Fatalf("suggestedName = %q, %q", name, by)
	}
	if name, by := suggestedName(s, &listedPeer{Public: pub, Suggested: "tea"}); name != "tea" || by != "" {
		t.Fatalf("suggestedName of a prefix = %q, %q", name, by)
	}
}

// Trusting a knock, through knockName and freeName: a knock whose claimed
// name is a room's is not offered it, the line says the room holds it,
// and the fallback is offered and taken.
func TestTrustingAKnockDoesNotOfferARoomsName(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	team := newUser(t, "team", relayURL)
	alice.run("card", "push", "--knocks")
	alice.run("room", "create", "team", "self")
	team.run("knock", alice.exportFingerprint(), "--yes")
	alice.run("inbox")
	held := alice.quarantined()
	if len(held) != 1 {
		t.Fatalf("%d in quarantine, want the knock", len(held))
	}

	atTerminal(t)
	out, err := alice.answer("\nn", "quarantine", "trust", held[0].Inner.ID[:12])
	if err != nil {
		t.Fatalf("trusting a knock named as a room: %v\n%s", err, out)
	}
	fallback := "peer-" + team.exportFingerprint()[:8]
	if !strings.Contains(out, `"team" is already the name of the room team, so it is not offered`) ||
		!strings.Contains(out, "Local name for "+team.exportFingerprint()[:16]+" ["+fallback+"]: ") {
		t.Fatalf("the trust's offer:\n%s", out)
	}
	if names := alice.peerNames(); len(names) != 1 || names[0] != fallback {
		t.Fatalf("the peer list: %v", names)
	}
	s, _, _ := alice.opened()
	if name, by := freeName(s, team.exportFingerprint(), "TEAM"); name != fallback || by != "the room team" {
		t.Fatalf("freeName = %q, %q", name, by)
	}
}

// delete names what goes and asks. Declined, the file is byte for byte as
// it was, stderr says nothing was deleted and the exit is 1; accepted by y,
// yes or Y, the room is gone; --yes, after the name, deletes without
// asking.
func TestRoomDeleteAsksAndDeclinedLeavesTheFile(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("room", "create", "team", "self", "bob")
	alice.run("room", "create", "pair", "bob")
	before := alice.roomsBytes()

	for _, no := range []string{"n", "", "no", "yess"} {
		var out string
		var err error
		stderr := captureStderr(t, func() { out, err = alice.answer(no, "room", "delete", "team") })
		if !strings.Contains(stderr, "nothing was deleted; team is kept") {
			t.Fatalf("a declined delete answered %q said on stderr:\n%s", no, stderr)
		}
		if !strings.Contains(out, "delete the room team and its list of 2 member(s)? The peers stay on your peer list [y/N]: ") {
			t.Fatalf("the question:\n%s", out)
		}
		refusedWith(t, "a declined delete answered "+no, err, exitUsage, "cancelled")
		if !bytes.Equal(alice.roomsBytes(), before) {
			t.Fatalf("a declined delete changed rooms.json")
		}
	}

	out, err := alice.answer("y", "room", "delete", "TEAM")
	if err != nil || !strings.Contains(out, "room team deleted") {
		t.Fatalf("an accepted delete: %v\n%s", err, out)
	}
	if rooms := alice.rooms(); len(rooms) != 1 || rooms[0].Name != "pair" {
		t.Fatalf("after the delete: %+v", rooms)
	}
	if names := alice.peerNames(); len(names) != 1 {
		t.Fatalf("a room's delete touched the peer list: %v", names)
	}
	for _, yes := range []string{"yes", "Y"} {
		alice.run("room", "create", "team", "self", "bob")
		out, err := alice.answer(yes, "room", "delete", "team")
		if err != nil || !strings.Contains(out, "room team deleted") {
			t.Fatalf("a delete answered %q: %v\n%s", yes, err, out)
		}
		if rooms := alice.rooms(); len(rooms) != 1 || rooms[0].Name != "pair" {
			t.Fatalf("after a delete answered %q: %+v", yes, rooms)
		}
	}

	// --yes asks nothing: an answer of n on standard input is not read.
	out, err = alice.answer("n", "room", "delete", "pair", "--yes")
	if err != nil || strings.Contains(out, "[y/N]") || !strings.Contains(out, "room pair deleted") {
		t.Fatalf("delete --yes: %v\n%s", err, out)
	}
	if rooms := alice.rooms(); len(rooms) != 0 {
		t.Fatalf("after delete --yes: %+v", rooms)
	}
	_, err = alice.tryRun("room", "delete", "pair", "--yes")
	refusedWith(t, "delete of no room", err, exitUsage, "there is no room pair")
}

// An empty room cannot be kept, so rm of the last member deletes the room
// and says so; rm of one of several says what is left.
func TestRoomRmOfTheLastMemberDeletesTheRoomAndSaysSo(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("room", "create", "team", "self", "bob")
	alice.run("room", "create", "other", "bob")

	out := alice.run("room", "rm", "team", "bob")
	if !strings.Contains(out, "1 removed from team, which has 1 member(s)") {
		t.Fatalf("rm of one of two:\n%s", out)
	}
	_, err := alice.tryRun("room", "rm", "team", "bob")
	refusedWith(t, "rm of somebody not in it", err, exitUsage,
		"bob names bob ("+bob.exportFingerprint()[:16]+"), who is not in team; auu room show team lists who is, by a short id that names them alone")

	out = alice.run("room", "rm", "team", "self")
	if !strings.Contains(out, "team had nobody left and is deleted") {
		t.Fatalf("rm of the last:\n%s", out)
	}
	if rooms := alice.rooms(); len(rooms) != 1 || rooms[0].Name != "other" {
		t.Fatalf("after the last rm: %+v", rooms)
	}
	_, err = alice.tryRun("room", "show", "team")
	refusedWith(t, "show of a deleted room", err, exitUsage, "there is no room team")

	// Both at once, in one rm.
	alice.run("room", "create", "two", "self", "bob")
	out = alice.run("room", "rm", "two", "self", "bob")
	if !strings.Contains(out, "two had nobody left and is deleted") {
		t.Fatalf("rm of both:\n%s", out)
	}
	if rooms := alice.rooms(); len(rooms) != 1 {
		t.Fatalf("after rm of both: %+v", rooms)
	}
}

// A member is added by RELAY!NAME with its relays kept as the via and
// shown, and a room holds at most 32: an add past that is refused and
// nothing is written.
func TestRoomAddKeepsTheViaAndHoldsTheCeiling(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	alice.run("room", "create", "team", "self")
	out := alice.run("room", "add", "team", "far!near!bob")
	if !strings.Contains(out, "1 added to team, which has 2 member(s)") {
		t.Fatalf("add:\n%s", out)
	}
	if rooms := alice.rooms(); rooms[0].Members[1].Via != "far!near" {
		t.Fatalf("the via kept: %+v", rooms[0].Members)
	}
	if out := alice.run("room", "show", "team"); !strings.Contains(out, bob.exportFingerprint()[:16]+"  by far!near") {
		t.Fatalf("show of a member with a via:\n%s", out)
	}
	_, err := alice.tryRun("room", "add", "team", "far!far!bob")
	refusedWith(t, "a via that repeats a relay", err, exitUsage, `address repeats "far"`)

	// Thirty more peers make 32 with alice and bob; one more is over.
	s, _, _ := alice.opened()
	var names []string
	for i := range store.MaxRoomMembers - 1 {
		name := fmt.Sprintf("p%02d", i)
		id, err := identity.Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AddPeer(id.Public()); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	alice.run(append([]string{"room", "add", "team"}, names[:store.MaxRoomMembers-2]...)...)
	if rooms := alice.rooms(); len(rooms[0].Members) != store.MaxRoomMembers {
		t.Fatalf("%d members, want %d", len(rooms[0].Members), store.MaxRoomMembers)
	}
	before := alice.roomsBytes()
	_, err = alice.tryRun("room", "add", "team", names[store.MaxRoomMembers-2])
	refusedWith(t, "the 33rd member", err, exitUsage, "team would have 33 members, and a room holds at most 32")
	if !bytes.Equal(alice.roomsBytes(), before) {
		t.Fatal("a refused add changed rooms.json")
	}
	_, err = alice.tryRun(append([]string{"room", "create", "big", "self", "bob"}, names...)...)
	refusedWith(t, "a create of 33", err, exitUsage, "big would have 33 members")
	if !bytes.Equal(alice.roomsBytes(), before) {
		t.Fatal("a refused create changed rooms.json")
	}
}

// A rooms file written by hand with a member who is not on the peer list
// is not broken: ls counts them, show names them and the two remedies,
// --json carries the problem, the file is not rewritten by reading it, and
// rm by the fingerprint show prints removes them.
func TestARoomsFileWrittenByHandWithAMemberOffTheListIsSaidAndKept(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	alice.run("peers", "add", bob.exportLine())
	doc := fmt.Sprintf(`{"v":1,"rooms":[{"name":"team","members":[{"fp":%q},{"fp":%q,"via":"far"}]}]}`,
		bob.exportFingerprint(), carol.exportFingerprint())
	alice.writeRooms(doc)

	if out := alice.run("room", "ls"); !strings.Contains(out, fmt.Sprintf("%-20s 2 member(s); 1 not on your peer list", "team")) {
		t.Fatalf("ls:\n%s", out)
	}
	out := alice.run("room", "show", "team")
	for _, want := range []string{
		fmt.Sprintf("  %-20s %s", "bob", bob.exportFingerprint()[:16]),
		fmt.Sprintf("  %-20s %s  by far", "(not on your peer list)", carol.exportFingerprint()[:16]),
		"1 not on your peer list: remove each with auu room rm, or add them again with auu peers add",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show lacks %q:\n%s", want, out)
		}
	}
	var shown roomJSON
	if err := json.Unmarshal([]byte(alice.run("room", "show", "team", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown.Members) != 2 || shown.Members[1].Problem != "not on your peer list" || shown.Members[1].Name != "" ||
		shown.Members[0].Problem != "" || shown.Problem != "" {
		t.Fatalf("show --json: %+v", shown)
	}
	if got := alice.roomsBytes(); string(got) != doc {
		t.Fatalf("reading the rooms rewrote the file:\n%s", got)
	}

	// Removed by the fingerprint show prints, though no peer has it, and
	// with the relays it is reached by in front, as it was added: the
	// fingerprint is read after them.
	out = alice.run("room", "rm", "team", "far!"+carol.exportFingerprint()[:16])
	if !strings.Contains(out, "1 removed from team, which has 1 member(s)") {
		t.Fatalf("rm by short fingerprint:\n%s", out)
	}
	if rooms := alice.rooms(); len(rooms[0].Members) != 1 || rooms[0].Members[0].FP != bob.exportFingerprint() {
		t.Fatalf("after rm: %+v", rooms)
	}
	// Fewer than eight characters is not taken as a fingerprint.
	_, err := alice.tryRun("room", "rm", "team", bob.exportFingerprint()[:7])
	refusedWith(t, "rm by seven characters", err, exitUsage, "is not in team")
}

// --json gives exactly the keys the shapes declare: ls an object of rooms,
// show one room, a member's via and problem only when there is one, and a
// room's problem when a peer has its name.
func TestRoomJSONShapes(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	dave := newUser(t, "dave", relayURL)
	alice.run("peers", "add", bob.exportLine())

	// No rooms: an empty list, not null.
	var empty map[string]any
	if err := json.Unmarshal([]byte(alice.run("room", "ls", "--json")), &empty); err != nil {
		t.Fatal(err)
	}
	if list, ok := empty["rooms"].([]any); !ok || len(list) != 0 || len(empty) != 1 {
		t.Fatalf("ls --json of no rooms: %v", empty)
	}

	// A room whose name a peer now has, written by hand on both sides, and
	// a member off the list.
	alice.writeRooms(fmt.Sprintf(`{"v":1,"rooms":[`+
		`{"name":"team","members":[{"fp":%q},{"fp":%q,"via":"far!near"},{"fp":%q}]},`+
		`{"name":"carol","members":[{"fp":%q}]}]}`,
		alice.exportFingerprint(), bob.exportFingerprint(), dave.exportFingerprint(), bob.exportFingerprint()))
	f, err := os.OpenFile(filepath.Join(alice.home, "authorized_peers"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(carol.exportLine() + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var ls map[string]any
	if err := json.Unmarshal([]byte(alice.run("room", "ls", "--json")), &ls); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keysOf(ls), []string{"rooms"}) {
		t.Fatalf("ls --json keys: %v", keysOf(ls))
	}
	list := ls["rooms"].([]any)
	if len(list) != 2 {
		t.Fatalf("ls --json: %d rooms", len(list))
	}
	team, other := list[0].(map[string]any), list[1].(map[string]any)
	if !reflect.DeepEqual(keysOf(team), []string{"members", "name"}) || team["name"] != "team" {
		t.Fatalf("a room's keys: %v", team)
	}
	if !reflect.DeepEqual(keysOf(other), []string{"members", "name", "problem"}) ||
		other["problem"] != "a peer is named carol too" {
		t.Fatalf("a room a peer is named as: %v", other)
	}
	members := team["members"].([]any)
	want := []map[string]any{
		{"fingerprint": alice.exportFingerprint(), "name": "you"},
		{"fingerprint": bob.exportFingerprint(), "name": "bob", "via": "far!near"},
		{"fingerprint": dave.exportFingerprint(), "name": "", "problem": "not on your peer list"},
	}
	if len(members) != len(want) {
		t.Fatalf("%d members", len(members))
	}
	for i, m := range members {
		if !reflect.DeepEqual(m, want[i]) {
			t.Fatalf("member %d: %v; want %v", i, m, want[i])
		}
	}

	// show --json is the one room, the same object ls gives.
	var shown map[string]any
	if err := json.Unmarshal([]byte(alice.run("room", "show", "TEAM", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(shown, team) {
		t.Fatalf("show --json: %v; ls gave %v", shown, team)
	}
	// The flag before the name reads the same.
	var before map[string]any
	if err := json.Unmarshal([]byte(alice.run("room", "show", "--json", "carol")), &before); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, other) {
		t.Fatalf("show --json carol: %v", before)
	}
	// The text says the room's problem and its remedy.
	out := alice.run("room", "show", "carol")
	if !strings.Contains(out, "a peer is named carol too: one name means one thing, so one of the two must go: auu room delete, or auu peers rm") {
		t.Fatalf("show of a room a peer is named as:\n%s", out)
	}
	if out := alice.run("room", "ls"); !strings.Contains(out, "carol") || !strings.Contains(out, "; a peer is named carol too") {
		t.Fatalf("ls:\n%s", out)
	}
}

// Nothing a room command prints carries a control byte from what it was
// given: a name typed on the command line, a rooms file written by hand,
// or a peer list whose name is not a name. The peer list refuses a line
// whose name breaks the name rule, so an escape there reaches a room
// command only as that refusal, escaped.
func TestRoomCommandsPrintEscaped(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("room", "create", "team", "bob")

	const hostile = "b\x1b[2Job"
	clean := func(what, out string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was not refused:\n%s", what, out)
		}
		if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(err.Error(), 0x1b) {
			t.Fatalf("%s printed an escape byte: %q, %q", what, out, err)
		}
		if !strings.Contains(err.Error(), `b\x1b[2Job`) {
			t.Fatalf("%s does not show the name escaped: %v", what, err)
		}
	}
	for _, args := range [][]string{
		{"room", "show", hostile},
		{"room", "delete", hostile, "--yes"},
		{"room", "add", hostile, "bob"},
		{"room", "create", hostile, "bob"},
		{"room", "add", "team", hostile},
		{"room", "create", "fine", hostile},
		{"room", "rm", "team", hostile},
		{"room", "add", "team", "far!" + hostile},
	} {
		out, err := alice.tryRun(args...)
		clean(strings.Join(args[:2], " ")+" of an escape", out, err)
	}

	// A rooms file with an escape in a room's name or a via: refused at
	// the read, the name escaped.
	before := alice.roomsBytes()
	for _, doc := range []string{
		fmt.Sprintf(`{"v":1,"rooms":[{"name":"b\u001b[2Job","members":[{"fp":%q}]}]}`, bob.exportFingerprint()),
		fmt.Sprintf(`{"v":1,"rooms":[{"name":"team","members":[{"fp":%q,"via":"b\u001b[2Job"}]}]}`, bob.exportFingerprint()),
	} {
		alice.writeRooms(doc)
		for _, args := range [][]string{{"room", "ls"}, {"room", "show", "team"}, {"room", "ls", "--json"}} {
			out, err := alice.tryRun(args...)
			clean("a hand-written escape at "+strings.Join(args, " "), out, err)
		}
	}
	alice.writeRooms(string(before))
}

// A peer list that does not read is said as damaged by every room command
// that reads it, exit 5, its words escaped, and never taken for an empty
// list: a room's members are not called off the list, nor told to be
// removed, because the file that would say who they are cannot be read.
func TestARoomCommandBesideADamagedPeerListSaysSo(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("room", "create", "team", "bob")
	const hostile = "b\x1b[2Job"
	peers := filepath.Join(alice.home, "authorized_peers")
	line := strings.TrimSuffix(bob.exportLine(), ".bob") + "." + hostile
	if err := os.WriteFile(peers, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := alice.roomsBytes()
	for _, args := range [][]string{
		{"room", "ls"}, {"room", "ls", "--json"}, {"room", "show", "team"}, {"room", "show", "team", "--json"},
		{"room", "create", "x", "self"}, {"room", "add", "team", "bob"}, {"room", "rm", "team", "bob"},
	} {
		out, err := alice.tryRun(args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitDamaged {
			t.Errorf("%s beside a damaged peer list: %v\n%s", strings.Join(args, " "), err, out)
			continue
		}
		if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(err.Error(), 0x1b) ||
			!strings.Contains(err.Error(), `b\x1b[2Job`) {
			t.Errorf("%s: the name not escaped: %q, %q", strings.Join(args, " "), out, err)
		}
	}
	if !bytes.Equal(alice.roomsBytes(), before) {
		t.Fatal("a room command beside a damaged peer list changed rooms.json")
	}
}

// room rm finds a member through the peer list first, as every other
// command finds a peer: a peer whose name is the first eight characters of
// another member's fingerprint names that peer, and the member whose
// fingerprint it is stays. Each one removed is said on a line of its own.
func TestRoomRmResolvesThroughThePeerListFirst(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	prefix := bob.exportFingerprint()[:8]
	alice.run("peers", "add", bob.exportLine())
	alice.run("peers", "add", strings.TrimSuffix(carol.exportLine(), ".carol")+"."+prefix)
	if names := alice.peerNames(); len(names) != 2 || names[1] != prefix {
		t.Fatalf("the peer list: %v", names)
	}
	alice.run("room", "create", "team", "bob", prefix)

	out := alice.run("room", "rm", "team", prefix)
	removed := "removed" + fmt.Sprintf("  %-20s %s", prefix, carol.exportFingerprint()[:16])
	if !strings.Contains(out, removed+"\n") || !strings.Contains(out, "1 removed from team, which has 1 member(s)") {
		t.Fatalf("rm by a peer's name that is the start of another member's fingerprint:\n%s", out)
	}
	if strings.Index(out, removed) > strings.Index(out, "1 removed from team") {
		t.Fatalf("the removed line comes after the count:\n%s", out)
	}
	if rooms := alice.rooms(); len(rooms[0].Members) != 1 || rooms[0].Members[0].FP != bob.exportFingerprint() {
		t.Fatalf("after rm: %+v", rooms)
	}
	// A second rm by the same name: carol is not in the room, and bob is
	// not taken in her place by his fingerprint.
	_, err := alice.tryRun("room", "rm", "team", prefix)
	refusedWith(t, "rm of a peer no longer in the room", err, exitUsage,
		prefix+" names "+prefix+" ("+carol.exportFingerprint()[:16]+"), who is not in team; auu room show team lists who is, by a short id that names them alone")
	if rooms := alice.rooms(); len(rooms[0].Members) != 1 {
		t.Fatalf("a refused rm removed: %+v", rooms)
	}
	// bob, the member those eight characters start, is named by more of
	// his fingerprint, as the sentence says: his short id.
	alice.run("room", "add", "team", prefix)
	out = alice.run("room", "rm", "team", bob.exportFingerprint()[:16])
	if !strings.Contains(out, "removed"+fmt.Sprintf("  %-20s %s", "bob", bob.exportFingerprint()[:16])+"\n") {
		t.Fatalf("rm by the short id of the member a peer's name shadows:\n%s", out)
	}
	alice.run("room", "add", "team", "bob")
	// One member named twice in one rm is said, and nothing goes.
	before := string(alice.roomsBytes())
	_, err = alice.tryRun("room", "rm", "team", "bob", bob.exportFingerprint()[:16])
	refusedWith(t, "rm of one member named twice", err, exitUsage,
		"bob and "+bob.exportFingerprint()[:16]+" are the same member of team; name each once")
	if after := string(alice.roomsBytes()); after != before {
		t.Fatalf("a refused rm wrote the file")
	}
	alice.run("room", "rm", "team", prefix)

	// A member with a via is said with it, and the last one removed is
	// said before the room is said deleted.
	alice.run("room", "add", "team", "far!"+prefix)
	out = alice.run("room", "rm", "team", "bob", prefix)
	for _, want := range []string{
		"removed" + fmt.Sprintf("  %-20s %s", "bob", bob.exportFingerprint()[:16]) + "\n",
		"removed" + fmt.Sprintf("  %-20s %s  by far", prefix, carol.exportFingerprint()[:16]) + "\n",
		"team had nobody left and is deleted",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rm of both lacks %q:\n%s", want, out)
		}
	}
}

// A room may not be named as a fingerprint's start could be typed: eight or
// more hex characters, in either case, are refused by create and by the read, a
// hand-written file holding one is damaged, and seven are a name.
func TestARoomNameLikeAFingerprintIsRefused(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	for _, name := range []string{"a325b6ac", bob.exportFingerprint()[:16], "0123456789", "DEADBEEF"} {
		_, err := alice.tryRun("room", "create", name, "bob")
		refusedWith(t, "a room named "+name, err, exitUsage,
			name+" could be the start of a fingerprint, which names a peer; give the room a name with a letter past f in it")
		if alice.roomsBytes() != nil {
			t.Fatalf("a refused create wrote rooms.json:\n%s", alice.roomsBytes())
		}
	}
	for _, name := range []string{"a325b6a", "a325b6ag"} {
		if out := alice.run("room", "create", name, "bob"); !strings.Contains(out, "room "+name+" made with 1 member(s)") {
			t.Fatalf("create %s:\n%s", name, out)
		}
	}

	alice.writeRooms(fmt.Sprintf(`{"v":1,"rooms":[{"name":"a325b6ac","members":[{"fp":%q}]}]}`, bob.exportFingerprint()))
	before := alice.roomsBytes()
	_, err := alice.tryRun("room", "ls")
	refusedWith(t, "ls of a hand-written name like a fingerprint", err, exitDamaged,
		alice.roomsPath()+` breaks a rule (room "a325b6ac"'s name could be the start of a fingerprint, which names a peer)`)
	if !bytes.Equal(alice.roomsBytes(), before) {
		t.Fatal("a refused read changed rooms.json")
	}
}

// A rooms file that does not read, or that breaks a rule, is damaged: every
// room command beside it exits 5 naming the file and what to do, and no
// peer is added under any name while it stands, by peers add or by a
// knock, since a name cannot be shown free of a file nobody can read.
// Those two say the file in the same words with exit 1, as they say any
// refusal of the add, and the knock is refused before it is posted. A
// file a later auu wrote is not damaged, and refuses with exit 1.
func TestADamagedRoomsFileIsSaidAsDamaged(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	carol.run("card", "push", "--listed", "--knocks")
	alice.run("peers", "add", bob.exportLine())
	alice.run("room", "create", "team", "bob")
	good := alice.roomsBytes()
	const advice = "fix it by hand, or move it aside and make the rooms again with auu room create"

	for _, tc := range []struct {
		what, doc, fact string
	}{
		{"truncated", string(good[:len(good)/2]), "does not read"},
		{"garbled", "not json\n", "does not read"},
		{"an empty room", `{"v":1,"rooms":[{"name":"team","members":[]}]}`, `breaks a rule (room "team" has nobody in it)`},
		{"a member not a fingerprint", `{"v":1,"rooms":[{"name":"team","members":[{"fp":"abc"}]}]}`,
			`breaks a rule (room "team" has a member whose fp is not a fingerprint)`},
	} {
		alice.writeRooms(tc.doc)
		for _, args := range [][]string{
			{"room", "ls"}, {"room", "ls", "--json"}, {"room", "show", "team"}, {"room", "create", "pair", "bob"},
			{"room", "add", "team", "self"}, {"room", "rm", "team", "bob"}, {"room", "delete", "team", "--yes"},
		} {
			_, err := alice.tryRun(args...)
			refusedWith(t, strings.Join(args, " ")+" beside a "+tc.what+" rooms file", err, exitDamaged,
				alice.roomsPath()+" "+tc.fact)
			if !strings.Contains(err.Error(), advice) {
				t.Fatalf("%s: no advice: %v", strings.Join(args, " "), err)
			}
		}
		// Any name, one no room could hold among them.
		for _, name := range []string{"carol", "team"} {
			_, err := alice.tryRun("peers", "add", strings.TrimSuffix(carol.exportLine(), ".carol")+"."+name)
			refusedWith(t, "peers add "+name+" beside a "+tc.what+" rooms file", err, exitUsage, alice.roomsPath()+" "+tc.fact)
		}
		atTerminal(t)
		_, err := alice.answer("y\ncarol", "knock", "carol")
		refusedWith(t, "a knock beside a "+tc.what+" rooms file", err, exitUsage, alice.roomsPath()+" "+tc.fact)
		if names := alice.peerNames(); len(names) != 1 {
			t.Fatalf("a peer was added beside a %s rooms file: %v", tc.what, names)
		}
		if got := alice.roomsBytes(); string(got) != tc.doc {
			t.Fatalf("a command beside a %s rooms file changed it:\n%s", tc.what, got)
		}
	}
	carol.run("inbox")
	if len(carol.quarantined()) != 0 {
		t.Fatal("a knock was posted beside a damaged rooms file")
	}

	// A later auu's file is said as that, not as damaged: a plain error,
	// which Main exits 1 on.
	alice.writeRooms(`{"v":2,"rooms":[]}`)
	_, err := alice.tryRun("room", "ls")
	var e *exitError
	if err == nil || asExit(err, &e) || errors.Is(err, store.ErrDamaged) ||
		!strings.Contains(err.Error(), "is version 2, and this auu reads version 1; a later auu wrote it") {
		t.Fatalf("ls of a later version: %v; want a plain error, exit 1, saying the version", err)
	}
	_, err = alice.tryRun("peers", "add", carol.exportLine())
	refusedWith(t, "peers add beside a later version", err, exitUsage, "is version 2")
}

// A member is somebody this machine can seal to, named once: an address
// that reaches yourself by relays is refused, as is a prefix two peers
// share, by create, add and rm, with the ambiguity said; and a room whose
// name a peer has in another case is said so by show though a prefix of
// that name is shared with another peer.
func TestRoomMembersAreNamedOnce(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bobby := newUser(t, "bobby", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("peers", "add", bobby.exportLine())

	for _, arg := range []string{"far!self", "far!near!" + alice.exportFingerprint()} {
		_, err := alice.tryRun("room", "create", "team", arg)
		refusedWith(t, "a member "+arg, err, exitUsage,
			arg+" names relays to reach yourself by; a copy to yourself goes nowhere, so name self alone")
	}
	_, err := alice.tryRun("room", "create", "team", "bo")
	refusedWith(t, "an ambiguous member", err, exitUsage, `"bo" matches 2 peers: bob (`)
	if err != nil && strings.Contains(err.Error(), "not on your peer list") {
		t.Fatalf("an ambiguous member called off the list: %v", err)
	}
	if alice.roomsBytes() != nil {
		t.Fatalf("a refused create wrote rooms.json:\n%s", alice.roomsBytes())
	}

	alice.run("room", "create", "team", "self", "bob", "bobby")
	before := alice.roomsBytes()
	_, err = alice.tryRun("room", "add", "team", "far!self")
	refusedWith(t, "add of far!self", err, exitUsage, "so name self alone")
	_, err = alice.tryRun("room", "rm", "team", "bo")
	refusedWith(t, "rm of an ambiguous member", err, exitUsage, `"bo" matches 2 peers`)
	if !bytes.Equal(alice.roomsBytes(), before) {
		t.Fatal("a refused add or rm changed rooms.json")
	}

	// A room named Bob, written by hand, beside peers bob and bobby: the
	// peer of the same name in another case is found, not an ambiguity.
	alice.writeRooms(fmt.Sprintf(`{"v":1,"rooms":[{"name":"Bob","members":[{"fp":%q}]}]}`, bobby.exportFingerprint()))
	out := alice.run("room", "show", "Bob")
	if !strings.Contains(out, "a peer is named bob too: one name means one thing, so one of the two must go: auu room delete, or auu peers rm") {
		t.Fatalf("show of a room a peer is named as in another case:\n%s", out)
	}
	var shown roomJSON
	if err := json.Unmarshal([]byte(alice.run("room", "show", "bob", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Problem != "a peer is named bob too" {
		t.Fatalf("show --json: %+v", shown)
	}
	if out := alice.run("room", "ls"); !strings.Contains(out, "; a peer is named bob too") {
		t.Fatalf("ls:\n%s", out)
	}
}
