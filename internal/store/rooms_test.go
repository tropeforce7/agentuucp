package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// roomFP is the nth made-up fingerprint for a room's member: 64 lowercase
// hex characters, which is all the rooms file holds a member to.
func roomFP(n int) string {
	return fmt.Sprintf("%064x", n+1)
}

// roomJSON writes a room as the file holds it, with n members.
func roomJSON(name string, n int) string {
	members := make([]string, n)
	for i := range members {
		members[i] = fmt.Sprintf(`{"fp":%q}`, roomFP(i))
	}
	return fmt.Sprintf(`{"name":%q,"members":[%s]}`, name, strings.Join(members, ","))
}

// roomsFileOf is a whole file of the rooms given, at version 1.
func roomsFileOf(rooms ...string) string {
	return `{"v":1,"rooms":[` + strings.Join(rooms, ",") + `]}`
}

// manyRooms is n rooms of one member each, named r0, r1 and so on.
func manyRooms(n int) string {
	rooms := make([]string, n)
	for i := range rooms {
		rooms[i] = roomJSON(fmt.Sprintf("r%d", i), 1)
	}
	return roomsFileOf(rooms...)
}

// hops is a via of n distinct relays.
func hops(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("h%d", i)
	}
	return strings.Join(names, "!")
}

// TestLimitRoomShapes: rooms.json is read strictly and held to every rule
// at the read. Each file below is refused by name and left byte for byte
// as it was found; the file at each ceiling, 32 members and 256 rooms, is
// read. SaveRooms refuses what the read would refuse and writes nothing.
func TestLimitRoomShapes(t *testing.T) {
	one := `{"fp":"` + roomFP(0) + `"}`
	for _, tc := range []struct {
		what string
		file string
		want string // in the error; "" for a file that is read
	}{
		{"32 members", roomsFileOf(roomJSON("team", MaxRoomMembers)), ""},
		{"33 members", roomsFileOf(roomJSON("team", MaxRoomMembers+1)), `room "team" has 33 people, and a room holds at most 32`},
		{"256 rooms", manyRooms(MaxRooms), ""},
		{"257 rooms", manyRooms(MaxRooms + 1), "257 rooms, and a home holds at most 256"},
		{"one member", roomsFileOf(roomJSON("team", 1)), ""},
		{"no rooms", `{"v":1,"rooms":[]}`, ""},
		{"a member twice", roomsFileOf(`{"name":"team","members":[` + one + `,` + one + `]}`),
			`room "team" has ` + roomFP(0)[:16] + ` twice`},
		{"a fingerprint one short", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0)[1:] + `"}]}`),
			`room "team" has a member whose fp is not a fingerprint`},
		{"a fingerprint in capitals", roomsFileOf(`{"name":"team","members":[{"fp":"` + strings.Repeat("A", 64) + `"}]}`),
			`room "team" has a member whose fp is not a fingerprint`},
		{"an empty fingerprint", roomsFileOf(`{"name":"team","members":[{"fp":""}]}`),
			`room "team" has a member whose fp is not a fingerprint`},
		{"a via that is not a relay name", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","via":"a/b"}]}`),
			`room "team"'s member ` + roomFP(0)[:16] + `: relay name "a/b"`},
		{"a via with an empty hop", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","via":"a!!b"}]}`),
			`relay name ""`},
		{"a via that repeats a relay", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","via":"a!A"}]}`),
			`address repeats "A"`},
		{"a via of 32 relays", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","via":"` + hops(relayapi.MaxHops) + `"}]}`),
			""},
		{"a via of 33 relays", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","via":"` + hops(relayapi.MaxHops+1) + `"}]}`),
			"an address names 33 relays; at most 32"},
		{"a via with an escape", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","via":"a\u001bb"}]}`),
			`relay name "a\x1bb"`},
		{"v 0", `{"v":0,"rooms":[]}`, "is version 0, and this auu reads version 1"},
		{"v absent", `{"rooms":[]}`, "is version 0, and this auu reads version 1"},
		{"v 2", `{"v":2,"rooms":[]}`, "is version 2, and this auu reads version 1"},
		{"an unknown key", `{"v":1,"rooms":[],"owner":"x"}`, `unknown field "owner"`},
		{"an unknown key in a member", roomsFileOf(`{"name":"team","members":[{"fp":"` + roomFP(0) + `","name":"bob"}]}`),
			`unknown field "name"`},
		{"a key twice", `{"v":1,"v":1,"rooms":[]}`, `"v"`},
		{"a key by case", `{"V":1,"rooms":[]}`, `"V"`},
		{"a key by case in a room", roomsFileOf(`{"Name":"team","members":[` + one + `]}`), `"Name"`},
		{"a trailing }", `{"v":1,"rooms":[]}}`, "does not read (trailing data after the value)"},
		{"a letter after the object", `{"v":1,"rooms":[]}x`, "does not read (trailing data after the value)"},
		{"two names equal by case", roomsFileOf(roomJSON("team", 1), roomJSON("TEAM", 1)),
			`two rooms are named "team" and "TEAM", which are the same name in any case`},
		{"an empty room", roomsFileOf(`{"name":"team","members":[]}`), `room "team" has nobody in it`},
		{"a room with no members key", roomsFileOf(`{"name":"team"}`), `room "team" has nobody in it`},
		{"a 65-byte name", roomsFileOf(roomJSON(strings.Repeat("a", 65), 1)), "room 1: identity: name is 65 bytes; at most 64"},
		{"a 64-byte name", roomsFileOf(roomJSON(strings.Repeat("z", 64), 1)), ""},
		{"a name of 8 hex characters", roomsFileOf(roomJSON("a325b6ac", 1)),
			`room "a325b6ac"'s name could be the start of a fingerprint, which names a peer`},
		{"a name of 8 hex characters in capitals", roomsFileOf(roomJSON("DEADBEEF", 1)),
			`room "DEADBEEF"'s name could be the start of a fingerprint, which names a peer`},
		{"a name that is a short id", roomsFileOf(roomJSON(roomFP(0)[:16], 1)), "could be the start of a fingerprint"},
		{"a name that is a fingerprint", roomsFileOf(roomJSON(roomFP(0), 1)), "could be the start of a fingerprint"},
		{"a name of 7 hex characters", roomsFileOf(roomJSON("a325b6a", 1)), ""},
		{"a name of 8 with a letter past f", roomsFileOf(roomJSON("a325b6ag", 1)), ""},
		{"a name with !", roomsFileOf(roomJSON("a!b", 1)), `name "a!b": letters, digits`},
		{"a name with a comma", roomsFileOf(roomJSON("a,b", 1)), `name "a,b": letters, digits`},
		{"an empty name", roomsFileOf(roomJSON("", 1)), "room 1: identity: name is empty"},
		{"the name self", roomsFileOf(roomJSON("Self", 1)), `the name "self" is reserved`},
		{"a name with an escape", roomsFileOf(`{"name":"a\u001bb","members":[` + one + `]}`), `name "a\x1bb"`},
		{"the second room's name bad", roomsFileOf(roomJSON("ok", 1), roomJSON("-x", 1)), "room 2: identity:"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s := newStore(t)
			if err := os.WriteFile(s.RoomsPath(), []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			rooms, err := s.Rooms()
			refused := tc.want != ""
			switch {
			case !refused && err != nil:
				t.Fatalf("refused: %v", err)
			case !refused:
				// Read, and written back by SaveRooms to a file that reads
				// as the same rooms.
				if err := s.SaveRooms(rooms); err != nil {
					t.Fatalf("SaveRooms of what Rooms read: %v", err)
				}
				again, err := s.Rooms()
				if err != nil || len(again) != len(rooms) {
					t.Fatalf("read back: %d rooms, %v; want %d", len(again), err, len(rooms))
				}
				return
			case err == nil:
				t.Fatalf("read %d rooms; want a refusal", len(rooms))
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused with %q; want %q", err, tc.want)
			}
			// A file that does not read or breaks a rule is damaged, for a
			// person to look at; one a later auu wrote is not.
			if later := strings.Contains(tc.want, "is version"); errors.Is(err, ErrDamaged) == later {
				t.Fatalf("refused with %v; damaged %v, want %v", err, errors.Is(err, ErrDamaged), !later)
			}
			if !strings.Contains(tc.want, "is version") && !strings.Contains(err.Error(),
				"fix it by hand, or move it aside and make the rooms again with auu room create") {
				t.Fatalf("the refusal does not say what to do: %v", err)
			}
			if !strings.Contains(err.Error(), s.RoomsPath()) {
				t.Fatalf("the refusal does not name the file: %v", err)
			}
			if strings.ContainsRune(err.Error(), 0x1b) {
				t.Fatalf("the refusal carries an escape byte: %q", err)
			}
			if got, _ := os.ReadFile(s.RoomsPath()); !bytes.Equal(got, []byte(tc.file)) {
				t.Fatal("the file was changed by a read that refused it")
			}
		})
	}

	// No file is no rooms, and no error.
	if rooms, err := newStore(t).Rooms(); err != nil || rooms != nil {
		t.Fatalf("no file: %v, %v", rooms, err)
	}

	// SaveRooms holds what it writes to the same rules, before it writes.
	member := func(n int) []RoomMember {
		out := make([]RoomMember, n)
		for i := range out {
			out[i] = RoomMember{FP: roomFP(i)}
		}
		return out
	}
	rooms := func(n int) []Room {
		out := make([]Room, n)
		for i := range out {
			out[i] = Room{Name: fmt.Sprintf("r%d", i), Members: member(1)}
		}
		return out
	}
	for _, tc := range []struct {
		what  string
		rooms []Room
		want  string
	}{
		{"32 members", []Room{{Name: "team", Members: member(MaxRoomMembers)}}, ""},
		{"33 members", []Room{{Name: "team", Members: member(MaxRoomMembers + 1)}}, "has 33 people"},
		{"256 rooms", rooms(MaxRooms), ""},
		{"257 rooms", rooms(MaxRooms + 1), "257 rooms"},
		{"a member twice", []Room{{Name: "team", Members: []RoomMember{{FP: roomFP(0)}, {FP: roomFP(0)}}}}, "twice"},
		{"a bad fingerprint", []Room{{Name: "team", Members: []RoomMember{{FP: "abc"}}}}, "fp is not a fingerprint"},
		{"a bad via", []Room{{Name: "team", Members: []RoomMember{{FP: roomFP(0), Via: "a b"}}}}, `relay name "a b"`},
		{"two names by case", []Room{{Name: "x", Members: member(1)}, {Name: "X", Members: member(1)}}, "which are the same name in any case"},
		{"an empty room", []Room{{Name: "team"}}, "has nobody in it"},
		{"a 65-byte name", []Room{{Name: strings.Repeat("a", 65), Members: member(1)}}, "65 bytes"},
		{"a!b", []Room{{Name: "a!b", Members: member(1)}}, "letters, digits"},
		{"a name like a fingerprint", []Room{{Name: "deadbeef", Members: member(1)}}, `room "deadbeef"'s name could be the start of a fingerprint`},
	} {
		t.Run("save "+tc.what, func(t *testing.T) {
			s := newStore(t)
			const before = `{"v":1,"rooms":[]}`
			if err := os.WriteFile(s.RoomsPath(), []byte(before), 0o600); err != nil {
				t.Fatal(err)
			}
			err := s.SaveRooms(tc.rooms)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				got, err := s.Rooms()
				if err != nil || len(got) != len(tc.rooms) {
					t.Fatalf("read back %d rooms, %v", len(got), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SaveRooms: %v; want %q", err, tc.want)
			}
			if got, _ := os.ReadFile(s.RoomsPath()); string(got) != before {
				t.Fatalf("a refused save wrote:\n%s", got)
			}
		})
	}
}

// A peer may not take a room's name, whichever way it is added: AddPeer
// and NameFree refuse it by EqualFold with the sentence naming the room,
// and RoomNameTaken says the room's own spelling. A room is matched by its
// whole name, so a prefix of it is free.
func TestAPeerMayNotTakeARoomsName(t *testing.T) {
	s := newStore(t)
	if err := s.SaveRooms([]Room{{Name: "Team", Members: []RoomMember{{FP: roomFP(0)}}}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Team", "team", "TEAM"} {
		p := peer(t, name)
		want := fmt.Sprintf(`peer name %q is the name of the room "Team", and a room and a peer may not share one; choose a different name`, name)
		if err := s.NameFree(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("NameFree(%s): %v", name, err)
		}
		if _, err := s.AddPeer(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("AddPeer(%s): %v", name, err)
		}
		if got := s.RoomNameTaken(name); got != "Team" {
			t.Fatalf("RoomNameTaken(%s) = %q", name, got)
		}
	}
	if peers, _ := s.Peers(); len(peers) != 0 {
		t.Fatalf("a refused name was added: %d peers", len(peers))
	}
	// A prefix and a longer name are names of their own.
	for _, name := range []string{"tea", "teams"} {
		if s.RoomNameTaken(name) != "" {
			t.Fatalf("RoomNameTaken(%s) called it a room's", name)
		}
		if _, err := s.AddPeer(peer(t, name)); err != nil {
			t.Fatalf("AddPeer(%s): %v", name, err)
		}
	}
	// A rooms file that does not read refuses the add with its own words,
	// since a name cannot be shown free of a file nobody can read.
	if err := os.WriteFile(s.RoomsPath(), []byte(`{"v":2,"rooms":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer(peer(t, "carol")); err == nil || !strings.Contains(err.Error(), "is version 2") {
		t.Fatalf("AddPeer beside an unreadable rooms file: %v", err)
	}
	if s.RoomNameTaken("carol") != "" {
		t.Fatal("RoomNameTaken took a name from a file that does not read")
	}
	if errors.Is(func() error { _, err := s.AddPeer(peer(t, "carol")); return err }(), ErrDamaged) {
		t.Fatal("a rooms file a later auu wrote was called damaged")
	}
	// A file that does not read, and one that breaks a rule, are damaged,
	// and refuse any name, one no room could have among them.
	for _, doc := range []string{`{"v":1,"rooms":[`, `{"v":1,"rooms":[{"name":"team","members":[]}]}`} {
		if err := os.WriteFile(s.RoomsPath(), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"carol", "team"} {
			_, err := s.AddPeer(peer(t, name))
			if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), s.RoomsPath()) {
				t.Fatalf("AddPeer(%s) beside %s: %v; want the file named as damaged", name, doc, err)
			}
			if err := s.NameFree(peer(t, name)); !errors.Is(err, ErrDamaged) {
				t.Fatalf("NameFree(%s) beside %s: %v", name, doc, err)
			}
		}
	}
	if peers, _ := s.Peers(); len(peers) != 2 {
		t.Fatalf("a peer was added beside a damaged rooms file: %d peers", len(peers))
	}
}
