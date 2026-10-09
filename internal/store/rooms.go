package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// rooms.json is the saved lists of recipients this home keeps by name: a
// room is a name and the people in it, each by fingerprint and, for one on
// another relay, the relays to go by. It is this home's alone. Nothing of
// it is posted, so a relay never learns that a room exists, and a second
// machine of the same identity has its own, as it has its own peer list.
//
// One file for every room, so that a room's name is never a path. It is
// read when a command needs it, never at Open, and held to every rule at
// the read. A file a hand wrote with a member no longer on the peer list, or
// a room's name the peer list now has too, is not broken: the list is the
// person's. Those are said where the room is shown.
const roomsFile = "rooms.json"

// MaxRooms is the most rooms the file holds (D55).
const MaxRooms = 256

// MaxRoomMembers is the most people a room holds: the protocol's ceiling on
// a message to several (D55).
const MaxRoomMembers = relayapi.MaxRecipients

// RoomMember is one person in a room: their fingerprint, the peer list's own
// key, and the relays to go by to reach them, nearest first, joined by "!",
// empty for somebody on the relay a send goes through.
type RoomMember struct {
	FP  string `json:"fp"`
	Via string `json:"via,omitempty"`
}

// Room is one saved list of recipients.
type Room struct {
	Name    string       `json:"name"`
	Members []RoomMember `json:"members"`
}

// roomsDoc is the file: a version, and the rooms in the order the person
// made them, which is the order they are listed.
type roomsDoc struct {
	V     int    `json:"v"`
	Rooms []Room `json:"rooms"`
}

// RoomsPath is where the rooms are kept.
func (s *Store) RoomsPath() string { return s.path(roomsFile) }

// Rooms reads every room, in the file's order: none when there is no file.
// It is read strictly, by wire.Decode as every strict reader in the tree
// is, and held to every rule at the read.
func (s *Store) Rooms() ([]Room, error) {
	data, err := regular.ReadFile(s.path(roomsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// A file that does not read is damaged, as every other file in the
	// home is said to be: a person has to look at it, and until they do,
	// no peer can be added under a name it might hold.
	const advice = "fix it by hand, or move it aside and make the rooms again with auu room create"
	var doc roomsDoc
	if err := wire.Decode(data, &doc); err != nil {
		return nil, damaged(s.path(roomsFile), "does not read", err, advice)
	}
	if doc.V != 1 {
		return nil, fmt.Errorf("%s is version %d, and this auu reads version 1; a later auu wrote it", s.path(roomsFile), doc.V)
	}
	if err := checkRooms(doc.Rooms); err != nil {
		return nil, damaged(s.path(roomsFile), "breaks a rule", err, advice)
	}
	return doc.Rooms, nil
}

// SaveRooms writes every room, held to the rules first, so that nothing
// this program writes is a file it would refuse to read.
func (s *Store) SaveRooms(rooms []Room) error {
	if err := checkRooms(rooms); err != nil {
		return err
	}
	if len(rooms) == 0 {
		rooms = []Room{}
	}
	data, err := json.MarshalIndent(roomsDoc{V: 1, Rooms: rooms}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(roomsFile), append(data, '\n'), fileMode)
}

// checkRooms holds a list of rooms to the rules: at most MaxRooms; each name
// a name by identity.ValidName and no two alike by EqualFold; each room one
// to MaxRoomMembers people; each a fingerprint, once in its room; each via
// relays' names by the address rule.
func checkRooms(rooms []Room) error {
	if len(rooms) > MaxRooms {
		return fmt.Errorf("%d rooms, and a home holds at most %d", len(rooms), MaxRooms)
	}
	for i, r := range rooms {
		if err := identity.ValidName(r.Name); err != nil {
			return fmt.Errorf("room %d: %w", i+1, err)
		}
		if LooksLikeFingerprint(r.Name) {
			return fmt.Errorf("room %q's name could be the start of a fingerprint, which names a peer", r.Name)
		}
		for _, earlier := range rooms[:i] {
			if strings.EqualFold(earlier.Name, r.Name) {
				return fmt.Errorf("two rooms are named %q and %q, which are the same name in any case", earlier.Name, r.Name)
			}
		}
		if len(r.Members) == 0 {
			return fmt.Errorf("room %q has nobody in it", r.Name)
		}
		if len(r.Members) > MaxRoomMembers {
			return fmt.Errorf("room %q has %d people, and a room holds at most %d", r.Name, len(r.Members), MaxRoomMembers)
		}
		seen := map[string]bool{}
		for _, m := range r.Members {
			if !identity.ValidFingerprint(m.FP) {
				return fmt.Errorf("room %q has a member whose fp is not a fingerprint", r.Name)
			}
			if seen[m.FP] {
				return fmt.Errorf("room %q has %s twice", r.Name, m.FP[:identity.ShortIDLen])
			}
			seen[m.FP] = true
			if m.Via != "" {
				if err := CheckAddress(strings.Split(m.Via, "!"), nil, relayapi.MaxHops); err != nil {
					return fmt.Errorf("room %q's member %s: %w", r.Name, m.FP[:identity.ShortIDLen], err)
				}
			}
		}
	}
	return nil
}

// LooksLikeFingerprint is a name a room may not take: eight or more hex
// characters, in either case, which a send's --to could read as the start
// of a peer's fingerprint, as Resolve matches one whatever its case.
func LooksLikeFingerprint(name string) bool {
	if len(name) < 8 {
		return false
	}
	for _, c := range name {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// RoomNamed is the room a name is, by EqualFold and nothing looser: a room
// is never reached by a prefix, so that a prefix still reaches the peer it
// always reached. Nil when no room has the name.
func RoomNamed(rooms []Room, name string) *Room {
	for i := range rooms {
		if strings.EqualFold(rooms[i].Name, name) {
			return &rooms[i]
		}
	}
	return nil
}

// roomNameTaken is the room whose name a peer's name would be, so that one
// name means one thing: a room and a peer may not share one (D56). A rooms
// file that does not read is said as it is, since a name cannot be shown
// free of a file nobody can read.
func (s *Store) roomNameTaken(name string) error {
	if name == "" {
		return nil
	}
	rooms, err := s.Rooms()
	if err != nil {
		return err
	}
	if r := RoomNamed(rooms, name); r != nil {
		return fmt.Errorf("peer name %q is the name of the room %q, and a room and a peer may not share one; choose a different name",
			name, r.Name)
	}
	return nil
}

// RoomNameTaken is the name of the room a name is, as the file spells it,
// or empty, for a command that offers a name it would otherwise suggest. A
// rooms file that does not read takes no name here; adding the peer says
// so.
func (s *Store) RoomNameTaken(name string) string {
	rooms, err := s.Rooms()
	if err != nil {
		return ""
	}
	if r := RoomNamed(rooms, name); r != nil {
		return r.Name
	}
	return ""
}
