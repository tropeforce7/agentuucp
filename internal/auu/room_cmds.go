package auu

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A room is a saved list of recipients, kept in rooms.json in the home and
// nowhere else (D55). These are its commands. A room is a list
// of people this machine can seal to, so a member must be on the peer list
// when the room is made or added to, `self` excepted (D58); a room and a
// peer may not share a name (D56).

func cmdRoom(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "ls":
			return roomLs(args[1:])
		case "show":
			return roomShow(args[1:])
		case "create":
			return roomCreate(args[1:])
		case "add":
			return roomAdd(args[1:])
		case "rm":
			return roomRm(args[1:])
		case "delete":
			return roomDelete(args[1:])
		}
	}
	return usageErrf("usage: %s room ls [--json] | show NAME [--json] | create NAME MEMBER... | add NAME MEMBER... | rm NAME MEMBER... | delete NAME [--yes]", prog)
}

// roomMemberJSON is one member as --json gives it.
type roomMemberJSON struct {
	Fingerprint string `json:"fingerprint"`
	// Name is the peer list's name for them, "you" for this identity, and
	// empty for somebody no longer on the peer list.
	Name string `json:"name"`
	Via  string `json:"via,omitempty"`
	// Problem says what is wrong with this member: they are no longer on
	// the peer list.
	Problem string `json:"problem,omitempty"`
}

// roomJSON is one room as --json gives it.
type roomJSON struct {
	Name    string           `json:"name"`
	Members []roomMemberJSON `json:"members"`
	// Problem says what is wrong with the room as it stands: a peer now
	// has its name.
	Problem string `json:"problem,omitempty"`
}

// roomView is what this machine makes of a room: each member by the peer
// list's name, and what is wrong with it as it stands.
func roomView(s *store.Store, self *identity.Public, r store.Room) roomJSON {
	out := roomJSON{Name: r.Name, Members: make([]roomMemberJSON, 0, len(r.Members))}
	for _, m := range r.Members {
		mj := roomMemberJSON{Fingerprint: m.FP, Via: m.Via}
		switch {
		case self != nil && m.FP == self.Fingerprint():
			mj.Name = "you"
		case s.IsAuthorized(m.FP):
			mj.Name = s.PeerName(m.FP)
		default:
			mj.Problem = "not on your peer list"
		}
		out.Members = append(out.Members, mj)
	}
	// A peer of the same name in any case, found as room create finds
	// one: Resolve matches a name exactly before a prefix, and its prefix
	// pass would call a name shared with two peers ambiguous.
	peers, _ := s.Peers()
	for _, p := range peers {
		if strings.EqualFold(p.Name, r.Name) {
			out.Problem = fmt.Sprintf("a peer is named %s too", p.Name)
			break
		}
	}
	return out
}

// memberLine is one member as a person reads it, every name escaped.
func memberLine(m roomMemberJSON) string {
	name := identity.Printable(m.Name)
	if m.Name == "" {
		name = "(" + m.Problem + ")"
	}
	line := fmt.Sprintf("  %-20s %s", name, m.Fingerprint[:identity.ShortIDLen])
	if m.Via != "" {
		line += "  by " + identity.Printable(m.Via)
	}
	return line
}

func roomLs(args []string) error {
	fs := newFlagSet("room ls")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("usage: %s room ls [--json]", prog)
	}
	s, self, rooms, err := openRooms()
	if err != nil {
		return err
	}
	views := make([]roomJSON, 0, len(rooms))
	for _, r := range rooms {
		views = append(views, roomView(s, self, r))
	}
	if *asJSON {
		return printJSON(struct {
			Rooms []roomJSON `json:"rooms"`
		}{views})
	}
	if len(views) == 0 {
		fmt.Printf("no rooms; make one with %s room create NAME MEMBER...\n", prog)
		return nil
	}
	for _, v := range views {
		line := fmt.Sprintf("%-20s %d member(s)", identity.Printable(v.Name), len(v.Members))
		if n := offList(v); n > 0 {
			line += fmt.Sprintf("; %d not on your peer list", n)
		}
		if v.Problem != "" {
			line += "; " + identity.PrintableText(v.Problem)
		}
		fmt.Println(line)
	}
	return nil
}

func offList(v roomJSON) int {
	n := 0
	for _, m := range v.Members {
		if m.Problem != "" {
			n++
		}
	}
	return n
}

func roomShow(args []string) error {
	fs := newFlagSet("room show")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s room show NAME [--json]", prog)
	}
	s, self, rooms, err := openRooms()
	if err != nil {
		return err
	}
	r, err := roomOf(rooms, positional[0])
	if err != nil {
		return err
	}
	v := roomView(s, self, *r)
	if *asJSON {
		return printJSON(v)
	}
	fmt.Printf("%s, %d member(s)\n", identity.Printable(v.Name), len(v.Members))
	for _, m := range v.Members {
		fmt.Println(memberLine(m))
	}
	if n := offList(v); n > 0 {
		fmt.Printf("%d not on your peer list: remove each with %s room rm, or add them again with %s peers add\n",
			n, prog, prog)
	}
	if v.Problem != "" {
		fmt.Printf("%s: one name means one thing, so one of the two must go: %s room delete, or %s peers rm\n",
			identity.PrintableText(v.Problem), prog, prog)
	}
	return nil
}

// openRooms opens the home, this identity and the rooms. The peer list is
// read first, so that one which does not read is said as it is: every
// member would otherwise look like somebody not on it, and the remedy
// printed would be to remove them all.
func openRooms() (*store.Store, *identity.Public, []store.Room, error) {
	s, err := openStore()
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := s.Peers(); err != nil {
		return nil, nil, nil, err
	}
	self, err := s.Self()
	if err != nil {
		return nil, nil, nil, err
	}
	rooms, err := s.Rooms()
	if err != nil {
		return nil, nil, nil, err
	}
	return s, self, rooms, nil
}

// roomOf is the room a typed name is, by its exact name and no prefix.
func roomOf(rooms []store.Room, name string) (*store.Room, error) {
	if r := store.RoomNamed(rooms, name); r != nil {
		return r, nil
	}
	return nil, usageErrf("there is no room %s; %s room ls lists them", identity.Printable(name), prog)
}

// roomMember is one MEMBER as typed: self, a peer by name, fingerprint or
// short id, or an address RELAY!...!NAME whose relays become the member's
// via. Anybody but self must be on the peer list: a room is a list of
// people this machine can seal to (D51).
func roomMember(s *store.Store, self *identity.Public, arg string) (store.RoomMember, error) {
	if arg == "self" {
		return store.RoomMember{FP: self.Fingerprint()}, nil
	}
	path, peer, err := address(arg, "")
	if err != nil {
		return store.RoomMember{}, err
	}
	// Resolve finds this identity and the peer list's people and nobody
	// else, so what it finds is somebody this machine can seal to.
	pub, err := s.Resolve(peer)
	var ambiguous *store.ErrAmbiguous
	if errors.As(err, &ambiguous) {
		return store.RoomMember{}, usageErrf("%v", err)
	}
	if err != nil {
		return store.RoomMember{}, usageErrf("%s is not on your peer list, and a room holds only people this machine can seal to; "+
			"add them with %s peers add first (%v)", identity.Printable(peer), prog, err)
	}
	if pub.Fingerprint() == self.Fingerprint() {
		if len(path) > 0 {
			return store.RoomMember{}, usageErrf("%s names relays to reach yourself by; a copy to yourself goes nowhere, so name self alone",
				identity.Printable(arg))
		}
		return store.RoomMember{FP: self.Fingerprint()}, nil
	}
	return store.RoomMember{FP: pub.Fingerprint(), Via: strings.Join(path, "!")}, nil
}

// addMembers adds what is typed to a room's members, refusing one named
// twice, here or already in it, and a room over its ceiling.
func addMembers(s *store.Store, self *identity.Public, r *store.Room, args []string) error {
	for _, arg := range args {
		m, err := roomMember(s, self, arg)
		if err != nil {
			return err
		}
		for _, have := range r.Members {
			if have.FP == m.FP {
				return usageErrf("%s is already in %s; name each once", identity.Printable(arg), identity.Printable(r.Name))
			}
		}
		r.Members = append(r.Members, m)
	}
	if len(r.Members) > store.MaxRoomMembers {
		return usageErrf("%s would have %d members, and a room holds at most %d", identity.Printable(r.Name), len(r.Members), store.MaxRoomMembers)
	}
	return nil
}

func roomCreate(args []string) error {
	fs := newFlagSet("room create")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return usageErrf("usage: %s room create NAME MEMBER...", prog)
	}
	s, self, rooms, err := openRooms()
	if err != nil {
		return err
	}
	name := positional[0]
	if err := identity.ValidName(name); err != nil {
		return usageErrf("%v", err)
	}
	// A name --to could read as the start of a peer's fingerprint would
	// send to the room where the person meant one peer.
	if store.LooksLikeFingerprint(name) {
		return usageErrf("%s could be the start of a fingerprint, which names a peer; give the room a name with a letter past f in it",
			identity.Printable(name))
	}
	if r := store.RoomNamed(rooms, name); r != nil {
		return usageErrf("there is a room %s already; %s room add NAME MEMBER adds to it", identity.Printable(r.Name), prog)
	}
	// One name means one thing: a room may not take a peer's (D56).
	peers, err := s.Peers()
	if err != nil {
		return err
	}
	for _, p := range peers {
		if strings.EqualFold(p.Name, name) {
			return usageErrf("%s is your peer %s's name, and a room and a peer may not share one; choose another",
				identity.Printable(name), p.Short())
		}
	}
	if len(rooms) >= store.MaxRooms {
		return usageErrf("this home has %d rooms, the most it holds; %s room delete one first", len(rooms), prog)
	}
	r := store.Room{Name: name}
	if err := addMembers(s, self, &r, positional[1:]); err != nil {
		return err
	}
	if err := s.SaveRooms(append(rooms, r)); err != nil {
		return err
	}
	fmt.Printf("room %s made with %d member(s)\n", identity.Printable(name), len(r.Members))
	return nil
}

func roomAdd(args []string) error {
	fs := newFlagSet("room add")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return usageErrf("usage: %s room add NAME MEMBER...", prog)
	}
	s, self, rooms, err := openRooms()
	if err != nil {
		return err
	}
	r, err := roomOf(rooms, positional[0])
	if err != nil {
		return err
	}
	before := len(r.Members)
	if err := addMembers(s, self, r, positional[1:]); err != nil {
		return err
	}
	if err := s.SaveRooms(rooms); err != nil {
		return err
	}
	fmt.Printf("%d added to %s, which has %d member(s)\n", len(r.Members)-before, identity.Printable(r.Name), len(r.Members))
	return nil
}

// memberIn is the member of a room a typed MEMBER names, found in
// Resolve's order: self, a peer by fingerprint, by name, or by a unique
// prefix of either, as anywhere else; and only when the peer list names
// nobody by it, a member's fingerprint by eight or more characters from
// its start, which is how a member no longer on the peer list is named.
// The peer list first, so that a peer whose name is the start of another
// member's fingerprint names that peer and not the other.
func memberIn(s *store.Store, self *identity.Public, r *store.Room, arg string) (int, error) {
	notIn := usageErrf("%s is not in %s; %s room show %s lists who is", identity.Printable(arg), identity.Printable(r.Name), prog, identity.Printable(r.Name))
	_, peer := store.SplitAddress(arg)
	pub, err := s.Resolve(peer)
	if err == nil {
		for i, m := range r.Members {
			if m.FP == pub.Fingerprint() {
				return i, nil
			}
		}
		// Somebody the peer list names, who is not in the room: said by
		// who it is, since the same word may also be the start of a
		// member's fingerprint, which then needs more of it.
		name := identity.Printable(pub.Name)
		if pub.Fingerprint() == self.Fingerprint() {
			name = "you"
		}
		return -1, usageErrf("%s names %s (%s), who is not in %s; %s room show %s lists who is, by a short id that names them alone",
			identity.Printable(arg), name, pub.Short(), identity.Printable(r.Name), prog, identity.Printable(r.Name))
	}
	var ambiguous *store.ErrAmbiguous
	if errors.As(err, &ambiguous) {
		return -1, usageErrf("%v", err)
	}
	lower := strings.ToLower(peer)
	matches, count := -1, 0
	if len(lower) >= 8 {
		for i, m := range r.Members {
			if strings.HasPrefix(m.FP, lower) {
				matches, count = i, count+1
			}
		}
	}
	switch {
	case count == 1:
		return matches, nil
	case count > 1:
		return -1, usageErrf("%s is the start of more than one member's fingerprint in %s; give more of it",
			identity.Printable(arg), identity.Printable(r.Name))
	}
	return -1, notIn
}

func roomRm(args []string) error {
	fs := newFlagSet("room rm")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return usageErrf("usage: %s room rm NAME MEMBER...", prog)
	}
	s, self, rooms, err := openRooms()
	if err != nil {
		return err
	}
	r, err := roomOf(rooms, positional[0])
	if err != nil {
		return err
	}
	// Each one removed is said by the peer list's name and short id, so
	// the person sees who went.
	// Every member is found in the room as it was, before anything goes,
	// so one named twice is said to be.
	var removed []string
	going := map[string]string{}
	for _, arg := range positional[1:] {
		i, err := memberIn(s, self, r, arg)
		if err != nil {
			return err
		}
		fp := r.Members[i].FP
		if first, twice := going[fp]; twice {
			return usageErrf("%s and %s are the same member of %s; name each once", identity.Printable(first), identity.Printable(arg), identity.Printable(r.Name))
		}
		going[fp] = arg
		removed = append(removed, memberLine(roomView(s, self, store.Room{Name: r.Name, Members: r.Members[i : i+1]}).Members[0]))
	}
	kept := r.Members[:0:0]
	for _, m := range r.Members {
		if _, ok := going[m.FP]; !ok {
			kept = append(kept, m)
		}
	}
	r.Members = kept
	for _, line := range removed {
		fmt.Printf("removed%s\n", line)
	}
	name := r.Name
	if len(r.Members) == 0 {
		// An empty room cannot be kept, so removing the last member
		// deletes the room, and says so.
		rooms = withoutRoom(rooms, name)
		if err := s.SaveRooms(rooms); err != nil {
			return err
		}
		fmt.Printf("%s had nobody left and is deleted\n", identity.Printable(name))
		return nil
	}
	if err := s.SaveRooms(rooms); err != nil {
		return err
	}
	fmt.Printf("%d removed from %s, which has %d member(s)\n", len(positional)-1, identity.Printable(name), len(r.Members))
	return nil
}

func withoutRoom(rooms []store.Room, name string) []store.Room {
	out := rooms[:0:0]
	for _, r := range rooms {
		if !strings.EqualFold(r.Name, name) {
			out = append(out, r)
		}
	}
	return out
}

func roomDelete(args []string) error {
	fs := newFlagSet("room delete")
	yes := fs.Bool("yes", false, "delete without asking")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s room delete NAME [--yes]", prog)
	}
	s, _, rooms, err := openRooms()
	if err != nil {
		return err
	}
	r, err := roomOf(rooms, positional[0])
	if err != nil {
		return err
	}
	name, n := r.Name, len(r.Members)
	// It names what goes and asks; --yes skips the question and nothing else.
	if !*yes && !confirm(fmt.Sprintf("delete the room %s and its list of %d member(s)? The peers stay on your peer list", identity.Printable(name), n)) {
		fmt.Fprintf(os.Stderr, "nothing was deleted; %s is kept\n", identity.Printable(name))
		return &exitError{code: exitUsage, err: errors.New("cancelled")}
	}
	if err := s.SaveRooms(withoutRoom(rooms, name)); err != nil {
		return err
	}
	fmt.Printf("room %s deleted\n", identity.Printable(name))
	return nil
}
