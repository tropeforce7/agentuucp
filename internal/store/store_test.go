package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func peer(t *testing.T, name string) *identity.Public {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id.Public()
}

func TestIdentityRoundTrip(t *testing.T) {
	s := newStore(t)
	if s.HasIdentity() {
		t.Fatal("fresh store claims an identity")
	}
	if _, err := s.Identity(); err == nil {
		t.Fatal("expected ErrNoIdentity")
	}
	id, _ := identity.Generate("ada")
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if !s.HasIdentity() {
		t.Fatal("identity not detected after save")
	}
	loaded, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint() != id.Fingerprint() || loaded.Name != "ada" {
		t.Fatal("identity changed across save and load")
	}
}

func TestConfigRoundTrip(t *testing.T) {
	s := newStore(t)
	got, err := s.Config()
	if err != nil || got.Name != "" || got.DefaultRelay != "" {
		t.Fatalf("expected empty config, got %+v %v", got, err)
	}
	if err := s.SaveConfig(Config{DefaultRelay: "work", Name: "ada"}); err != nil {
		t.Fatal(err)
	}
	got, err = s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultRelay != "work" || got.Name != "ada" {
		t.Fatalf("config round trip: %+v", got)
	}
}

func TestAddPeerDedupeAndConflicts(t *testing.T) {
	s := newStore(t)
	alice := peer(t, "alice")

	added, err := s.AddPeer(alice)
	if err != nil || !added {
		t.Fatalf("first add: %v %v", added, err)
	}
	added, err = s.AddPeer(alice)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("duplicate peer was added twice")
	}
	peers, err := s.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	// A different key claiming a name already in use is refused, so a peer
	// cannot be silently impersonated by name.
	impostor := peer(t, "alice")
	if _, err := s.AddPeer(impostor); err == nil {
		t.Fatal("accepted a second key under an existing peer name")
	}
}

// CheckPeer refuses what AddPeer refuses, in the same words, and writes
// nothing: the store's own key, a name the export line's rule refuses, a
// name another peer's folds equal to, a room's name. A key already held
// and a fresh one are not refused, and checking either writes nothing.
func TestCheckPeerRefusesWhatAddPeerRefusesWithoutWriting(t *testing.T) {
	s := newStore(t)
	self, err := identity.Generate("me")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(self); err != nil {
		t.Fatal(err)
	}
	alice := peer(t, "alice")
	if _, err := s.AddPeer(alice); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRooms([]Room{{Name: "Team", Members: []RoomMember{{FP: roomFP(0)}}}}); err != nil {
		t.Fatal(err)
	}
	file := s.path(peersFile)
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func(what string) {
		t.Helper()
		after, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Fatalf("CheckPeer of %s wrote the peers file:\n%s", what, after)
		}
	}

	invalid := peer(t, "x")
	invalid.Name = "-bad name"
	for _, tc := range []struct {
		what string
		pub  *identity.Public
	}{
		{"its own key", self.Public()},
		{"an invalid name", invalid},
		{"a name folding equal to a peer's", peer(t, "Alice")},
		{"a room's name", peer(t, "team")},
	} {
		checked := s.CheckPeer(tc.pub)
		unchanged(tc.what)
		if checked == nil {
			t.Fatalf("CheckPeer took %s", tc.what)
		}
		_, added := s.AddPeer(tc.pub)
		if added == nil || added.Error() != checked.Error() {
			t.Fatalf("for %s CheckPeer said %q and AddPeer %v", tc.what, checked, added)
		}
		unchanged(tc.what)
	}

	if err := s.CheckPeer(alice); err != nil {
		t.Fatalf("CheckPeer of a held key: %v", err)
	}
	unchanged("a held key")
	if err := s.CheckPeer(peer(t, "carol")); err != nil {
		t.Fatalf("CheckPeer of a fresh key: %v", err)
	}
	unchanged("a fresh key")
}

func TestPeersFileIgnoresCommentsAndBlanks(t *testing.T) {
	s := newStore(t)
	alice := peer(t, "alice")
	if _, err := s.AddPeer(alice); err != nil {
		t.Fatal(err)
	}
	// Rewrite the file with comments and blank lines around the entry.
	existing, err := s.Peers()
	if err != nil || len(existing) != 1 {
		t.Fatal("setup failed")
	}
	content := "# my colleagues\n\n" + existing[0].ExportLine() + "\n\n# end\n"
	if err := writeFileAtomic(s.path(peersFile), []byte(content), fileMode); err != nil {
		t.Fatal(err)
	}
	peers, err := s.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Fingerprint() != alice.Fingerprint() {
		t.Fatal("comments or blank lines broke parsing")
	}
}

func TestRemovePeer(t *testing.T) {
	s := newStore(t)
	alice, bob := peer(t, "alice"), peer(t, "bob")
	s.AddPeer(alice)
	s.AddPeer(bob)

	removed, err := s.RemovePeer(alice.Fingerprint())
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	peers, _ := s.Peers()
	if len(peers) != 1 || peers[0].Fingerprint() != bob.Fingerprint() {
		t.Fatal("wrong peer removed")
	}
	removed, err = s.RemovePeer(alice.Fingerprint())
	if err != nil || removed {
		t.Fatal("removing an absent peer should report false")
	}
}

func TestResolve(t *testing.T) {
	s := newStore(t)
	alice, bob := peer(t, "alice"), peer(t, "bob")
	s.AddPeer(alice)
	s.AddPeer(bob)

	// Exact fingerprint.
	got, err := s.Resolve(alice.Fingerprint())
	if err != nil || got.Fingerprint() != alice.Fingerprint() {
		t.Fatalf("exact fingerprint: %v %v", got, err)
	}
	// Exact name.
	got, err = s.Resolve("bob")
	if err != nil || got.Fingerprint() != bob.Fingerprint() {
		t.Fatalf("exact name: %v", err)
	}
	// Fingerprint prefix.
	got, err = s.Resolve(alice.Fingerprint()[:12])
	if err != nil || got.Fingerprint() != alice.Fingerprint() {
		t.Fatalf("fingerprint prefix: %v", err)
	}
	// Name prefix, case insensitive.
	got, err = s.Resolve("AL")
	if err != nil || got.Fingerprint() != alice.Fingerprint() {
		t.Fatalf("name prefix: %v", err)
	}
	// Too short to be a fingerprint prefix, and not a name prefix.
	if _, err := s.Resolve("zz"); err == nil {
		t.Fatal("resolved a nonexistent peer")
	}
	if _, err := s.Resolve(""); err == nil {
		t.Fatal("resolved an empty query")
	}
}

func TestResolveAmbiguous(t *testing.T) {
	s := newStore(t)
	// Two peers sharing a name prefix.
	for _, name := range []string{"alice-work", "alice-home"} {
		if _, err := s.AddPeer(peer(t, name)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.Resolve("alice")
	if err == nil {
		t.Fatal("ambiguous prefix resolved")
	}
	var amb *ErrAmbiguous
	if !asAmbiguous(err, &amb) {
		t.Fatalf("expected ErrAmbiguous, got %T: %v", err, err)
	}
	if len(amb.Candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %v", amb.Candidates)
	}
	if !strings.Contains(err.Error(), "alice-work") {
		t.Fatalf("ambiguity error should name candidates: %v", err)
	}
}

func asAmbiguous(err error, target **ErrAmbiguous) bool {
	e, ok := err.(*ErrAmbiguous)
	if ok {
		*target = e
	}
	return ok
}

func TestResolveEmptyPeerList(t *testing.T) {
	s := newStore(t)
	if _, err := s.Resolve("anyone"); err == nil {
		t.Fatal("resolved against an empty peer list")
	}
}

func TestCursor(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("", "https://relay.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.CursorFor(r)
	if err != nil || n != 0 {
		t.Fatalf("fresh cursor: %d %v", n, err)
	}
	if err := s.SetCursorFor(r, 42); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CursorFor(r); n != 42 {
		t.Fatalf("cursor: %d", n)
	}
}

func stored(id string, when time.Time) *Stored {
	return &Stored{
		RelayID:  1,
		Relay:    "relay",
		Received: when,
		Inner: &envelope.Inner{
			ID:   id,
			From: strings.Repeat("a", 64),
			To:   strings.Repeat("b", 64),
			Body: message.Body{Type: message.TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Text: "hi"},
		},
	}
}

func TestSaveLoadListMove(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := stored("00000000000000000000000000000001", now.Add(-time.Hour))
	second := stored("00000000000000000000000000000002", now)
	// The listing is in the order of arrival here, which is not the order
	// of the saves below.
	first.Arrived, second.Arrived = now.Add(-time.Hour), now

	for _, m := range []*Stored{second, first} { // saved out of order on purpose
		if err := s.Save(Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(Inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Inner.ID != first.Inner.ID {
		t.Fatal("listing is not in arrival order")
	}

	loaded, err := s.Load(Inbox, first.Inner.ID)
	if err != nil || loaded.Inner.Body.Text != "hi" {
		t.Fatalf("load: %v", err)
	}

	if err := s.MarkRead(Inbox, first.Inner.ID); err != nil {
		t.Fatal(err)
	}
	loaded, _ = s.Load(Inbox, first.Inner.ID)
	if !loaded.Read {
		t.Fatal("MarkRead did not stick")
	}

	if err := s.Move(Inbox, Quarantine, second.Inner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(Inbox, second.Inner.ID); err == nil {
		t.Fatal("message still in the inbox after move")
	}
	if _, err := s.Load(Quarantine, second.Inner.ID); err != nil {
		t.Fatal("message missing from quarantine after move")
	}
}

// Message ids become file names, so a malformed one must never reach the disk.
func TestSaveRejectsMalformedID(t *testing.T) {
	s := newStore(t)
	for _, id := range []string{"", "../../etc/passwd", "short", strings.Repeat("z", 32)} {
		m := stored(id, time.Now())
		if err := s.Save(Inbox, m); err == nil {
			t.Fatalf("saved message with id %q", id)
		}
	}
}

func TestFind(t *testing.T) {
	s := newStore(t)
	m := stored("abcdef00000000000000000000000001", time.Now())
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	other := stored("abcdef00000000000000000000000002", time.Now())
	if err := s.Save(Sent, other); err != nil {
		t.Fatal(err)
	}

	box, found, err := s.Find(m.Inner.ID)
	if err != nil || box != Inbox || found.Inner.ID != m.Inner.ID {
		t.Fatalf("exact find: %v %v", box, err)
	}
	if _, _, err := s.Find("abcdef"); err == nil {
		t.Fatal("ambiguous prefix resolved")
	}
	if _, _, err := s.Find("abc"); err == nil {
		t.Fatal("accepted a prefix shorter than 4 characters")
	}
	box, found, err = s.Find("abcdef0000000000000000000000000")
	if err == nil {
		t.Fatal("expected ambiguity on a shared 31-character prefix")
	}
	if box, found, err = s.Find("abcdef00000000000000000000000002"); err != nil || box != Sent {
		t.Fatalf("find in sent: %v %v %v", box, found, err)
	}
}

func TestPeerNameAndAuthorization(t *testing.T) {
	s := newStore(t)
	alice := peer(t, "alice")
	s.AddPeer(alice)

	if got := s.PeerName(alice.Fingerprint()); got != "alice" {
		t.Fatalf("PeerName: %q", got)
	}
	if !s.IsAuthorized(alice.Fingerprint()) {
		t.Fatal("known peer reported unauthorized")
	}
	stranger := peer(t, "mallory")
	if s.IsAuthorized(stranger.Fingerprint()) {
		t.Fatal("unknown peer reported authorized")
	}
	if got := s.PeerName(stranger.Fingerprint()); got != "" {
		t.Fatalf("PeerName for stranger: %q", got)
	}
}

// A fingerprint prefix must be long enough to be unambiguous; below the
// threshold the query falls through to name matching instead. Both sides of
// that edge, one character apart.
func TestFingerprintPrefixBoundary(t *testing.T) {
	s := newStore(t)
	alice := peer(t, "alice")
	if _, err := s.AddPeer(alice); err != nil {
		t.Fatal(err)
	}

	fp := alice.Fingerprint()
	for _, n := range []int{minPrefix, minPrefix + 1, 16, 64} {
		got, err := s.Resolve(fp[:n])
		if err != nil {
			t.Fatalf("a %d character fingerprint prefix did not resolve: %v", n, err)
		}
		if got.Fingerprint() != fp {
			t.Fatalf("a %d character prefix resolved to the wrong peer", n)
		}
	}
	// One below the threshold is not treated as a fingerprint, and does not
	// match the name either, so the lookup fails.
	if _, err := s.Resolve(fp[:minPrefix-1]); err == nil {
		t.Fatalf("a %d character prefix resolved as a fingerprint", minPrefix-1)
	}
}

// A message id prefix has its own, lower, threshold: these are typed
// constantly and resolved against a local spool.
func TestMessageIDPrefixBoundary(t *testing.T) {
	const minIDPrefix = 4
	s := newStore(t)
	id := "0123456789abcdef0123456789abcdef"
	if err := s.Save(Inbox, stored(id, time.Now())); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{minIDPrefix, minIDPrefix + 1, 32} {
		if _, _, err := s.Find(id[:n]); err != nil {
			t.Fatalf("a %d character id prefix did not resolve: %v", n, err)
		}
	}
	if _, _, err := s.Find(id[:minIDPrefix-1]); err == nil {
		t.Fatalf("a %d character id prefix resolved", minIDPrefix-1)
	}
}

// A thread's order is the receiver's, not the sender's clock. The stamp
// inside a message is whatever its sender wrote, and FindThread once
// ordered by it first, so a peer who stamped a message in the year 9999
// was "latest" on the thread for as long as it was kept and every reply by
// thread went to them. Now arrival here comes first, then the relay's id,
// then the relay's received, and the stamp only breaks a tie.
func TestAThreadIsOrderedByArrivalNotTheSendersClock(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	fromTheFuture := stored("00000000000000000000000000000001", now.Add(-time.Hour))
	fromTheFuture.Inner.Time = now.AddDate(1, 0, 0)
	fromTheFuture.RelayID = 1
	fromTheFuture.Arrived = now.Add(-time.Hour)
	honest := stored("00000000000000000000000000000002", now)
	honest.Inner.Time = now
	honest.RelayID = 2
	honest.Arrived = now
	for _, m := range []*Stored{honest, fromTheFuture} {
		if err := s.Save(Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	_, latest, err := s.FindThread("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Inner.ID != honest.Inner.ID {
		t.Errorf("FindThread chose %s, stamped %s; want the one that arrived last, %s",
			latest.Inner.ID, latest.Inner.Time.Format(time.RFC3339), honest.Inner.ID)
	}
	if !LaterThan(honest, fromTheFuture) || LaterThan(fromTheFuture, honest) {
		t.Error("LaterThan does not order by arrival")
	}
	// Two that arrived in the same second are ordered by the relay's id,
	// and only two the relay numbered alike by the stamp.
	a := stored("00000000000000000000000000000003", now)
	b := stored("00000000000000000000000000000004", now)
	a.Arrived, b.Arrived = now, now
	a.RelayID, b.RelayID = 5, 6
	a.Inner.Time, b.Inner.Time = now.Add(time.Hour), now
	if !LaterThan(b, a) {
		t.Error("the relay's id does not order two that arrived in the same second")
	}
	b.RelayID = 5
	if !LaterThan(a, b) {
		t.Error("the stamp does not break a tie")
	}
}

// The file-path review at af0d96e (reviews/trace/): the provenance rule
// applied to every path the store joins, independently of the ledger.

// reviewHome makes a home two levels below a scratch directory, with a
// sibling directory outside it that no path built from the home should
// ever reach. It returns the store, the outside directory, and a file in
// it.
func reviewHome(t *testing.T) (*Store, string, string) {
	t.Helper()
	scratch := t.TempDir()
	home := filepath.Join(scratch, "home")
	s, err := Open(home)
	if err != nil {
		t.Fatalf("opening the home: %v", err)
	}
	outside := filepath.Join(scratch, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	witness := filepath.Join(outside, "witness")
	if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s, outside, witness
}

// TestRemoveRefusesAnIDThatIsNotAName: Remove joined the id onto the box
// and removed the tree at <box>/<id>.d with no rule run on the id, though
// Load refuses one that is not 32 lowercase hex characters. Its one
// caller passes an id from Load, but the store's exported edge is a
// boundary of its own: an id that walks out of the box is refused, and
// nothing outside the home is touched.
func TestRemoveRefusesAnIDThatIsNotAName(t *testing.T) {
	s, outside, witness := reviewHome(t)
	victim := filepath.Join(outside, "victim.d")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "../../outside/victim"
	err := s.Remove(Inbox, id)
	if _, statErr := os.Stat(victim); statErr != nil {
		t.Errorf("Remove(Inbox, %q) removed %s, a directory outside the home (Remove returned %v)", id, victim, err)
	}
	if err == nil || !strings.Contains(err.Error(), "not a message id") {
		t.Errorf("Remove(Inbox, %q) returned %v; expected an error saying the id is not a message id", id, err)
	}
	if _, statErr := os.Stat(witness); statErr != nil {
		t.Errorf("the witness file outside the home is gone: %v", statErr)
	}
}

// TestKeepDamagedRefusesARelayNameThatIsNotAName: KeepDamaged built
// damaged/<relay>/<id>.bin from the record's relay name with no rule run
// on the name. Every caller passes a name read back from a directory the
// store made, but the store is what makes that so, and now it checks.
func TestKeepDamagedRefusesARelayNameThatIsNotAName(t *testing.T) {
	s, outside, _ := reviewHome(t)
	relay := "../../outside"
	kept, _, err := s.KeepDamaged(DamagedRecord{
		RelayID: 7, Relay: relay, Received: time.Now(), Cause: "review",
	}, []byte("bytes"))
	if _, statErr := os.Stat(filepath.Join(outside, "7.bin")); statErr == nil {
		t.Errorf("KeepDamaged with Relay=%q wrote outside the home (kept=%v, err=%v)", relay, kept, err)
	}
	if err == nil || !strings.Contains(err.Error(), "relay name") {
		t.Errorf("KeepDamaged with Relay=%q returned %v; expected an error naming the relay-name rule", relay, err)
	}
	if _, err := s.DamagedPath(relay, 7); err == nil {
		t.Errorf("DamagedPath(%q) made a path", relay)
	}
}

// TestSetLeftBehindRefusesARelayNameThatIsNotAName: SetLeftBehind joined
// the relay name onto relays/ and wrote there with no rule run on the
// name, as SaveRelay does run one; LeftBehind read the same way.
func TestSetLeftBehindRefusesARelayNameThatIsNotAName(t *testing.T) {
	s, outside, _ := reviewHome(t)
	relay := "../../outside"
	err := s.SetLeftBehind(relay, []LeftEntry{{RelayID: 1, ID: strings.Repeat("a", 32)}})
	if _, statErr := os.Stat(filepath.Join(outside, leftBehindFile)); statErr == nil {
		t.Errorf("SetLeftBehind(%q) wrote outside the home (err=%v)", relay, err)
	}
	if err == nil || !strings.Contains(err.Error(), "relay name") {
		t.Errorf("SetLeftBehind(%q) returned %v; expected an error naming the relay-name rule", relay, err)
	}
	if _, err := s.LeftBehind(relay); err == nil {
		t.Errorf("LeftBehind(%q) read a path", relay)
	}
}

// withDeadline runs fn and reports whether it returned within d.
func withDeadline(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestADefaultRelayNameIsAlwaysFound: defaultRelayName tried the URL's
// host as it was, then host-port, host-2, host-3, ... until one was
// neither taken nor invalid, and a host the rule refuses — an IPv6
// literal begins with a colon, a hostname can be longer than a name may
// be, a host of dots has no letter to begin with — was refused with every
// suffix, so the loop never returned: 'auu relay add', an enrolment
// token naming such a relay and Open of a legacy home that did spun for
// ever. Now the base is made valid first, and the loop has a ceiling.
func TestADefaultRelayNameIsAlwaysFound(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://[2001:db8::1]:8443", "2001db81"},
		{"https://[::1]:8443", "1"},
		{"https://" + strings.Repeat("a", 70) + ".example", strings.Repeat("a", 59)},
		{"https://relay.example.com", "relay.example.com"},
		{"https://relay.example.com:8443", "relay.example.com"},
	} {
		s, _, _ := reviewHome(t)
		var r *Relay
		var err error
		if !withDeadline(3*time.Second, func() { r, err = s.AddRelay("", tc.url) }) {
			t.Fatalf("AddRelay(\"\", %q) did not return within 3s", tc.url)
		}
		if err != nil {
			t.Fatalf("AddRelay(\"\", %q): %v", tc.url, err)
		}
		if r.Name != tc.want {
			t.Errorf("AddRelay(\"\", %q) named the relay %q, want %q", tc.url, r.Name, tc.want)
		}
		if err := ValidRelayName(r.Name); err != nil {
			t.Errorf("the derived name %q is not valid: %v", r.Name, err)
		}
	}
	// Bases the rule refuses outright: dots alone, a control character,
	// the reserved word.
	for _, host := range []string{"...", "\x01", "self"} {
		got, err := defaultRelayName("https://"+host, nil)
		if err != nil || got != "relay" {
			t.Errorf("defaultRelayName for host %q: %q, %v; want relay", host, got, err)
		}
	}
	// The second relay on a host gets the port, the third a number, and
	// past the ceiling an error rather than a name.
	taken := []*Relay{{Name: "relay.example.com"}}
	if got, _ := defaultRelayName("https://relay.example.com:8443", taken); got != "relay.example.com-8443" {
		t.Errorf("second on the host: %q", got)
	}
	for n := 2; n <= 1000; n++ {
		taken = append(taken, &Relay{Name: fmt.Sprintf("relay.example.com-%d", n)})
	}
	taken = append(taken, &Relay{Name: "relay.example.com-8443"})
	if got, err := defaultRelayName("https://relay.example.com:8443", taken); err == nil || !strings.Contains(err.Error(), "--name") {
		t.Errorf("past the ceiling: %q, %v; want an error naming --name", got, err)
	}
}
