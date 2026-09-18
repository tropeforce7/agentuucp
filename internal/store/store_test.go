package store

import (
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
		t.Fatal("listing is not in received order")
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
	if err := s.Save(Inbox, &Stored{Inner: &envelope.Inner{ID: id}}); err != nil {
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
// and the stamp only breaks a tie.
func TestAThreadIsOrderedByArrivalNotTheSendersClock(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	fromTheFuture := stored("00000000000000000000000000000001", now.Add(-time.Hour))
	fromTheFuture.Inner.Time = now.AddDate(1, 0, 0)
	fromTheFuture.RelayID = 1
	honest := stored("00000000000000000000000000000002", now)
	honest.Inner.Time = now
	honest.RelayID = 2
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
