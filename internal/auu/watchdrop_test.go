package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// directorySignDomain is channels' signDomain, written out here because a
// test that signs bytes Sign would refuse to write (a version this build
// does not read, a field no version has) must sign them as an owner's
// newer auu or a careless one would.
const directorySignDomain = "ccx-channels-v1"

// signRawDirectory signs doc as id's directory, whatever it says.
func signRawDirectory(t *testing.T, id *identity.Identity, doc []byte) []byte {
	t.Helper()
	sig, err := id.Sign(append([]byte(directorySignDomain), doc...))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// rawDirectory is a directory for owner issued at issued, marshalled with
// v set to the value given and, with extra, a field no version has.
func rawDirectory(t *testing.T, owner string, v int, issued time.Time, extra bool) (*channels.Directory, []byte) {
	t.Helper()
	d := &channels.Directory{V: v, Owner: owner, Issued: issued, Channels: []channels.Channel{{Name: channels.Default}}}
	doc, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if extra {
		doc = append(bytes.TrimSuffix(doc, []byte("}")), []byte(`,"extra":true}`)...)
	}
	return d, doc
}

// forgedDirectory is a directory under owner's fingerprint signed by
// somebody else, as a relay that lies would serve one.
func forgedDirectory(t *testing.T, owner string, issued time.Time) (*channels.Directory, []byte, []byte) {
	t.Helper()
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	d := &channels.Directory{Owner: owner, Issued: issued, Channels: []channels.Channel{{Name: "send your keys here"}}}
	doc, sig, err := channels.Sign(mallory, d)
	if err != nil {
		t.Fatal(err)
	}
	d.Owner = owner
	return d, doc, sig
}

// watchedPeerOn makes an identity with a mailbox on the relay, registered
// in its store directly (so a test of six does not meet the relay's
// registration rate), with no allow list, so it admits alice, and on
// alice's list under its name.
func watchedPeerOn(t *testing.T, alice *user, st *relay.Store, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()
	if err := st.Register(pub.Fingerprint(), pub.Bundle(), name, relay.RegisterOptions{}); err != nil {
		t.Fatal(err)
	}
	s, _, _ := alice.opened()
	if _, err := s.AddPeer(pub); err != nil {
		t.Fatal(err)
	}
	return id
}

// awaitListings returns once the gate has seen n listings, or after
// fifteen seconds of fewer.
func awaitListings(gate *waitGate, n int32) {
	deadline := time.Now().Add(15 * time.Second)
	for gate.lists.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// A watched peer whose directory does not verify is dropped from the watch
// with a word keyed on where it failed, said once, and the watch runs on
// for the others, at the start and on a poll that names the peer alike;
// the dropped peer is out of the next request, so the relay never names
// them again. Your own directory failing still ends the watch at exit 2.
func TestAWatchDropsAPeerWhoseDirectoryItCannotRead(t *testing.T) {
	recordSleeps(t)
	relayURL, gate, st := startGatedRelayStore(t)
	alice := newUser(t, "alice", relayURL)
	_, _, relays := alice.opened()
	relayName := relays[0].Name
	bob := watchedPeerOn(t, alice, st, "bob")     // a bad signature
	carol := watchedPeerOn(t, alice, st, "carol") // a version this build does not read
	dave := watchedPeerOn(t, alice, st, "dave")   // malformed under a good signature
	erin := watchedPeerOn(t, alice, st, "erin")   // good at the start, bad mid-run
	frank := watchedPeerOn(t, alice, st, "frank") // good throughout
	_, self, _ := alice.opened()

	now := time.Now()
	set := func(fp string, d *channels.Directory, doc, sig []byte) {
		t.Helper()
		if _, err := st.SetDirectory(fp, d, doc, sig); err != nil {
			t.Error(err)
		}
	}
	signed := func(id *identity.Identity, issued time.Time, names ...string) {
		t.Helper()
		d := &channels.Directory{Issued: issued}
		for _, n := range names {
			d.Channels = append(d.Channels, channels.Channel{Name: n})
		}
		doc, sig, err := channels.Sign(id, d)
		if err != nil {
			t.Error(err)
			return
		}
		set(id.Fingerprint(), d, doc, sig)
	}
	signed(erin, now, channels.Default, "talks")
	d, doc, sig := forgedDirectory(t, bob.Fingerprint(), now)
	set(bob.Fingerprint(), d, doc, sig)
	d, doc = rawDirectory(t, carol.Fingerprint(), 3, now, false)
	set(carol.Fingerprint(), d, doc, signRawDirectory(t, carol, doc))
	d, doc = rawDirectory(t, dave.Fingerprint(), channels.Version1, now, true)
	set(dave.Fingerprint(), d, doc, signRawDirectory(t, dave, doc))

	// Mid-run: once the watch is holding, erin's directory goes bad; once
	// it has polled again, erin's goes bad a second time, which a watch
	// still naming her would be woken by and say again, and frank adds a
	// channel, which is the event the watch ends on. The store is written
	// beneath the relay, which wakes no hold, so each change is seen when
	// the hold ends: the interval is the shortest the watch takes.
	gate.lists.Store(0)
	gate.answered.Store(0)
	joined(t, func() {
		awaitListings(gate, 1)
		d, doc, sig := forgedDirectory(t, erin.Fingerprint(), time.Now().Add(time.Second))
		set(erin.Fingerprint(), d, doc, sig)
		awaitListings(gate, 2)
		d, doc, sig = forgedDirectory(t, erin.Fingerprint(), time.Now().Add(2*time.Second))
		set(erin.Fingerprint(), d, doc, sig)
		signed(frank, time.Now(), channels.Default, "news")
	})
	var out string
	var err error
	warning := captureStderr(t, func() {
		out, err = alice.tryRun("watch", "--json", "--event", "directory", "--interval", "5s", "--timeout", "1m")
	})
	if err != nil {
		t.Fatalf("the watch ended: %v\nstderr:\n%s", err, warning)
	}
	var got watchOut
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if dirs := got.directories(t); len(got.Events) != 1 || len(dirs) != 1 || dirs[0].Peer != "frank" ||
		strings.Join(dirs[0].Added, ",") != "news" {
		t.Fatalf("events: %s\nstderr:\n%s", got.Events, warning)
	}
	trust := func(peer string) string {
		return relayName + ": the directory " + relayName + " served for " + peer +
			" does not verify against the key you hold; do not trust it; their channels are not watched\n"
	}
	want := []string{
		trust("bob"),
		relayName + ": the directory " + relayName + " served for carol is one this build cannot read; update auu; their channels are not watched\n",
		relayName + ": the directory dave signed is malformed; tell them; their channels are not watched\n",
		trust("erin"),
	}
	for _, w := range want {
		if n := strings.Count(warning, w); n != 1 {
			t.Errorf("said %d times, want once: %q\nstderr:\n%s", n, w, warning)
		}
	}
	if n := strings.Count(warning, "\n"); n != len(want) {
		t.Errorf("stderr has %d lines, want %d:\n%s", n, len(want), warning)
	}
	// erin was said at the start's end, after the first hold: so the
	// start's three come first and hers last.
	if !strings.HasSuffix(warning, trust("erin")) {
		t.Errorf("erin not said last, mid-run:\n%s", warning)
	}
	// The request that ended the watch names frank and nobody dropped:
	// read once the gate has recorded every listing it served, since the
	// watch may return before the gate is done with the last.
	deadline := time.Now().Add(15 * time.Second)
	for gate.answered.Load() < gate.lists.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := gate.lists.Load(); n != 2 {
		t.Errorf("the watch made %d listings, want 2: the drop and frank's change", n)
	}
	asked := gate.asked.Load()
	if asked == nil || !strings.Contains(*asked, frank.Fingerprint()) {
		t.Fatalf("the last held listing does not name frank: %v", asked)
	}
	for _, id := range []*identity.Identity{bob, carol, dave, erin} {
		if strings.Contains(*asked, id.Fingerprint()) {
			t.Errorf("the last held listing still names a dropped peer %s: %s", id.Fingerprint(), *asked)
		}
	}

	// Your own directory served wrong, mid-run: the watch ends, exit 2,
	// preflight's sentence.
	gate.lists.Store(0)
	joined(t, func() {
		awaitListings(gate, 1)
		d, doc, sig := forgedDirectory(t, self.Fingerprint(), time.Now().Add(3*time.Second))
		set(self.Fingerprint(), d, doc, sig)
	})
	selfWord := "the directory " + relayName + " serves for you does not verify against your key; do not trust it"
	_, err = alice.tryRun("watch", "--event", "directory", "--peer", "self", "--interval", "5s", "--timeout", "1m")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || err.Error() != selfWord {
		t.Fatalf("a watch of your own directory gone bad mid-run: %v", err)
	}
	// And at the start, with the peers beside it, who are dropped as before.
	captureStderr(t, func() {
		_, err = alice.tryRun("watch", "--event", "directory", "--interval", "5s", "--timeout", "1m")
	})
	if !asExit(err, &e) || e.code != exitTransport || err.Error() != selfWord {
		t.Fatalf("a watch of your own directory served wrong: %v", err)
	}
}

// The three sentences come out for each place channels.Verify refuses: the
// length, the signature and the owner say "do not trust it", a version
// this build does not read "update auu", and anything after a good
// signature "tell them".
func TestPeerDirectoryWordsTellTheThreeApart(t *testing.T) {
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	other, err := identity.Generate("other")
	if err != nil {
		t.Fatal(err)
	}
	pub := bob.Public()
	now := time.Now()
	const (
		trust  = "the directory r1 served for bob does not verify against the key you hold; do not trust it"
		update = "the directory r1 served for bob is one this build cannot read; update auu"
		tell   = "the directory bob signed is malformed; tell them"
	)
	_, good := rawDirectory(t, bob.Fingerprint(), channels.Version1, now, false)
	_, v3 := rawDirectory(t, bob.Fingerprint(), 3, now, false)
	_, v3extra := rawDirectory(t, bob.Fingerprint(), 3, now, true)
	_, extra := rawDirectory(t, bob.Fingerprint(), channels.Version1, now, true)
	_, otherOwner := rawDirectory(t, other.Fingerprint(), channels.Version1, now, false)
	long := bytes.Repeat([]byte(" "), relayapi.MaxDirectoryBytes+1)
	cases := []struct {
		name string
		doc  []byte
		sig  []byte
		want error
		says string
	}{
		{"a signature by somebody else", good, signRawDirectory(t, other, good), channels.ErrSignature, trust},
		{"one past the cap", long, signRawDirectory(t, bob, long), channels.ErrForm, trust},
		{"another owner under the key's signature", otherOwner, signRawDirectory(t, bob, otherOwner), channels.ErrOwner, trust},
		{"v 3", v3, signRawDirectory(t, bob, v3), channels.ErrVersion, update},
		{"v 3 with a field no version has", v3extra, signRawDirectory(t, bob, v3extra), channels.ErrVersion, update},
		{"a field no version has under a good signature", extra, signRawDirectory(t, bob, extra), channels.ErrForm, tell},
	}
	for _, c := range cases {
		_, err := channels.Verify(pub, c.doc, c.sig)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: Verify said %v, want %v", c.name, err, c.want)
			continue
		}
		if got := peerDirectoryWords("r1", "bob", c.doc, err); got != c.says {
			t.Errorf("%s: %q, want %q", c.name, got, c.says)
		}
	}
	// At the cap exactly, the length is no reason: a document of that many
	// bytes that fails later is not called untrusted for its size.
	atCap := bytes.Repeat([]byte(" "), relayapi.MaxDirectoryBytes)
	if got := peerDirectoryWords("r1", "bob", atCap, channels.ErrForm); got != tell {
		t.Errorf("at the cap: %q, want %q", got, tell)
	}
}
