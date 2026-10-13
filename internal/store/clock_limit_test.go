package store

import (
	"strings"
	"testing"
	"time"
)

// TestLimitAStoredArrivalIsThisMachinesClock: the ledger row of
// Stored.Arrived says it is held by Save, which writes this machine's clock
// into a record that has none, and names the two other writers, deliverStream
// carrying a record's own earlier Arrived into the record it saves again,
// and Load lending a record an earlier release kept the relay's received
// (D80, G9, shown by TestARecordV0170WroteReadsArrivedAsReceived and the
// tests beside it, TestLimitALegacyArrivalsBoundsAreExact among them). The
// limit walk holds the row to naming every function of the tree that
// writes the field, so no path the row does not name puts a value there;
// this test shows what the named writer puts there, through the file and
// back.
func TestLimitAStoredArrivalIsThisMachinesClock(t *testing.T) {
	s := newStore(t)
	const id = "00000000000000000000000000000071"

	// A record saved with no arrival is given this machine's clock at the
	// save, and reads back as exactly that.
	m := stored(id, time.Now().Add(-time.Hour).UTC().Truncate(time.Second))
	before := time.Now().UTC()
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	if m.Arrived.Before(before) || m.Arrived.After(after) {
		t.Fatalf("Save gave the arrival %v, not this machine's clock between %v and %v", m.Arrived, before, after)
	}
	back, err := s.Load(Inbox, id)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Arrived.Equal(m.Arrived) {
		t.Fatalf("the arrival read back as %v, want %v", back.Arrived, m.Arrived)
	}
	if back.Arrived.Equal(back.Received) {
		t.Fatal("the arrival is the relay's received, not this machine's clock")
	}

	// Saved again with the arrival it has, as deliverStream saves a held
	// record's own, it is kept and not stamped anew.
	if err := s.Save(Inbox, back); err != nil {
		t.Fatal(err)
	}
	again, err := s.Load(Inbox, id)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Arrived.Equal(m.Arrived) {
		t.Fatalf("a second save moved the arrival from %v to %v", m.Arrived, again.Arrived)
	}
}

// TestLimitTheSeenIntermediatesNotBeforeRoundTrips: the ledger row of
// Relay.ServerIntNotBefore says it is held by SeenIntermediateFor, which
// the client's OnSeen calls with the NotBefore of the server intermediate
// it verified against the pinned anchor, and names SaveAnchorFor and
// RemoveAnchorFor, which clear it. The limit walk holds the row to naming
// every function of the tree that writes the field; this test shows each
// named writer's value through the relay's file and back: exactly the
// NotBefore it was handed, and the zero time after a new anchor or none.
func TestLimitTheSeenIntermediatesNotBeforeRoundTrips(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	spki := strings.Repeat("deadbeef", 8)
	notBefore := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	read := func(when string) *Relay {
		t.Helper()
		back, err := s.Relay("work")
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		return back
	}

	if err := s.SeenIntermediateFor(r, spki, notBefore); err != nil {
		t.Fatal(err)
	}
	if got := read("after SeenIntermediateFor").ServerIntNotBefore; !got.Equal(notBefore) {
		t.Fatalf("after SeenIntermediateFor the not-before reads %v, want %v", got, notBefore)
	}

	if err := s.SaveAnchorFor(r, testAnchor(t, "work")); err != nil {
		t.Fatal(err)
	}
	if got := read("after SaveAnchorFor").ServerIntNotBefore; !got.IsZero() {
		t.Fatalf("a new anchor left the not-before %v", got)
	}

	if err := s.SeenIntermediateFor(r, spki, notBefore); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAnchorFor(r); err != nil {
		t.Fatal(err)
	}
	if got := read("after RemoveAnchorFor").ServerIntNotBefore; !got.IsZero() {
		t.Fatalf("removing the anchor left the not-before %v", got)
	}
}
