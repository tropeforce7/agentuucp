package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The inbox, a thread's latest and serve's opener are in the order of
// arrival here, not of the relay's received: a relay's received is its own
// word, and one with its clock ahead could pin its message atop the inbox
// within the skew. Two messages on one thread from two relays: north's
// arrived first and carries the later received, five minutes ahead of this
// clock, and south's arrived a minute after it. North's is listed first and
// south's is the thread's latest, and the same is true when north's
// received is an honest one, so the five minutes change nothing.
func TestTheInboxIsOrderedByArrivalHere(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, northReceived := range []time.Time{now.Add(5 * time.Minute), now.Add(-2 * time.Minute)} {
		s := newStore(t)
		north := stored("00000000000000000000000000000009", northReceived)
		north.Relay, north.RelayID = "north", 9
		north.Arrived = now.Add(-time.Minute)
		south := stored("00000000000000000000000000000001", now.Add(-time.Minute))
		south.Relay, south.RelayID = "south", 3
		south.Arrived = now
		// Saved in the other order, so the listing is not the saves'.
		for _, m := range []*Stored{south, north} {
			if err := s.Save(Inbox, m); err != nil {
				t.Fatal(err)
			}
		}
		list, err := s.List(Inbox)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].Inner.ID != north.Inner.ID || list[1].Inner.ID != south.Inner.ID {
			t.Errorf("north received %v: the inbox lists %v; want north's then south's, the order they arrived in",
				northReceived, arrivalIDs(list))
		}
		_, latest, err := s.FindThread(south.Inner.Body.Thread[:16])
		if err != nil {
			t.Fatal(err)
		}
		if latest.Inner.ID != south.Inner.ID {
			t.Errorf("north received %v: FindThread chose %s; want south's, which arrived last", northReceived, latest.Inner.ID)
		}
		if !LaterThan(south, north) || LaterThan(north, south) {
			t.Errorf("north received %v: LaterThan does not order by arrival", northReceived)
		}
	}

	// Under one arrival the relay's id comes next, then the relay's
	// received, then the sender's stamp, and last the id, so that two
	// records are equal only when they are one.
	a := stored("00000000000000000000000000000002", now)
	b := stored("00000000000000000000000000000001", now)
	a.Arrived, b.Arrived = now, now
	a.Inner.Time, b.Inner.Time = now, now
	if ArrivalOrder(a, b) <= 0 {
		t.Error("the id does not break the last tie")
	}
	if ArrivalOrder(a, a) != 0 {
		t.Error("a record is not equal to itself")
	}
	b.Inner.Time = now.Add(time.Hour)
	if ArrivalOrder(a, b) >= 0 {
		t.Error("the sender's stamp does not come before the id")
	}
	a.Received = now.Add(time.Second)
	if ArrivalOrder(a, b) <= 0 {
		t.Error("the relay's received does not come before the sender's stamp")
	}
	b.RelayID = 2
	if ArrivalOrder(a, b) >= 0 {
		t.Error("the relay's id does not come before its received")
	}
	a.Arrived = now.Add(-time.Second)
	b.Received = now.Add(-time.Hour)
	b.RelayID = 0
	if ArrivalOrder(a, b) >= 0 {
		t.Error("arrival does not come first")
	}
}

func arrivalIDs(list []*Stored) []string {
	out := make([]string, len(list))
	for i, m := range list {
		out[i] = m.Inner.ID
	}
	return out
}

// A record v0.15.0 to v0.17.0 wrote has no arrived key: it loads with its
// received as its arrival, and is listed where its received puts it among
// records that have one. The record is written in v0.17.0's exact keys.
// Marked read, it is saved with that arrival and stays where it was.
func TestARecordV0170WroteReadsArrivedAsReceived(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	before := stored("00000000000000000000000000000001", now.Add(-2*time.Hour))
	before.Arrived = now.Add(-time.Hour)
	after := stored("00000000000000000000000000000003", now.Add(-2*time.Hour))
	after.Arrived = now
	for _, m := range []*Stored{after, before} {
		if err := s.Save(Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	id := "00000000000000000000000000000002"
	received := now.Add(-30 * time.Minute)
	record := `{
  "relay_id": 7,
  "relay": "relay",
  "received": "` + received.Format(time.RFC3339Nano) + `",
  "read": false,
  "inner": {
    "v": 1,
    "from": "` + strings.Repeat("a", 64) + `",
    "from_bundle": null,
    "to": "` + strings.Repeat("b", 64) + `",
    "id": "` + id + `",
    "time": "` + received.Add(-time.Minute).Format(time.RFC3339Nano) + `",
    "body": {"type": "ask", "thread": "0123456789abcdef0123456789abcdef", "text": "from v0.17.0"}
  },
  "sender_name": "alice",
  "channel": "jostle"
}
`
	if strings.Contains(record, `"arrived"`) {
		t.Fatal("the older record has an arrived key")
	}
	if err := os.MkdirAll(filepath.Dir(s.msgPath(Inbox, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.msgPath(Inbox, id), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := s.Load(Inbox, id)
	if err != nil {
		t.Fatalf("v0.17.0's record: %v", err)
	}
	if !m.Arrived.Equal(received) || !m.Received.Equal(received) {
		t.Errorf("v0.17.0's record loaded with arrived %v and received %v; want both %v", m.Arrived, m.Received, received)
	}
	listed := func(when string) {
		t.Helper()
		list, err := s.List(Inbox)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 3 || list[0].Inner.ID != before.Inner.ID || list[1].Inner.ID != id || list[2].Inner.ID != after.Inner.ID {
			t.Errorf("%s: the inbox lists %v; want the older record between the one that arrived before its received and the one after", when, arrivalIDs(list))
		}
	}
	listed("as v0.17.0 wrote it")
	if err := s.MarkRead(Inbox, id); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.msgPath(Inbox, id))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"arrived": "`+received.Format(time.RFC3339Nano)+`"`) {
		t.Errorf("marked read, the older record was written without its received as its arrival:\n%s", data)
	}
	listed("marked read")
}

// Save sets a record's arrival when it has none, and never after: a record
// saved, loaded, marked read, moved and saved again keeps its first. One
// given an arrival an hour back is saved with it, so a save that set its
// own clock over one already there would be seen without waiting.
func TestSaveSetsArrivedOnce(t *testing.T) {
	s := newStore(t)
	given := stored("00000000000000000000000000000002", time.Now().UTC())
	given.Arrived = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	want := given.Arrived
	if err := s.Save(Inbox, given); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRead(Inbox, given.Inner.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Move(Inbox, Sent, given.Inner.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(Sent, given.Inner.ID); err != nil || !got.Arrived.Equal(want) {
		t.Fatalf("a record saved with an arrival, marked read and moved: %v, arrived %v; want %v", err, got.Arrived, want)
	}

	m := stored("00000000000000000000000000000001", time.Now().UTC().Add(-time.Hour))
	before := time.Now().UTC()
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	first := m.Arrived
	if first.IsZero() || first.Before(before) || first.After(time.Now().UTC()) || first.Location() != time.UTC {
		t.Fatalf("Save set arrived %v; want this clock at the save, in UTC", first)
	}
	loaded, err := s.Load(Inbox, m.Inner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Arrived.Equal(first) {
		t.Fatalf("loaded arrived %v; want the first, %v", loaded.Arrived, first)
	}
	if err := s.MarkRead(Inbox, m.Inner.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Move(Inbox, Quarantine, m.Inner.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.Load(Quarantine, m.Inner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Read || !again.Arrived.Equal(first) {
		t.Fatalf("marked read and moved: read %v, arrived %v; want read and the first, %v", again.Read, again.Arrived, first)
	}
	again.SenderName = "renamed"
	if err := s.Save(Quarantine, again); err != nil {
		t.Fatal(err)
	}
	last, err := s.Load(Quarantine, m.Inner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !last.Arrived.Equal(first) || last.SenderName != "renamed" {
		t.Errorf("saved again: arrived %v; want the first, %v", last.Arrived, first)
	}
}
