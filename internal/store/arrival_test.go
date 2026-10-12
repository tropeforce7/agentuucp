package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
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

// v0170Record is a record in v0.17.0's exact keys, with no arrived key,
// received at the stamp given as it is written in the file.
func v0170Record(t *testing.T, id, received string) string {
	t.Helper()
	record := `{
  "relay_id": 7,
  "relay": "relay",
  "received": "` + received + `",
  "read": false,
  "inner": {
    "v": 1,
    "from": "` + strings.Repeat("a", 64) + `",
    "from_bundle": null,
    "to": "` + strings.Repeat("b", 64) + `",
    "id": "` + id + `",
    "time": "2026-01-01T00:00:00Z",
    "body": {"type": "ask", "thread": "0123456789abcdef0123456789abcdef", "text": "from v0.17.0"}
  },
  "sender_name": "alice",
  "channel": "jostle"
}
`
	if strings.Contains(record, `"arrived"`) {
		t.Fatal("the older record has an arrived key")
	}
	return record
}

// v0.15.0 to v0.17.0 kept whatever received a relay listed, and one a
// hostile relay set past either end of what this program can write back
// would put a time in serve's ledger that its save refuses (D80). Such a
// record, written in v0.17.0's keys with no arrived key and its file's
// time set to a known instant, loads with that instant as its arrival and
// its received as it was, and says so once on standard error across two
// loads; marked read, it is saved with that arrival, which the file's new
// time does not move. The stamps either side of each end are the nearest
// RFC 3339 can carry: at the earliest a received still stands in for the
// arrival, a nanosecond past either end it does not. The latest is
// writable but far ahead of this machine's clock, so since G9 it is not
// lent either and the record arrives at its file's time. A past received
// given at -12:00 is lent, and the loaded arrival is UTC whichever branch
// gave it, as Save writes one (NEXT.md item 20: under UTC a file time in
// the local zone was invisible here). The third branch, this machine's
// clock, is TestALegacyArrivalIsHeldToTheSkew's.
func TestARecordKeptWithAnUnwritableReceivedArrivesAtItsFilesTime(t *testing.T) {
	fileTime := time.Date(2026, time.March, 14, 15, 9, 26, 0, time.UTC)
	for _, c := range []struct {
		name, received string
		writable, lent bool
	}{
		{"the trace's stamp, UTC year 10000", "9999-12-31T23:59:59-12:00", false, false},
		{"a nanosecond after the latest", "9999-12-31T23:59:00-00:01", false, false},
		// Writable, and once lent as the arrival; G9 refuses it as ahead
		// of this machine's clock by more than relayapi.MaxSkew, so it
		// now arrives at the file's time and is warned about.
		{"the latest", "9999-12-31T23:59:59.999999999Z", true, false},
		{"the earliest", "0000-01-01T00:00:00Z", true, true},
		{"a nanosecond before the earliest", "0000-01-01T00:00:59.999999999+00:01", false, false},
		{"the year 0 at +01:00, UTC year -1", "0000-01-01T00:00:00+01:00", false, false},
		{"a past received at -12:00, behind UTC", "2026-03-13T20:00:00-12:00", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			received, err := time.Parse(time.RFC3339Nano, c.received)
			if err != nil {
				t.Fatal(err)
			}
			if got := received.UTC().Year() >= 0 && received.UTC().Year() <= 9999; got != c.writable {
				t.Fatalf("%s is in UTC year %d, so the case proves nothing", c.received, received.UTC().Year())
			}
			s := newStore(t)
			id := "00000000000000000000000000000002"
			path := s.msgPath(Inbox, id)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(v0170Record(t, id, c.received)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, fileTime, fileTime); err != nil {
				t.Fatal(err)
			}
			want := received.UTC()
			if !c.lent {
				want = fileTime
			}
			var loads [2]*Stored
			stderr := captureStderr(t, func() {
				for i := range loads {
					if loads[i], err = s.Load(Inbox, id); err != nil {
						return
					}
				}
			})
			if err != nil {
				t.Fatalf("v0.17.0's record received %s: %v", c.received, err)
			}
			for _, m := range loads {
				if !m.Arrived.Equal(want) || !m.Received.Equal(received) {
					t.Errorf("loaded with arrived %v and received %v; want %v and %v", m.Arrived, m.Received, want, received)
				}
				if m.Arrived.Location() != time.UTC {
					t.Errorf("loaded with arrived %v in %v; want UTC, as Save writes one", m.Arrived, m.Arrived.Location())
				}
			}
			warning := "warning: " + path + " holds a received time this program cannot write back or that is ahead of this machine's clock; " +
				"it is ordered as arriving at " + fileTime.Format(time.RFC3339) + ", the file's time\n"
			if c.lent && stderr != "" {
				t.Errorf("a received lent as the arrival was warned about:\n%s", stderr)
			}
			if !c.lent && stderr != warning {
				t.Errorf("two loads said:\n%q\nwant once:\n%q", stderr, warning)
			}

			// Marked read, the record is written with the arrival it
			// loaded with, and keeps it after the file's time has moved.
			captureStderr(t, func() { err = s.MarkRead(Inbox, id) })
			if err != nil {
				t.Fatalf("marked read: %v", err)
			}
			if fi, err := os.Stat(path); err != nil || fi.ModTime().Equal(fileTime) {
				t.Fatalf("the file's time after the mark is %v (%v); want it moved, or the test proves nothing", fi.ModTime(), err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"arrived": "`+want.Format(time.RFC3339Nano)+`"`) {
				t.Errorf("marked read, the record was written without arrived %v:\n%s", want, data)
			}
			m, err := s.Load(Inbox, id)
			if err != nil {
				t.Fatal(err)
			}
			if !m.Read || !m.Arrived.Equal(want) || !m.Received.Equal(received) {
				t.Errorf("marked read: read %v, arrived %v, received %v; want read, %v and %v", m.Read, m.Arrived, m.Received, want, received)
			}
		})
	}
}

// G9's edges. A record an earlier release kept with no arrived lends its
// received as the arrival only up to this machine's clock plus
// relayapi.MaxSkew, and its file's time is held to the same bound. A
// received at now plus the skew is lent with nothing said; one a second
// further is not, and the record arrives at its file's time. A file time
// at now plus the skew is taken; one a second further is not, and the
// record arrives at this machine's clock at the load, said as such.
// arrivedBefore reads the real clock, so "now" here is taken before the
// write and the load runs a moment later: the stamp on the edge is inside
// it by that moment, and the second past it is outside by all but that.
func TestALegacyArrivalIsHeldToTheSkew(t *testing.T) {
	past := time.Date(2026, time.March, 14, 15, 9, 26, 0, time.UTC)
	for _, c := range []struct {
		name string
		// received and file are offsets from now; a received of zero
		// is the year 9000, which no clock lends.
		received, file time.Duration
		pastFile       bool
		want           string // "received", "file" or "clock"
	}{
		{"a received at now plus the skew", relayapi.MaxSkew, 0, true, "received"},
		{"a received a second past it", relayapi.MaxSkew + time.Second, 0, true, "file"},
		{"a file time at now plus the skew", 0, relayapi.MaxSkew, false, "file"},
		{"a file time a second past it", 0, relayapi.MaxSkew + time.Second, false, "clock"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			id := "00000000000000000000000000000002"
			path := s.msgPath(Inbox, id)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			received := time.Date(9000, time.January, 1, 0, 0, 0, 0, time.UTC)
			if c.received != 0 {
				received = now.Add(c.received)
			}
			fileTime := past
			if !c.pastFile {
				fileTime = now.Add(c.file)
			}
			if err := os.WriteFile(path, []byte(v0170Record(t, id, received.Format(time.RFC3339Nano))), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, fileTime, fileTime); err != nil {
				t.Fatal(err)
			}
			if fi, err := os.Stat(path); err != nil || !fi.ModTime().Equal(fileTime) {
				t.Fatalf("the file's time is %v (%v); want %v, or the case proves nothing", fi.ModTime(), err, fileTime)
			}
			var m *Stored
			var err error
			stderr := captureStderr(t, func() { m, err = s.Load(Inbox, id) })
			loaded := time.Now().UTC()
			if err != nil {
				t.Fatal(err)
			}
			if m.Arrived.Location() != time.UTC {
				t.Errorf("loaded with arrived %v in %v; want UTC", m.Arrived, m.Arrived.Location())
			}
			prefix := "warning: " + path + " holds a received time this program cannot write back or that is ahead of this machine's clock; " +
				"it is ordered as arriving at "
			switch c.want {
			case "received":
				if !m.Arrived.Equal(received) || stderr != "" {
					t.Errorf("arrived %v, said %q; want the received %v lent with nothing said", m.Arrived, stderr, received)
				}
			case "file":
				want := prefix + fileTime.Format(time.RFC3339) + ", the file's time\n"
				if !m.Arrived.Equal(fileTime) || stderr != want {
					t.Errorf("arrived %v, said %q; want the file's time %v, said %q", m.Arrived, stderr, fileTime, want)
				}
			case "clock":
				want := prefix + m.Arrived.Format(time.RFC3339) + ", this machine's clock\n"
				if m.Arrived.Before(now) || m.Arrived.After(loaded) || stderr != want {
					t.Errorf("arrived %v, said %q; want this machine's clock between %v and %v, said %q", m.Arrived, stderr, now, loaded, want)
				}
			}
		})
	}
}

// legacyArrival's bounds, one nanosecond apart, against a fixed now: a
// received at now plus relayapi.MaxSkew is lent and a nanosecond past it
// is not, the file's time is held to the same bound, and the writable
// span's two ends are where Writable puts them, the latest falling to the
// file's time since it is past the skew. Every cell asserts the arrival,
// its zone and which source the warning names.
func TestLimitALegacyArrivalsBoundsAreExact(t *testing.T) {
	now := time.Date(2026, time.October, 12, 12, 0, 0, 0, time.UTC)
	bound := now.Add(relayapi.MaxSkew)
	file := time.Date(2026, time.March, 14, 15, 9, 26, 0, time.UTC)
	ptr := func(t time.Time) *time.Time { return &t }
	behind := time.FixedZone("UTC-12", -12*3600)
	past := now.Add(-time.Hour)
	const lent, fileTime, clock = "", "the file's time", "this machine's clock"
	for _, c := range []struct {
		name     string
		received time.Time
		modTime  *time.Time
		want     time.Time
		which    string
		zone     *time.Location // now's zone, UTC when nil
	}{
		{"received at now plus the skew", bound, ptr(file), bound, lent, nil},
		{"received a nanosecond past it", bound.Add(time.Nanosecond), ptr(file), file, fileTime, nil},
		{"file time at now plus the skew", bound.Add(time.Nanosecond), ptr(bound), bound, fileTime, nil},
		{"file time a nanosecond past it", bound.Add(time.Nanosecond), ptr(bound.Add(time.Nanosecond)), now, clock, nil},
		{"no file time", bound.Add(time.Nanosecond), nil, now, clock, nil},
		{"received at the earliest writable", relayapi.EarliestWritable, ptr(file), relayapi.EarliestWritable, lent, nil},
		{"received a nanosecond before it", relayapi.EarliestWritable.Add(-time.Nanosecond), ptr(file), file, fileTime, nil},
		{"received at the latest writable", relayapi.LatestWritable, ptr(file), file, fileTime, nil},
		{"received in a zone behind UTC", past.In(behind), ptr(file), past, lent, nil},
		{"file time in a zone behind UTC", bound.Add(time.Nanosecond), ptr(file.In(behind)), file, fileTime, nil},
		{"now in a zone behind UTC", bound.Add(time.Nanosecond), nil, now, clock, behind},
	} {
		t.Run(c.name, func(t *testing.T) {
			at := now
			if c.zone != nil {
				at = now.In(c.zone)
			}
			got, which := legacyArrival(c.received, c.modTime, at)
			if !got.Equal(c.want) || got.Location() != time.UTC || which != c.which {
				t.Errorf("legacyArrival = %v (%v), %q; want %v in UTC, %q", got, got.Location(), which, c.want, c.which)
			}
		})
	}
}
