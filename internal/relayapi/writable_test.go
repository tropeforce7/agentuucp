package relayapi

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

// The ends of what this program writes a time as, and one step past each:
// the named ends are accepted and round-trip through both writers, JSON
// and RFC 3339 in UTC, and a nanosecond past either is refused by Writable
// and is a time neither writer gives back.
func TestLimitWritable(t *testing.T) {
	ns := time.Nanosecond
	for _, c := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"the earliest", EarliestWritable, true},
		{"the latest", LatestWritable, true},
		{"a nanosecond before the earliest", EarliestWritable.Add(-ns), false},
		{"a nanosecond after the latest", LatestWritable.Add(ns), false},
		{"the least Unix second", time.Unix(math.MinInt64, 0), false},
		{"the latest instant", time.Unix(math.MaxInt64-62135596800, 999999999), false},
		{"the year 10000", time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC), false},
		{"the year 0 at +14:00, the year -1 in UTC", time.Date(0, time.January, 1, 0, 0, 0, 0, time.FixedZone("", 14*3600)), false},
	} {
		if got := Writable(c.at); got != c.want {
			t.Errorf("%s (%s): Writable %v, want %v", c.name, c.at, got, c.want)
		}
	}

	// The named ends are the writer's own: each goes out and comes back
	// whole by both routes.
	for _, end := range []time.Time{EarliestWritable, LatestWritable} {
		data, err := json.Marshal(end)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", end, err)
		}
		var back time.Time
		if err := json.Unmarshal(data, &back); err != nil || !back.Equal(end) {
			t.Fatalf("JSON round trip of %s: %s, %v, %v", end, data, back, err)
		}
		s := end.UTC().Format(time.RFC3339Nano)
		parsed, err := time.Parse(time.RFC3339Nano, s)
		if err != nil || !parsed.Equal(end) {
			t.Fatalf("RFC 3339 round trip of %s: %q, %v, %v", end, s, parsed, err)
		}
	}

	// A nanosecond past each is not: JSON refuses to write it, and the
	// RFC 3339 form in UTC does not parse back to it.
	for _, past := range []time.Time{EarliestWritable.Add(-ns), LatestWritable.Add(ns)} {
		if data, err := json.Marshal(past); err == nil {
			t.Errorf("json.Marshal wrote %s as %s", past, data)
		}
		s := past.UTC().Format(time.RFC3339Nano)
		if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil && parsed.Equal(past) {
			t.Errorf("RFC 3339 round trip of %s past the end came back whole as %q", past, s)
		}
	}
}
