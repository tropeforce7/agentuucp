package channels

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// A pushed directory's issued is held to the relay's allowance for a
// request's clock, to what this program can write, and to what a watch can
// carry as nanoseconds; a channel's bounds are held to what this program
// can write, and a refusal of one names the channel and the field.
func TestLimitADirectoryIssuedIsHeldToTheSkew(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	const (
		ahead   = "ahead of now"
		outside = "outside the years 0000 to 9999"
		watch   = "a watch can carry"
	)
	ns := time.Nanosecond
	// The grammar's values around the skew's edge, then this bound's own.
	expect := map[string]string{
		testutil.AtTheEdge: "", testutil.ASecondBefore: "", testutil.ASecondPast: ahead,
		testutil.ADayAhead: ahead, testutil.AYearAhead: ahead, testutil.AYearPast: "",
		testutil.TheEarliest: outside, testutil.OnePastYear9999: ahead, testutil.TheLatest: ahead,
	}
	type edgeCase = struct {
		name   string
		issued time.Time
		refuse string // "" when accepted
	}
	var cases []edgeCase
	for _, e := range testutil.TimeEdges(now.Add(relayapi.MaxSkew)) {
		refuse, ok := expect[e.Name]
		if !ok {
			t.Fatalf("no answer for %s", e.Name)
		}
		cases = append(cases, edgeCase{e.Name, e.At, refuse})
	}
	for _, c := range append(cases, []edgeCase{
		{"now", now, ""},
		// The earliest writable is before what a watch can carry, so it
		// is refused here, by the watch's bound and not the writer's.
		{"the earliest writable", relayapi.EarliestWritable, watch},
		{"a nanosecond before the earliest writable", relayapi.EarliestWritable.Add(-ns), outside},
		{"the earliest a watch can carry", time.Unix(0, math.MinInt64), ""},
		{"a nanosecond before the earliest a watch can carry", time.Unix(0, math.MinInt64).Add(-ns), watch},
	}...) {
		err := CheckIssued(&Directory{Issued: c.issued}, now)
		switch {
		case c.refuse == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.refuse != "" && err == nil:
			t.Errorf("%s: accepted", c.name)
		case c.refuse != "" && !strings.Contains(err.Error(), c.refuse):
			t.Errorf("%s: %v, want it to say %q", c.name, err, c.refuse)
		case c.refuse != "" && errors.Is(err, ErrBound):
			t.Errorf("%s: an issued refusal is ErrBound: %v", c.name, err)
		case c.refuse != "" && errors.Is(err, relayapi.ErrAheadOfNow) != (c.refuse == ahead):
			// The skew refusal alone is the clock's, and says so by its
			// error, which the relay reads to name its clock.
			t.Errorf("%s: errors.Is(err, ErrAheadOfNow) is %v, want %v", c.name, errors.Is(err, relayapi.ErrAheadOfNow), c.refuse == ahead)
		}
	}

	// A channel's bounds: a nanosecond outside what this program writes is
	// refused naming the channel and the field, and a bound at the edge is
	// taken.
	at := func(t time.Time) *time.Time { return &t }
	before, after := relayapi.EarliestWritable.Add(-ns), relayapi.LatestWritable.Add(ns)
	for _, c := range []struct {
		name  string
		ch    Channel
		field string // "" when accepted
	}{
		{"not_before a nanosecond before the earliest", Channel{Name: "bug reports", NotBefore: at(before)}, "not_before"},
		{"not_after a nanosecond after the latest", Channel{Name: "bug reports", NotAfter: at(after)}, "not_after"},
		{"not_before a nanosecond after the latest", Channel{Name: "bug reports", NotBefore: at(after)}, "not_before"},
		{"not_after a nanosecond before the earliest", Channel{Name: "bug reports", NotAfter: at(before)}, "not_after"},
		{"both at the writable edges", Channel{Name: "bug reports",
			NotBefore: at(relayapi.EarliestWritable), NotAfter: at(relayapi.LatestWritable)}, ""},
	} {
		d := &Directory{Issued: now, Channels: []Channel{{Name: Default}, c.ch}}
		err := CheckIssued(d, now)
		switch {
		case c.field == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.field != "" && err == nil:
			t.Errorf("%s: accepted", c.name)
		case c.field != "" && (!strings.Contains(err.Error(), "channel bug reports: "+c.field+" ") ||
			!strings.Contains(err.Error(), outside)):
			t.Errorf("%s: %v, want it to name the channel, %s and the years", c.name, err, c.field)
		case c.field != "" && errors.Is(err, relayapi.ErrAheadOfNow):
			t.Errorf("%s: a bound's refusal is ErrAheadOfNow: %v", c.name, err)
		case c.field != "" && !errors.Is(err, ErrBound):
			t.Errorf("%s: a bound's refusal is not ErrBound: %v", c.name, err)
		}
	}
}
