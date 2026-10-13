package vouch

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// TestLimitAVouchIssuedIsHeldToTheSkew: a vouch issued more than
// relayapi.MaxStampAhead ahead of the clock it is held to, the chain of
// clocks a sealed stamp crosses (D83), is refused, by Verify
// and by Sign, and one issued at any time before that edge is taken, since
// a stamp has no past bound. It feeds now, the edge and a second either
// side, a day and a year ahead, a year past, the ends of what the wire
// carries, and the type's own extremes; TestAVouchFromTheFutureIsRefused
// has the edge and a second either side as well.
//
// The clock is injected, so the dates are exact against now. The check is
// relayapi.Ahead, in whole seconds as a request's freshness is, so nine
// tenths of a second past the edge is the edge's second and taken, and a
// whole second past is refused; it compares Unix seconds and subtracts
// nothing, so no difference saturates, and the far-future values are the
// year 10000 and the latest instant a time.Time holds.
//
// A vouch travels as JSON, and json.Marshal refuses a year outside 0000 to
// 9999, so time.Unix(math.MinInt64, 0) and the year 10000 written in UTC
// never reach Verify: the ends of what the wire carries are the first of
// year 0 at +23:59 and the last instant of 9999 at -23:59, and they go
// through Verify, while the type's extremes go through fromTheFuture, the
// rule both Sign and Verify run, and through Sign, which refuses the far
// past at the encoding.
//
// time.Unix(math.MaxInt64, 0) overflows time.Time's internal count, and
// compared as a time it lands before the epoch, before even
// time.Unix(math.MinInt64, 0), which After took as old. Ahead reads it
// back through Unix, which undoes the wrap and gives MaxInt64 seconds, so
// fromTheFuture now refuses it as the far future it was written as:
// stricter than After, not weaker. The latest instant the type holds is
// time.Unix(math.MaxInt64 - 62135596800, 999999999), the seconds from
// year 1 to the epoch taken off, and that one is refused too.
func TestLimitAVouchIssuedIsHeldToTheSkew(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	refusal := "ahead of this machine's clock"

	// The grammar's values around the edge: the five the wire carries go
	// through Verify, and the three it cannot through the rule and Sign.
	type edgeCase = struct {
		label  string
		issued time.Time
		ok     bool
	}
	var carried, extremes []edgeCase
	for _, e := range testutil.TimeEdges(now.Add(relayapi.MaxStampAhead)) {
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast:
			carried = append(carried, edgeCase{e.Name, e.At, true})
		case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead:
			carried = append(carried, edgeCase{e.Name, e.At, false})
		case testutil.TheEarliest:
			extremes = append(extremes, edgeCase{e.Name, e.At, true})
		case testutil.OnePastYear9999, testutil.TheLatest:
			extremes = append(extremes, edgeCase{e.Name, e.At, false})
		default:
			t.Fatalf("no answer for %s", e.Name)
		}
	}

	for _, c := range append(carried, []edgeCase{
		{"now", now, true},
		{"nine tenths of a second past the edge, its second", now.Add(relayapi.MaxStampAhead + 900*time.Millisecond), true},
		{"the old edge a second past, five minutes and a second", now.Add(relayapi.MaxSkew + time.Second), true},
		{"the latest instant the wire carries, the year 10000 in UTC",
			time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60))), false},
		{"the earliest instant the wire carries, the year -1 in UTC",
			time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60)), true},
	}...) {
		t.Run(c.label, func(t *testing.T) {
			d := base(v, x)
			d.Issued = c.issued
			doc, sig := signRaw(t, v, d)
			_, err := Verify(v.Public(), doc, sig, now)
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), refusal)) {
				t.Fatalf("got %v; want the refusal of a future issue time", err)
			}
		})
	}

	for _, c := range append(extremes, edgeCase{
		"time.Unix(math.MaxInt64, 0), read back by Unix as the far future", time.Unix(math.MaxInt64, 0), false,
	}) {
		t.Run(c.label, func(t *testing.T) {
			d := base(v, x)
			d.Issued = c.issued
			err := fromTheFuture(d, now)
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), refusal)) {
				t.Fatalf("got %v; want the refusal of a future issue time", err)
			}
			// Sign runs the same rule, then the encoding: a stamp the rule
			// takes and the wire cannot carry is refused by json, with an
			// error and not a panic.
			_, _, err = Sign(v, d, now)
			switch {
			case c.ok && (err == nil || !strings.Contains(err.Error(), "year outside of range")):
				t.Fatalf("Sign: %v; want the encoding's refusal of the year", err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), refusal)):
				t.Fatalf("Sign: %v; want the refusal of a future issue time", err)
			}
		})
	}
	if !time.Unix(math.MaxInt64, 0).Before(time.Unix(math.MinInt64, 0)) || time.Unix(math.MaxInt64, 0).Unix() != math.MaxInt64 {
		t.Error("time.Unix(math.MaxInt64, 0) no longer compares before time.Unix(math.MinInt64, 0) while reading back as MaxInt64 seconds; the comment above is out of date")
	}
}
