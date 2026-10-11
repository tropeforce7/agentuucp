package vouch

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitAVouchIssuedIsHeldToTheSkew: a vouch issued more than
// relayapi.MaxSkew ahead of the clock it is held to is refused, by Verify
// and by Sign, and one issued at any time before that edge is taken, since
// a stamp has no past bound. It feeds now, the edge and a second either
// side, a day and a year ahead, a year past, the ends of what the wire
// carries, and the type's own extremes; TestAVouchFromTheFutureIsRefused
// has the edge and a second either side as well.
//
// The clock is injected, so the dates are exact against now. The check is
// After and not Sub, so no difference saturates, and the far-future values
// are the year 10000 and the latest instant a time.Time holds.
//
// A vouch travels as JSON, and json.Marshal refuses a year outside 0000 to
// 9999, so time.Unix(math.MinInt64, 0) and the year 10000 written in UTC
// never reach Verify: the ends of what the wire carries are the first of
// year 0 at +23:59 and the last instant of 9999 at -23:59, and they go
// through Verify, while the type's extremes go through fromTheFuture, the
// rule both Sign and Verify run, and through Sign, which refuses the far
// past at the encoding.
//
// time.Unix(math.MaxInt64, 0) is not the far future: the seconds overflow
// time.Time's internal count and the instant lands before the epoch,
// before even time.Unix(math.MinInt64, 0), so fromTheFuture takes it as
// old. The latest instant the type holds is time.Unix(math.MaxInt64 -
// 62135596800, 999999999), the seconds from year 1 to the epoch taken
// off, and that one is refused.
func TestLimitAVouchIssuedIsHeldToTheSkew(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	refusal := "ahead of this machine's clock"

	for _, c := range []struct {
		label  string
		issued time.Time
		ok     bool
	}{
		{"now", now, true},
		{"a second inside the skew", now.Add(relayapi.MaxSkew - time.Second), true},
		{"at the skew", now.Add(relayapi.MaxSkew), true},
		{"a second past the skew", now.Add(relayapi.MaxSkew + time.Second), false},
		{"a day ahead", now.Add(24 * time.Hour), false},
		{"a year ahead", now.AddDate(1, 0, 0), false},
		{"a year past", now.AddDate(-1, 0, 0), true},
		{"the latest instant the wire carries, the year 10000 in UTC",
			time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60))), false},
		{"the earliest instant the wire carries, the year -1 in UTC",
			time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60)), true},
	} {
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

	latest := time.Unix(math.MaxInt64-62135596800, 999999999)
	for _, c := range []struct {
		label  string
		issued time.Time
		ok     bool
	}{
		{"time.Unix(math.MinInt64, 0)", time.Unix(math.MinInt64, 0), true},
		{"time.Unix(math.MaxInt64, 0), which overflows to the past", time.Unix(math.MaxInt64, 0), true},
		{"the year 10000", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"the latest instant a time.Time holds", latest, false},
	} {
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
	if !time.Unix(math.MaxInt64, 0).Before(time.Unix(math.MinInt64, 0)) {
		t.Error("time.Unix(math.MaxInt64, 0) is no longer before time.Unix(math.MinInt64, 0); the comment above is out of date")
	}
}
