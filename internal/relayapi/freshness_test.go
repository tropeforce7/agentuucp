package relayapi

import (
	"math"
	"testing"
	"time"
)

// The window has two edges and the check must sit exactly on them.
func TestFreshAtBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	skew := int64(MaxSkew / time.Second)

	cases := []struct {
		name string
		ts   int64
		want bool
	}{
		{"one second before the window", now.Unix() - skew - 1, false},
		{"on the earliest edge", now.Unix() - skew, true},
		{"now", now.Unix(), true},
		{"on the latest edge", now.Unix() + skew, true},
		{"one second after the window", now.Unix() + skew + 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (&Auth{TS: c.ts}).FreshAt(now); got != c.want {
				t.Fatalf("FreshAt(ts=%d) = %v, want %v", c.ts, got, c.want)
			}
		})
	}
}

// FreshAt used to compute now-ts and take its absolute value. There is no
// correct abs over a two's-complement integer: -MinInt64 is MinInt64. A
// timestamp chosen to make the subtraction wrap to exactly MinInt64 stayed
// negative after negation and compared as inside the window, so a request
// stamped 2^63 seconds away was accepted as fresh.
func TestFreshAtDoesNotTakeAnAbsoluteValue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	// now - ts == MinInt64 exactly.
	wrapping := now.Unix() + math.MinInt64
	if (&Auth{TS: wrapping}).FreshAt(now) {
		t.Fatalf("a timestamp of %d, which is 2^63 seconds from now, was reported fresh", wrapping)
	}

	// And the extremes of the type, from both directions.
	for _, ts := range []int64{
		math.MinInt64, math.MinInt64 + 1, math.MaxInt64, math.MaxInt64 - 1, 0, -1,
		now.Unix() + math.MinInt64 + 1, now.Unix() - math.MinInt64,
	} {
		if (&Auth{TS: ts}).FreshAt(now) {
			t.Errorf("FreshAt(ts=%d) was fresh; nothing that far away is", ts)
		}
	}
}

// The clock itself can sit near the extremes without the check misbehaving.
func TestFreshAtWithExtremeClock(t *testing.T) {
	for _, sec := range []int64{0, 1, math.MaxInt32, math.MinInt32} {
		now := time.Unix(sec, 0)
		if !(&Auth{TS: sec}).FreshAt(now) {
			t.Errorf("a request stamped with the current time was stale at now=%d", sec)
		}
		if (&Auth{TS: math.MaxInt64}).FreshAt(now) {
			t.Errorf("MaxInt64 was fresh at now=%d", sec)
		}
	}
}
