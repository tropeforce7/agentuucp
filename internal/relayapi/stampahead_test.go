package relayapi

import (
	"math"
	"testing"
	"time"
)

// TestLimitMaxStampAheadIsTheChain pins the claim and not the number
// alone: a sealed stamp crosses the sender's clock to its relay within
// MaxSkew, each relay to the next within CourierSkew for at most MaxHops
// of them, and the last relay to the reader within MaxSkew (D83). The
// figures the comment and the guides give follow from the four: forty-two
// minutes over the protocol's hops, eighteen at the default max_hops of 8,
// eleven over one courier hop.
func TestLimitMaxStampAheadIsTheChain(t *testing.T) {
	if MaxStampAhead != 2*MaxSkew+MaxHops*CourierSkew {
		t.Errorf("MaxStampAhead is %s; the chain 2*MaxSkew + MaxHops*CourierSkew is %s", MaxStampAhead, 2*MaxSkew+MaxHops*CourierSkew)
	}
	if MaxStampAhead != 42*time.Minute {
		t.Errorf("MaxStampAhead is %s; the guides say forty-two minutes", MaxStampAhead)
	}
	if MaxHops != 32 {
		t.Errorf("MaxHops is %d; the chain's forty-two minutes is over thirty-two hops", MaxHops)
	}
	if CourierSkew != time.Minute {
		t.Errorf("CourierSkew is %s; relays keep to the minute", CourierSkew)
	}
	if MaxSkew != 5*time.Minute {
		t.Errorf("MaxSkew is %s; the chain's figures assume five minutes", MaxSkew)
	}
	for _, c := range []struct {
		hops int
		want time.Duration
	}{{1, 11 * time.Minute}, {8, 18 * time.Minute}, {MaxHops, 42 * time.Minute}} {
		if got := 2*MaxSkew + time.Duration(c.hops)*CourierSkew; got != c.want {
			t.Errorf("the chain over %d hops is %s; the comment says %s", c.hops, got, c.want)
		}
	}
	// The bound is a whole number of seconds, so Ahead's division loses
	// nothing of it.
	if MaxStampAhead%time.Second != 0 || CourierSkew%time.Second != 0 {
		t.Errorf("MaxStampAhead %s or CourierSkew %s is not whole seconds", MaxStampAhead, CourierSkew)
	}
}

// TestLimitAheadIsInWholeSeconds: Ahead judges as FreshAt does, by Unix
// seconds, so the edge is taken, a stamp nine tenths of a second past it
// is taken (Unix floors it to the edge), and one a second past is
// refused. The type's extremes go through Unix and come back as what they
// are: time.Unix(math.MaxInt64, 0), whose internal count wraps, reads back
// as MaxInt64 seconds and is the far future, not the past.
func TestLimitAheadIsInWholeSeconds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	by := MaxStampAhead
	for _, c := range []struct {
		name string
		t    time.Time
		want bool
	}{
		{"a year past", now.AddDate(-1, 0, 0), false},
		{"now", now, false},
		{"a second inside the edge", now.Add(by - time.Second), false},
		{"on the edge", now.Add(by), false},
		{"nine tenths of a second past the edge, floored to it", now.Add(by + 900*time.Millisecond), false},
		{"the last nanosecond of the edge's second", now.Add(by + time.Second - time.Nanosecond), false},
		{"a second past the edge", now.Add(by + time.Second), true},
		{"a day ahead", now.Add(24 * time.Hour), true},
		{"a year ahead", now.AddDate(1, 0, 0), true},
		{"time.Unix(math.MinInt64, 0)", time.Unix(math.MinInt64, 0), false},
		{"time.Unix(math.MinInt64+1, 0)", time.Unix(math.MinInt64+1, 0), false},
		{"time.Unix(math.MaxInt64, 0), read back as MaxInt64 seconds", time.Unix(math.MaxInt64, 0), true},
		{"time.Unix(math.MaxInt64-1, 0)", time.Unix(math.MaxInt64-1, 0), true},
		{"the latest instant a time.Time holds", time.Unix(math.MaxInt64-62135596800, 999999999), true},
		{"EarliestWritable", EarliestWritable, false},
		{"LatestWritable", LatestWritable, true},
		{"the zero time", time.Time{}, false},
	} {
		if got := Ahead(c.t, now, by); got != c.want {
			t.Errorf("%s (%d s): Ahead %v, want %v", c.name, c.t.Unix(), got, c.want)
		}
	}

	// A clock part-way through its second judges by the second it is in,
	// as FreshAt does: the stamp at the edge's whole second is taken
	// though it is less than the bound past a clock reading of .999, and
	// one a second on is refused though it is not quite a second past.
	late := time.Unix(1_700_000_000, 999_999_999)
	if Ahead(time.Unix(1_700_000_000+int64(by/time.Second), 999_999_999), late, by) {
		t.Error("the edge's second was refused against a clock late in its second")
	}
	if !Ahead(time.Unix(1_700_000_000+int64(by/time.Second)+1, 0), late, by) {
		t.Error("the second past the edge was taken against a clock late in its second")
	}

	// One bound: at or after now, a request at a second is inside the
	// window exactly when a sealed stamp at that second is not ahead.
	for _, sec := range []int64{0, 1, int64(by/time.Second) - 1, int64(by / time.Second), int64(by/time.Second) + 1} {
		fresh := (&Auth{TS: now.Unix() + sec}).FreshWithin(now, by)
		ahead := Ahead(time.Unix(now.Unix()+sec, 0), now, by)
		if fresh == ahead {
			t.Errorf("%d s ahead: FreshWithin %v and Ahead %v; one bound says one is the other's negation", sec, fresh, ahead)
		}
	}
}

// TestLimitFreshWithin: FreshAt's two edges for any window, at the
// courier's minute and at a user's five, a second either side of each
// edge, and the type's extremes, which no window takes.
func TestLimitFreshWithin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, skew := range []time.Duration{CourierSkew, MaxSkew} {
		s := int64(skew / time.Second)
		for _, c := range []struct {
			name string
			ts   int64
			want bool
		}{
			{"one second before the window", now.Unix() - s - 1, false},
			{"on the earliest edge", now.Unix() - s, true},
			{"now", now.Unix(), true},
			{"on the latest edge", now.Unix() + s, true},
			{"one second after the window", now.Unix() + s + 1, false},
			{"MinInt64", math.MinInt64, false},
			{"MaxInt64", math.MaxInt64, false},
			{"2^63 seconds from now", now.Unix() + math.MinInt64, false},
		} {
			if got := (&Auth{TS: c.ts}).FreshWithin(now, skew); got != c.want {
				t.Errorf("%s, %s: FreshWithin(ts=%d) = %v, want %v", skew, c.name, c.ts, got, c.want)
			}
		}
	}
	// FreshAt is FreshWithin at MaxSkew, and a courier's window is inside
	// a user's: sixty-one seconds out is fresh for one and not the other.
	for _, off := range []int64{-301, -300, -61, -60, 0, 60, 61, 300, 301} {
		a := &Auth{TS: now.Unix() + off}
		if a.FreshAt(now) != a.FreshWithin(now, MaxSkew) {
			t.Errorf("%d s out: FreshAt %v, FreshWithin(MaxSkew) %v", off, a.FreshAt(now), a.FreshWithin(now, MaxSkew))
		}
	}
	if a := (&Auth{TS: now.Unix() + 61}); !a.FreshAt(now) || a.FreshWithin(now, CourierSkew) {
		t.Error("sixty-one seconds out should be fresh for a user and not for a courier")
	}
}
