package relayapi

import (
	"testing"
	"time"
)

// Ahead at MaxSkew is the issued bound of every owner document and FreshAt the
// request's: on the ahead side they are one bound, in whole seconds, so a
// document is ahead exactly when a request stamped in its second is stale
// (G13). The zone an issued time is written in changes nothing.
func TestLimitAheadAtMaxSkewAgreesWithFreshAt(t *testing.T) {
	behind := time.FixedZone("UTC-7", -7*60*60)
	for _, ns := range []int{0, 999999999} {
		now := time.Date(2026, 10, 11, 12, 0, 0, ns, time.UTC)
		edge := now.Add(MaxSkew)
		for _, off := range []time.Duration{
			-time.Second,
			0,
			500 * time.Millisecond,
			999999999 * time.Nanosecond,
			time.Second,
			1500 * time.Millisecond,
		} {
			issued := edge.Add(off)
			fresh := (&Auth{TS: issued.Unix()}).FreshAt(now)
			got := Ahead(issued, now, MaxSkew)
			if got != !fresh {
				t.Errorf("now %s, edge%+v: Ahead %v, FreshAt %v", now.Format(time.RFC3339Nano), off, got, fresh)
			}
			if z := Ahead(issued.In(behind), now, MaxSkew); z != got {
				t.Errorf("now %s, edge%+v: in %s Ahead %v, in UTC %v", now.Format(time.RFC3339Nano), off, behind, z, got)
			}
		}
	}
	// The anchors: the edge itself is taken, a second past it refused,
	// whatever now's nanoseconds.
	for _, ns := range []int{0, 999999999} {
		now := time.Date(2026, 10, 11, 12, 0, 0, ns, time.UTC)
		if Ahead(now.Add(MaxSkew), now, MaxSkew) {
			t.Errorf("now %s: now+MaxSkew is ahead", now.Format(time.RFC3339Nano))
		}
		if !Ahead(now.Add(MaxSkew+time.Second), now, MaxSkew) {
			t.Errorf("now %s: now+MaxSkew+1s is not ahead", now.Format(time.RFC3339Nano))
		}
	}
}
