package relay

import (
	"math"
	"testing"
)

// TestLimitTheInflightCapHasACeiling: MaxInflight is the capacity of the
// channel that counts requests at once, and had no ceiling of its own
// (P5, the second trace's F-C3). The command refuses one over
// MaxInflightCeiling (TestLimitRelaySettings), and a server given more,
// by a library caller, holds it to the ceiling; at and under it, the
// number is taken as it is.
func TestLimitTheInflightCapHasACeiling(t *testing.T) {
	st, _, _ := directoryStore(t)
	for give, want := range map[int64]int{
		1:                      1,
		256:                    256,
		MaxInflightCeiling:     MaxInflightCeiling,
		MaxInflightCeiling + 1: MaxInflightCeiling,
		math.MaxInt64:          MaxInflightCeiling,
	} {
		limits := DefaultLimits()
		limits.MaxInflight, limits.MaxWaiting = give, 0
		s := NewServer(st, Config{Limits: limits, Logger: slogDiscard()})
		if got := cap(s.inflight); got != want {
			t.Errorf("MaxInflight %d gave a capacity of %d, want %d", give, got, want)
		}
		s.Close()
	}
}
