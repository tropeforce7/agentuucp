package store

import (
	"math"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// TestLimitRenewalAtTheExtremes: Expiring compares a certificate's
// not_after with now plus RenewBefore, with After, which holds over the
// type's whole range, to decide whether this machine renews. Against a
// fixed now, time.Unix(math.MinInt64, 0) is renewed and the year 10000 and
// the latest instant a time.Time holds are not, without a panic; the edge
// of the window is shown either side, as TestRenewalHappensBeforeExpiry
// shows it a second either side through the command.
//
// time.Unix(math.MaxInt64, 0) is not the far future: its seconds overflow
// time.Time's own count and the instant lands before the epoch, so a
// certificate with that not_after is rightly renewed. The latest instant
// the type holds is time.Unix(math.MaxInt64 - 62135596800, 999999999).
func TestLimitRenewalAtTheExtremes(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	type edgeCase = struct {
		label    string
		notAfter time.Time
		renew    bool
	}
	// The grammar's values around the window's edge, now + RenewBefore.
	var cases []edgeCase
	for _, e := range testutil.TimeEdges(now.Add(RenewBefore)) {
		switch e.Name {
		case testutil.ASecondBefore, testutil.AYearPast, testutil.TheEarliest:
			cases = append(cases, edgeCase{e.Name, e.At, true})
		case testutil.AtTheEdge, testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead,
			testutil.OnePastYear9999, testutil.TheLatest:
			cases = append(cases, edgeCase{e.Name, e.At, false})
		default:
			t.Fatalf("no answer for %s", e.Name)
		}
	}
	for _, c := range append(cases, []edgeCase{
		{"now", now, true},
		{"a nanosecond inside the window", now.Add(RenewBefore - time.Nanosecond), true},
		{"time.Unix(math.MaxInt64, 0), which overflows to the past", time.Unix(math.MaxInt64, 0), true},
	}...) {
		rec := &CertRecord{NotAfter: c.notAfter}
		if got := rec.Expiring(now); got != c.renew {
			t.Errorf("%s: Expiring %v, want %v", c.label, got, c.renew)
		}
	}
}
