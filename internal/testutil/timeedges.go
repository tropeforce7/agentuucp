package testutil

import (
	"math"
	"time"
)

// The names of the values TimeEdges gives, one for each the limit ledger's
// grammar lists for a bound row's test (internal/limits/ledger.txt): the
// edge and a second either side, a day and a year ahead, a year past, the
// earliest and latest instants, and, for a deadline, one past year 9999.
const (
	AtTheEdge       = "at the edge"
	ASecondBefore   = "a second before the edge"
	ASecondPast     = "a second past the edge"
	ADayAhead       = "a day ahead"
	AYearAhead      = "a year ahead"
	AYearPast       = "a year past"
	TheEarliest     = "the earliest instant"
	OnePastYear9999 = "one past year 9999"
	TheLatest       = "the latest instant"
)

// TimeEdge is one value a bound row's test feeds, by its name.
type TimeEdge struct {
	Name string
	At   time.Time
}

// TimeEdges gives every value the limit ledger's grammar names for a bound
// row's test, around edge: the edge itself and a second either side of it;
// a day and a year ahead of it and a year past it; and the instants that
// do not depend on it, the earliest, the first past year 9999 and the
// latest. The ledger's walk holds every test a bound row names to calling
// this, so a test feeds the values by construction rather than by habit;
// the test ranges over them and fails on a name it has no answer for.
func TimeEdges(edge time.Time) []TimeEdge {
	return []TimeEdge{
		{AtTheEdge, edge},
		{ASecondBefore, edge.Add(-time.Second)},
		{ASecondPast, edge.Add(time.Second)},
		{ADayAhead, edge.AddDate(0, 0, 1)},
		{AYearAhead, edge.AddDate(1, 0, 0)},
		{AYearPast, edge.AddDate(-1, 0, 0)},
		{TheEarliest, EarliestInstant()},
		{OnePastYear9999, PastYear9999()},
		{TheLatest, LatestInstant()},
	}
}

// EarliestInstant is time.Unix(math.MinInt64, 0), the earliest instant
// whose Unix second the type can say: an earlier one holds, but its Unix
// method wraps to a time in the far future.
func EarliestInstant() time.Time { return time.Unix(math.MinInt64, 0) }

// LatestInstant is time.Unix(math.MaxInt64-62135596800, 999999999), the
// latest instant a time.Time holds; time.Unix(math.MaxInt64, 0) is not it,
// since it wraps to before 1970.
func LatestInstant() time.Time { return time.Unix(math.MaxInt64-62135596800, 999999999) }

// PastYear9999 is the first instant of the year 10000 in UTC, one past
// what RFC 3339, and so the wire, can write.
func PastYear9999() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }
