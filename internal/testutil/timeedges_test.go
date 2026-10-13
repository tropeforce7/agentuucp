package testutil

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

// TestTimeEdgesAreTheGrammarsValues holds TimeEdges to the limit ledger's
// sentence: the header says a bound's test feeds "the edge and a second
// either side, a day and a year ahead, a year past, and the earliest and
// latest instants", and a deadline's "the earliest instant and one past
// year 9999"; TimeEdges gives exactly those, each the value its name says,
// in that order, and the header still says them.
func TestTimeEdgesAreTheGrammarsValues(t *testing.T) {
	header, err := os.ReadFile("../limits/ledger.txt")
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(strings.ReplaceAll(string(header), "#", " ")), " ")
	for _, sentence := range []string{
		"feeds the edge and a second either side, a day and a year ahead, a year past, and the earliest and latest instants",
		"feeds the earliest instant and one past year 9999",
		"testutil.TimeEdges",
	} {
		if !strings.Contains(flat, sentence) {
			t.Errorf("the ledger's header no longer says %q; TimeEdges is held to it, so change both", sentence)
		}
	}

	edge := time.Date(2026, 10, 11, 12, 5, 0, 0, time.UTC)
	want := []TimeEdge{
		{AtTheEdge, edge},
		{ASecondBefore, time.Date(2026, 10, 11, 12, 4, 59, 0, time.UTC)},
		{ASecondPast, time.Date(2026, 10, 11, 12, 5, 1, 0, time.UTC)},
		{ADayAhead, time.Date(2026, 10, 12, 12, 5, 0, 0, time.UTC)},
		{AYearAhead, time.Date(2027, 10, 11, 12, 5, 0, 0, time.UTC)},
		{AYearPast, time.Date(2025, 10, 11, 12, 5, 0, 0, time.UTC)},
		{TheEarliest, time.Unix(math.MinInt64, 0)},
		{OnePastYear9999, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{TheLatest, time.Unix(math.MaxInt64-62135596800, 999999999)},
	}
	got := TimeEdges(edge)
	if len(got) != len(want) {
		t.Fatalf("TimeEdges gave %d values, want %d: %v", len(got), len(want), got)
	}
	names := map[string]bool{}
	for i := range want {
		if got[i].Name != want[i].Name || !got[i].At.Equal(want[i].At) {
			t.Errorf("value %d: %s %v, want %s %v", i, got[i].Name, got[i].At, want[i].Name, want[i].At)
		}
		if names[got[i].Name] {
			t.Errorf("%q is given twice", got[i].Name)
		}
		names[got[i].Name] = true
	}

	// The extremes are what their names say: the earliest's Unix second
	// is the least an int64 holds, and it does not wrap; nothing the type
	// holds is after the latest, which time.Unix(math.MaxInt64, 0) is not,
	// since that wraps to before 1970; one past year 9999 is the first
	// instant RFC 3339 cannot write, and the instant before it can be.
	if s := EarliestInstant().Unix(); s != math.MinInt64 {
		t.Errorf("the earliest instant's Unix second is %d, want math.MinInt64", s)
	}
	if !LatestInstant().After(time.Unix(math.MaxInt64, 0)) || LatestInstant().Add(time.Nanosecond).After(LatestInstant()) {
		t.Errorf("the latest instant %v is not the latest the type holds", LatestInstant())
	}
	if _, err := PastYear9999().MarshalText(); err == nil {
		t.Error("one past year 9999 was written as text; the wire cannot carry it")
	}
	if _, err := PastYear9999().Add(-time.Nanosecond).MarshalText(); err != nil {
		t.Errorf("the last instant of year 9999 was refused: %v", err)
	}
}
