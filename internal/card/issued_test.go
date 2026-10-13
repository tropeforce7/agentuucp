package card

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// A pushed document's issued is held to the relay's own allowance for a
// request's clock, relayapi.MaxSkew ahead of now, and to what this program
// can write; a document from the past, however far, is taken.
func TestLimitACardIssuedIsHeldToTheSkew(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	const ahead = "ahead of now"
	const outside = "outside the years 0000 to 9999"
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
		{"the earliest writable", relayapi.EarliestWritable, ""},
		{"a nanosecond before the earliest writable", relayapi.EarliestWritable.Add(-time.Nanosecond), outside},
	}...) {
		err := CheckIssued(&Document{Issued: c.issued}, now)
		switch {
		case c.refuse == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.refuse != "" && err == nil:
			t.Errorf("%s: accepted", c.name)
		case c.refuse != "" && !strings.Contains(err.Error(), c.refuse):
			t.Errorf("%s: %v, want it to say %q", c.name, err, c.refuse)
		case c.refuse != "" && errors.Is(err, relayapi.ErrAheadOfNow) != (c.refuse == ahead):
			// The skew refusal alone is the clock's, and says so by its
			// error, which the relay reads to name its clock.
			t.Errorf("%s: errors.Is(err, ErrAheadOfNow) is %v, want %v", c.name, errors.Is(err, relayapi.ErrAheadOfNow), c.refuse == ahead)
		}
	}
}
