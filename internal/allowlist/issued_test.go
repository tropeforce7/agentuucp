package allowlist

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A pushed document's issued is held to the relay's own allowance for a
// request's clock, relayapi.MaxSkew ahead of now, and to what this program
// can write; a document from the past, however far, is taken.
func TestLimitAnAllowlistIssuedIsHeldToTheSkew(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	const ahead = "ahead of now"
	const outside = "outside the years 0000 to 9999"
	for _, c := range []struct {
		name   string
		issued time.Time
		refuse string // "" when accepted
	}{
		{"now", now, ""},
		{"a second inside the skew", now.Add(relayapi.MaxSkew - time.Second), ""},
		{"at the skew", now.Add(relayapi.MaxSkew), ""},
		{"a second past the skew", now.Add(relayapi.MaxSkew + time.Second), ahead},
		{"a day ahead", now.AddDate(0, 0, 1), ahead},
		{"a year ahead", now.AddDate(1, 0, 0), ahead},
		{"a year past", now.AddDate(-1, 0, 0), ""},
		{"the earliest writable", relayapi.EarliestWritable, ""},
		{"a nanosecond before the earliest writable", relayapi.EarliestWritable.Add(-time.Nanosecond), outside},
		{"the least Unix second", time.Unix(math.MinInt64, 0), outside},
		{"the latest instant", time.Unix(math.MaxInt64-62135596800, 999999999), ahead},
	} {
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
