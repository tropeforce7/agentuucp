package main

import (
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TestLimitATokensNotAfterAtTheExtremes: token ls shows each token's time
// left as token.Until(not_after, now), which compares with Before and
// takes no difference it then negates; time.Sub saturates at the Duration
// limits for a gap over about 292 years, and Until says "expired long
// ago" at the saturated past and a count of days at the saturated future.
// Fed time.Unix(math.MinInt64, 0), the year 10000, the latest instant a
// time.Time holds, and the instants either side of where Sub saturates,
// against a fixed now, it answers each without a negative wrap: expired
// long ago, or in 106751 days, the most days a Duration holds.
//
// time.Unix(math.MaxInt64, 0) is not the far future: its seconds overflow
// time.Time's own count and the instant lands before the epoch, so Until
// rightly calls it expired long ago. The latest instant the type holds is
// time.Unix(math.MaxInt64 - 62135596800, 999999999).
//
// A relay's listing is JSON, which carries the years 0000 to 9999, so the
// listing itself is fed the ends of what it can carry, the first of year
// 0 at +23:59 and the last instant of 9999 at -23:59, and prints the same
// two sentences.
func TestLimitATokensNotAfterAtTheExtremes(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	const most = "in 106751 days"
	for _, c := range []struct {
		label string
		at    time.Time
		want  string
	}{
		{"time.Unix(math.MinInt64, 0)", time.Unix(math.MinInt64, 0), "expired long ago"},
		{"a nanosecond past where Sub saturates", now.Add(-time.Duration(math.MaxInt64)).Add(-time.Nanosecond), "expired long ago"},
		{"where the difference is the largest Duration", now.Add(-time.Duration(math.MaxInt64)), "expired long ago"},
		{"a nanosecond inside it", now.Add(-time.Duration(math.MaxInt64)).Add(time.Nanosecond), "expired 106751 days ago"},
		{"a year past", now.AddDate(-1, 0, 0), "expired 365 days ago"},
		{"a day ahead", now.Add(24 * time.Hour), "in 24 hours"},
		{"a year ahead", now.AddDate(1, 0, 0), "in 365 days"},
		{"a nanosecond inside where Sub saturates", now.Add(time.Duration(math.MaxInt64)), most},
		{"a nanosecond past it", now.Add(time.Duration(math.MaxInt64)).Add(time.Nanosecond), most},
		{"the year 10000", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), most},
		{"the latest instant a time.Time holds", time.Unix(math.MaxInt64-62135596800, 999999999), most},
		{"time.Unix(math.MaxInt64, 0), which overflows to the past", time.Unix(math.MaxInt64, 0), "expired long ago"},
	} {
		if got := token.Until(c.at, now); got != c.want {
			t.Errorf("%s: %q, want %q", c.label, got, c.want)
		}
	}

	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	earliest := time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60))
	latest := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60)))
	rec := func(id string, notAfter time.Time) relayapi.TokenRecord {
		return relayapi.TokenRecord{ID: id, Issuer: boss.Fingerprint(), Use: token.UseRegister, State: relayapi.TokenLive,
			Note: "x", NotBefore: earliest, NotAfter: notAfter, Uses: 1, UsesLeft: 1}
	}
	srv := fakeRelay(t, map[string]any{
		"/v1/admin/tokens": relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{
			rec(strings.Repeat("1", 32), earliest),
			rec(strings.Repeat("2", 32), latest),
		}},
	})
	out := newPersona(t, "boss", srv.URL).run("token", "ls")
	for _, want := range []string{"expired long ago", most} {
		if !strings.Contains(out, want) {
			t.Errorf("token ls does not say %q:\n%s", want, out)
		}
	}
	// No time left is a negative duration: no minus sign stands before a
	// digit anywhere in the listing, the EXPIRES column among it.
	if negative.MatchString(out) {
		t.Errorf("token ls printed a negative number %q:\n%s", negative.FindString(out), out)
	}
}

// negative is a minus sign directly before a digit.
var negative = regexp.MustCompile(`-[0-9]`)
