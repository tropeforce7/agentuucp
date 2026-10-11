package channels

import (
	"math"
	"strings"
	"testing"
	"time"
)

// TestLimitAChannelWindowAtTheExtremes: a channel's not_before and
// not_after are compared with now by OpenAt and with each other by
// Validate, with Before and After, which hold over the type's whole range.
// Fed time.Unix(math.MinInt64, 0) and the year 10000 as either bound, both
// answer without a panic and rightly: a window from the first to the
// second is open now, one that opens in the year 10000 is not yet open and
// says when, one that closed at the far past is closed, and a window whose
// not_before is after its not_after is refused by Validate, naming both.
// The not-yet rows take the year 10000 rather than a date from the clock,
// since no clock this suite runs under will reach it.
//
// time.Unix(math.MaxInt64, 0) is not the far future: its seconds overflow
// time.Time's own count, and the instant lands before the epoch, so as a
// not_after it is a channel closed long ago. The far-future value that is
// one is the latest instant the type holds, time.Unix(math.MaxInt64 -
// 62135596800, 999999999). Both are fed, and each answers as the instant
// it really is.
//
// The json writer cannot carry a year outside 0000 to 9999, so Sign
// refuses a directory with either extreme in it, with json's error and
// not a panic, and such a directory never travels. What the wire can
// carry at its ends, the first of year 0 at +23:59 and the last instant of
// 9999 at -23:59, the year -1 and the year 10000 in UTC, signs, verifies
// and keeps its answers.
func TestLimitAChannelWindowAtTheExtremes(t *testing.T) {
	id := owner(t)
	now := time.Now()
	far := time.Unix(math.MinInt64, 0)
	y10k := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	wrapped := time.Unix(math.MaxInt64, 0)
	latest := time.Unix(math.MaxInt64-62135596800, 999999999)
	ptr := func(t time.Time) *time.Time { return &t }

	for _, c := range []struct {
		label     string
		nb, na    *time.Time
		valid     bool
		open      bool
		whyPrefix string
	}{
		{"from the far past to the year 10000", ptr(far), ptr(y10k), true, true, ""},
		{"from the far past, no end", ptr(far), nil, true, true, ""},
		{"no start, to the year 10000", nil, ptr(y10k), true, true, ""},
		{"opening in the year 10000", ptr(y10k), nil, true, false, "opens 10000-01-01T00:00:00Z"},
		{"closed at the far past", nil, ptr(far), true, false, "closed "},
		{"the year 10000 before the far past", ptr(y10k), ptr(far), false, false, "opens 10000-01-01T00:00:00Z"},
		{"the far past at both edges", ptr(far), ptr(far), true, false, "closed "},
		{"the year 10000 at both edges", ptr(y10k), ptr(y10k), true, false, "opens 10000-01-01T00:00:00Z"},
		{"to the latest instant the type holds", ptr(now.Add(-time.Hour)), ptr(latest), true, true, ""},
		{"to time.Unix(math.MaxInt64, 0), which is in the past", nil, ptr(wrapped), true, false, "closed "},
	} {
		t.Run(c.label, func(t *testing.T) {
			d := base(id)
			d.Channels[1].NotBefore, d.Channels[1].NotAfter = c.nb, c.na
			err := d.Validate()
			if c.valid && err != nil {
				t.Errorf("Validate: %v", err)
			}
			if !c.valid && (err == nil || !strings.Contains(err.Error(), "is after not_after")) {
				t.Errorf("Validate: %v; want the window refused as backwards", err)
			}
			open, why := d.Channels[1].OpenAt(now)
			if open != c.open || !strings.HasPrefix(why, c.whyPrefix) {
				t.Errorf("OpenAt: open %v, %q; want %v, %q", open, why, c.open, c.whyPrefix)
			}
			if c.open && why != "" {
				t.Errorf("OpenAt: open with the reason %q", why)
			}
			if _, _, err := Sign(id, d); c.valid && (err == nil || !strings.Contains(err.Error(), "year outside of range")) {
				t.Errorf("Sign: %v; want json's refusal of the year", err)
			}
		})
	}

	// The ends of the wire round-trip, and answer as the instants they are.
	earliest := time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60))
	wireLatest := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60)))
	for _, c := range []struct {
		label     string
		nb, na    *time.Time
		open      bool
		whyPrefix string
	}{
		{"the whole of the wire", ptr(earliest), ptr(wireLatest), true, ""},
		{"opening at the wire's last instant", ptr(wireLatest), nil, false, "opens 10000-01-01T23:58:59Z"},
		{"closed at the wire's first instant", nil, ptr(earliest), false, "closed -0001-12-31T00:01:00Z"},
	} {
		t.Run(c.label, func(t *testing.T) {
			d := base(id)
			d.Channels[1].NotBefore, d.Channels[1].NotAfter = c.nb, c.na
			doc, sig, err := Sign(id, d)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			got, err := Verify(id.Public(), doc, sig)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			open, why := got.Channels[1].OpenAt(time.Now())
			if open != c.open || !strings.HasPrefix(why, c.whyPrefix) {
				t.Errorf("OpenAt: open %v, %q; want %v, %q", open, why, c.open, c.whyPrefix)
			}
		})
	}
}
