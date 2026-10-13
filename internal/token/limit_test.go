package token

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// TestLimitClaimsIntegers: the three integers a token carries, at the
// edges Validate holds them to and one step past, and at the type's
// extremes. not_before is positive; not_after is positive and after
// not_before; both are at most the last second of the year 9999 (G26);
// uses is within [1, MaxUses].
func TestLimitClaimsIntegers(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	id := admin(t)
	// base leaves the id and the issuer for Issue to fill; Validate wants
	// them first, so they are filled here as Issue would.
	base := func(now time.Time) Claims {
		c := base(now)
		c.ID = strings.Repeat("7", 32)
		c.Issuer = id.Fingerprint()
		return c
	}
	refused := func(t *testing.T, what string, c Claims, says string) {
		t.Helper()
		err := c.Validate()
		if err == nil {
			t.Errorf("%s was accepted", what)
			return
		}
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), says) {
			t.Errorf("%s: %v; want ErrForm saying %q", what, err, says)
		}
	}
	accepted := func(t *testing.T, what string, c Claims) {
		t.Helper()
		if err := c.Validate(); err != nil {
			t.Errorf("%s was refused: %v", what, err)
		}
	}

	t.Run("not_before", func(t *testing.T) {
		for _, n := range []int64{0, -1, math.MinInt64} {
			c := base(now)
			c.NotBefore = n
			refused(t, "not_before "+strconv.FormatInt(n, 10), c, "not_before is missing")
		}
		c := base(now)
		c.NotBefore = 1
		accepted(t, "not_before 1", c)
		c = base(now)
		c.NotBefore = math.MaxInt64
		// G26: a not_before past the end of the year 9999 is refused by
		// its own bound before the order of the two is looked at.
		refused(t, "not_before MaxInt64", c, "not_before is 9223372036854775807, past 253402300799, the end of the year 9999")
	})

	t.Run("not_after", func(t *testing.T) {
		for _, n := range []int64{0, -1, math.MinInt64} {
			c := base(now)
			c.NotAfter = n
			refused(t, "not_after "+strconv.FormatInt(n, 10), c, "not_after is required")
		}
		c := base(now)
		c.NotAfter = c.NotBefore
		refused(t, "not_after equal to not_before", c, "not_after is not after not_before")
		c = base(now)
		c.NotAfter = c.NotBefore - 1
		refused(t, "not_after one before not_before", c, "not_after is not after not_before")
		c = base(now)
		c.NotAfter = c.NotBefore + 1
		accepted(t, "not_after one after not_before", c)
		c = base(now)
		c.NotAfter = math.MaxInt64
		// G26: this was taken, stored, and then failed every answer that
		// carried it as a time; it is refused naming the bound.
		refused(t, "not_after MaxInt64", c, "not_after is 9223372036854775807, past 253402300799, the end of the year 9999")
	})

	t.Run("uses", func(t *testing.T) {
		for _, n := range []int{0, -1, MaxUses + 1, math.MinInt, math.MaxInt} {
			c := base(now)
			c.Uses = n
			refused(t, "uses "+strconv.Itoa(n), c, "uses must be between 1 and "+strconv.Itoa(MaxUses))
		}
		for _, n := range []int{1, MaxUses} {
			c := base(now)
			c.Uses = n
			accepted(t, "uses "+strconv.Itoa(n), c)
		}
	})
}

// TestLimitATokensDatesAreHeldToTheLastWritableSecond (G26): not_before
// and not_after are each held to 253402300799, the last whole second of
// the year 9999, which is the latest a time can be written as JSON. One
// past it was taken, stored by the relay, and then the issue answer and
// every listing failed, since json.Marshal refuses a year past 9999. At the
// bound each is taken and one past it is refused naming the field, the
// value and the bound; the times made of them are in UTC; and a token at
// the edge, issued and parsed back, has times that marshal, so it can be
// listed.
func TestLimitATokensDatesAreHeldToTheLastWritableSecond(t *testing.T) {
	const last = 253402300799
	if got := latestWritableUnix; got != last {
		t.Fatalf("the bound is %d, want %d, the last second of the year 9999", got, last)
	}
	if got := time.Unix(last, 0).UTC(); got.Year() != 9999 || got.Month() != time.December || got.Day() != 31 ||
		got.Hour() != 23 || got.Minute() != 59 || got.Second() != 59 {
		t.Fatalf("%d is %v, not the last second of the year 9999", last, got)
	}
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	id := admin(t)
	claims := func(notBefore, notAfter int64) Claims {
		c := base(now)
		c.ID, c.Issuer = strings.Repeat("7", 32), id.Fingerprint()
		c.NotBefore, c.NotAfter = notBefore, notAfter
		return c
	}
	pastSays := func(field string, n int64) string {
		return field + " is " + strconv.FormatInt(n, 10) + ", past 253402300799, the end of the year 9999"
	}

	t.Run("not_after", func(t *testing.T) {
		if err := claims(now.Unix(), last).Validate(); err != nil {
			t.Errorf("not_after %d was refused: %v", int64(last), err)
		}
		err := claims(now.Unix(), last+1).Validate()
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), pastSays("not_after", last+1)) {
			t.Errorf("not_after %d: %v; want ErrForm saying %q", int64(last+1), err, pastSays("not_after", last+1))
		}
	})

	// The grammar's values around the last second, as not_after: those
	// that are not past it are taken, and the rest refused by the form.
	t.Run("the grammar's values around the bound", func(t *testing.T) {
		for _, e := range testutil.TimeEdges(time.Unix(last, 0)) {
			n := e.At.Unix()
			err := claims(now.Unix(), n).Validate()
			switch e.Name {
			case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast:
				if err != nil {
					t.Errorf("%s, not_after %d: refused: %v", e.Name, n, err)
				}
			case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead, testutil.OnePastYear9999, testutil.TheLatest, testutil.TheEarliest:
				if !errors.Is(err, ErrForm) {
					t.Errorf("%s, not_after %d: %v; want ErrForm", e.Name, n, err)
				}
			default:
				t.Fatalf("no answer for %s", e.Name)
			}
		}
	})

	t.Run("not_before", func(t *testing.T) {
		// At the bound not_before passes its own check; no not_after can
		// then be after it and still be written, so what refuses the pair
		// is the order of the two, never the bound.
		err := claims(last, last).Validate()
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "not_after is not after not_before") {
			t.Errorf("not_before %d with not_after equal: %v; want the order refused", int64(last), err)
		}
		if strings.Contains(err.Error(), "past 253402300799") {
			t.Errorf("not_before %d is refused by the bound: %v", int64(last), err)
		}
		if err := claims(last-1, last).Validate(); err != nil {
			t.Errorf("not_before %d, a second before not_after at the bound, was refused: %v", int64(last-1), err)
		}
		err = claims(last+1, last).Validate()
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), pastSays("not_before", last+1)) {
			t.Errorf("not_before %d: %v; want ErrForm saying %q", int64(last+1), err, pastSays("not_before", last+1))
		}
	})

	t.Run("a token at the edge is issued, read back and can be listed", func(t *testing.T) {
		c := base(now)
		c.NotBefore, c.NotAfter = last-1, last
		raw, err := Issue(id, c)
		if err != nil {
			t.Fatalf("Issue at the edge: %v", err)
		}
		u, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.Verify(id.Public(), now, 0); !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("Verify at the edge: %v; want only not yet valid", err)
		}
		for _, tm := range []struct {
			name string
			at   time.Time
			unix int64
		}{
			{"NotBeforeTime", u.Claims.NotBeforeTime(), last - 1},
			{"NotAfterTime", u.Claims.NotAfterTime(), last},
		} {
			if tm.at.Location() != time.UTC {
				t.Errorf("%s is in %v, want UTC", tm.name, tm.at.Location())
			}
			if tm.at.Unix() != tm.unix {
				t.Errorf("%s is %d, want %d", tm.name, tm.at.Unix(), tm.unix)
			}
			b, err := json.Marshal(tm.at)
			if err != nil {
				t.Errorf("%s at the edge does not marshal: %v", tm.name, err)
				continue
			}
			var round time.Time
			if err := json.Unmarshal(b, &round); err != nil || !round.Equal(tm.at) {
				t.Errorf("%s marshals as %s, which reads back as %v, %v", tm.name, b, round, err)
			}
		}
		// The fault the bound closes: one second further cannot be written.
		if _, err := json.Marshal(time.Unix(last+1, 0).UTC()); err == nil {
			t.Error("a time one second past the year 9999 marshals; the bound is no longer the encoder's")
		}
	})
}

// TestLimitAnchorClaimOneShort: a token's anchor claim is 64 hex
// characters or absent, held at Validate before enrol prints its first
// sixteen; one character short, one long, and uppercase are each refused.
func TestLimitAnchorClaimOneShort(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	id := admin(t)
	for _, bad := range []string{strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64)} {
		c := base(now)
		c.ID, c.Issuer, c.Anchor = strings.Repeat("7", 32), id.Fingerprint(), bad
		if err := c.Validate(); !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "anchor must be 64 lowercase hex characters") {
			t.Errorf("anchor %q: %v; want ErrForm naming the shape", bad, err)
		}
	}
	c := base(now)
	c.ID, c.Issuer, c.Anchor = strings.Repeat("7", 32), id.Fingerprint(), strings.Repeat("a", 64)
	if err := c.Validate(); err != nil {
		t.Errorf("an anchor as written: %v", err)
	}
}
