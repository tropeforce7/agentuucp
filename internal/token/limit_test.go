package token

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLimitClaimsIntegers: the three integers a token carries, at the
// edges Validate holds them to and one step past, and at the type's
// extremes. not_before is positive; not_after is positive and after
// not_before; uses is within [1, MaxUses].
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
		refused(t, "not_before MaxInt64, with not_after behind it", c, "not_after is not after not_before")
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
		accepted(t, "not_after MaxInt64", c)
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
