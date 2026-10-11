package envelope

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The two ends of what an RFC 3339 stamp can carry. time.Time's decoder
// takes the years 0000 to 9999 as written, and an offset up to a minute
// short of a day either way, so the earliest instant on the wire is the
// first of year 0 at +23:59, the last day of year -1 in UTC, and the
// latest is the last instant of 9999 at -23:59, a day into the year 10000
// in UTC. Nothing outside them can be decoded, so nothing outside them
// reaches a check that runs after the decode.
var (
	wireEarliest = time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60))
	wireLatest   = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60)))
)

// TestLimitAnInnerTimeIsHeldToTheSkew: Open refuses an inner stamped more
// than relayapi.MaxSkew ahead of the reader's clock, as malformed and
// saying it is in the future, and takes every stamp up to that edge,
// however old, since a stamp has no past bound: a message may have been
// stored and forwarded for years.
//
// Open reads time.Now() itself, after the test reads it, so a stamp at
// the test's now plus the skew is at the edge or inside it when Open
// looks, and the accepted rows cannot flake. A stamp a second past the
// edge is refused only while less than a second passes between the
// test's clock and Open's; the row measures that and tries again when it
// did not hold, rather than reporting a slow machine as a wrong answer.
//
// The check is After and not Sub, so there is no instant at which a
// difference saturates; the far-future rows are the latest instant the
// wire carries and the year 10000 instead. The type's own extremes, its
// earliest instant time.Unix(math.MinInt64, 0) and its latest
// time.Unix(math.MaxInt64-62135596800, 999999999), and the year 10000
// written in UTC, cannot be sealed at all: json.Marshal refuses a year
// outside 0000 to 9999, with an error and not a panic, so the earliest and
// latest instants the wire carries stand for them at Open.
func TestLimitAnInnerTimeIsHeldToTheSkew(t *testing.T) {
	alice, bob := pair(t)
	inner := func(when time.Time) *Inner {
		return &Inner{
			V: Version, From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
			ID: "0123456789abcdef0123456789abcdef", Time: when, Body: body(t),
		}
	}
	stamped := func(when time.Time) *Envelope {
		t.Helper()
		innerBytes, err := json.Marshal(inner(when))
		if err != nil {
			t.Fatal(err)
		}
		plaintext := append(append([]byte{}, mustSign(t, alice, sigInput(bob.Fingerprint(), innerBytes))...), innerBytes...)
		return sealPlaintext(t, bob.Public(), plaintext)
	}
	refusedAsFuture := func(label string, err error) {
		t.Helper()
		if Cause(err) != ErrMalformed || !strings.Contains(errors.Unwrap(err).Error(), "in the future") {
			t.Errorf("%s: %v (beneath: %v); want malformed, in the future", label, err, errors.Unwrap(err))
		}
	}

	for _, c := range []struct {
		label string
		ahead time.Duration
	}{
		{"a second inside the skew", relayapi.MaxSkew - time.Second},
		{"at the skew", relayapi.MaxSkew},
		{"now", 0},
		{"a year past", -365 * 24 * time.Hour},
	} {
		if _, _, err := Open(bob, stamped(time.Now().Add(c.ahead))); err != nil {
			t.Errorf("%s: %v; want opened", c.label, err)
		}
	}

	// A second past the edge, tried until Open's clock read within a second
	// of the test's.
	for attempt := 0; ; attempt++ {
		start := time.Now()
		_, _, err := Open(bob, stamped(start.Add(relayapi.MaxSkew+time.Second)))
		if err != nil || time.Since(start) < time.Second {
			refusedAsFuture("a second past the skew", err)
			break
		}
		if attempt == 4 {
			t.Fatal("a second past the skew: five tries each took a second or more to seal and open")
		}
	}

	for _, c := range []struct {
		label string
		when  time.Time
	}{
		{"a day ahead", time.Now().Add(24 * time.Hour)},
		{"a year ahead", time.Now().AddDate(1, 0, 0)},
		{"the latest instant the wire carries, the year 10000 in UTC", wireLatest},
	} {
		_, _, err := Open(bob, stamped(c.when))
		refusedAsFuture(c.label, err)
	}

	// No past bound: the earliest instant the wire carries is opened.
	if _, _, err := Open(bob, stamped(wireEarliest)); err != nil {
		t.Errorf("the earliest instant the wire carries: %v; want opened", err)
	}

	// The type's extremes cannot be sealed, so they never reach Open; the
	// refusal is json's error and not a panic.
	for _, c := range []struct {
		label string
		when  time.Time
	}{
		{"time.Unix(math.MinInt64, 0)", time.Unix(math.MinInt64, 0)},
		{"the year 10000", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"the latest instant a time.Time holds", time.Unix(math.MaxInt64-62135596800, 999999999)},
	} {
		if _, err := json.Marshal(inner(c.when)); err == nil || !strings.Contains(err.Error(), "year outside of range") {
			t.Errorf("%s: marshalled with %v; want the year refused", c.label, err)
		}
	}
}
