package envelope

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
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
// than relayapi.MaxStampAhead ahead of the reader's clock, the chain of
// clocks a sealed stamp crosses (D83), as malformed and saying it is in
// the future, and takes every stamp up to that edge, however old, since a
// stamp has no past bound: a message may have been stored and forwarded
// for years.
//
// The bound is in whole seconds, as a request's freshness is
// (relayapi.Ahead): the edge rows are stamped at a whole second, the test
// clock's second plus the bound, so a stamp nine tenths of a second past
// the edge is that second and taken, and one a whole second past is the
// next. Open reads time.Now() itself, after the test reads it, so the
// accepted rows cannot flake. A stamp a second past the edge is refused
// only while Open's clock is in the same second as the test's; the row
// measures that and tries again when it was not, rather than reporting a
// slow machine or a second's turn as a wrong answer.
//
// Ahead compares Unix seconds and subtracts nothing, so there is no
// instant at which a difference saturates; the far-future rows are the
// latest instant the wire carries and the year 10000 instead. The type's
// own extremes, its earliest instant time.Unix(math.MinInt64, 0) and its
// latest time.Unix(math.MaxInt64-62135596800, 999999999),
// time.Unix(math.MaxInt64, 0), and the year 10000 written in UTC, cannot
// be sealed at all: json.Marshal refuses a year outside 0000 to 9999, with
// an error and not a panic, so the earliest and latest instants the wire
// carries stand for them at Open.
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

	// The grammar's values around the edge, from the test clock's whole
	// second, so a row is the second it names whatever the fraction of the
	// clock.
	edgeFrom := func(sec int64) []testutil.TimeEdge {
		return testutil.TimeEdges(time.Unix(sec, 0).Add(relayapi.MaxStampAhead))
	}
	secondPast := func(sec int64) time.Time {
		for _, e := range edgeFrom(sec) {
			if e.Name == testutil.ASecondPast {
				return e.At
			}
		}
		t.Fatal("TimeEdges gives no second past the edge")
		return time.Time{}
	}
	for _, e := range edgeFrom(time.Now().Unix()) {
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast:
			if _, _, err := Open(bob, stamped(e.At)); err != nil {
				t.Errorf("%s: %v; want opened", e.Name, err)
			}
		case testutil.ASecondPast:
			// Tried until Open's clock read in the test's second.
			for attempt := 0; ; attempt++ {
				sec := time.Now().Unix()
				_, _, err := Open(bob, stamped(secondPast(sec)))
				if err != nil || time.Now().Unix() == sec {
					refusedAsFuture(e.Name, err)
					break
				}
				if attempt == 4 {
					t.Fatal("a second past the edge: five tries each crossed a second to seal and open")
				}
			}
		case testutil.ADayAhead, testutil.AYearAhead:
			_, _, err := Open(bob, stamped(e.At))
			refusedAsFuture(e.Name, err)
		case testutil.TheEarliest, testutil.OnePastYear9999, testutil.TheLatest:
			// The type's extremes cannot be sealed, so they never reach
			// Open; the refusal is json's error and not a panic.
			if _, err := json.Marshal(inner(e.At)); err == nil || !strings.Contains(err.Error(), "year outside of range") {
				t.Errorf("%s: marshalled with %v; want the year refused", e.Name, err)
			}
		default:
			t.Fatalf("no answer for %s", e.Name)
		}
	}

	// This bound's own rows.
	for _, c := range []struct {
		label string
		ahead time.Duration
	}{
		{"twice the skew, two peers the relay accepts", 2 * relayapi.MaxSkew},
		{"nine tenths of a second past the edge, its second", relayapi.MaxStampAhead + 900*time.Millisecond},
		{"now", 0},
	} {
		at := time.Unix(time.Now().Unix(), 0).Add(c.ahead)
		if _, _, err := Open(bob, stamped(at)); err != nil {
			t.Errorf("%s: %v; want opened", c.label, err)
		}
	}
	_, _, err := Open(bob, stamped(wireLatest))
	refusedAsFuture("the latest instant the wire carries, the year 10000 in UTC", err)

	// No past bound: the earliest instant the wire carries is opened.
	if _, _, err := Open(bob, stamped(wireEarliest)); err != nil {
		t.Errorf("the earliest instant the wire carries: %v; want opened", err)
	}

	// Nor can time.Unix(math.MaxInt64, 0), which wraps to before 1970.
	if _, err := json.Marshal(inner(time.Unix(math.MaxInt64, 0))); err == nil || !strings.Contains(err.Error(), "year outside of range") {
		t.Errorf("time.Unix(math.MaxInt64, 0): marshalled with %v; want the year refused", err)
	}
}
