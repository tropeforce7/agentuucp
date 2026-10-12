package stream

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitAManifestTimeIsHeldToTheSkew: OpenManifest refuses a manifest
// stamped more than relayapi.MaxStampAhead ahead of the reader's clock,
// the chain of clocks a sealed stamp crosses (D83), as a form error saying
// it is in the future, and takes every stamp up to that edge, however
// old, since a stamp has no past bound: the envelope's rule, on the
// stream's path.
//
// The bound is in whole seconds (relayapi.Ahead), so the edge rows are
// stamped from the test clock's whole second: nine tenths of a second
// past the edge is the edge's second and taken. OpenManifest reads
// time.Now() after the test does, so the accepted rows cannot flake; the
// row a second past is judged only when OpenManifest's clock was in the
// test's second, and tried again otherwise.
//
// Ahead compares Unix seconds and subtracts nothing, so no difference
// saturates; the far-future rows are the latest instant the wire carries,
// the year 10000 in UTC, instead. The type's own extremes, its earliest
// instant time.Unix(math.MinInt64, 0) and its latest
// time.Unix(math.MaxInt64-62135596800, 999999999), time.Unix(math.MaxInt64,
// 0), and the year 10000 written in UTC, cannot be sealed, since
// json.Marshal refuses a year outside 0000 to 9999 with an error and not a
// panic, so the earliest and latest instants an RFC 3339 stamp carries,
// the first of year 0 at +23:59 and the last instant of 9999 at -23:59,
// stand for them at OpenManifest.
func TestLimitAManifestTimeIsHeldToTheSkew(t *testing.T) {
	from, to := pair(t)
	build := func() *Manifest {
		t.Helper()
		m, err := BuildManifest(from, to.Public(), "0123456789abcdef0123456789abcdef",
			Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Text: "x"},
			sourcesOf(memSource{"a", []byte("x")}), MinChunkSize)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	open := func(when time.Time) error {
		t.Helper()
		sources := sourcesOf(memSource{"a", []byte("x")})
		m := build()
		m.Time = when
		var buf bytes.Buffer
		if err := Seal(&buf, from, to.Public(), m, sources); err != nil {
			t.Fatal(err)
		}
		blob := buf.Bytes()
		n, err := ManifestLength(blob[:HeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenManifest(to, blob[:HeaderSize], blob[HeaderSize:HeaderSize+n])
		return err
	}
	refusedAsFuture := func(label string, err error) {
		t.Helper()
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "in the future") {
			t.Errorf("%s: %v; want ErrForm, in the future", label, err)
		}
	}

	for _, c := range []struct {
		label string
		ahead time.Duration
	}{
		{"twice the skew, two peers the relay accepts", 2 * relayapi.MaxSkew},
		{"a second inside the edge", relayapi.MaxStampAhead - time.Second},
		{"at the edge", relayapi.MaxStampAhead},
		{"nine tenths of a second past the edge, its second", relayapi.MaxStampAhead + 900*time.Millisecond},
		{"now", 0},
		{"a year past", -365 * 24 * time.Hour},
	} {
		if err := open(time.Unix(time.Now().Unix(), 0).Add(c.ahead)); err != nil {
			t.Errorf("%s: %v; want opened", c.label, err)
		}
	}

	for attempt := 0; ; attempt++ {
		sec := time.Now().Unix()
		err := open(time.Unix(sec, 0).Add(relayapi.MaxStampAhead + time.Second))
		if err != nil || time.Now().Unix() == sec {
			refusedAsFuture("a second past the edge", err)
			break
		}
		if attempt == 4 {
			t.Fatal("a second past the edge: five tries each crossed a second to seal and open")
		}
	}

	latest := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60)))
	for _, c := range []struct {
		label string
		when  time.Time
	}{
		{"a day ahead", time.Now().Add(24 * time.Hour)},
		{"a year ahead", time.Now().AddDate(1, 0, 0)},
		{"the latest instant the wire carries, the year 10000 in UTC", latest},
	} {
		refusedAsFuture(c.label, open(c.when))
	}

	// No past bound: the earliest instant the wire carries is opened.
	earliest := time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60))
	if err := open(earliest); err != nil {
		t.Errorf("the earliest instant the wire carries: %v; want opened", err)
	}

	// The type's extremes cannot be encoded, so they never reach
	// OpenManifest; the refusal is json's error and not a panic.
	for _, c := range []struct {
		label string
		when  time.Time
	}{
		{"time.Unix(math.MinInt64, 0)", time.Unix(math.MinInt64, 0)},
		{"the year 10000", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"the latest instant a time.Time holds", time.Unix(math.MaxInt64-62135596800, 999999999)},
		{"time.Unix(math.MaxInt64, 0)", time.Unix(math.MaxInt64, 0)},
	} {
		m := build()
		m.Time = c.when
		if _, err := json.Marshal(m); err == nil || !strings.Contains(err.Error(), "year outside of range") {
			t.Errorf("%s: marshalled with %v; want the year refused", c.label, err)
		}
	}
}
