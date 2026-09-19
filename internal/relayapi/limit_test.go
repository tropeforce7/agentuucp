package relayapi

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLimitAuthTimestamp: the timestamp in an auth header is open, read
// as text: the type's minimum, a negative, zero and the type's maximum
// each parse and are each stale at any real clock, compared against the
// window's edges and never subtracted; the text one past the type's
// maximum, a sign inside the digits and a digit outside ASCII are each a
// bad timestamp, and a leading plus is the number.
func TestLimitAuthTimestamp(t *testing.T) {
	fp := strings.Repeat("a", 64)
	nonce := base64.StdEncoding.EncodeToString(make([]byte, nonceBytes))
	sig := base64.StdEncoding.EncodeToString([]byte("sig"))
	header := func(ts string) string { return "v1 " + fp + " " + ts + " " + nonce + " " + sig }
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	for _, ts := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
		a, err := ParseAuth(header(strconv.FormatInt(ts, 10)))
		if err != nil || a.TS != ts {
			t.Errorf("timestamp %d: %+v %v; want it read as written", ts, a, err)
			continue
		}
		// Stale at every real clock; a clock at the epoch reads zero as
		// fresh, which is the window working, not a hole.
		for _, clock := range []time.Time{now, time.Unix(math.MaxInt64/2, 0)} {
			if a.FreshAt(clock) {
				t.Errorf("timestamp %d is fresh at %s", ts, clock)
			}
		}
	}
	for _, ts := range []string{"9223372036854775808", "-9223372036854775809", "1-2", "\u0661", "0x1", "1.0", ""} {
		_, err := ParseAuth(header(ts))
		if err == nil || (!strings.Contains(err.Error(), "bad timestamp") && !strings.Contains(err.Error(), "malformed")) {
			t.Errorf("timestamp %q: %v; want a bad timestamp or a malformed header", ts, err)
		}
	}
	for _, tc := range []struct {
		text string
		want int64
	}{{"+1", 1}, {"-0", 0}, {strconv.FormatInt(now.Unix(), 10), now.Unix()}} {
		a, err := ParseAuth(header(tc.text))
		if err != nil || a.TS != tc.want {
			t.Errorf("timestamp %q: %+v %v; want %d", tc.text, a, err, tc.want)
		}
	}
	if a, _ := ParseAuth(header(strconv.FormatInt(now.Unix(), 10))); a == nil || !a.FreshAt(now) {
		t.Error("the clock's own reading is not fresh")
	}
}
