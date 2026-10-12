package main

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// max_bytes has an upper bound as well as a lower one: above it, max_bytes
// plus the framing allowance overflows int64 and http.MaxBytesReader, handed a
// negative limit, refuses every body.
func TestLimitMaxBytesBoundaries(t *testing.T) {
	ceiling := relayapi.MaxBytesCeiling
	cases := []struct {
		value  int64
		accept bool
	}{
		{math.MinInt64, false},
		{-1, false},
		{0, false},
		{1, true},
		{ceiling - 1, true},
		{ceiling, true},
		{ceiling + 1, false},
		{math.MaxInt64, false},
		{math.MaxInt64 - relayapi.FramingAllowance, false},
	}
	// knock_max_bytes must sit at or under max_bytes, and its default
	// does not under a small max_bytes, so it is unset beside, as
	// max_waiting is beside a small max_inflight.
	for _, c := range cases {
		t.Run(strconv.FormatInt(c.value, 10), func(t *testing.T) {
			_, err := resolve(t, "", "--max-bytes", strconv.FormatInt(c.value, 10), "--knock-max-bytes", "0")
			if c.accept && err != nil {
				t.Fatalf("max_bytes %d was refused: %v", c.value, err)
			}
			if !c.accept {
				if err == nil {
					t.Fatalf("max_bytes %d was accepted", c.value)
				}
				if !strings.Contains(err.Error(), "max_bytes") {
					t.Fatalf("error %q does not name the setting", err)
				}
			}
		})
	}

	// The property the ceiling exists for.
	if relayapi.MaxBytesCeiling > math.MaxInt64-relayapi.FramingAllowance {
		t.Fatal("the ceiling does not prevent the overflow it exists for")
	}
}

// Every numeric limit at the extremes of its type; max_open_uploads, the
// one with a ceiling, is TestLimitRelaySettings' at its own edges.
func TestLimitsAtTypeExtremes(t *testing.T) {
	flags := []string{
		"--limit-requests", "--limit-posts", "--limit-post-bytes",
		"--limit-unauthenticated", "--limit-registrations", "--max-mailboxes",
		"--mailbox-max-messages", "--mailbox-max-bytes", "--relay-max-bytes",
		"--max-upload-opens-per-hour", "--max-inflight", "--max-waiting",
	}
	// max_waiting must sit under max_inflight when both are set, so each is
	// taken to its extremes with the other unlimited; the pair is
	// TestMaxWaitingMustBeUnderMaxInflight's.
	alone := map[string][]string{
		"--max-inflight": {"--max-waiting", "0"},
		"--max-waiting":  {"--max-inflight", "0"},
	}
	for _, flag := range flags {
		t.Run(flag, func(t *testing.T) {
			with := func(value string) []string { return append([]string{flag, value}, alone[flag]...) }
			// MaxInt64 is a real, very large limit and must be accepted.
			if _, err := resolve(t, "", with(strconv.FormatInt(math.MaxInt64, 10))...); err != nil {
				t.Fatalf("%s at MaxInt64 was refused: %v", flag, err)
			}
			// Zero means unlimited and must be accepted.
			if _, err := resolve(t, "", with("0")...); err != nil {
				t.Fatalf("%s at 0 was refused: %v", flag, err)
			}
			// One is the smallest real limit.
			if _, err := resolve(t, "", with("1")...); err != nil {
				t.Fatalf("%s at 1 was refused: %v", flag, err)
			}
			for _, bad := range []string{"-1", strconv.FormatInt(math.MinInt64, 10)} {
				_, err := resolve(t, "", with(bad)...)
				if err == nil {
					t.Fatalf("%s at %s was accepted", flag, bad)
				}
				if !strings.Contains(err.Error(), "must not be negative") {
					t.Fatalf("%s at %s: error %q does not explain", flag, bad, err)
				}
			}
			// A value that does not fit int64 is a parse error, not a silent
			// truncation.
			if _, err := resolve(t, "", with("99999999999999999999")...); err == nil {
				t.Fatalf("%s accepted a value that does not fit int64", flag)
			}
		})
	}
}

// token_max_age is a duration, so its boundary is one nanosecond.
func TestTokenMaxAgeBoundaries(t *testing.T) {
	for _, c := range []struct {
		value  string
		accept bool
	}{
		{"0s", false},
		{"-1s", false},
		{"1ns", true},
		{"1s", true},
		{"720h", true},
		{"87600h", true}, // ten years
		{"soon", false},
		{"", true}, // empty falls back to the default
	} {
		name := c.value
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			args := []string{}
			if c.value != "" {
				args = append(args, "--token-max-age", c.value)
			}
			cfg, err := resolve(t, "", args...)
			if c.accept != (err == nil) {
				t.Fatalf("token_max_age %q: err=%v, want accepted=%v", c.value, err, c.accept)
			}
			if err != nil {
				if !strings.Contains(err.Error(), "token_max_age") {
					t.Fatalf("error %q does not name the setting", err)
				}
				return
			}
			if d, err := cfg.TokenMaxAge(); err != nil || d <= 0 {
				t.Fatalf("TokenMaxAge() = %v, %v", d, err)
			}
		})
	}
}

// A relay must actually start with the extremes it accepts.
func TestRelayStartsWithExtremeLimits(t *testing.T) {
	cfg, err := resolve(t, "",
		"--max-bytes", strconv.FormatInt(relayapi.MaxBytesCeiling, 10),
		"--max-inflight", strconv.FormatInt(math.MaxInt64, 10),
		"--max-waiting", strconv.FormatInt(math.MaxInt64-1, 10),
		"--limit-post-bytes", strconv.FormatInt(math.MaxInt64, 10))
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Limits.Relay()
	if l.MaxInflight != math.MaxInt64 || l.MaxWaiting != math.MaxInt64-1 || cfg.MaxBytes != relayapi.MaxBytesCeiling {
		t.Fatalf("the extremes did not survive resolution: %+v", l)
	}
	if _, err := cfg.TokenMaxAge(); err != nil {
		t.Fatal(err)
	}
	_ = time.Second
}
