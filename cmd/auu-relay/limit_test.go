package main

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitRelaySettings: every integer setting of the relay, from the
// file and from its flag. max_bytes is within [1, MaxBytesCeiling]
// (TestLimitMaxBytesBoundaries walks its edges); max_stream_bytes and the
// eleven limits are zero or more, zero meaning unlimited: a negative and
// the type's minimum are refused naming the setting, and zero and the
// type's maximum are taken. A flag is read as text: the text one past the
// type's maximum, a sign inside the digits, a leading space and a digit
// outside ASCII are the flag package's refusals, a minus before zero is
// zero, and a plus sign is the number.
func TestLimitRelaySettings(t *testing.T) {
	settings := []struct{ key, flag string }{
		{"max_stream_bytes", "--max-stream-bytes"},
		{"limits.requests_per_minute", "--limit-requests"},
		{"limits.posts_per_minute", "--limit-posts"},
		{"limits.post_bytes_per_hour", "--limit-post-bytes"},
		{"limits.unauthenticated_per_minute", "--limit-unauthenticated"},
		{"limits.registrations_per_hour", "--limit-registrations"},
		{"limits.max_mailboxes", "--max-mailboxes"},
		{"limits.mailbox_max_messages", "--mailbox-max-messages"},
		{"limits.mailbox_max_bytes", "--mailbox-max-bytes"},
		{"limits.relay_max_bytes", "--relay-max-bytes"},
		{"limits.max_inflight", "--max-inflight"},
		{"limits.max_waiting", "--max-waiting"},
	}
	// max_waiting must sit under max_inflight when both are set, so each
	// is taken to its extremes with the other unlimited.
	alone := map[string]string{"limits.max_inflight": "limits.max_waiting", "limits.max_waiting": "limits.max_inflight"}
	aloneFlag := map[string]string{"--max-inflight": "--max-waiting", "--max-waiting": "--max-inflight"}

	fileWith := func(key string, value string) string {
		name := key
		if strings.HasPrefix(key, "limits.") {
			name = strings.TrimPrefix(key, "limits.")
			other := ""
			if o, ok := alone[key]; ok {
				other = `, "` + strings.TrimPrefix(o, "limits.") + `": 0`
			}
			return writeFile(t, `{"limits": {"`+name+`": `+value+other+`}}`)
		}
		return writeFile(t, `{"`+name+`": `+value+`}`)
	}
	flagsWith := func(flag, value string) []string {
		args := []string{flag, value}
		if o, ok := aloneFlag[flag]; ok {
			args = append(args, o, "0")
		}
		return args
	}
	short := func(key string) string { return strings.TrimPrefix(key, "limits.") }

	for _, s := range settings {
		t.Run(s.key, func(t *testing.T) {
			for _, v := range []int64{-1, math.MinInt64} {
				text := strconv.FormatInt(v, 10)
				if _, err := resolve(t, fileWith(s.key, text)); err == nil || !strings.Contains(err.Error(), short(s.key)) {
					t.Errorf("%s %d in the file: %v; want the refusal naming it", s.key, v, err)
				}
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err == nil || !strings.Contains(err.Error(), short(s.key)) {
					t.Errorf("%s %d: %v; want the refusal naming the setting", s.flag, v, err)
				}
			}
			for _, v := range []int64{0, math.MaxInt64} {
				text := strconv.FormatInt(v, 10)
				if _, err := resolve(t, fileWith(s.key, text)); err != nil {
					t.Errorf("%s %d in the file: %v; want it taken", s.key, v, err)
				}
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err != nil {
					t.Errorf("%s %d: %v; want it taken", s.flag, v, err)
				}
			}
			for _, text := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.0", ""} {
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err == nil || !strings.Contains(err.Error(), `invalid value "`+text+`" for flag -`+strings.TrimPrefix(s.flag, "--")) {
					t.Errorf("%s %q: %v; want the flag package's refusal", s.flag, text, err)
				}
			}
			for _, text := range []string{"-0", "+1"} {
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err != nil {
					t.Errorf("%s %q: %v; want it taken", s.flag, text, err)
				}
			}
			// The file is JSON: a number the type cannot hold is the
			// decoder's refusal, naming the field.
			if _, err := resolve(t, fileWith(s.key, "9223372036854775808")); err == nil {
				t.Errorf("%s one past the type's maximum in the file was taken", s.key)
			}
		})
	}

	t.Run("max_bytes", func(t *testing.T) {
		ceiling := strconv.FormatInt(relayapi.MaxBytesCeiling, 10)
		for _, text := range []string{"0", "-1", strconv.FormatInt(math.MinInt64, 10), strconv.FormatInt(relayapi.MaxBytesCeiling+1, 10), strconv.FormatInt(math.MaxInt64, 10)} {
			if _, err := resolve(t, fileWith("max_bytes", text)); err == nil || !strings.Contains(err.Error(), "max_bytes") {
				t.Errorf("max_bytes %s in the file: %v; want the refusal naming it", text, err)
			}
		}
		for _, text := range []string{"1", ceiling} {
			if _, err := resolve(t, fileWith("max_bytes", text)); err != nil {
				t.Errorf("max_bytes %s in the file: %v; want it taken", text, err)
			}
		}
		for _, text := range []string{"9223372036854775808", "1-2", " 1", "\u0661", ""} {
			if _, err := resolve(t, "", "--max-bytes", text); err == nil || !strings.Contains(err.Error(), `invalid value "`+text+`" for flag -max-bytes`) {
				t.Errorf("--max-bytes %q: %v; want the flag package's refusal", text, err)
			}
		}
		if _, err := resolve(t, "", "--max-bytes", "-0"); err == nil || !strings.Contains(err.Error(), "max_bytes must be positive") {
			t.Errorf("--max-bytes -0: %v; want zero refused", err)
		}
		if _, err := resolve(t, "", "--max-bytes", "+1"); err != nil {
			t.Errorf("--max-bytes +1: %v; want it taken", err)
		}
	})
}

// TestLimitDurationSettings: the three durations the relay's file carries
// as text, read by time.ParseDuration. client_certs.lifetime is within
// [an hour, ten years]; upload_ttl and admin.token_max_age are more than
// nothing. One under and one over a bound, zero, a negative, the text one
// past the type's maximum, a bare number, "inf", a unit alone and a digit
// outside ASCII are each refused naming the setting; the bounds, a plus
// sign and an empty setting (the default) are taken.
func TestLimitDurationSettings(t *testing.T) {
	file := func(key, value string) string {
		switch key {
		case "client_certs.lifetime":
			return writeFile(t, `{"client_certs": {"mode": "off", "lifetime": "`+value+`"}}`)
		case "admin.token_max_age":
			return writeFile(t, `{"admin": {"token_max_age": "`+value+`"}}`)
		}
		return writeFile(t, `{"`+key+`": "`+value+`"}`)
	}
	forms := []string{"9223372037s", "1", "inf", "s", "-1h", "\u0661h", "1.5", "1h "}
	t.Run("client_certs.lifetime", func(t *testing.T) {
		for _, v := range append([]string{"59m59s", "87601h", "0s", "-1s"}, forms...) {
			if _, err := resolve(t, file("client_certs.lifetime", v)); err == nil || !strings.Contains(err.Error(), "client_certs.lifetime") {
				t.Errorf("lifetime %q: %v; want the refusal naming it", v, err)
			}
		}
		for _, v := range []string{"1h", "+1h", "87600h", ""} {
			if _, err := resolve(t, file("client_certs.lifetime", v)); err != nil {
				t.Errorf("lifetime %q: %v; want it taken", v, err)
			}
		}
	})
	for _, key := range []string{"upload_ttl", "admin.token_max_age"} {
		t.Run(key, func(t *testing.T) {
			for _, v := range append([]string{"0s", "-1s", "-9223372036854775808ns"}, forms...) {
				if _, err := resolve(t, file(key, v)); err == nil || !strings.Contains(err.Error(), key) {
					t.Errorf("%s %q: %v; want the refusal naming it", key, v, err)
				}
			}
			for _, v := range []string{"1ns", "+1s", "9223372036854775807ns", ""} {
				if _, err := resolve(t, file(key, v)); err != nil {
					t.Errorf("%s %q: %v; want it taken", key, v, err)
				}
			}
		})
	}
}
