package relayapi

import (
	"encoding/base64"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"math"
	"net/http"
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

// TestLimitAuthHeaderLength: an auth header is held to the length its five
// fields and four spaces can reach, MaxAuthHeader, before a field is cut
// from it. The header the client itself signs — a 64-hex fingerprint, a
// ten-digit timestamp, a 16-byte nonce and a 64-byte Ed25519 signature in
// base64 — is under the rule with the room an int64's twenty characters
// leave; one exactly at the rule, its timestamp padded to twenty
// characters, parses; one byte over it is refused by the length rule
// alone, whatever its fields say. The server's own header cap,
// MaxHeaderBytes, is two orders of magnitude above this; TestLimitRequestHeadersAreCapped
// in internal/relay shows that one.
func TestLimitAuthHeaderLength(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", "https://relay.example/v1/mailbox/"+id.Fingerprint(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(id, req, []byte("body")); err != nil {
		t.Fatal(err)
	}
	own := req.Header.Get(AuthHeader)
	if len(own) > MaxAuthHeader {
		t.Fatalf("the client's own header is %d bytes, over MaxAuthHeader %d", len(own), MaxAuthHeader)
	}
	// The room: the timestamp's twenty characters less the ten it has.
	if room := MaxAuthHeader - len(own); room != 10 {
		t.Errorf("the client's own header is %d bytes under MaxAuthHeader, want 10 (an int64's twenty characters less a ten-digit timestamp)", room)
	}
	if _, err := ParseAuth(own); err != nil {
		t.Errorf("the client's own header: %v", err)
	}

	fp := strings.Repeat("a", 64)
	nonce := base64.StdEncoding.EncodeToString(make([]byte, nonceBytes))
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	header := func(ts string) string { return "v1 " + fp + " " + ts + " " + nonce + " " + sig }
	at := header(strings.Repeat("0", 10) + "1758326400")
	if len(at) != MaxAuthHeader {
		t.Fatalf("the test's header at the rule is %d bytes, want %d", len(at), MaxAuthHeader)
	}
	if a, err := ParseAuth(at); err != nil || a.TS != 1758326400 {
		t.Errorf("a header exactly at MaxAuthHeader: %+v %v; want it parsed", a, err)
	}
	over := header(strings.Repeat("0", 11) + "1758326400")
	if len(over) != MaxAuthHeader+1 {
		t.Fatalf("the test's header over the rule is %d bytes, want %d", len(over), MaxAuthHeader+1)
	}
	if _, err := ParseAuth(over); err == nil || !strings.Contains(err.Error(), "longer than its shape") {
		t.Errorf("a header one byte over MaxAuthHeader: %v; want the length rule's refusal", err)
	}
	// Longer still, and not a header at all: the same refusal, by length,
	// before any field is looked at.
	if _, err := ParseAuth(strings.Repeat("x", MaxHeaderBytes)); err == nil || !strings.Contains(err.Error(), "longer than its shape") {
		t.Errorf("a header of MaxHeaderBytes: %v; want the length rule's refusal", err)
	}
}
