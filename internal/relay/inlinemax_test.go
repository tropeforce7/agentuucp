package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// R10: the largest envelope a relay stores in a mailbox row is inline_max,
// max_bytes and never more than relayapi.MaxPageBytes, since a row over it
// is one no client of this release can list. The post, a courier's
// delivery and the knock refuse an envelope over it 413 by name with
// nothing stored, the post and forward routes read a body of inline_max and
// the framing allowance at most, and the health answer says max_bytes as
// set and knock_max_bytes as the knock route holds it.

// padTo is the JSON object raw with spaces before its closing brace, n
// bytes in all: white space a strict decode takes, so the envelope is the
// same envelope at any size from its own up.
func padTo(t *testing.T, raw []byte, n int64) []byte {
	t.Helper()
	if int64(len(raw)) > n || len(raw) == 0 || raw[len(raw)-1] != '}' {
		t.Fatalf("padTo: an object of %d bytes cannot be padded to %d", len(raw), n)
	}
	out := make([]byte, 0, n)
	out = append(out, raw[:len(raw)-1]...)
	out = append(out, bytes.Repeat([]byte(" "), int(n)-len(raw))...)
	return append(out, '}')
}

// inlineRoute is one route that stores an envelope in a mailbox row:
// send posts an envelope of n bytes, and rows counts what it stored.
type inlineRoute struct {
	name     string
	send     func(t *testing.T, n int64) (int, []byte)
	rows     func(t *testing.T) int64
	limit    int64  // the size taken, one over refused
	refusal  string // the sentence of the refusal
	readPath string // the route whose body cap is limit + FramingAllowance, or ""
}

// inlineRelay is a relay at maxBytes with knock_max_bytes knockMax, which
// forwards and takes deliveries from a courier, and the routes that store
// an envelope on it, each held to inline.
func inlineRelay(t *testing.T, maxBytes, knockMax, inline int64) (*harness, *identity.Identity, []inlineRoute) {
	t.Helper()
	courier := neighbourID(t, "alpha")
	c, err := NewCourier(CourierConfig{
		Home:           courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"}),
		AuthorizedFile: couriersFile(t, courier), PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	// One post a minute: a post refused for its size spends no post, so
	// the one at the cap after it is taken.
	h := newHarness(t, Config{Courier: c, CourierLimits: DefaultCourierLimits(), MaxBytes: maxBytes,
		Limits: Limits{PostsPerMinute: 1, KnockMaxBytes: knockMax}})
	quiet(t, h)
	h.enroll(courier)
	alice, bob, carol, dave := h.user(t, "alice"), h.user(t, "bob"), h.user(t, "carol"), h.user(t, "dave")
	if status, body, _ := h.pushCard(carol, carol, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	countRows := func(t *testing.T, fp string) int64 { return int64(len(h.stored(t, fp))) }
	knockText := fmt.Sprintf("knock too large: at most %d bytes (knock_max_bytes)", inline)
	return h, alice, []inlineRoute{
		{
			name: "the post",
			send: func(t *testing.T, n int64) (int, []byte) {
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), padTo(t, sealed(t, alice, bob.Public(), "post"), n), nil)
				return status, body
			},
			rows:     func(t *testing.T) int64 { return countRows(t, bob.Fingerprint()) },
			limit:    inline,
			refusal:  "envelope too large",
			readPath: "/v1/mailbox/" + bob.Fingerprint(),
		},
		{
			// The forward with no path left: delivered into a mailbox here.
			name: "a courier's delivery",
			send: func(t *testing.T, n int64) (int, []byte) {
				env, err := json.Marshal(sealedFor(alice.Fingerprint(), fmt.Sprintf("delivery %d", n)))
				if err != nil {
					t.Fatal(err)
				}
				// Built by hand: json.Marshal would compact the envelope's
				// padding away, and the relay stores the bytes as sent.
				req := append(append([]byte(`{"envelope":`), padTo(t, env, n)...), `,"path":[],"via":[]}`...)
				status, body, _ := h.send(courier, "POST", "/v1/forward", req, nil)
				return status, body
			},
			rows:     func(t *testing.T) int64 { return countRows(t, alice.Fingerprint()) },
			limit:    inline,
			refusal:  "envelope too large",
			readPath: "/v1/forward",
		},
		{
			name: "the knock",
			send: func(t *testing.T, n int64) (int, []byte) {
				// dave, whose one post a minute the post's sender has not spent.
				status, body, _ := h.send(dave, "POST", "/v1/mailbox/"+carol.Fingerprint()+"/knock",
					padTo(t, sealedKnock(t, dave, carol.Public(), "", "dave would like to exchange keys"), n), nil)
				return status, body
			},
			rows:     func(t *testing.T) int64 { return h.knockRows(carol.Fingerprint()) },
			limit:    inline,
			refusal:  knockText,
			readPath: "/v1/mailbox/" + carol.Fingerprint() + "/knock",
		},
	}
}

// checkInlineRoutes holds each route to its limit: one byte over refused
// 413 by its sentence with nothing stored, then the limit taken and one
// row stored; and a body declared one over limit + FramingAllowance
// refused 413 before a byte, naming that cap.
func checkInlineRoutes(t *testing.T, h *harness, routes []inlineRoute) {
	t.Helper()
	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			status, body := r.send(t, r.limit+1)
			if status != http.StatusRequestEntityTooLarge || errorText(t, body) != r.refusal {
				t.Fatalf("an envelope of %d bytes, one over: %d %.200s; want 413 %q", r.limit+1, status, body, r.refusal)
			}
			if n := r.rows(t); n != 0 {
				t.Fatalf("%d rows stored after the refusal; want none", n)
			}
			status, body = r.send(t, r.limit)
			if status/100 != 2 {
				t.Fatalf("an envelope of exactly %d bytes: %d %.200s; want it taken", r.limit, status, body)
			}
			if n := r.rows(t); n != 1 {
				t.Fatalf("%d rows stored after the one at the limit; want 1", n)
			}
		})
	}
}

// checkReadCaps holds each route's body cap to limit + FramingAllowance:
// a body declared one over it is refused 413 naming the cap.
func checkReadCaps(t *testing.T, h *harness, from *identity.Identity, routes []inlineRoute) {
	t.Helper()
	for _, r := range routes {
		cap := r.limit + relayapi.FramingAllowance
		status, body, _ := h.rawRequest(from, "POST", r.readPath, nil, cap+1, nil)
		want := fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, cap)
		if status != http.StatusRequestEntityTooLarge || errorText(t, body) != want {
			t.Errorf("%s, a body declared one over %d: %d %.200s; want 413 %q", r.name, cap, status, body, want)
		}
	}
}

// health is the relay's health answer.
func (h *harness) health(t *testing.T) relayapi.HealthResponse {
	t.Helper()
	status, body := h.do(nil, "GET", "/v1/health", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("health: %d %s", status, body)
	}
	var resp relayapi.HealthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestLimitInlineMax: on a relay whose max_bytes is the ceiling, an
// envelope of exactly MaxPageBytes is taken on the post, a courier's
// delivery and the knock, and one of a byte more refused 413 by the
// route's sentence with no row stored, with knock_max_bytes unset and set
// above MaxPageBytes alike; a post refused for its size spends no post.
// The post, forward and knock routes read a body of MaxPageBytes and the
// framing allowance at most. The health answer says max_bytes as set and
// knock_max_bytes as MaxPageBytes. A relay at the default max_bytes, 16
// MiB, under MaxPageBytes, is held to it exactly as before.
func TestLimitInlineMax(t *testing.T) {
	for _, tc := range []struct {
		name               string
		maxBytes, knockMax int64
		inline             int64
	}{
		{"max_bytes at the ceiling, knock_max_bytes unset", relayapi.MaxBytesCeiling, 0, relayapi.MaxPageBytes},
		{"max_bytes at the ceiling, knock_max_bytes above MaxPageBytes", relayapi.MaxBytesCeiling, 2 * relayapi.MaxPageBytes, relayapi.MaxPageBytes},
		{"max_bytes at the default", relayapi.DefaultMaxBytes, 0, relayapi.DefaultMaxBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, alice, routes := inlineRelay(t, tc.maxBytes, tc.knockMax, tc.inline)
			hr := h.health(t)
			if hr.MaxBytes != tc.maxBytes || hr.KnockMaxBytes != tc.inline {
				t.Errorf("health says max_bytes %d and knock_max_bytes %d; want %d, the setting, and %d",
					hr.MaxBytes, hr.KnockMaxBytes, tc.maxBytes, tc.inline)
			}
			checkInlineRoutes(t, h, routes)
			// Last: a cap read wider than this waits for the body it
			// declared, and the probe ends the test at its deadline.
			checkReadCaps(t, h, alice, routes)
		})
	}
}
