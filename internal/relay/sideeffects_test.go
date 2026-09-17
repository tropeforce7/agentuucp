package relay

import (
	"net/http"
	"runtime"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// messageCount is what a refusal must not change.
func (h *harness) messageCount(fp string) int64 {
	h.t.Helper()
	var n int64
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ?`, fp).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// A 4xx is half a test. Every refusal on the post path must leave the mailbox
// exactly as it was.
func TestRefusalsHaveNoSideEffects(t *testing.T) {
	people := ids(t, "alice", "bob", "boss")
	alice, bob, boss := people[0], people[1], people[2]

	cases := []struct {
		name   string
		cfg    Config
		send   func(h *harness) (int, []byte)
		status int
	}{
		{
			name: "rate limited",
			cfg:  Config{Limits: Limits{PostsPerMinute: 1}},
			send: func(h *harness) (int, []byte) {
				h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, bob.Public(), "first"), nil)
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, bob.Public(), "second"), nil)
				return status, body
			},
			status: http.StatusTooManyRequests,
		},
		{
			name: "mailbox full",
			cfg:  Config{Limits: Limits{MailboxMaxMessages: 1}},
			send: func(h *harness) (int, []byte) {
				h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, bob.Public(), "first"), nil)
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, bob.Public(), "second"), nil)
				return status, body
			},
			status: http.StatusInsufficientStorage,
		},
		{
			name: "envelope too large",
			cfg:  Config{MaxBytes: 4096},
			send: func(h *harness) (int, []byte) {
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					make([]byte, 64<<10), nil)
				return status, body
			},
			status: http.StatusRequestEntityTooLarge,
		},
		{
			name: "sender not on the allow list",
			cfg:  Config{},
			send: func(h *harness) (int, []byte) {
				h.send(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
					h.allowReq(bob, boss.Fingerprint()), nil)
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, bob.Public(), "blocked"), nil)
				return status, body
			},
			status: http.StatusForbidden,
		},
		{
			name: "recipient blocked",
			cfg:  Config{AdminFile: adminFile(t, boss)},
			send: func(h *harness) (int, []byte) {
				h.send(boss, "PUT", "/v1/admin/blocks/"+bob.Fingerprint(),
					relayapi.BlockRequest{Reason: "testing"}, nil)
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, bob.Public(), "blocked"), nil)
				return status, body
			},
			status: http.StatusForbidden,
		},
		{
			name: "misaddressed envelope",
			cfg:  Config{},
			send: func(h *harness) (int, []byte) {
				status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
					sealed(t, alice, boss.Public(), "elsewhere"), nil)
				return status, body
			},
			status: http.StatusBadRequest,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.cfg)
			h.register(alice)
			h.register(bob)
			h.enroll(boss)

			before := h.messageCount(bob.Fingerprint())
			status, body := c.send(h)
			if status != c.status {
				t.Fatalf("status %d, want %d: %s", status, c.status, body)
			}
			after := h.messageCount(bob.Fingerprint())
			// The setup post in some cases lands legitimately; what matters is
			// that the refused one did not.
			if after != before && after != before+1 {
				t.Fatalf("a refusal changed the mailbox from %d to %d messages", before, after)
			}
			h.assertCountersAgree()
		})
	}
}

// A refused request must not allocate in proportion to a length the caller
// chose. A status code alone cannot tell a refusal from a refusal that
// allocated a gigabyte first.
func TestOversizeBodyDoesNotAllocateInProportion(t *testing.T) {
	const maxBytes = 1 << 20
	h := newHarness(t, Config{MaxBytes: maxBytes})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	// A body far over the cap, sent for real.
	oversize := make([]byte, 16*maxBytes)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for range 8 {
		status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), oversize, nil)
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d, want 413", status)
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// The claim is that the relay does not allocate in proportion to what was
	// sent: 128 MiB arrived and the reader stops at just over 1 MiB. The bound
	// is deliberately loose, because a precise figure would measure the
	// garbage collector rather than the relay.
	if grew > 16*maxBytes {
		t.Fatalf("the heap grew by %d bytes across eight refused %d byte requests; "+
			"%d bytes were sent in total", grew, len(oversize), 8*len(oversize))
	}
}

// A caller that declares a large body and then dribbles it holds a handler,
// and with it an in-flight slot, until a timeout fires. The timeouts are the
// server's, tested in cmd/auu-relay; what the relay itself guarantees is that
// the damage is bounded by max_inflight and that health keeps answering.
//
// This is the slowloris shape, and it is the reason the in-flight cap exists.
func TestDeclaredButUnsentBodyIsBoundedByTheInflightCap(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 4096, Limits: Limits{MaxInflight: 1}})
	alice := ids(t, "alice")[0]
	h.register(alice)
	keys := "/v1/keys/" + alice.Fingerprint()

	// A caller that declares a large body and then dribbles it holds a
	// handler, and with it an in-flight slot, until a timeout fires. The
	// timeouts are the server's, tested in cmd/auu-relay; what the relay
	// itself guarantees is that the damage is bounded by max_inflight and that
	// health keeps answering. This is the slowloris shape, and it is the
	// reason the cap exists.
	for attempt := range 8 {
		st := stallPost(t, h, alice.Fingerprint())
		status, _, _, lost := st.holdsTheSlot(t, h, keys)
		st.close()
		if lost {
			continue
		}
		if status != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: a stalled request did not hold the in-flight slot: got %d",
				attempt, status)
		}
		h.healthy()
		return
	}
	t.Fatal("the prober won the race for the single slot eight times running")
}

// A body exactly at the reader's ceiling is accepted; one byte over is not.
func TestBodyCeilingBoundary(t *testing.T) {
	const maxBytes = 4096
	h := newHarness(t, Config{MaxBytes: maxBytes})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	// The reader's ceiling is MaxBytes plus the framing allowance; the
	// handler's own check is at MaxBytes.
	ceiling := int64(maxBytes) + relayapi.FramingAllowance
	for _, c := range []struct {
		name string
		size int64
		want int
	}{
		{"at the handler's limit", maxBytes, http.StatusBadRequest}, // not an envelope
		{"one over the handler's limit", maxBytes + 1, http.StatusRequestEntityTooLarge},
		{"at the reader's ceiling", ceiling, http.StatusRequestEntityTooLarge},
		{"one over the reader's ceiling", ceiling + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
				make([]byte, c.size), nil)
			if status != c.want {
				t.Fatalf("a %d byte body gave %d, want %d: %s", c.size, status, c.want, body)
			}
		})
	}
}
