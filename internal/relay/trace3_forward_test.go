package relay

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The third adversarial trace (reviews/trace/trace-3-v0.17.0/), F15: the
// post and a courier's delivery refused an envelope over max_bytes, but a
// forward that named a path was queued and stored whatever its size up to
// the route's body cap of max_bytes and the framing allowance, offered to
// the neighbour, whose delivery refused it.

// pathForward posts, as from, a forward of env padded to n bytes with a
// path of one relay, bar. Built by hand: json.Marshal would compact the
// envelope's padding away, and the relay holds the bytes as sent.
func pathForward(t *testing.T, h *harness, from *identity.Identity, env *envelope.Envelope, n int64) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	req := append(append([]byte(`{"envelope":`), padTo(t, raw, n)...), `,"path":["bar"],"via":[]}`...)
	status, body, _ := h.send(from, "POST", "/v1/forward", req, nil)
	return status, body
}

// storedFiles is how many regular files the relay's message tree holds,
// the queue's, the mailboxes' and the temporary ones alike.
func (h *harness) storedFiles(t *testing.T) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(h.store.dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAForwardWithAPathIsHeldToMaxBytes: on a relay at max_bytes 4096, the
// trace's 5551-byte envelope and one of a byte over max_bytes are refused
// 413 "envelope too large" on a forward with a path, as the post and a
// courier's delivery refuse them, with no row queued, no hash kept, no file
// written and nothing of the poster's carried share spent; an envelope of
// exactly max_bytes is queued.
func TestAForwardWithAPathIsHeldToMaxBytes(t *testing.T) {
	courier := neighbourID(t, "alpha")
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	c, err := NewCourier(CourierConfig{Home: root, AuthorizedFile: couriersFile(t, courier), PublicURL: "https://mine.example"}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	const maxBytes = int64(4096)
	h := newHarness(t, Config{MaxBytes: maxBytes, Courier: c, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, h)
	h.enroll(courier)
	user := h.user(t, "alice")
	bob := h.user(t, "bob")

	env := sealedFor(bob.Fingerprint(), strings.Repeat("x", int(maxBytes)))
	raw, _ := json.Marshal(env)
	if int64(len(raw)) <= maxBytes {
		t.Fatalf("test envelope is %d bytes, not over %d", len(raw), maxBytes)
	}

	// The post route: refused.
	if status, body := h.do(user, "POST", "/v1/mailbox/"+bob.Fingerprint(), raw, nil); status != 413 {
		t.Fatalf("post of %d bytes over max_bytes %d: %d %s", len(raw), maxBytes, status, body)
	}
	// A courier delivering it here: refused.
	if status, _, body := h.forward(courier, request(env, nil, nil)); status != 413 {
		t.Fatalf("delivery of %d bytes over max_bytes %d: %d %s", len(raw), maxBytes, status, body)
	}

	share := left(h.server.lim.carried, user.Fingerprint())
	nothingKept := func(t *testing.T, what string, hash string) {
		t.Helper()
		if n := h.outboundRows(t); n != 0 {
			t.Errorf("%s: %d rows queued; want none", what, n)
		}
		if n := h.carriedRows(t); n != 0 {
			t.Errorf("%s: %d hashes kept; want none", what, n)
		}
		if kept, err := h.store.Carried(hash); err != nil || kept {
			t.Errorf("%s: the envelope's hash is kept: %v, %v", what, kept, err)
		}
		if n := h.storedFiles(t); n != 0 {
			t.Errorf("%s: %d files under the message tree; want none", what, n)
		}
		if got := left(h.server.lim.carried, user.Fingerprint()); got != share {
			t.Errorf("%s: the poster's carried share is %d; it was %d before", what, got, share)
		}
	}

	// A user forwarding it onward: refused as the post and the delivery
	// refuse it.
	status, answer, body := h.forward(user, request(env, []string{"bar"}, nil))
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != "envelope too large" {
		t.Fatalf("a forward with a path of a %d-byte envelope on a relay at max_bytes %d: %d (row %d) %s; want 413 %q",
			len(raw), maxBytes, status, answer.ID, body, "envelope too large")
	}
	nothingKept(t, fmt.Sprintf("the %d-byte forward", len(raw)), CarriedHash(carried(env)))

	// One byte over max_bytes: refused, with nothing kept.
	edge := sealedFor(h.fpOf(t, "far"), "at the edge")
	hash := CarriedHash(carried(edge))
	status, body = pathForward(t, h, user, edge, maxBytes+1)
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != "envelope too large" {
		t.Fatalf("a forward with a path of %d bytes, one over: %d %s; want 413 %q", maxBytes+1, status, body, "envelope too large")
	}
	nothingKept(t, "the forward one over", hash)

	// Exactly max_bytes, the same envelope: queued, its hash kept, its
	// share spent. The refusal before wrote no hash, so this is no retry.
	status, body = pathForward(t, h, user, edge, maxBytes)
	if status != http.StatusCreated {
		t.Fatalf("a forward with a path of exactly %d bytes: %d %s; want 201", maxBytes, status, body)
	}
	if n := h.outboundRows(t); n != 1 {
		t.Errorf("the forward at max_bytes queued %d rows; want 1", n)
	}
	if kept, err := h.store.Carried(hash); err != nil || !kept {
		t.Errorf("the forward at max_bytes kept no hash: %v, %v", kept, err)
	}
	if _, bytes := h.queueCounters(t); bytes != maxBytes {
		t.Errorf("the queue holds %d bytes; want %d", bytes, maxBytes)
	}
	if got := left(h.server.lim.carried, user.Fingerprint()); got != share-1 {
		t.Errorf("the forward at max_bytes left %d of the share; want %d", got, share-1)
	}
}

// TestAForwardWithAPathIsHeldToMaxPageBytes: on a relay whose max_bytes is
// the ceiling, above MaxPageBytes, a forward with a path is held to
// MaxPageBytes, the largest row a client of this release can list, as the
// post and a courier's delivery are: one byte over is refused 413 with no
// row queued and no hash kept.
func TestAForwardWithAPathIsHeldToMaxPageBytes(t *testing.T) {
	c, err := NewCourier(CourierConfig{
		Home:           courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"}),
		AuthorizedFile: couriersFile(t), PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, Config{MaxBytes: relayapi.MaxBytesCeiling, Courier: c, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, h)
	user := h.user(t, "alice")
	env := sealedFor(h.fpOf(t, "far"), "over the page")
	status, body := pathForward(t, h, user, env, relayapi.MaxPageBytes+1)
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != "envelope too large" {
		t.Fatalf("a forward with a path of %d bytes, one over MaxPageBytes: %d %.200s; want 413 %q",
			relayapi.MaxPageBytes+1, status, body, "envelope too large")
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows queued; want none", n)
	}
	if kept, err := h.store.Carried(CarriedHash(carried(env))); err != nil || kept {
		t.Errorf("the envelope's hash is kept: %v, %v", kept, err)
	}
}
