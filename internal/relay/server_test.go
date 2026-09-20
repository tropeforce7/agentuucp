package relay

import (
	"bytes"
	"crypto/mldsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	server *Server
	store  *Store
	clock  *testClock
	logs   *syncBuffer
}

// testClock is the injected time source the rate limiters read, so a test can
// step past a refill period without sleeping.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// syncBuffer collects the access log. Requests are served on many goroutines,
// so it has to be safe to write from all of them.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// nonceCount reports how many replay-protection rows the relay is holding.
func (h *harness) nonceCount() int {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM nonces`).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	// Streams are a capability the library leaves off unless asked, as
	// auu-relay asks. Tests want them on unless they are testing the refusal.
	if !cfg.streamsSet {
		cfg.Streams = true
	}
	_ = cfg.streamsSet
	logs := &syncBuffer{}
	cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
	clock := newTestClock()
	if cfg.Now == nil {
		cfg.Now = clock.Now
	}
	server := NewServer(store, cfg)
	srv := httptest.NewUnstartedServer(server)
	// The header cap auu-relay's listener sets, so a test here meets the
	// same 431 net/http answers in deployment.
	srv.Config.MaxHeaderBytes = relayapi.MaxHeaderBytes
	srv.Start()
	// Close wakes what the relay holds before the listener waits for it,
	// as auu-relay does: a test that leaves a listing held would otherwise
	// wait out the hold here.
	t.Cleanup(func() { server.Close(); srv.Close() })
	return &harness{t: t, srv: srv, server: server, store: store, clock: clock, logs: logs}
}

// do signs and sends a request, returning the status and body.
func (h *harness) do(id *identity.Identity, method, path string, payload any, headers map[string]string) (int, []byte) {
	h.t.Helper()
	var body []byte
	if payload != nil {
		var err error
		if raw, ok := payload.([]byte); ok {
			body = raw
		} else if body, err = json.Marshal(payload); err != nil {
			h.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if id != nil {
		if err := relayapi.SignRequest(id, req, body); err != nil {
			h.t.Fatal(err)
		}
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, out
}

func (h *harness) register(id *identity.Identity) {
	h.t.Helper()
	status, body := h.registerWith(id, "")
	if status != http.StatusOK {
		h.t.Fatalf("register: status %d: %s", status, body)
	}
	var resp relayapi.RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		h.t.Fatal(err)
	}
	if resp.FP != id.Fingerprint() {
		h.t.Fatalf("register returned fp %s, want %s", resp.FP, id.Fingerprint())
	}
}

// registerWith registers an identity, its certificate request carrying tok.
// The key is thrown away: tests that need to hold one use machineKey.
func (h *harness) registerWith(id *identity.Identity, tok string) (int, []byte) {
	h.t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		h.t.Fatal(err)
	}
	return h.registerKey(id, key, tok)
}

// registerBody is a register request carrying a fresh certificate request,
// for the tests that send one through h.send because they want the response
// header or a specific status. A request without one is malformed: the
// enrolment token lives inside it.
func (h *harness) registerBody(id *identity.Identity, name, tok string) relayapi.RegisterRequest {
	h.t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		h.t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "test-machine", tok)
	if err != nil {
		h.t.Fatal(err)
	}
	return relayapi.RegisterRequest{Bundle: id.Public().Bundle(), Name: name, CSR: csr}
}

// registerKey registers with a key the caller holds, so it can go on to use
// the certificate that comes back.
func (h *harness) registerKey(id *identity.Identity, key *mldsa.PrivateKey, tok string) (int, []byte) {
	h.t.Helper()
	csr, err := clientca.NewCSR(key, "test-machine", tok)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do(id, "POST", "/v1/register",
		relayapi.RegisterRequest{Bundle: id.Public().Bundle(), Name: id.Name, CSR: csr}, nil)
}

func sealed(t *testing.T, from *identity.Identity, to *identity.Public, text string) []byte {
	t.Helper()
	env, _, err := envelope.Seal(from, to, message.Body{
		Type: message.TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Subject: "s", Text: text,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ids(t *testing.T, names ...string) []*identity.Identity {
	t.Helper()
	var out []*identity.Identity
	for _, n := range names {
		id, err := identity.Generate(n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func TestDeliveryRoundTrip(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	raw := sealed(t, alice, bob.Public(), "does the relay see this?")
	status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), raw, nil)
	if status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}

	status, body = h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?after=0", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	var list relayapi.ListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(list.Messages))
	}

	// The relay handed back something bob can actually open, byte for byte.
	var env envelope.Envelope
	if err := json.Unmarshal(list.Messages[0].Envelope, &env); err != nil {
		t.Fatal(err)
	}
	inner, sender, err := envelope.Open(bob, &env)
	if err != nil {
		t.Fatal(err)
	}
	if sender.Fingerprint() != alice.Fingerprint() || inner.Body.Text != "does the relay see this?" {
		t.Fatal("message did not survive the relay")
	}

	id := list.Messages[0].ID
	status, body = h.do(bob, "DELETE", "/v1/mailbox/"+bob.Fingerprint()+"/"+strconv.FormatInt(id, 10), nil, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}

	status, body = h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?after=0", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list after ack: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Messages) != 0 {
		t.Fatalf("acked message still listed: %d left", len(list.Messages))
	}
}

func TestUnregisteredSenderRejected(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "bob", "mallory")
	bob, mallory := people[0], people[1]
	h.register(bob)

	if status, _ := h.do(mallory, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, mallory, bob.Public(), "spam"), nil); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unregistered sender, got %d", status)
	}
	// And an entirely unsigned request.
	if status, _ := h.do(nil, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, mallory, bob.Public(), "spam"), nil); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unsigned request, got %d", status)
	}
}

func TestCannotReadAnotherMailbox(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sealed(t, alice, bob.Public(), "x"), nil)

	if status, _ := h.do(alice, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil); status != http.StatusForbidden {
		t.Fatalf("alice listed bob's mailbox: status %d", status)
	}
	if status, _ := h.do(alice, "DELETE", "/v1/mailbox/"+bob.Fingerprint()+"/1", nil, nil); status != http.StatusForbidden {
		t.Fatalf("alice deleted from bob's mailbox: status %d", status)
	}
	if status, _ := h.do(alice, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		relayapi.AllowRequest{}, nil); status != http.StatusForbidden {
		t.Fatalf("alice rewrote bob's allowlist: status %d", status)
	}
}

func TestOversizeEnvelopeRejected(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 4096})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	big := make([]byte, 64<<10)
	if status, _ := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), big, nil); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversize post, got %d", status)
	}
}

func TestReplayRejected(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	raw := sealed(t, alice, bob.Public(), "once")
	req, err := http.NewRequest("POST", h.srv.URL+"/v1/mailbox/"+bob.Fingerprint(), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(alice, req, raw); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get(relayapi.AuthHeader)

	send := func() int {
		r, err := http.NewRequest("POST", h.srv.URL+"/v1/mailbox/"+bob.Fingerprint(), bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(relayapi.AuthHeader, auth)
		resp, err := h.srv.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status := send(); status != http.StatusOK {
		t.Fatalf("first send: %d", status)
	}
	if status := send(); status != http.StatusUnauthorized {
		t.Fatalf("replay accepted: status %d", status)
	}
}

func TestRegisterCannotClaimAnotherFingerprint(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "mallory")
	alice, mallory := people[0], people[1]

	// Mallory signs with her own key but submits alice's bundle.
	body := h.registerBody(mallory, "alice", "")
	body.Bundle = alice.Public().Bundle()
	status, _ := h.do(mallory, "POST", "/v1/register", body, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 when bundle and signer disagree, got %d", status)
	}
}

func TestKeysLookupAndHealth(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)

	status, body := h.do(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("keys: %d %s", status, body)
	}
	var keys relayapi.KeysResponse
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatal(err)
	}
	pub, err := identity.ParseBundle(keys.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Fingerprint() != alice.Fingerprint() {
		t.Fatal("keys lookup returned the wrong bundle")
	}
	if keys.Created.IsZero() || time.Since(keys.Created) > time.Minute {
		t.Fatalf("the lookup does not say when the mailbox was registered: %v", keys.Created)
	}

	// The short id listings print finds the same mailbox; a hex string of
	// any other length is neither a fingerprint nor a short id.
	status, body = h.do(nil, "GET", "/v1/keys/"+alice.Public().Short(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("lookup by short id: %d %s", status, body)
	}
	var byShort relayapi.KeysResponse
	if err := json.Unmarshal(body, &byShort); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(byShort.Bundle, keys.Bundle) {
		t.Fatal("the short id found a different mailbox")
	}
	if status, _ := h.do(nil, "GET", "/v1/keys/"+alice.Fingerprint()[:20], nil, nil); status != http.StatusBadRequest {
		t.Fatalf("a 20-character prefix was accepted: %d", status)
	}

	if status, _ := h.do(nil, "GET", "/v1/keys/"+strings.Repeat("a", 64), nil, nil); status != http.StatusNotFound {
		t.Fatal("expected 404 for unknown mailbox")
	}
	if status, _ := h.do(nil, "GET", "/v1/keys/"+strings.Repeat("a", 16), nil, nil); status != http.StatusNotFound {
		t.Fatal("expected 404 for an unknown short id")
	}
	if status, _ := h.do(nil, "GET", "/v1/keys/nothex", nil, nil); status != http.StatusBadRequest {
		t.Fatal("expected 400 for malformed fingerprint")
	}
	if status, _ := h.do(nil, "GET", "/v1/health", nil, nil); status != http.StatusOK {
		t.Fatal("health check failed")
	}
}

func TestPostToUnknownMailbox(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "ghost")
	alice, ghost := people[0], people[1]
	h.register(alice)

	if status, _ := h.do(alice, "POST", "/v1/mailbox/"+ghost.Fingerprint(),
		sealed(t, alice, ghost.Public(), "hello?"), nil); status != http.StatusNotFound {
		t.Fatal("expected 404 posting to an unregistered mailbox")
	}
}

func TestPostMisaddressedEnvelope(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	// An envelope sealed for carol, posted into bob's mailbox.
	if status, _ := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, carol.Public(), "misaddressed"), nil); status != http.StatusBadRequest {
		t.Fatal("relay accepted an envelope addressed elsewhere")
	}
}

func TestBadFingerprintInPath(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	if status, _ := h.do(alice, "GET", "/v1/mailbox/..%2F..%2Fetc", nil, nil); status != http.StatusBadRequest {
		t.Fatal("expected 400 for a malformed mailbox path")
	}
}

// The relay is a dumb spool: what comes back out must be byte-for-byte what
// went in, with no re-encoding in between.
func TestStoredEnvelopeReturnedVerbatim(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	sent := sealed(t, alice, bob.Public(), "verbatim please")
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sent, nil); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	_, body := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil)
	var list relayapi.ListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(list.Messages))
	}
	if !bytes.Equal([]byte(list.Messages[0].Envelope), sent) {
		t.Fatal("relay did not return the stored bytes verbatim")
	}
}

// An unauthenticated caller must not be able to write anything to the relay's
// database, including a nonce.
func TestUnauthenticatedCallerCannotWriteNonces(t *testing.T) {
	h := newHarness(t, Config{})
	bob := ids(t, "bob")[0]
	h.register(bob)
	stranger := ids(t, "stranger")[0]

	before := h.nonceCount()
	for i := 0; i < 5; i++ {
		if status, _ := h.do(stranger, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", status)
		}
	}
	if after := h.nonceCount(); after != before {
		t.Fatalf("unauthenticated requests wrote %d nonce rows", after-before)
	}

	// A genuine caller does consume one.
	if status, _ := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil); status != http.StatusOK {
		t.Fatal("authenticated request failed")
	}
	if after := h.nonceCount(); after != before+1 {
		t.Fatalf("expected exactly one nonce consumed, got %d", after-before)
	}
}
