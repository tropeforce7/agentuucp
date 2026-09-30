package relay

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// send is do plus the response header, because a limit is as much about
// Retry-After as it is about the status.
func (h *harness) send(id *identity.Identity, method, path string, payload any, headers map[string]string) (int, []byte, http.Header) {
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
	return resp.StatusCode, out, resp.Header
}

// retryAfter reads the header a 429 or 503 must carry, insisting it is a whole
// number of seconds and never zero.
func (h *harness) retryAfter(header http.Header) int {
	h.t.Helper()
	raw := header.Get("Retry-After")
	if raw == "" {
		h.t.Fatal("no Retry-After header on a refusal")
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		h.t.Fatalf("Retry-After %q is not an integer number of seconds", raw)
	}
	if secs < 1 {
		h.t.Fatalf("Retry-After is %d; a client would come straight back", secs)
	}
	return secs
}

// enroll registers an identity straight into the store. A test that is
// measuring the per-address budget must not spend it setting the scene, and
// registering over HTTP costs a token like everything else.
func (h *harness) enroll(ids ...*identity.Identity) {
	h.t.Helper()
	for _, id := range ids {
		if err := h.store.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, RegisterOptions{}); err != nil {
			h.t.Fatal(err)
		}
	}
}

func errorText(t *testing.T, body []byte) string {
	t.Helper()
	var e relayapi.ErrorResponse
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("response is not an error object: %s", body)
	}
	return e.Error
}

// healthy asserts the relay is still answering its health check. Monitoring
// has to keep working while everything else is being refused.
func (h *harness) healthy() {
	h.t.Helper()
	if status, _, _ := h.send(nil, "GET", "/v1/health", nil, nil); status != http.StatusOK {
		h.t.Fatalf("health check returned %d while limits were being enforced", status)
	}
}

func TestPostsPerIdentityAreLimited(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{PostsPerMinute: 3}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	for i := range 3 {
		if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "burst"), nil); status != http.StatusOK {
			t.Fatalf("post %d of the burst: %d %s", i+1, status, body)
		}
	}
	status, body, header := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "one too many"), nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("fourth post in the minute returned %d, want 429: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "posts") {
		t.Fatalf("error %q does not name the limit that refused it", got)
	}
	// Three a minute is one token every twenty seconds.
	if secs := h.retryAfter(header); secs != 20 {
		t.Fatalf("Retry-After %ds, want 20s", secs)
	}
	h.healthy()

	h.clock.advance(20 * time.Second)
	if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "after the refill"), nil); status != http.StatusOK {
		t.Fatalf("post after one refill period: %d %s", status, body)
	}
	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "greedy"), nil); status != http.StatusTooManyRequests {
		t.Fatalf("one refill period produced more than one token: %d", status)
	}

	// Bob's budget is his own; alice's flood has not touched it.
	if status, body, _ := h.send(bob, "POST", "/v1/mailbox/"+alice.Fingerprint(),
		sealed(t, bob, alice.Public(), "unaffected"), nil); status != http.StatusOK {
		t.Fatalf("a second identity was charged for the first one's traffic: %d %s", status, body)
	}
}

func TestPostByteBudget(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	one := sealed(t, alice, bob.Public(), "sized")

	t.Run("larger than the whole budget can never succeed", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{PostBytesPerHour: int64(len(one)) - 1}})
		h.register(alice)
		h.register(bob)
		status, body, header := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), one, nil)
		if status != http.StatusTooManyRequests {
			t.Fatalf("status %d, want 429: %s", status, body)
		}
		got := errorText(t, body)
		if !strings.Contains(got, "post bytes") {
			t.Fatalf("error %q does not name the limit", got)
		}
		if !strings.Contains(got, "waiting will not help") {
			t.Fatalf("error %q does not say that retrying is pointless", got)
		}
		h.retryAfter(header)
	})

	t.Run("two posts that together overflow it", func(t *testing.T) {
		// Room for one envelope and a little, but not for two.
		h := newHarness(t, Config{Limits: Limits{PostBytesPerHour: int64(len(one))*2 - 1}})
		h.register(alice)
		h.register(bob)
		if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), one, nil); status != http.StatusOK {
			t.Fatalf("first post: %d %s", status, body)
		}
		status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "sized"), nil)
		if status != http.StatusTooManyRequests {
			t.Fatalf("second post: %d, want 429: %s", status, body)
		}
		if got := errorText(t, body); strings.Contains(got, "waiting will not help") {
			t.Fatal("a post that fits the budget was reported as impossible")
		}
	})
}

func TestUnauthenticatedRateIsPerAddress(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{UnauthenticatedPerMinute: 2}})
	alice := ids(t, "alice")[0]
	h.enroll(alice)

	for i := range 2 {
		if status, _, _ := h.send(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil); status != http.StatusOK {
			t.Fatalf("key lookup %d: %d", i+1, status)
		}
	}
	status, body, header := h.send(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("third key lookup: %d, want 429", status)
	}
	if got := errorText(t, body); !strings.Contains(got, "unauthenticated") {
		t.Fatalf("error %q does not name the limit", got)
	}
	h.retryAfter(header)
	h.healthy()

	// With the address bucket empty, a request carrying no auth header must be
	// refused without reading the database. Closing the store turns any read
	// into a 500, so a 429 here proves nothing was read.
	h.store.Close()
	if status, _, _ := h.send(nil, "GET", "/v1/mailbox/"+alice.Fingerprint(), nil, nil); status != http.StatusTooManyRequests {
		t.Fatalf("an unauthenticated request touched the database: status %d, want 429", status)
	}
}

func TestBadSignaturesAreChargedButNeverBlockAGoodOne(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{UnauthenticatedPerMinute: 2}})
	people := ids(t, "victim", "neighbour")
	victim, neighbour := people[0], people[1]
	h.enroll(victim, neighbour)

	// A well-formed header signed by the wrong key, claiming to be the victim.
	forged := func() map[string]string {
		req, err := http.NewRequest("GET", h.srv.URL+"/v1/mailbox/"+victim.Fingerprint(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := relayapi.SignRequest(neighbour, req, nil); err != nil {
			t.Fatal(err)
		}
		// Same shape, same nonce format, victim's fingerprint, wrong signature.
		fields := strings.Fields(req.Header.Get(relayapi.AuthHeader))
		fields[1] = victim.Fingerprint()
		return map[string]string{relayapi.AuthHeader: strings.Join(fields, " ")}
	}

	// The first two are verified before being charged, so they get a 401 and
	// learn nothing; the third finds the bucket empty.
	for i := range 2 {
		if status, _, _ := h.send(nil, "GET", "/v1/mailbox/"+victim.Fingerprint(), nil, forged()); status != http.StatusUnauthorized {
			t.Fatalf("forged request %d: %d, want 401", i+1, status)
		}
		// And throughout, a correct signature from the same address works.
		if status, _, _ := h.send(victim, "GET", "/v1/mailbox/"+victim.Fingerprint(), nil, nil); status != http.StatusOK {
			t.Fatalf("a genuine caller was refused after %d forged requests", i+1)
		}
	}
	if status, _, _ := h.send(nil, "GET", "/v1/mailbox/"+victim.Fingerprint(), nil, forged()); status != http.StatusTooManyRequests {
		t.Fatalf("a third forged request was not rate limited: %d", status)
	}

	// The whole point: the victim named in those forged headers is unharmed.
	if status, body, _ := h.send(victim, "GET", "/v1/mailbox/"+victim.Fingerprint(), nil, nil); status != http.StatusOK {
		t.Fatalf("failed authentication naming the victim cost the victim their budget: %d %s", status, body)
	}
	h.healthy()
}

// The relay reads no X-Forwarded-For at all: a forged one must not buy a
// fresh per-address budget, whatever address the connection comes from.
func TestForwardedForHasNoEffect(t *testing.T) {
	alice := ids(t, "alice")[0]
	lookup := "/v1/keys/" + alice.Fingerprint()
	h := newHarness(t, Config{Limits: Limits{UnauthenticatedPerMinute: 1}})
	h.enroll(alice)
	if status, _, _ := h.send(nil, "GET", lookup, nil,
		map[string]string{"X-Forwarded-For": "203.0.113.1"}); status != http.StatusOK {
		t.Fatal("first lookup refused")
	}
	if status, _, _ := h.send(nil, "GET", lookup, nil,
		map[string]string{"X-Forwarded-For": "203.0.113.2"}); status != http.StatusTooManyRequests {
		t.Fatalf("a forged X-Forwarded-For bought a new budget: %d", status)
	}
	if !strings.Contains(h.logs.String(), "limit=unauthenticated") {
		t.Fatalf("the refusal was not logged by name:\n%s", h.logs.String())
	}
}

func TestMailboxMessageQuota(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MailboxMaxMessages: 2}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	for i := range 2 {
		if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "queued"), nil); status != http.StatusOK {
			t.Fatalf("post %d: %d %s", i+1, status, body)
		}
	}
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "overflow"), nil)
	if status != http.StatusInsufficientStorage {
		t.Fatalf("third post: %d, want 507: %s", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgMailboxFull {
		t.Fatalf("error %q, want %q", got, relayapi.MsgMailboxFull)
	}
	h.healthy()

	// Bob collects one message, which is the only thing that frees the quota.
	if status, _, _ := h.send(bob, "DELETE", "/v1/mailbox/"+bob.Fingerprint()+"/1", nil, nil); status != http.StatusNoContent {
		t.Fatal("delete failed")
	}
	if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "room again"), nil); status != http.StatusOK {
		t.Fatalf("post after the recipient made room: %d %s", status, body)
	}
}

func TestMailboxByteQuota(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	one := int64(len(sealed(t, alice, bob.Public(), "sized")))

	h := newHarness(t, Config{Limits: Limits{MailboxMaxBytes: one*2 - 1}})
	h.register(alice)
	h.register(bob)

	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "sized"), nil); status != http.StatusOK {
		t.Fatal("first post refused")
	}
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "sized"), nil)
	if status != http.StatusInsufficientStorage {
		t.Fatalf("second post: %d, want 507: %s", status, body)
	}
	if status, _, _ := h.send(bob, "DELETE", "/v1/mailbox/"+bob.Fingerprint()+"/1", nil, nil); status != http.StatusNoContent {
		t.Fatal("delete failed")
	}
	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "sized"), nil); status != http.StatusOK {
		t.Fatal("post after the recipient made room was refused")
	}
}

func TestRelayByteQuota(t *testing.T) {
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	one := int64(len(sealed(t, alice, bob.Public(), "sized")))

	h := newHarness(t, Config{Limits: Limits{RelayMaxBytes: one*2 - 1}})
	for _, id := range people {
		h.register(id)
	}
	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "sized"), nil); status != http.StatusOK {
		t.Fatal("first post refused")
	}
	// A different mailbox entirely: the relay as a whole is what is full.
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+carol.Fingerprint(),
		sealed(t, alice, carol.Public(), "sized"), nil)
	if status != http.StatusInsufficientStorage {
		t.Fatalf("post into a second mailbox: %d, want 507: %s", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgRelayFull {
		t.Fatalf("error %q, want %q", got, relayapi.MsgRelayFull)
	}
	if status, _, _ := h.send(bob, "DELETE", "/v1/mailbox/"+bob.Fingerprint()+"/1", nil, nil); status != http.StatusNoContent {
		t.Fatal("delete failed")
	}
	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+carol.Fingerprint(),
		sealed(t, alice, carol.Public(), "sized"), nil); status != http.StatusOK {
		t.Fatal("post after the relay was drained was refused")
	}
}

// The counters are the only thing a quota consults, so they have to agree with
// the rows they claim to count.
func TestCountersMatchTheMessagesTable(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	for range 5 {
		if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "counted"), nil); status != http.StatusOK {
			t.Fatal("post refused")
		}
	}
	for _, id := range []int64{2, 4} {
		if status, _, _ := h.send(bob, "DELETE",
			fmt.Sprintf("/v1/mailbox/%s/%d", bob.Fingerprint(), id), nil, nil); status != http.StatusNoContent {
			t.Fatalf("delete %d failed", id)
		}
	}
	h.assertCountersAgree()

	// Corrupt them the way a crash between two statements would, and reopen.
	if _, err := h.store.db.Exec(`UPDATE mailboxes SET queued_messages = 99, queued_bytes = 12345`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`UPDATE relay_stats SET queued_messages = 0, queued_bytes = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	path := h.dbPath()
	h.store.Close()

	reopened, err := OpenStore(path, filepath.Join(filepath.Dir(path), "messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Reconciled() == 0 {
		t.Fatal("reopening did not notice the counters were wrong")
	}
	h.store = reopened
	h.assertCountersAgree()
}

// dbPath asks SQLite where its own file is, so a test can reopen it.
func (h *harness) dbPath() string {
	h.t.Helper()
	var seq int
	var name, file string
	if err := h.store.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
		h.t.Fatal(err)
	}
	return file
}

func (h *harness) assertCountersAgree() {
	h.t.Helper()
	rows, err := h.store.db.Query(`
		SELECT m.fp, m.queued_messages, m.queued_bytes,
			(SELECT COUNT(*) FROM messages WHERE to_fp = m.fp),
			(SELECT COALESCE(SUM(size), 0) FROM messages WHERE to_fp = m.fp)
		FROM mailboxes m`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		var storedN, storedB, realN, realB int64
		if err := rows.Scan(&fp, &storedN, &storedB, &realN, &realB); err != nil {
			h.t.Fatal(err)
		}
		if storedN != realN || storedB != realB {
			h.t.Fatalf("mailbox %s counters say %d messages / %d bytes, table says %d / %d",
				fp[:8], storedN, storedB, realN, realB)
		}
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}

	usage, err := h.store.RelayUsage()
	if err != nil {
		h.t.Fatal(err)
	}
	var realN, realB int64
	if err := h.store.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages`).Scan(&realN, &realB); err != nil {
		h.t.Fatal(err)
	}
	if usage.Messages != realN || usage.Bytes != realB {
		h.t.Fatalf("relay counters say %d messages / %d bytes, table says %d / %d",
			usage.Messages, usage.Bytes, realN, realB)
	}
	var storedQN, storedQB, realQN, realQB int64
	if err := h.store.db.QueryRow(`
		SELECT outbound_messages, outbound_bytes,
			(SELECT COUNT(*) FROM outbound WHERE state = ?),
			(SELECT COALESCE(SUM(size), 0) FROM outbound WHERE state = ?)
		FROM relay_stats WHERE id = 1`, OutWaiting, OutWaiting).Scan(&storedQN, &storedQB, &realQN, &realQB); err != nil {
		h.t.Fatal(err)
	}
	if storedQN != realQN || storedQB != realQB {
		h.t.Fatalf("queue counters say %d messages / %d bytes, waiting rows say %d / %d",
			storedQN, storedQB, realQN, realQB)
	}
}

func TestRegistrationCap(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MaxMailboxes: 1}})
	people := ids(t, "first", "second")
	first, second := people[0], people[1]
	h.register(first)

	status, body, _ := h.send(second, "POST", "/v1/register",
		h.registerBody(second, second.Name, ""), nil)
	if status != http.StatusForbidden {
		t.Fatalf("second registration: %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "not accepting new registrations") {
		t.Fatalf("error %q does not explain the refusal", got)
	}
	// Changing your own name is not asking for a new mailbox.
	if status, body, _ := h.send(first, "POST", "/v1/register",
		h.registerBody(first, "renamed", ""), nil); status != http.StatusOK {
		t.Fatalf("re-registration under the cap: %d %s", status, body)
	}
}

func TestRegistrationsPerAddress(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{RegistrationsPerHour: 2}})
	people := ids(t, "one", "two", "three")
	h.register(people[0])
	h.register(people[1])

	status, body, header := h.send(people[2], "POST", "/v1/register",
		h.registerBody(people[2], "three", ""), nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("third registration from one address: %d, want 429: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "registrations") {
		t.Fatalf("error %q does not name the limit", got)
	}
	// Two an hour is one every half hour.
	if secs := h.retryAfter(header); secs != 1800 {
		t.Fatalf("Retry-After %ds, want 1800s", secs)
	}
}

func TestInflightCap(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MaxInflight: 1}})
	alice := ids(t, "alice")[0]
	h.register(alice)
	keys := "/v1/keys/" + alice.Fingerprint()

	// With a single slot the prober can arrive first and take it, leaving the
	// stalled request to be the one refused. That is a lost race rather than a
	// failure, and it is retried. A broken cap looks different and still
	// fails: the stalled request goes unanswered, holding the slot, and the
	// prober gets through anyway.
	for attempt := range 8 {
		st := stallPost(t, h, alice, 1<<20)
		status, body, header, lost := st.holdsTheSlot(t, h, keys)
		if lost {
			st.close()
			continue
		}
		if status != http.StatusServiceUnavailable {
			st.close()
			t.Fatalf("attempt %d: a request stalled inside the handler held the only "+
				"in-flight slot, but a second request got %d instead of 503: %s",
				attempt, status, body)
		}

		if got := errorText(t, body); !strings.Contains(got, "busy") {
			t.Fatalf("error %q does not say the relay is busy", got)
		}
		if secs := h.retryAfter(header); secs != 1 {
			t.Fatalf("Retry-After %ds, want 1s", secs)
		}
		// Health is exempt, so monitoring does not flap while the relay is full.
		h.healthy()

		// Closing the connection ends the stalled read, and the slot comes back.
		st.close()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if status, _, _ := h.send(nil, "GET", keys, nil, nil); status == http.StatusOK {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("the in-flight slot was never released")
	}
	t.Fatal("the prober won the race for the single slot eight times running")
}

func TestEveryLimitAtZeroIsUnlimited(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	// Comfortably past every default, from one identity, in one minute of
	// relay time, with the injected clock never moving.
	for i := range 200 {
		if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "unlimited"), nil); status != http.StatusOK {
			t.Fatalf("post %d was refused with %d: %s", i+1, status, body)
		}
	}
	for i := range 100 {
		if status, _, _ := h.send(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil); status != http.StatusOK {
			t.Fatalf("key lookup %d was refused with %d", i+1, status)
		}
	}
}

// A database from before the first kept version is refused, never
// carried forward: the sentence names the file, the version found, the
// version written, the floor, the message directory, which goes with the
// file since a new database beside old mail is the lost database the next
// start refuses over, and what the deletion costs. Version 0 with tables
// in it is a database from before the version was recorded, refused the
// same way; version 0 with none is a new file. A refusal writes nothing:
// the version reads back as found and no copy stands beside the file.
func TestADatabaseFromBeforeTheFloorIsRefusedNotMigrated(t *testing.T) {
	for version := 0; version < firstKeptVersion; version++ {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "old.db")
			messages := filepath.Join(dir, "messages")
			store, err := OpenStore(path, messages)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
				t.Fatal(err)
			}
			store.Close()

			_, err = OpenStore(path, messages)
			if err == nil {
				t.Fatalf("a version %d database was opened", version)
			}
			want := fmt.Sprintf("relay: %s is schema version %d, but this relay writes version %d and carries forward "+
				"only a database from schema %d on: "+
				"delete it and the message directory beside it, %s, and the relay recreates both at the next start; "+
				"every machine enrolled on it enrols again", path, version, schemaVersion, firstKeptVersion, messages)
			if err.Error() != want {
				t.Fatalf("error %q\nwant  %q", err, want)
			}
			// Refused means untouched: the version is still the one found.
			db := openVersion(t, path)
			if db != version {
				t.Fatalf("the refusal left the database at version %d, want %d", db, version)
			}
			if copies, _ := filepath.Glob(path + ".before-schema-*"); len(copies) != 0 {
				t.Fatalf("the refusal kept a copy: %v", copies)
			}
		})
	}
}

// openVersion reads a database's user_version with none of OpenStore's
// checks, as an operator with sqlite3 would.
func openVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestNewerDatabaseIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	store, err := OpenStore(path, filepath.Join(filepath.Dir(path), "messages"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	store.Close()

	if _, err := OpenStore(path, filepath.Join(filepath.Dir(path), "messages")); err == nil || !strings.Contains(err.Error(), "newer release") {
		t.Fatalf("error %v does not explain that the database is from a newer relay", err)
	}
}

func TestAccessLogModes(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]

	post := func(h *harness) {
		h.register(alice)
		h.register(bob)
		if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), "logged"), nil); status != http.StatusOK {
			t.Fatal("post refused")
		}
	}

	t.Run("full names both ends", func(t *testing.T) {
		h := newHarness(t, Config{AccessLog: AccessLogFull})
		post(h)
		logged := h.logs.String()
		if !strings.Contains(logged, alice.Fingerprint()[:16]) {
			t.Fatal("the full log does not record the verified caller")
		}
		if !strings.Contains(logged, bob.Fingerprint()) {
			t.Fatal("the full log does not record the request path")
		}
	})

	t.Run("minimal keeps the graph out of the log", func(t *testing.T) {
		h := newHarness(t, Config{AccessLog: AccessLogMinimal})
		post(h)
		logged := h.logs.String()
		for _, fp := range []string{alice.Fingerprint(), bob.Fingerprint()} {
			if strings.Contains(logged, fp[:16]) {
				t.Fatalf("the minimal log contains a fingerprint:\n%s", logged)
			}
		}
		if strings.Contains(logged, "fp=") {
			t.Fatalf("the minimal log still carries an fp field:\n%s", logged)
		}
		// It is still enough to operate the relay.
		if !strings.Contains(logged, `path=/v1/mailbox/{fp}`) || !strings.Contains(logged, "method=POST") {
			t.Fatalf("the minimal log does not record the route:\n%s", logged)
		}
		if !strings.Contains(logged, "status=200") {
			t.Fatalf("the minimal log does not record the status:\n%s", logged)
		}
	})
}

// The limit field is what turns a wall of 429s into a diagnosis. The two
// knock refusals are named apart: the sender's budget as knocks, the
// recipient's cap as knocks_waiting.
func TestRefusalsAreNamedInTheLog(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{UnauthenticatedPerMinute: 1, KnocksPerHour: 1, MaxKnocksWaiting: 1}})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	h.enroll(alice, bob, carol)
	h.send(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil)
	h.send(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil)

	if !strings.Contains(h.logs.String(), "limit=unauthenticated") {
		t.Fatalf("the log does not name the limit that refused a request:\n%s", h.logs.String())
	}
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	if status, body, _ := h.knock(alice, bob, "hi"); status != http.StatusOK {
		t.Fatalf("the first knock: %d %s", status, body)
	}
	if status, _, _ := h.knock(carol, bob, "hi"); status != http.StatusTooManyRequests {
		t.Fatalf("a knock at the recipient's cap: %d", status)
	}
	if status, _, _ := h.knock(alice, bob, "hi"); status != http.StatusTooManyRequests {
		t.Fatalf("a knock over the sender's budget: %d", status)
	}
	lines := strings.Split(h.logs.String(), "\n")
	named := func(limit string) bool {
		for _, l := range lines {
			if strings.Contains(l, "status=429") && strings.Contains(l, "limit="+limit+" ") {
				return true
			}
		}
		return false
	}
	if !named("knocks_waiting") || !named("knocks") {
		t.Fatalf("the log does not name the two knock limits apart:\n%s", h.logs.String())
	}
}

// The shape an operator should see when one agent runs away with itself: the
// burst gets through, the rest are told when to come back, and everybody else
// carries on unaffected.
func TestDefaultLimitsUnderAFlood(t *testing.T) {
	h := newHarness(t, Config{Limits: DefaultLimits()})
	people := ids(t, "flooder", "bystander", "recipient")
	flooder, bystander, recipient := people[0], people[1], people[2]
	h.enroll(flooder, bystander, recipient)

	accepted, refused := 0, 0
	retries := map[int]int{}
	for range 100 {
		status, _, header := h.send(flooder, "POST", "/v1/mailbox/"+recipient.Fingerprint(),
			sealed(t, flooder, recipient.Public(), "flood"), nil)
		switch status {
		case http.StatusOK:
			accepted++
		case http.StatusTooManyRequests:
			refused++
			retries[h.retryAfter(header)]++
		default:
			t.Fatalf("unexpected status %d during the flood", status)
		}
		// The relay stays useful to everybody else throughout.
		if status, _, _ := h.send(bystander, "GET", "/v1/mailbox/"+bystander.Fingerprint(), nil, nil); status != http.StatusOK {
			t.Fatalf("a second identity was refused with %d while the first was flooding", status)
		}
		h.healthy()
	}

	want := DefaultLimits().PostsPerMinute
	if int64(accepted) != want {
		t.Fatalf("%d posts accepted, want the burst of %d", accepted, want)
	}
	if refused != 100-int(want) {
		t.Fatalf("%d posts refused, want %d", refused, 100-int(want))
	}
	// Thirty a minute is one token every two seconds, so that is the whole of
	// the advice the relay should be giving.
	if len(retries) != 1 || retries[2] != refused {
		t.Fatalf("Retry-After values were %v, want every refusal to ask for 2s", retries)
	}
	// And the bystander can still post, not merely read.
	if status, _, _ := h.send(bystander, "POST", "/v1/mailbox/"+recipient.Fingerprint(),
		sealed(t, bystander, recipient.Public(), "unaffected"), nil); status != http.StatusOK {
		t.Fatalf("a second identity could not post after the flood: %d", status)
	}
	t.Logf("100 posts at defaults: %d accepted, %d refused, Retry-After %v", accepted, refused, retries)
}

// TestTheReportingRateIsATenthOfThePostingRate: the relationship the relay
// guide explains, held to the numbers rather than left in prose.
//
// This test exists because of what it would have caught. The default shipped at
// 600, equal to the posting rate, where the plan had already settled on 60 — not
// a mistyped number but a figure reasoned from how fast a backlog drains, by
// somebody who never checked it against the decision. The drift test beside it
// compares the command's defaults to the library's, so it proved the two copies
// agreed and said nothing about whether either agreed with the specification.
//
// A literal assertion that the rate is 60 would only restate the code. What is
// worth pinning is the claim the guide makes about *why*: a report costs the
// relay being told a row of the reporting courier's own share, so the rate
// decides how fast one neighbour may spend that share on reports, and a tenth of
// the posting rate is the conservative choice. Change either number for a good
// reason and this fails, which is the point — it asks whether the ratio was
// meant to go too.
func TestTheReportingRateIsATenthOfThePostingRate(t *testing.T) {
	d := DefaultCourierLimits()
	if d.PostsPerMinute != 10*d.ReportsPerMinute {
		t.Errorf("posting is %d a minute and reporting %d; the relay guide says reporting is a "+
			"tenth of posting, and if that is no longer meant the guide's paragraph in 1.10 "+
			"has to change with it", d.PostsPerMinute, d.ReportsPerMinute)
	}
	// And the arithmetic the guide gives, which is the reason for the ratio:
	// how long one neighbour needs to fill its whole share of the queue with
	// reports, at this rate and at the posting rate.
	atReporting := d.QueueMaxMessagesPerCourier / d.ReportsPerMinute
	atPosting := d.QueueMaxMessagesPerCourier / d.PostsPerMinute
	if atReporting < 150 || atReporting > 180 {
		t.Errorf("a neighbour fills its share in %d minutes; the guide says nearly three hours",
			atReporting)
	}
	if atPosting < 15 || atPosting > 18 {
		t.Errorf("at the posting rate it would be %d minutes; the guide says about seventeen",
			atPosting)
	}
}
