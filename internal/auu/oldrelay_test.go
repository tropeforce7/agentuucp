package auu

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// v5Relay is a relay from before channels, canned: it answers the routes a
// send and a fetch need in the shape schema version 5 answered them, stores
// a posted envelope's bytes verbatim without reading anything but the
// mailbox it is for, lists messages with queued and without channel, and
// knows no channel route at all. It verifies nothing, which is not the
// point; what an old relay does with a field it has never heard of is.
type v5Relay struct {
	mu    sync.Mutex
	next  int64
	queue map[string][]v5Message
	seen  []string
	// listings is the query of every mailbox listing, as it came: a v5
	// relay reads after and limit from it and nothing else.
	listings []string
	// allow is what the allow route read from its last body: the array
	// alone, since a relay from before signed lists knows no other field
	// and json.Unmarshal ignores what it has not heard of. nil until one
	// arrives, so a test can tell no push from an empty one.
	allow []string
}

type v5Message struct {
	id  int64
	raw json.RawMessage
}

func (f *v5Relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	mailbox := strings.HasPrefix(r.URL.Path, "/v1/mailbox/")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/mailbox/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
		// The fake stands for a relay from before signed lists, stubs and
		// held listings, which is what its tests are about; it carries
		// max_bytes, which this client requires of every relay it talks
		// to since PLAN-HTTP, since a relay without it is refused by name
		// before anything else — TestARelayWithoutMaxBytesIsRefusedByName.
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "max_bytes": 16777216})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/register":
		json.NewEncoder(w).Encode(map[string]any{"fp": strings.Fields(r.Header.Get("X-CCX-Auth"))[1]})
	case r.Method == http.MethodPost && mailbox && len(parts) == 1:
		// A v5 handlePost: json.Unmarshal into {v, to, ct}, which ignores
		// a field it does not know, then the bytes stored as they came.
		var env struct {
			V  int    `json:"v"`
			To string `json:"to"`
			CT []byte `json:"ct"`
		}
		if err := json.Unmarshal(body, &env); err != nil || env.To != parts[0] {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": "malformed envelope"})
			return
		}
		if f.queue == nil {
			f.queue = map[string][]v5Message{}
		}
		f.next++
		f.queue[parts[0]] = append(f.queue[parts[0]], v5Message{id: f.next, raw: json.RawMessage(body)})
		json.NewEncoder(w).Encode(map[string]any{"id": f.next})
	case r.Method == http.MethodGet && mailbox && len(parts) == 1:
		f.listings = append(f.listings, r.URL.RawQuery)
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		out := []map[string]any{}
		for _, m := range f.queue[parts[0]] {
			if m.id > after {
				out = append(out, map[string]any{"id": m.id, "received": "2026-09-13T00:00:00Z",
					"kind": "envelope", "size": len(m.raw), "envelope": m.raw})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"messages": out, "queued": len(f.queue[parts[0]])})
	case r.Method == http.MethodPut && mailbox && len(parts) == 2 && parts[1] == "allow":
		// A v6 handleAllow: the array and nothing else.
		var req struct {
			Allow []string `json:"allow"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": "malformed allow request"})
			return
		}
		if req.Allow == nil {
			req.Allow = []string{}
		}
		f.allow = req.Allow
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && mailbox && len(parts) == 2:
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		kept := f.queue[parts[0]][:0:0]
		for _, m := range f.queue[parts[0]] {
			if m.id != id {
				kept = append(kept, m)
			}
		}
		f.queue[parts[0]] = kept
		w.WriteHeader(http.StatusNoContent)
	default:
		// Everything else, the channel routes included, is a 404 from a
		// v5 ServeMux: the same shape as a mailbox that is not there.
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"error": "404 page not found"})
	}
}

// drop removes one message from every mailbox, as another machine of the
// same identity acknowledging it would.
func (f *v5Relay) drop(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for fp, msgs := range f.queue {
		kept := msgs[:0:0]
		for _, m := range msgs {
			if m.id != id {
				kept = append(kept, m)
			}
		}
		f.queue[fp] = kept
	}
}

func (f *v5Relay) asked(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.seen {
		if s == path {
			return true
		}
	}
	return false
}

// Decision 3 from the old relay's side: a relay from before channels takes a
// post carrying ch for a channel it cannot read, stores the envelope as it
// came, and lists it without channel; the receiver files it by the sealed
// record and says nothing, and says the channel is not in its directory
// once it has one that leaves it out — which is what pushing a directory to
// that relay cannot give it.
func TestAnOldRelayTakesAPostForAChannelItCannotRead(t *testing.T) {
	old := &v5Relay{}
	srv := httptest.NewServer(old)
	defer srv.Close()
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())

	// Nobody has a directory anywhere, and the relay could not hold one.
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a bug", "--json", "the bug")), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Channel != "bug reports" {
		t.Fatalf("send --json through an old relay: %+v", sent)
	}
	old.mu.Lock()
	stored := old.queue[sent.To]
	old.mu.Unlock()
	if len(stored) != 1 || !strings.Contains(string(stored[0].raw), `"ch":"bug reports"`) {
		t.Fatalf("the old relay did not store the envelope as it came: %d messages", len(stored))
	}

	var out string
	warning := captureStderr(t, func() { out = bob.run("inbox", "--json") })
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if warning != "" {
		t.Fatalf("a fetch from an old relay drew a warning:\n%s", warning)
	}
	if got.Fetch.Delivered != 1 || len(got.Fetch.Gone) != 0 || len(got.Messages) != 1 || got.Messages[0].Channel != "bug reports" {
		t.Fatalf("the fetch: %+v %+v", got.Fetch, got.Messages)
	}
	s, _, _ := bob.opened()
	if _, rec, err := s.Find(got.Messages[0].ID); err != nil || rec.Channel != "bug reports" || rec.Inner.Channel != "bug reports" {
		t.Fatalf("filed as %+v (%v)", rec, err)
	}
	if text := bob.run("read", got.Messages[0].ID); !strings.Contains(text, "channel: bug reports\n") {
		t.Fatalf("read:\n%s", text)
	}

	// bob defines channels; the old relay cannot take the directory, the
	// file is written anyway, and the command says so and exits 2.
	out, err := bob.tryRun("channel", "create", "cfp")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport ||
		!strings.Contains(out, ": could not push the directory: relay returned 404") ||
		err.Error() != s.ChannelsPath()+" is written; run 'auu channel push' once the relay above can be reached" {
		t.Fatalf("create against an old relay: %v\n%s", err, out)
	}
	if d := bob.channelsOf(); d == nil || len(d.Channels) != 2 {
		t.Fatalf("the local file after: %+v", d)
	}
	if !old.asked("PUT /v1/mailbox/" + sent.To + "/channels") {
		t.Fatal("the push was never attempted")
	}
	// The old relay still takes a post for bug reports, and now bob's
	// directory leaves it out.
	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "another", "x")
	text := bob.run("inbox")
	if !strings.Contains(text, `1 message(s) arrived for channels no longer in your directory: "bug reports"`+"\n") ||
		strings.Count(text, `  in "bug reports"`) != 2 {
		t.Fatalf("inbox after defining channels:\n%s", text)
	}
	// And a sender's listing of bob through the old relay: the route is
	// not there, which the client tells from an empty directory only by
	// the sentence, so it is a transport error, not "one channel".
	if _, err := alice.tryRun("channel", "ls", "bob"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("ls of a peer through an old relay: %v", err)
	}
}

// Decision 2 of PLAN-ALLOW from the old relay's side: a client of this
// version sends the senders as an array beside the signed document, so a
// relay from before signed lists, which reads the array and nothing else,
// is told the list rather than an empty one. Without the array it would
// have read nothing and cleared the mailbox's list in silence.
func TestANewClientStillSendsTheArrayForAnOldRelay(t *testing.T) {
	old := &v5Relay{}
	srv := httptest.NewServer(old)
	defer srv.Close()
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())

	out := alice.run("allow", "push")
	if !strings.Contains(out, "will now accept mail for you from 1 peer(s) only") {
		t.Fatalf("allow push against an old relay:\n%s", out)
	}
	old.mu.Lock()
	got := old.allow
	old.mu.Unlock()
	if len(got) != 1 || got[0] != bob.exportFingerprint() {
		t.Fatalf("the old relay read %v from the push, want bob's fingerprint alone", got)
	}
	// And a clear is an empty array, as it always was.
	alice.run("allow", "clear")
	old.mu.Lock()
	got = old.allow
	old.mu.Unlock()
	if got == nil || len(got) != 0 {
		t.Fatalf("the old relay read %v from the clear, want an empty array", got)
	}
	// A fetch from the old relay, which says nothing about the list, draws
	// no warning.
	var fetched string
	warning := captureStderr(t, func() { fetched = alice.run("inbox") })
	if warning != "" {
		t.Fatalf("a fetch from an old relay drew a warning:\n%s\n%s", warning, fetched)
	}
}

// TestARelayWithoutMaxBytesIsRefusedByName: a relay whose health answer
// carries no max_bytes is one from before the field, and the client
// refuses it at the first request that reads health — registration —
// naming the field, since a listing page is sized by it and nothing else
// can say how much of a page to hold.
func TestARelayWithoutMaxBytesIsRefusedByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()
	alice := &user{t: t, home: t.TempDir()}
	alice.run("init", "--name", "alice", "--relay", srv.URL)
	_, err := alice.tryRun("register")
	if err == nil || !strings.Contains(err.Error(), "max_bytes is not the relay's max_bytes") {
		t.Fatalf("register against a relay from before max_bytes: %v; want the refusal naming the field", err)
	}
}
