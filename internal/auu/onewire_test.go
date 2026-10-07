package auu

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestARelayWithoutMaxBytesIsRefusedByName: a relay whose health answer
// carries no max_bytes is refused by the client at the first request that
// reads health — registration — naming the field, since a listing page
// is sized by it and nothing else can say how much of a page to hold.
// Nothing on the wire is from before: an answer without a field every
// relay sends is not read as an older relay, and the sentence says so.
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
		t.Fatalf("register against a relay whose health answer lacks max_bytes: %v; want the refusal naming the field", err)
	}
}

// The knock cap the same way, through the one command that sizes itself by
// it: a health answer without knock_max_bytes is refused by name, with
// nothing of the answer used, so a knock is never sealed against a cap the
// relay did not say.
func TestARelayWithoutAKnockCapIsRefusedByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "max_bytes": 16777216, "registration": "open", "wire_level": 1})
	}))
	defer srv.Close()
	alice := &user{t: t, home: t.TempDir()}
	alice.run("init", "--name", "alice", "--relay", srv.URL)
	_, err := alice.tryRun("register")
	if err == nil || !strings.Contains(err.Error(), "knock_max_bytes is not the relay's knock cap") {
		t.Fatalf("register against a relay whose health answer lacks knock_max_bytes: %v; want the refusal naming the field", err)
	}
}
