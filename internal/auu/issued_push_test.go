package auu

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/relay"
)

// 'auu channel push' sends the stored directory under its stored issue. A
// stored issue a year ahead, left by a clock that has since gone back, is
// refused before any request with the advice to issue it anew, and a
// channel created afterwards does: it is issued now and pushed.
func TestAStoredDirectoryIssuedAheadIsRefusedBeforeAnyRequest(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// The relay behind a gate: while it is shut, any request at all fails
	// the test.
	var shut atomic.Bool
	var reached atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(target)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shut.Load() {
			reached.Add(1)
			t.Errorf("the relay was reached while the push should have been refused: %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"error":"the gate is shut"}`, http.StatusTeapot)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gate.Close()

	alice := newUser(t, "alice", gate.URL)
	s, id, _ := alice.opened()
	ahead := time.Now().AddDate(1, 0, 0).UTC()
	if err := s.SetDirectory(&channels.Directory{V: channels.Version, Owner: id.Fingerprint(), Issued: ahead,
		Channels: []channels.Channel{{Name: channels.Default}}}); err != nil {
		t.Fatal(err)
	}

	shut.Store(true)
	out, err := alice.tryRun("channel", "push")
	shut.Store(false)
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage ||
		!strings.Contains(err.Error(), "the directory cannot be pushed: ") ||
		!strings.Contains(err.Error(), "ahead of now") ||
		!strings.Contains(err.Error(), "create, update or close a channel") {
		t.Fatalf("a push of a directory issued a year ahead: %v\n%s", err, out)
	}
	if strings.Contains(err.Error(), "update that channel's bound") {
		t.Fatalf("an issue's refusal gives a bound's advice: %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the refused push made %d request(s)", n)
	}
	if held, _ := heldBy(t, st, id); held != nil {
		t.Fatalf("the relay holds a directory after the refusal: %+v", held)
	}

	// The advice works: a channel created now issues the directory anew
	// and the relay takes it.
	before := time.Now()
	alice.run("channel", "create", "bugs")
	held, _ := heldBy(t, st, id)
	if held == nil || held.Find("bugs") == nil || held.Issued.Before(before.Add(-time.Second)) || held.Issued.After(time.Now()) {
		t.Fatalf("the relay after a channel was created: %+v", held)
	}
	local, found, err := s.Directory()
	if err != nil || !found || !local.Issued.Equal(held.Issued) {
		t.Fatalf("the local file after the create: %+v %v %v, relay issued %s", local, found, err, held.Issued)
	}
}

// A stored directory issued now whose channel closes in the year 10000 in
// UTC is refused before any request too, with the advice that fits: the
// bound is the owner's to change, and issuing the directory anew would not
// mend it.
func TestAStoredDirectoryWithABoundPastTheYearsIsRefusedBeforeAnyRequest(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var shut atomic.Bool
	var reached atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(target)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shut.Load() {
			reached.Add(1)
			t.Errorf("the relay was reached while the push should have been refused: %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"error":"the gate is shut"}`, http.StatusTeapot)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gate.Close()

	alice := newUser(t, "alice", gate.URL)
	s, id, _ := alice.opened()
	closes := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.FixedZone("", -14*3600))
	if closes.UTC().Year() != 10000 {
		t.Fatalf("the bound is %s in UTC, not in the year 10000", closes.UTC())
	}
	if err := s.SetDirectory(&channels.Directory{V: channels.Version, Owner: id.Fingerprint(), Issued: time.Now().UTC(),
		Channels: []channels.Channel{{Name: channels.Default}, {Name: "bugs", NotAfter: &closes}}}); err != nil {
		t.Fatal(err)
	}

	shut.Store(true)
	out, err := alice.tryRun("channel", "push")
	shut.Store(false)
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage ||
		!strings.Contains(err.Error(), "the directory cannot be pushed: ") ||
		!strings.Contains(err.Error(), "channel bugs: not_after") ||
		!strings.Contains(err.Error(), "update that channel's bound") {
		t.Fatalf("a push of a directory with a bound in the year 10000: %v\n%s", err, out)
	}
	if strings.Contains(err.Error(), "issue it anew") || strings.Contains(err.Error(), "create, update or close a channel") {
		t.Fatalf("a bound's refusal gives the re-issue advice: %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the refused push made %d request(s)", n)
	}
	if held, _ := heldBy(t, st, id); held != nil {
		t.Fatalf("the relay holds a directory after the refusal: %+v", held)
	}
}
