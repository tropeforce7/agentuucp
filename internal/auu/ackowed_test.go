package auu

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

func TestAnUpgradeDeliveryRetriesAFailedAcknowledgement(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var refuse atomic.Bool
	var blocked atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			blocked.Add(1)
			http.Error(w, "temporary refusal of acknowledgement", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()
	alice := newUser(t, "alice", front.URL)
	bob := newUser(t, "bob", front.URL)
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "keep", "default", "off")
	streamSections(t, alice, bob, "waiting upgrade", critical("review-upgrade-ack"))
	in, _ := fetchJSON(t, bob)
	if len(in.Fetch.Newer) != 1 {
		t.Fatalf("not waiting: %+v", in.Fetch)
	}
	t.Cleanup(wire.Register("review-upgrade-ack", wire.OnManifest))
	refuse.Store(true)
	if _, err := bob.tryRun("inbox", "--json"); err == nil || blocked.Load() == 0 {
		t.Fatalf("expected refused ack, blocked=%d err=%v", blocked.Load(), err)
	}
	rec := recordOf(t, bob, store.Inbox, "waiting upgrade")
	if rec.Newer != "" || rec.PayloadOnRelay {
		t.Fatalf("payload not delivered: %+v", rec)
	}
	refuse.Store(false)
	for i := 0; i < 2; i++ {
		out, err := bob.tryRun("inbox", "--json")
		t.Logf("retry %d: err=%v output=%s", i+1, err, out)
	}
	if rows := adv2RowIDs(t, st, bob.exportFingerprint()); len(rows) != 0 {
		t.Errorf("acknowledgement was never retried: relay still holds %v after two healthy fetches", rows)
	}
}

func TestAQuarantineTrustRetriesAFailedAcknowledgement(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var refuse atomic.Bool
	var blocked atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			blocked.Add(1)
			http.Error(w, "temporary refusal of acknowledgement", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()
	alice := newUser(t, "alice", front.URL)
	bob := newUser(t, "bob", front.URL)
	bob.run("channel", "keep", "default", "off")
	streamSections(t, alice, bob, "quarantined ack", nil)
	bob.run("inbox", "--json")
	rec := recordOf(t, bob, store.Quarantine, "quarantined ack")
	refuse.Store(true)
	if _, err := bob.answer("alice", "quarantine", "trust", rec.Inner.ID); err == nil || blocked.Load() == 0 {
		t.Fatalf("expected refused ack: %v", err)
	}
	refuse.Store(false)
	out, err := bob.answer("alice", "quarantine", "trust", rec.Inner.ID)
	if err != nil {
		t.Fatalf("trust retry: %v", err)
	}
	t.Logf("trust retry reports: %s", out)
	if rows := adv2RowIDs(t, st, bob.exportFingerprint()); len(rows) != 0 {
		t.Errorf("successful trust retry left unacknowledged copy %v", rows)
	}
	if _, err := bob.tryRun("inbox", "--json"); err != nil {
		t.Errorf("inbox after successful trust retry: %v", err)
	}
}

// TestARegularStreamDeliveryRetriesAFailedAcknowledgement is the fetch's
// own row of G32: a stream from an admitted sender to a channel that does
// not keep, delivered whole and then refused its acknowledgement, leaves a
// record that says the relay holds it and owes it the acknowledgement; the
// next healthy fetch acknowledges it without asking the relay for a byte of
// it again, and the record then says the relay holds nothing.
func TestARegularStreamDeliveryRetriesAFailedAcknowledgement(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var refuse atomic.Bool
	var blocked, blobs atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			blocked.Add(1)
			http.Error(w, "temporary refusal of acknowledgement", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blob") {
			blobs.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()
	alice := newUser(t, "alice", front.URL)
	bob := newUser(t, "bob", front.URL)
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "keep", "default", "off")
	streamSections(t, alice, bob, "regular stream ack", nil)
	refuse.Store(true)
	if _, err := bob.tryRun("inbox", "--json"); err == nil || blocked.Load() == 0 {
		t.Fatalf("expected refused ack, blocked=%d err=%v", blocked.Load(), err)
	}
	rec := recordOf(t, bob, store.Inbox, "regular stream ack")
	if rec.PayloadOnRelay || !rec.OnRelay || !rec.AckOwed {
		t.Fatalf("after a refused acknowledgement the record says on_relay=%v ack_owed=%v payload_on_relay=%v; "+
			"want the relay holding it with the acknowledgement owed", rec.OnRelay, rec.AckOwed, rec.PayloadOnRelay)
	}
	before := blobs.Load()
	refuse.Store(false)
	if out, err := bob.tryRun("inbox", "--json"); err != nil {
		t.Fatalf("healthy fetch after a refused acknowledgement: %v\n%s", err, out)
	}
	if rows := adv2RowIDs(t, st, bob.exportFingerprint()); len(rows) != 0 {
		t.Errorf("acknowledgement was never retried: relay still holds %v after a healthy fetch", rows)
	}
	if n := blobs.Load() - before; n != 0 {
		t.Errorf("the owed acknowledgement downloaded the stream again: %d blob requests", n)
	}
	rec = recordOf(t, bob, store.Inbox, "regular stream ack")
	if rec.OnRelay || rec.AckOwed {
		t.Errorf("after the acknowledgement the record says on_relay=%v ack_owed=%v; want neither", rec.OnRelay, rec.AckOwed)
	}
	if out, err := bob.tryRun("inbox", "--json"); err != nil {
		t.Errorf("a later fetch: %v\n%s", err, out)
	}
}

// An owed acknowledgement is made only of the copy it is owed for (G32,
// the reader's finding): a relay whose numbering began again after the
// acknowledgement was refused holds new mail under the record's old id,
// and the next fetch delivers that mail rather than acknowledging it away;
// the record says the relay no longer holds its copy.
func TestAnOwedAcknowledgementIsNotMadeOfARenumberedRow(t *testing.T) {
	r := startResettable(t)
	target, err := url.Parse(r.url)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var refuse atomic.Bool
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if refuse.Load() && q.Method == http.MethodDelete && strings.HasPrefix(q.URL.Path, "/v1/mailbox/") {
			http.Error(w, "temporary refusal of acknowledgement", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, q)
	}))
	defer front.Close()
	alice, bob := watchers(t, front.URL)
	bob.run("channel", "keep", "default", "off")
	streamSections(t, alice, bob, "owed stream", nil)
	refuse.Store(true)
	if _, err := bob.tryRun("inbox", "--json"); err == nil {
		t.Fatal("the refused acknowledgement was not said")
	}
	if rec := recordOf(t, bob, store.Inbox, "owed stream"); !rec.OnRelay || !rec.AckOwed {
		t.Fatalf("the record does not owe its acknowledgement: %+v", rec)
	}
	refuse.Store(false)
	r.renumber(t, bob.exportFingerprint())
	alice.run("send", "--to", "bob", "--subject", "new mail", "hello")
	bob.run("inbox", "--json")
	if rec := recordOf(t, bob, store.Inbox, "new mail"); rec == nil {
		t.Fatal("the new mail under the old id was acknowledged away instead of delivered")
	}
	if rec := recordOf(t, bob, store.Inbox, "owed stream"); rec.OnRelay || rec.AckOwed {
		t.Fatalf("the owed record still owes, for a copy the relay no longer holds: %+v", rec)
	}
}
