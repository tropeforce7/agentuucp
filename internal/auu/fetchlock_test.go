package auu

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// settleGate is a relay front that refuses acknowledgements while told to
// and holds the first owed acknowledgement's check once armed: the one-row
// stub listing a fetch makes before it acknowledges what an earlier fetch
// delivered (stillListed), which is the round trip a trust or an rm landed
// inside. It counts every such check.
type settleGate struct {
	refuse  atomic.Bool
	armed   atomic.Bool
	checks  atomic.Int64
	held    chan struct{}
	release chan struct{}
	once    sync.Once
	// onAllow, when set, is called as an allow list push arrives.
	onAllow atomic.Pointer[func()]
}

func (g *settleGate) open() { g.once.Do(func() { close(g.release) }) }

func startSettleGate(t *testing.T) (*settleGate, string, *relay.Store) {
	t.Helper()
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	g := &settleGate{held: make(chan struct{}), release: make(chan struct{})}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.refuse.Load() && r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			http.Error(w, "temporary refusal of acknowledgement", http.StatusForbidden)
			return
		}
		if f := g.onAllow.Load(); f != nil && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/allow") {
			(*f)()
		}
		if q := r.URL.Query(); r.Method == http.MethodGet && q.Get("stubs") == "1" && q.Get("limit") == "1" {
			g.checks.Add(1)
			if g.armed.CompareAndSwap(true, false) {
				close(g.held)
				<-g.release
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	// Opened before the front closes, so a held check never holds the
	// close up.
	t.Cleanup(front.Close)
	t.Cleanup(g.open)
	return g, front.URL, st
}

// heldFetch starts a fetch for u in another process and returns once the
// gate holds it at its owed acknowledgement's check, its fetch lock taken.
// Its done channel closes when that process has ended.
func heldFetch(t *testing.T, u *user, g *settleGate) chan struct{} {
	t.Helper()
	g.armed.Store(true)
	done := joined(t, func() { u.inAnotherProcess("inbox", "--json") })
	select {
	case <-g.held:
	case <-time.After(15 * time.Second):
		t.Fatal("the fetch never reached its owed acknowledgement")
	}
	return done
}

// openOnWait opens the gate the first time a command in this process finds
// a fetch lock held, so that a command which takes the lock waits for the
// held fetch and the fetch then finishes; one that does not take it never
// calls this, and the gate is opened after it.
func openOnWait(t *testing.T, g *settleGate) *atomic.Int64 {
	t.Helper()
	var waited atomic.Int64
	fetchLockSleep = func(time.Duration) {
		waited.Add(1)
		g.open()
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { fetchLockSleep = time.Sleep })
	return &waited
}

// boxHolds says whether u's box holds a record under id.
func boxHolds(t *testing.T, u *user, box store.Box, id string) bool {
	t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(box)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Inner.ID == id {
			return true
		}
	}
	return false
}

// owedInQuarantine is a stranger's stream whose trust fetched its payload
// and was then refused the acknowledgement, so the quarantine record says
// the relay holds it and is owed the acknowledgement.
func owedInQuarantine(t *testing.T, g *settleGate, alice, bob *user) *store.Stored {
	t.Helper()
	bob.run("channel", "keep", "default", "off")
	streamSections(t, alice, bob, "trust in a fetch", nil)
	bob.run("inbox", "--json")
	rec := recordOf(t, bob, store.Quarantine, "trust in a fetch")
	g.refuse.Store(true)
	if _, err := bob.answer("alice", "quarantine", "trust", rec.Inner.ID); err == nil {
		t.Fatal("the first trust was not refused its acknowledgement")
	}
	g.refuse.Store(false)
	rec = recordOf(t, bob, store.Quarantine, "trust in a fetch")
	if !rec.OnRelay || !rec.AckOwed {
		t.Fatalf("the quarantine record says on_relay=%v ack_owed=%v; want the acknowledgement owed", rec.OnRelay, rec.AckOwed)
	}
	return rec
}

// A trust run while a fetch settles the same record's owed acknowledgement
// waits for the fetch, as the fetch lock makes two fetches do, and reads
// the record again once it has the lock: the message ends in the inbox
// alone, under the name given, and the trust does not
// check again what the fetch settled. Without the lock the fetch saved its
// copy of the record back into the quarantine after the move, and the
// message was in both boxes.
func TestATrustDuringAFetchLeavesTheMessageInTheInboxAlone(t *testing.T) {
	g, url, _ := startSettleGate(t)
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	rec := owedInQuarantine(t, g, alice, bob)
	id := rec.Inner.ID

	waited := openOnWait(t, g)
	before := g.checks.Load()
	fetched := heldFetch(t, bob, g)
	out, err := bob.answer("alice", "quarantine", "trust", id)
	g.open()
	<-fetched
	if err != nil {
		t.Fatalf("trust: %v\n%s", err, out)
	}
	if waited.Load() == 0 {
		t.Error("the trust did not wait for the fetch settling its record")
	}
	if boxHolds(t, bob, store.Quarantine, id) {
		t.Error("the message is still in the quarantine after its trust: a fetch saved it back")
	}
	in := recordOf(t, bob, store.Inbox, "trust in a fetch")
	if in.SenderName != "alice" {
		t.Errorf("the inbox record names the sender %q, want the name given at the trust", in.SenderName)
	}
	if in.OnRelay || in.AckOwed {
		t.Errorf("the inbox record says on_relay=%v ack_owed=%v; want the acknowledgement made", in.OnRelay, in.AckOwed)
	}
	// One check, the fetch's: the trust read the record again under the
	// lock and found the acknowledgement made.
	if n := g.checks.Load() - before; n != 1 {
		t.Errorf("the relay was asked %d times whether it still holds the message, want once, by the fetch", n)
	}
}

// An rm run while a fetch settles the same record's owed acknowledgement
// waits for the fetch, and the message stays removed. Without the lock the
// fetch saved its copy back after the removal.
func TestAnRmDuringAFetchLeavesTheMessageRemoved(t *testing.T) {
	g, url, _ := startSettleGate(t)
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "keep", "default", "off")
	streamSections(t, alice, bob, "rm in a fetch", nil)
	g.refuse.Store(true)
	if _, err := bob.tryRun("inbox", "--json"); err == nil {
		t.Fatal("the fetch was not refused its acknowledgement")
	}
	g.refuse.Store(false)
	rec := recordOf(t, bob, store.Inbox, "rm in a fetch")
	if !rec.OnRelay || !rec.AckOwed {
		t.Fatalf("the inbox record says on_relay=%v ack_owed=%v; want the acknowledgement owed", rec.OnRelay, rec.AckOwed)
	}
	id := rec.Inner.ID

	waited := openOnWait(t, g)
	fetched := heldFetch(t, bob, g)
	out, err := bob.tryRun("rm", "--local-only", id)
	g.open()
	<-fetched
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	if waited.Load() == 0 {
		t.Error("the rm did not wait for the fetch settling its record")
	}
	if boxHolds(t, bob, store.Inbox, id) {
		t.Error("the removed message is back in the inbox: a fetch saved it back")
	}
}

// A trust or an rm that cannot have the fetch lock says another fetch is
// running, at exit 2, and changes nothing: the record byte for byte as it
// was, nobody added, nothing acknowledged.
func TestATrustOrAnRmRefusedTheFetchLockChangesNothing(t *testing.T) {
	g, url, st := startSettleGate(t)
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	rec := owedInQuarantine(t, g, alice, bob)
	id := rec.Inner.ID

	s, _, relays := bob.opened()
	lock, err := lockfile.Try(filepath.Join(s.RelayDir(relays[0]), fetchLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	fetchLockWait = 0
	t.Cleanup(func() { fetchLockWait = time.Minute })

	path := filepath.Join(bob.home, "quarantine", id+".json")
	was, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := s.Peers()
	if err != nil {
		t.Fatal(err)
	}
	rows := adv2RowIDs(t, st, bob.exportFingerprint())
	want := "another auu is fetching from " + relays[0].Name + "; try again in a moment"
	for _, args := range [][]string{{"quarantine", "trust", id}, {"rm", id}, {"rm", "--local-only", id}} {
		_, err := bob.answer("alice", args...)
		if err == nil || !strings.Contains(err.Error(), want) || exitCodeOf(err) != 2 {
			t.Errorf("%v with the fetch lock held: %v (exit %d), want %q at exit 2", args, err, exitCodeOf(err), want)
		}
		now, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(now, was) {
			t.Errorf("%v with the fetch lock held changed the record: %v", args, err)
		}
		if after, err := s.Peers(); err != nil || len(after) != len(peers) {
			t.Errorf("%v with the fetch lock held changed the peers: %d, want %d (%v)", args, len(after), len(peers), err)
		}
		if after := adv2RowIDs(t, st, bob.exportFingerprint()); len(after) != len(rows) {
			t.Errorf("%v with the fetch lock held acknowledged: rows %v, want %v", args, after, rows)
		}
	}
	if boxHolds(t, bob, store.Inbox, id) {
		t.Error("a refused trust moved the message")
	}
}

// A trust lets go of the fetch lock once the message is moved, before it
// asks whether to push the allow list: the question waits on the person,
// and a fetch of that relay waiting behind it would give up after a minute.
func TestATrustLetsTheFetchLockGoBeforeItsQuestion(t *testing.T) {
	g, url, _ := startSettleGate(t)
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	rec := owedInQuarantine(t, g, alice, bob)
	bob.run("allow", "push")
	s, _, relays := bob.opened()
	path := filepath.Join(s.RelayDir(relays[0]), fetchLockName)
	var pushed, free atomic.Bool
	f := func() {
		pushed.Store(true)
		if l, err := lockfile.Try(path); err == nil {
			free.Store(true)
			l.Release()
		}
	}
	g.onAllow.Store(&f)
	out, err := bob.answer("alice\ny", "quarantine", "trust", rec.Inner.ID)
	if err != nil {
		t.Fatalf("trust: %v\n%s", err, out)
	}
	if !pushed.Load() {
		t.Fatalf("the trust pushed no allow list:\n%s", out)
	}
	if !free.Load() {
		t.Error("the fetch lock was still held when the trust pushed the allow list it had asked about")
	}
}
