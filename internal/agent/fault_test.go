package agent

import (
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// faultingAgent is an agent whose clock faults once when tripped, so a test
// can plant a fault where the agent next reads the time.
type faultingAgent struct {
	server *Server
	client *Client
	log    *logBuffer
	trip   *atomic.Bool
}

func startFaultingAgent(t *testing.T) *faultingAgent {
	t.Helper()
	runtimeDirFor(t)
	home := newFakeHome(t)
	trip := &atomic.Bool{}
	now := func() time.Time {
		if trip.CompareAndSwap(true, false) {
			panic("a fault planted in the agent's clock")
		}
		return time.Now()
	}
	buf := &logBuffer{}
	s := NewServer(home, Options{Now: now, Log: log.New(buf, "", 0)})
	l, err := Listen(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		s.Stop()
		<-done
		l.Close()
	})
	c, err := NewClient(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	return &faultingAgent{server: s, client: c, log: buf, trip: trip}
}

// A fault answering one connection closes that connection, and the agent
// answers the next (S59): the connection's goroutine is outside every
// handler net/http would recover, so a panic there ended the agent and
// every machine's unlock with it. What it held is locked, since a fault
// part way through an unlock can leave the keys half set, and the fault is
// said once with its stack.
func TestAFaultInAConnectionEndsThatConnection(t *testing.T) {
	a := startFaultingAgent(t)
	if err := a.client.Unlock([]byte(passphrase), time.Hour, ScopeReceive); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	a.trip.Store(true)
	if _, err := a.client.Status(); err == nil {
		t.Fatal("the faulted connection was answered")
	}
	st, err := a.client.Status()
	if err != nil {
		t.Fatalf("the connection after a fault: %v; log:\n%s", err, a.log.String())
	}
	if !st.Locked {
		t.Errorf("the agent still holds its keys after a fault answering a connection; log:\n%s", a.log.String())
	}
	said := a.log.String()
	if n := strings.Count(said, "a connection to the agent ended with a fault"); n != 1 ||
		!strings.Contains(said, "a fault planted in the agent's clock") || !strings.Contains(said, "goroutine ") {
		t.Fatalf("the fault was said %d times, want once with its stack:\n%s", n, said)
	}
}

// A fault in the agent's expiry, which runs on its own timer outside any
// connection, locks the agent rather than ending it (S59).
func TestAFaultInTheExpiryLocks(t *testing.T) {
	a := startFaultingAgent(t)
	if err := a.client.Unlock([]byte(passphrase), time.Second, ScopeReceive); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	a.trip.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(a.log.String(), "the agent's expiry ended with a fault") {
		if time.Now().After(deadline) {
			t.Fatalf("the expiry never faulted; log:\n%s", a.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, err := a.client.Status()
	if err != nil {
		t.Fatalf("the agent after a fault in its expiry: %v", err)
	}
	if !st.Locked {
		t.Error("the agent still holds its keys after a fault in its expiry")
	}
}

// A fault in the watch of the agent's socket stops the agent cleanly (S59):
// going on without the watch would leave an agent that no longer heard
// SIGTERM or saw its socket go.
func TestAFaultInTheWatchStopsTheAgent(t *testing.T) {
	old := statSocket
	var faulted atomic.Bool
	statSocket = func(l *Listener) (socketState, error) {
		if faulted.CompareAndSwap(false, true) {
			panic("a fault planted in the watch")
		}
		return l.stat()
	}
	w := runWatched(t, 20*time.Millisecond)
	select {
	case err := <-w.done:
		// Put back for runWatched's own wait at cleanup.
		w.done <- err
	case <-time.After(stopBound):
		t.Fatalf("the agent did not stop after a fault in its watch; log:\n%s", w.log.String())
	}
	statSocket = old
	if said := w.log.String(); !strings.Contains(said, "the agent's watch of its socket ended with a fault") ||
		!strings.Contains(said, "a fault planted in the watch") {
		t.Fatalf("the fault was said as:\n%s", said)
	}
}
