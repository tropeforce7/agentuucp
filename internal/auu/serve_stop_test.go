package auu

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A stop reaches a fetch in flight (G38, R54): the round passed no context
// to the fetch, so an expert told to stop waited out a relay that had not
// answered until the request's own timeout. With --once and in the long
// run, the round ends with the stop as soon as it is given.
func TestServeStopReachesAFetchInFlight(t *testing.T) {
	for _, longRun := range []bool{false, true} {
		name := "once"
		if longRun {
			name = "long"
		}
		t.Run(name, func(t *testing.T) {
			_, bob := newExpert(t, modeReadOnly)
			// A relay that holds the mailbox read open until released,
			// and answers 400 then, so that a fetch it lets go of is
			// never mistaken for one that was stopped.
			entered, release := make(chan struct{}, 1), make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if strings.HasPrefix(req.URL.Path, "/v1/mailbox/") && !strings.HasSuffix(req.URL.Path, "/queue") {
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-release:
					case <-req.Context().Done():
					}
					http.Error(w, "fixture released", http.StatusBadRequest)
					return
				}
				if req.URL.Path == "/v1/health" {
					io.WriteString(w, listingAdvHealth)
					return
				}
				http.NotFound(w, req)
			}))
			defer srv.Close()
			defer close(release)
			repointRelay(t, bob.user, srv.URL)
			s, id, _ := bob.opened()
			cfg, err := loadServeConfig(bob.path)
			if err != nil {
				t.Fatal(err)
			}
			r := &serveRun{s: s, id: id, cfg: cfg, led: bob.ledgerOf(t), root: s.ServeDir()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.round(ctx, false, longRun) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the fetch never reached the relay")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("the stopped round returned %v; want the stop", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("the round still waits on the fetch after the stop")
				// The relay may have let the request go already, so the
				// release is offered and not insisted on.
				select {
				case release <- struct{}{}:
				case <-time.After(time.Second):
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("the fetch did not end after the relay let it go")
				}
			}
		})
	}
}

// A stop ends the fetch where it is (G38, R54): the relay it was waiting on
// is not said to be unreachable, and the relays after it are not asked.
// With one relay the fetch's own error already carries the stop; this is
// two, the first holding the fetch open and the second counting what it is
// asked.
func TestServeStopAsksNoFurtherRelay(t *testing.T) {
	_, bob := newExpert(t, modeReadOnly)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	holding := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/v1/mailbox/") && !strings.HasSuffix(req.URL.Path, "/queue") {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-req.Context().Done():
			}
			http.Error(w, "fixture released", http.StatusBadRequest)
			return
		}
		if req.URL.Path == "/v1/health" {
			io.WriteString(w, listingAdvHealth)
			return
		}
		http.NotFound(w, req)
	}))
	defer holding.Close()
	defer close(release)
	var asked atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		asked.Add(1)
		http.NotFound(w, req)
	}))
	defer second.Close()

	first := repointRelay(t, bob.user, holding.URL)
	s, id, _ := bob.opened()
	r, err := s.Relay(first)
	if err != nil {
		t.Fatal(err)
	}
	other := *r
	other.Name, other.URL = "zz-second", second.URL
	if err := s.SaveRelay(&other); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRegistered(&other); err != nil {
		t.Fatal(err)
	}
	relays, err := selectedRelays(s, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 2 || relays[0].Name != first || relays[1].Name != other.Name {
		t.Fatalf("the round would fetch %v; want %s then %s, or the test proves nothing", relays, first, other.Name)
	}
	cfg, err := loadServeConfig(bob.path)
	if err != nil {
		t.Fatal(err)
	}
	run := &serveRun{s: s, id: id, cfg: cfg, led: bob.ledgerOf(t), root: s.ServeDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var roundErr error
	stderr := captureStderr(t, func() {
		done := make(chan error, 1)
		go func() { done <- run.round(ctx, false, true) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Error("the fetch never reached the first relay")
			return
		}
		cancel()
		select {
		case roundErr = <-done:
		case <-time.After(5 * time.Second):
			t.Error("the round still waits on the fetch after the stop")
		}
	})
	if !errors.Is(roundErr, context.Canceled) {
		t.Fatalf("the stopped round returned %v; want the stop", roundErr)
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("the relay after the stopped one was asked %d times", n)
	}
	if strings.Contains(stderr, "could not be reached") {
		t.Fatalf("a stop was said as a relay that could not be reached:\n%s", stderr)
	}
}
