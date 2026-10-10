package auu

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The third adversarial trace, at v0.17.0, on the order of a listing's
// rows: a relay that answers every listing with the same row, whatever
// `after` says, kept a fetch in its loop for ever, acknowledging the row and
// keeping it again on every turn. Its test is here as the regression test,
// renamed for what it proves, with the stand-in relay and its inputs as the
// trace wrote them.

// listingAdvHealth is the trace's health answer for its stand-in relay.
const listingAdvHealth = `{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1}`

// The trace's stand-in answers every listing with row 7. Asked after 0,
// row 7 is above it and honest, so bob's cursor is set to 7 before the
// fetch: the first listing asks after 7, gets row 7 back, and that page is
// refused as malformed naming the id. The fetch ends there as a transport
// failure, having asked once, acknowledged nothing and kept nothing under
// damaged/.
func TestAListingPageThatRepeatsARowIsRefusedByName(t *testing.T) {
	bob := newUser(t, "bob", startRelay(t))
	var listings, deletes atomic.Int64
	const enough = 60
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, listingAdvHealth)
		case r.Method == "DELETE":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			if listings.Add(1) > enough {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"error":"the stand-in gave up","code":""}`)
				return
			}
			io.WriteString(w, `{"messages":[{"id":7,"received":"2026-10-10T00:00:00Z","kind":"envelope","size":2,"channel":"default","via":"","envelope":{}}],`+
				`"queued":1,"first":7,"last":7,"allow":"none","card":"none","directory":"none"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	defer hostile.Close()
	repointRelay(t, bob, hostile.URL)

	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCursorFor(r, 7); err != nil {
		t.Fatal(err)
	}
	damagedBefore := listingDamagedFiles(t, s.DamagedDir())

	done := make(chan error, 1)
	go func() {
		_, err := bob.tryRun("inbox")
		done <- err
	}()
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("inbox still running after %d listings", listings.Load())
	}
	t.Logf("inbox ended after %d listings and %d DELETEs: %v", listings.Load(), deletes.Load(), err)

	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("the fetch of a page repeating row 7: %v; want a transport failure, exit %d", err, exitTransport)
	}
	if !errors.Is(err, client.ErrMalformedAnswer) ||
		!strings.Contains(err.Error(), "in the listing, id is not above the id asked after") ||
		!strings.Contains(err.Error(), hostile.URL) {
		t.Errorf("the failure %q is not a malformed listing from %s naming the id", err, hostile.URL)
	}
	if n := listings.Load(); n != 1 {
		t.Errorf("the fetch asked for the listing %d times; want once, ending at the first repeated page", n)
	}
	if n := deletes.Load(); n != 0 {
		t.Errorf("the fetch acknowledged %d times; want nothing acknowledged from a refused page", n)
	}
	if damagedAfter := listingDamagedFiles(t, s.DamagedDir()); !slices.Equal(damagedAfter, damagedBefore) {
		t.Errorf("damaged/ went from %q to %q; want it untouched", damagedBefore, damagedAfter)
	}
	if cursor, err := s.CursorFor(r); err != nil || cursor != 7 {
		t.Errorf("the cursor is %d (%v); want it left at 7", cursor, err)
	}
}

// listingDamagedFiles is every path under damaged/, relative to it, in
// order; a damaged/ that does not exist is empty.
func listingDamagedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir {
			rel, _ := filepath.Rel(dir, path)
			paths = append(paths, rel)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return paths
}
