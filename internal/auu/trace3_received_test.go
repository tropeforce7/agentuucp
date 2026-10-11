package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The third adversarial trace, at v0.17.0, on a relay's received stamp: a
// relay listed a row received at "9999-12-31T23:59:59-12:00", a valid RFC
// 3339 stamp whose UTC year is 10000. The fetch kept it as it was, 'rm
// --local-only' wrote it into the relay's left-behind file as
// "10000-01-01T11:59:59Z", and the file's own reader refused that line, so
// every later fetch, rm and wait on the relay stopped on a damaged home
// until a person deleted the file. Its test is here as the regression
// test, renamed for what it proves, with the stand-in relay and its inputs
// as the trace wrote them.

// receivedAdvHealth is the trace's health answer for its stand-in relay.
const receivedAdvHealth = `{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1}`

// receivedFromTheFuture is the trace's stamp: year 9999 at -12:00, UTC
// year 10000.
const receivedFromTheFuture = "9999-12-31T23:59:59-12:00"

// The listing carrying the stamp is refused as malformed, naming received
// and the relay, before anything of it is used: the fetch is a transport
// failure, delivers and keeps nothing and acknowledges nothing. A record
// an earlier release kept with that stamp, planted here in the store, is
// then removed with 'rm --local-only': the left-behind line is refused
// before it is written, naming the message, the record stays, and the
// left-behind file is as it was, absent first and byte-equal after an
// ordinary entry is in it.
func TestAReceivedTimeFromTheFutureIsRefusedBeforeItIsKept(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("peers", "add", alice.exportLine())
	inner := &envelope.Inner{V: envelope.Version,
		ID: "00112233445566778899aabbccddeeff", Time: time.Now().UTC(),
		Body: message.Body{Type: message.TypeNote, Thread: "00112233445566778899aabbccddeeff", Subject: "hello", Text: "from alice"},
	}
	env := sealByHand(t, alice, bob, inner)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var listings, deletes, others atomic.Int64
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, receivedAdvHealth)
		case r.Method == "DELETE":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			if strings.Count(r.URL.Path, "/") != 3 {
				others.Add(1)
			} else {
				listings.Add(1)
			}
			if strings.Contains(r.URL.RawQuery, "after=0") {
				body := "" // a stubs listing carries the row without its envelope
				if !strings.Contains(r.URL.RawQuery, "stubs=1") {
					body = fmt.Sprintf(`,"envelope":%s`, raw)
				}
				fmt.Fprintf(w, `{"messages":[{"id":1,"received":%q,"kind":"envelope","size":%d,"channel":"default","via":""%s}],`+
					`"queued":1,"first":1,"last":1,"allow":"none","card":"none","directory":"none"}`, receivedFromTheFuture, len(raw), body)
				return
			}
			io.WriteString(w, `{"messages":[],"queued":1,"first":1,"last":1,"allow":"none","card":"none","directory":"none"}`)
		default:
			others.Add(1)
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	defer hostile.Close()
	relayName := repointRelay(t, bob, hostile.URL)

	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	damagedBefore := listingDamagedFiles(t, s.DamagedDir())

	_, err = bob.tryRun("inbox")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("the fetch of a listing received in UTC year 10000: %v; want a transport failure, exit %d", err, exitTransport)
	}
	if !errors.Is(err, client.ErrMalformedAnswer) ||
		!strings.Contains(err.Error(), "in the listing, received is not a time no further ahead of this machine's clock than a request may be, and within the years 0000 to 9999") ||
		!strings.Contains(err.Error(), hostile.URL) {
		t.Errorf("the failure %q is not a malformed listing from %s naming received", err, hostile.URL)
	}
	if n := listings.Load(); n != 1 {
		t.Errorf("the fetch asked for the listing %d times; want once, ending at the refused page", n)
	}
	if n := others.Load(); n != 0 {
		t.Errorf("the fetch asked the relay for %d things besides the listing; want nothing fetched", n)
	}
	if n := deletes.Load(); n != 0 {
		t.Errorf("the fetch acknowledged %d times; want nothing acknowledged from a refused page", n)
	}
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		if kept, err := s.List(box); err != nil || len(kept) != 0 {
			t.Errorf("%s holds %d records (%v); want nothing kept", box, len(kept), err)
		}
	}
	if damagedAfter := listingDamagedFiles(t, s.DamagedDir()); !slices.Equal(damagedAfter, damagedBefore) {
		t.Errorf("damaged/ went from %q to %q; want it untouched", damagedBefore, damagedAfter)
	}
	if cursor, err := s.CursorFor(r); err != nil || cursor != 0 {
		t.Errorf("the cursor is %d (%v); want it left at 0", cursor, err)
	}

	// An earlier release kept the row as the relay listed it: the record
	// is planted with that stamp, still on the relay.
	received, err := time.Parse(time.RFC3339, receivedFromTheFuture)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(store.Inbox, &store.Stored{RelayID: 1, Relay: relayName, Received: received, Inner: inner,
		SenderName: "alice", RelaySize: int64(len(raw)), OnRelay: true}); err != nil {
		t.Fatal(err)
	}
	leftBehind := filepath.Join(s.RelayDir(r), "left-behind")
	rmRefused := func(t *testing.T) {
		t.Helper()
		before, beforeErr := os.ReadFile(leftBehind)
		_, err := bob.tryRun("rm", "--local-only", inner.ID)
		if err == nil {
			t.Fatal("rm --local-only of a record received in UTC year 10000 succeeded; want it refused before the left-behind file is written")
		}
		if !strings.Contains(err.Error(), "message "+inner.ID+" on the relay has a received time this program cannot write back") {
			t.Errorf("the refusal %q does not name the message", err)
		}
		after, afterErr := os.ReadFile(leftBehind)
		switch {
		case errors.Is(beforeErr, fs.ErrNotExist):
			if !errors.Is(afterErr, fs.ErrNotExist) {
				t.Errorf("the left-behind file was absent and is now there (%v): %q", afterErr, after)
			}
		case beforeErr != nil:
			t.Fatal(beforeErr)
		case afterErr != nil || !bytes.Equal(before, after):
			t.Errorf("the left-behind file went from %q to %q (%v); want it byte-equal", before, after, afterErr)
		}
		if m, err := s.Holding(store.Inbox, inner.ID); err != nil || m == nil {
			t.Errorf("the record is gone (%v); want it kept, since its relay copy could not be remembered", err)
		}
		if entries, err := s.LeftBehind(relayName); err != nil {
			t.Errorf("the left-behind file no longer reads: %v", err)
		} else if slices.ContainsFunc(entries, func(e store.LeftEntry) bool { return e.RelayID == 1 }) {
			t.Errorf("the left-behind file names relay id 1: %+v", entries)
		}
	}
	t.Run("with no left-behind file", rmRefused)

	// With an ordinary entry already there, the file is left byte-equal.
	if err := s.SetLeftBehind(relayName, []store.LeftEntry{{RelayID: 9, ID: "ffeeddccbbaa99887766554433221100",
		Received: time.Now().UTC().Truncate(time.Second), Size: 3}}); err != nil {
		t.Fatal(err)
	}
	t.Run("with an ordinary entry left behind", rmRefused)
}
