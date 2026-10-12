package auu

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The second adversarial review's tests on a record's arrival (G9), with
// the stand-in relays and the inputs as the review wrote them.

// legacyArrivalHealth is the review's health answer for its stand-in relay.
const legacyArrivalHealth = `{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1}`

// F11: the lower edge. A received of 0000-01-01T00:00:00Z is within what
// 15cab8c holds (stamp: not ahead, Writable in UTC), and this machine's zone
// is twelve hours behind UTC, where the same instant is the year -1. The
// fetch, rm --local-only, a second fetch, read and inbox --json must all
// work: nothing may write that time in the local zone.
func TestAReceivedAtYearZeroInAZoneBehindUTCIsKeptAndWrittenBack(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("UTC-12", -12*3600)
	defer func() { time.Local = saved }()
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("peers", "add", alice.exportLine())
	const id = "00112233445566778899aabbccddeeff"
	env := sealByHand(t, alice, bob, &envelope.Inner{V: envelope.Version, ID: id, Time: time.Now().UTC(),
		Body: message.Body{Type: message.TypeNote, Thread: id, Subject: "hello", Text: "from alice"}})
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, legacyArrivalHealth)
		case r.Method == "DELETE":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			if r.URL.Query().Get("after") == "0" {
				body := ""
				if r.URL.Query().Get("stubs") != "1" {
					body = fmt.Sprintf(`,"envelope":%s`, raw)
				}
				fmt.Fprintf(w, `{"messages":[{"id":1,"received":"0000-01-01T00:00:00Z","kind":"envelope","size":%d,"channel":"default","via":""%s}],`+
					`"queued":1,"first":1,"last":1,"allow":"none","card":"none","directory":"none"}`, len(raw), body)
				return
			}
			io.WriteString(w, `{"messages":[],"queued":1,"first":1,"last":1,"allow":"none","card":"none","directory":"none"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	defer hostile.Close()
	repointRelay(t, bob, hostile.URL)
	if first := bob.inboxJSON(); first.Fetch.Delivered != 1 {
		t.Fatalf("first fetch: %+v", first.Fetch)
	}
	for _, args := range [][]string{{"read", id}, {"inbox", "--json", "--no-fetch"}, {"rm", "--local-only", id}, {"inbox"}, {"inbox", "--json"}} {
		out, err := bob.tryRun(args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

// 608ef9e/1bb2fa3 residual (G9): a record v0.15.0 to v0.17.0 kept has no
// arrived, and Load lent it the relay's received whenever that could be
// written back, however far ahead of now it was. Those releases kept
// whatever received a relay sent; one a hostile relay stamped in the year
// 9000 was the newest message in the inbox and the latest on its thread
// after the upgrade, and the first save that touched it (a mark as read)
// wrote 9000 as its arrival for good. Load now holds the lent arrival to
// the skew as the fetch holds the stamp (15cab8c), and such a record
// arrives at its file's time. The file's time is set to the arrival the
// record had before it was rewritten, which is before the second
// message's, so the record lists first, below the message fetched after
// it, and the read writes the file's time back as the arrival and never
// the year 9000.
func TestALegacyRecordStampedAheadArrivesAtItsFileTime(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("send", "--to", "bob", "--subject", "legacy", "kept by v0.17.0")
	bob.inboxJSON()
	// A message that arrives after it.
	alice.run("send", "--to", "bob", "--subject", "fresh", "arrived later")
	bob.inboxJSON()
	// Make it the record v0.17.0 would have written from a hostile relay:
	// no arrived, received in the year 9000.
	s, _, _ := bob.opened()
	rec := recordOf(t, bob, store.Inbox, "legacy")
	fresh := recordOf(t, bob, store.Inbox, "fresh")
	path := filepath.Join(bob.home, string(store.Inbox), rec.Inner.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "arrived")
	m["received"] = "9000-01-01T00:00:00Z"
	data, _ = json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fileTime := rec.Arrived.Truncate(time.Second)
	if !fileTime.Before(fresh.Arrived) {
		t.Fatalf("the legacy record arrived at %v, not before the fresh one at %v, so the order proves nothing", fileTime, fresh.Arrived)
	}
	if err := os.Chtimes(path, fileTime, fileTime); err != nil {
		t.Fatal(err)
	}
	got := bob.inboxJSON("--no-fetch")
	if len(got.Messages) != 2 {
		t.Fatalf("inbox: %+v", got.Messages)
	}
	first, last := got.Messages[0], got.Messages[len(got.Messages)-1]
	_, latest, err := s.FindThread(rec.Inner.Body.Thread)
	t.Logf("inbox order: %q (arrived %s), %q (arrived %s); latest on its thread %v",
		first.Subject, first.Arrived, last.Subject, last.Arrived, err == nil && latest != nil && latest.Inner.ID == rec.Inner.ID)
	if first.Subject != "legacy" || last.Subject != "fresh" {
		t.Fatalf("a legacy record whose relay stamped it in the year 9000 lists as %q then %q; want it first, at its file's time, below the message fetched after it",
			first.Subject, last.Subject)
	}
	if !first.Arrived.Equal(fileTime) {
		t.Errorf("the legacy record lists arrived %v; want its file's time %v", first.Arrived, fileTime)
	}
	bob.run("read", rec.Inner.ID)
	after := bob.stored(store.Inbox, rec.Inner.ID)
	if !after.Read || !after.Arrived.Equal(fileTime) || after.Arrived.Year() == 9000 {
		t.Errorf("the read wrote read %v, arrived %s; want read and its file's time %s",
			after.Read, after.Arrived.Format(time.RFC3339), fileTime.Format(time.RFC3339))
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), `"arrived": "`+fileTime.UTC().Format(time.RFC3339Nano)+`"`) {
		t.Errorf("the read did not write the file's time back as the arrival:\n%s", written)
	}
}

// F11/608ef9e: a fresh fetch at the edge. A relay stamps its row four
// minutes and fifty seconds ahead, inside the five 15cab8c allows; the
// record keeps that received but arrives as now, so a message fetched a
// moment later still lists after it, and the stamp pins nothing.
func TestAReceivedJustInsideTheSkewPinsNothing(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	bob.run("peers", "add", alice.exportLine())
	alice.run("peers", "add", bob.exportLine())
	const id = "00112233445566778899aabbccddeef0"
	env := sealByHand(t, alice, bob, &envelope.Inner{V: envelope.Version, ID: id, Time: time.Now().UTC(),
		Body: message.Body{Type: message.TypeNote, Thread: id, Subject: "ahead", Text: "stamped ahead"}})
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ahead := time.Now().Add(4*time.Minute + 50*time.Second).UTC().Format(time.RFC3339Nano)
	var served atomic.Bool
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, legacyArrivalHealth)
		case r.Method == "DELETE":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			if r.URL.Query().Get("after") == "0" && !served.Load() {
				served.Store(true)
				// The review's stand-in said last 0 here; a fetch now
				// stops at the last the first page names (R6), so the
				// row it lists is named.
				fmt.Fprintf(w, `{"messages":[{"id":1,"received":%q,"kind":"envelope","size":%d,"channel":"default","via":"","envelope":%s}],`+
					`"queued":1,"first":1,"last":1,"allow":"none","card":"none","directory":"none"}`, ahead, len(raw), raw)
				return
			}
			io.WriteString(w, `{"messages":[],"queued":0,"first":0,"last":0,"allow":"none","card":"none","directory":"none"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	defer hostile.Close()
	name := repointRelay(t, bob, hostile.URL)
	if got := bob.inboxJSON(); got.Fetch.Delivered != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	// A second message through a second relay, fetched after.
	second := startRelay(t)
	bob.run("relay", "add", second, "--name", "second")
	bob.run("register", "--relay", "second")
	alice.run("relay", "add", second, "--name", "second")
	alice.run("register", "--relay", "second")
	alice.run("send", "--to", "bob", "--relay", "second", "--subject", "later", "fetched after")
	got := bob.inboxJSON()
	t.Logf("relay %s; inbox: %+v", name, func() (s []string) {
		for _, m := range got.Messages {
			s = append(s, m.Subject+" received "+m.Received.Format(time.RFC3339))
		}
		return
	}())
	if n := len(got.Messages); n != 2 || got.Messages[n-1].Subject != "later" {
		t.Fatalf("a received stamped 4m50s ahead pinned its message: %+v", got.Messages)
	}
}
