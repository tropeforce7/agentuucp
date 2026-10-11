package auu

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The ends of what an RFC 3339 stamp carries: time.Time's decoder takes
// the years 0000 to 9999 as written and an offset up to a minute short of
// a day, so the earliest instant a relay can send is the first of year 0
// at +23:59, in the year -1 in UTC, and the latest the last instant of
// 9999 at -23:59, in the year 10000 in UTC.
var (
	wireEarliest = time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("", 23*3600+59*60))
	wireLatest   = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60)))
)

// TestLimitQueueTimesAtTheExtremes: the inbox's queue line picks, per
// neighbour, the earliest next try and the earliest give-up among the
// waiting rows, with Before, and shows them. Fed time.Unix(math.MinInt64,
// 0) and the year 10000 in either order, on one neighbour's rows, the line
// is written without a panic and names the far past as the earliest of
// each; and the listing 'auu queue' prints renders every one of the rows.
// Before holds over the type's whole range, so nothing here can wrap.
//
// time.Unix(math.MinInt64, 0) is the earliest instant, and is rendered by
// the time package with a year it cannot compute, 292277026596; that is
// a display of a value the wire cannot carry, since a relay's answer is
// JSON and its decoder refuses a year outside 0000 to 9999. The ends of
// what the wire does carry are fed too and picked the same way.
func TestLimitQueueTimesAtTheExtremes(t *testing.T) {
	far := time.Unix(math.MinInt64, 0)
	y10k := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	row := func(id int64, last, next, up time.Time) relayapi.QueuedMessage {
		return relayapi.QueuedMessage{ID: id, Neighbour: "bar", State: "waiting", Tries: 1,
			LastTry: last, NextTry: next, GivesUp: up}
	}
	for _, c := range []struct {
		label           string
		rows            []relayapi.QueuedMessage
		next, up, since time.Time
		later           time.Time
	}{
		{"the far past first",
			[]relayapi.QueuedMessage{row(1, far, far, far), row(2, y10k, y10k, y10k)},
			far, far, far, y10k},
		{"the year 10000 first",
			[]relayapi.QueuedMessage{row(1, y10k, y10k, y10k), row(2, far, far, far)},
			far, far, far, y10k},
		{"mixed per field",
			[]relayapi.QueuedMessage{row(1, y10k, far, y10k), row(2, far, y10k, far)},
			far, far, far, y10k},
		{"the ends of the wire",
			[]relayapi.QueuedMessage{row(1, wireLatest, wireLatest, wireLatest), row(2, wireEarliest, wireEarliest, wireEarliest)},
			wireEarliest, wireEarliest, wireEarliest, wireLatest},
	} {
		t.Run(c.label, func(t *testing.T) {
			got := queueLine(relayFetch{Relay: "work", Outbound: c.rows})
			for _, want := range []string{
				"2 waiting at work for bar",
				"unreachable since " + stamp(c.since),
				"next try " + stamp(c.next),
				"gives up " + stamp(c.up),
			} {
				if !strings.Contains(got, want) {
					t.Errorf("%q does not contain %q", got, want)
				}
			}
			// The later one is not the one shown, where the two render
			// differently at all.
			if stamp(c.later) != stamp(c.next) && strings.Contains(got, "next try "+stamp(c.later)) {
				t.Errorf("%q shows the later next try", got)
			}
			if stamp(c.later) != stamp(c.up) && strings.Contains(got, "gives up "+stamp(c.later)) {
				t.Errorf("%q shows the later give-up", got)
			}

			var rows []queuedJSON
			for _, q := range c.rows {
				rows = append(rows, queuedJSON{ID: q.ID, Neighbour: q.Neighbour, State: q.State, Tries: q.Tries,
					LastTry: q.LastTry, NextTry: q.NextTry, GivesUp: q.GivesUp, Relay: "work"})
			}
			out, _ := captureStdout(t, func() error { printQueue(rows); return nil })
			for _, q := range c.rows {
				want := "1 try since " + stamp(q.LastTry) + ", next try " + stamp(q.NextTry) + ", gives up " + stamp(q.GivesUp)
				if !strings.Contains(out, want) {
					t.Errorf("the listing does not show %q:\n%s", want, out)
				}
			}
		})
	}
	if stamp(far) == "never" || stamp(y10k) == "never" {
		t.Error("an extreme time rendered as never, which is the zero time's word")
	}
}

// TestLimitACertificatesNotAfterAtTheExtremes: 'auu cert ls' compares each
// certificate's not_after with now, with After, for its state word: one
// whose not_after has passed is "expired" and one still to come "expires".
// A relay answering the earliest and the latest instants the wire carries,
// the year -1 and the year 10000 in UTC, gets "expired" and "expires" with
// the dates, without a panic. time.Unix(math.MinInt64, 0) and the year
// 10000 written in UTC cannot come from a relay at all: the answer is
// JSON and the relay's encoder refuses a year outside 0000 to 9999, which
// the test shows, and the comparison the command makes is shown on them
// directly.
func TestLimitACertificatesNotAfterAtTheExtremes(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)

	const oldSerial = "0123456789abcdef0123456789abcdef"
	const newSerial = "fedcba9876543210fedcba9876543210"
	answer, err := json.Marshal(relayapi.CertsResponse{Certs: []relayapi.CertRecord{
		{Serial: oldSerial, Label: "old", NotBefore: wireEarliest, NotAfter: wireEarliest},
		{Serial: newSerial, Label: "new", NotBefore: wireEarliest, NotAfter: wireLatest},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// The relay itself for everything but the listing, which says what the
	// test needs said.
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certs") {
			w.Header().Set("Content-Type", "application/json")
			w.Write(answer)
			return
		}
		req, _ := http.NewRequest(r.Method, relayURL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer front.Close()
	alice.run("relay", "add", front.URL, "--name", "edge")

	out := alice.run("cert", "ls", "--relay", "edge")
	for _, want := range []string{
		oldSerial[:16] + "  old                   expired " + wireEarliest.Local().Format("2006-01-02"),
		newSerial[:16] + "  new                   expires " + wireLatest.Local().Format("2006-01-02"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cert ls does not show %q:\n%s", want, out)
		}
	}
	// --json writes them back out as the relay sent them.
	if _, err := alice.tryRun("cert", "ls", "--relay", "edge", "--json"); err != nil {
		t.Errorf("cert ls --json: %v", err)
	}

	// The type's extremes, which no relay can send.
	far := time.Unix(math.MinInt64, 0)
	y10k := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, when := range []time.Time{far, y10k} {
		if _, err := json.Marshal(relayapi.CertRecord{Serial: oldSerial, NotAfter: when}); err == nil || !strings.Contains(err.Error(), "year outside of range") {
			t.Errorf("a not_after of %v was encoded with %v; want the year refused", when, err)
		}
	}
	if now := time.Now(); !now.After(far) || now.After(y10k) {
		t.Error("now is not after the far past, or is after the year 10000")
	}
}
