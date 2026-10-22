package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A fetch takes what the relay held when it began, and asks a bounded
// number of pages (G3, R6): it stops at the relay's last as it stood on the
// first page, a re-fetch from the relay's first id excepted, and at 64
// pages whatever the relay says, the cursor saved at the last row taken and
// the rest left for the next fetch.

// The review's test, renamed for what it now proves, with its assertion as
// the review wrote it and one change to its stand-in: the queue route is
// answered with a refusal, as a relay that forwards nothing does, so that
// the listings it counts are the fetch's own and the stricter count added
// here can hold. The review's stand-in answered that route as a listing,
// which its "more than three" allowed for; its assertion passes either way.
// The review saw 301 listings, 300 rows acknowledged and 600 files under
// damaged/; the fetch now lists twice, the second page's row being past the
// first page's last, takes the first row, keeps it, and ends with exit 0
// and "more" in --json, the cursor at the row it took.
func TestAListingNumberingUpwardEndsAtThePageCap(t *testing.T) {
	bob := newUser(t, "bob", startRelay(t))
	var listings, deletes atomic.Int64
	const enough = 300
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, listingAdvHealth)
		case r.Method == "DELETE":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/queue"):
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			if listings.Add(1) > enough {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"error":"the stand-in gave up","code":""}`)
				return
			}
			after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			next := after + 1
			fmt.Fprintf(w, `{"messages":[{"id":%d,"received":"2026-10-10T00:00:00Z","kind":"envelope","size":2,"channel":"default","via":"","envelope":{}}],`+
				`"queued":1,"first":%d,"last":%d,"allow":"none","card":"none","directory":"none"}`, next, next, next)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	defer hostile.Close()
	relayName := repointRelay(t, bob, hostile.URL)
	type ran struct {
		out, said string
		err       error
	}
	done := make(chan ran, 1)
	go func() {
		var r ran
		r.said = stderrWhile(t, func() { r.out, r.err = bob.tryRun("inbox", "--json") })
		done <- r
	}()
	var got ran
	select {
	case got = <-done:
		t.Logf("inbox ended after %d listings and %d DELETEs: %v", listings.Load(), deletes.Load(), got.err)
	case <-time.After(120 * time.Second):
		t.Fatalf("inbox still running after %d listings", listings.Load())
	}
	kept, _ := os.ReadDir(filepath.Join(bob.home, "damaged", relayName))
	if n := listings.Load(); n > 3 {
		t.Fatalf("a relay numbering one junk row upward on every page kept the fetch asking %d times, acknowledging %d rows and keeping %d files under damaged/, "+
			"until the stand-in refused; the order check of 2d4ecf9 stops only a repeated id", n, deletes.Load(), len(kept))
	}

	if got.err != nil {
		t.Fatalf("the fetch that stopped where it began: %v; want exit 0\n%s", got.err, got.said)
	}
	if n := listings.Load(); n > 2 {
		t.Errorf("the fetch listed %d times; want at most two, the second page's row being past the first page's last", n)
	}
	if n := deletes.Load(); n != 1 {
		t.Errorf("the fetch acknowledged %d rows; want the first page's one", n)
	}
	if len(kept) != 2 {
		t.Errorf("damaged/%s holds %d files; want the one row's bytes and record", relayName, len(kept))
	}
	if c := cursorOf(t, bob); c != 1 {
		t.Errorf("the cursor is %d; want 1, the row taken", c)
	}
	if strings.Contains(got.said, "pages in one fetch") {
		t.Errorf("a fetch stopped where it began said %q; the stop says nothing", got.said)
	}
	fetchMore, relayMore := moreOf(t, got.out)
	if fetchMore == nil || !*fetchMore || relayMore == nil || !*relayMore {
		t.Errorf("--json says more %v in the fetch and %v for the relay; want true in both\n%s", fetchMore, relayMore, got.out)
	}
}

// pagedStandIn is a relay that answers each listing with rows numbered
// upward from the id asked after, rows to a page, while page says there are
// more: a last ahead of every row, growing with the cursor, so that the
// first page's last never binds. Once page says no, it answers an empty
// page whose last is the cursor, and nothing queued.
type pagedStandIn struct {
	srv               *httptest.Server
	listings, deletes atomic.Int64
}

func startPagedStandIn(t *testing.T, rows int64, more func(after int64) bool) *pagedStandIn {
	t.Helper()
	p := &pagedStandIn{}
	const enough = 200
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, listingAdvHealth)
		case r.Method == "DELETE":
			p.deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/queue"):
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			if p.listings.Add(1) > enough {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"error":"the stand-in gave up","code":""}`)
				return
			}
			after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			if !more(after) {
				fmt.Fprintf(w, `{"messages":[],"queued":0,"first":%d,"last":%d,"allow":"none","card":"none","directory":"none"}`, after, after)
				return
			}
			var b strings.Builder
			for i := int64(1); i <= rows; i++ {
				if i > 1 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"id":%d,"received":"2026-10-10T00:00:00Z","kind":"envelope","size":2,"channel":"default","via":"","envelope":{}}`, after+i)
			}
			fmt.Fprintf(w, `{"messages":[%s],"queued":%d,"first":%d,"last":%d,"allow":"none","card":"none","directory":"none"}`,
				b.String(), rows, after+1, after+rows+1<<20)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// A relay whose last lies is held to 64 pages: the fetch asks 64 listings
// and not a 65th, says the sentence once, saves the cursor at the last row
// of page 64, exits 0 and says "more" in --json. The rows are junk kept
// under damaged/, two to a page, which the backstop does not mind since it
// counts pages; with damaged/ held to 100 messages for the test, the 128
// rows leave 100 there, the cap holding through a fetch. And at the edge
// below, a lie that ends after page 63 is drained by its empty 64th page
// with nothing said and no "more".
func TestLimitAFetchIsHeldTo64Pages(t *testing.T) {
	const rows = 2
	restore := store.DamagedMaxMessages
	store.DamagedMaxMessages = 100
	t.Cleanup(func() { store.DamagedMaxMessages = restore })

	run := func(t *testing.T, more func(after int64) bool) (*user, *pagedStandIn, string, string, error) {
		t.Helper()
		bob := newUser(t, "bob", startRelay(t))
		p := startPagedStandIn(t, rows, more)
		repointRelay(t, bob, p.srv.URL)
		var out string
		var err error
		said := stderrWhile(t, func() { out, err = bob.tryRun("inbox", "--json") })
		return bob, p, out, said, err
	}
	const sentence = ": this fetch took the 64 pages it asks at most; the rest waits for the next fetch\n"

	t.Run("a lie that runs on is cut at page 64", func(t *testing.T) {
		bob, p, out, said, err := run(t, func(int64) bool { return true })
		if err != nil {
			t.Fatalf("the fetch cut at 64 pages: %v; want exit 0\n%s", err, said)
		}
		if n := p.listings.Load(); n != 64 {
			t.Errorf("the fetch asked %d listings; want 64 and not a 65th", n)
		}
		if n := strings.Count(said, bob.defaultRelayName()+sentence); n != 1 {
			t.Errorf("the sentence was said %d times; want once\n%s", n, said)
		}
		if c := cursorOf(t, bob); c != 64*rows {
			t.Errorf("the cursor is %d; want %d, the last row of page 64", c, 64*rows)
		}
		if n := p.deletes.Load(); n != 64*rows {
			t.Errorf("%d rows acknowledged; want %d", n, 64*rows)
		}
		fetchMore, relayMore := moreOf(t, out)
		if fetchMore == nil || !*fetchMore || relayMore == nil || !*relayMore {
			t.Errorf("--json says more %v in the fetch and %v for the relay; want true in both", fetchMore, relayMore)
		}
		var in inboxJSON
		if err := json.Unmarshal([]byte(out), &in); err != nil {
			t.Fatal(err)
		}
		if in.Fetch.Unreadable != 64*rows || in.Fetch.Kept != 64*rows {
			t.Errorf("the fetch counted %d unreadable and %d kept; want %d of each", in.Fetch.Unreadable, in.Fetch.Kept, 64*rows)
		}
		s, err := store.Open(bob.home)
		if err != nil {
			t.Fatal(err)
		}
		if n, _, err := s.DamagedKept(); err != nil || n != store.DamagedMaxMessages {
			t.Errorf("damaged/ holds %d messages (%v); want %d, its cap", n, err, store.DamagedMaxMessages)
		}
	})

	t.Run("a lie that ends after page 63 is drained", func(t *testing.T) {
		bob, p, out, said, err := run(t, func(after int64) bool { return after < 63*rows })
		if err != nil {
			t.Fatalf("the fetch: %v; want exit 0\n%s", err, said)
		}
		if n := p.listings.Load(); n != 64 {
			t.Errorf("the fetch asked %d listings; want 63 with rows and the empty 64th", n)
		}
		if strings.Contains(said, "pages in one fetch") {
			t.Errorf("a fetch drained in 64 pages said %q", said)
		}
		if c := cursorOf(t, bob); c != 63*rows {
			t.Errorf("the cursor is %d; want %d", c, 63*rows)
		}
		fetchMore, relayMore := moreOf(t, out)
		if fetchMore != nil || relayMore != nil {
			t.Errorf("--json says more %v in the fetch and %v for the relay; want it absent", fetchMore, relayMore)
		}
	})
}

// hookedRelay is a real relay with a hook run once, after the next listing
// with bodies has been answered: mail posted there arrives during a fetch,
// past the page the fetch began from. It counts those listings; stubs,
// which a reset lists, are not among them.
type hookedRelay struct {
	url   string
	st    *relay.Store
	lists atomic.Int32
	after atomic.Pointer[func()]
}

func startHookedRelay(t *testing.T) *hookedRelay {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	inner := relay.NewServer(st, relay.Config{
		Streams: true,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limits:  relay.DefaultLimits(),
	})
	h := &hookedRelay{st: st}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isList := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") &&
			!strings.HasSuffix(r.URL.Path, "/channels") && !strings.HasSuffix(r.URL.Path, "/blob") &&
			!strings.HasSuffix(r.URL.Path, "/queue") && !strings.Contains(r.URL.RawQuery, "stubs=1")
		inner.ServeHTTP(w, r)
		if isList {
			h.lists.Add(1)
			if f := h.after.Swap(nil); f != nil {
				(*f)()
			}
		}
	}))
	t.Cleanup(func() { srv.Close(); inner.Close() })
	h.url = srv.URL
	return h
}

// sealed is a note from alice to bob as the relay stores it.
func sealed(t *testing.T, alice, bob *identity.Identity, subject string) []byte {
	t.Helper()
	env, _, err := envelope.SealFor(alice, bob.Public(), "", message.Body{Type: message.TypeAsk,
		Thread: strings.Repeat("a", 32), Subject: subject, Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// put puts a note sealed for bob on the relay directly, as
// TestRemovingTheNewestMailIsNotAReset does: hundreds of posts through the
// route would meet its posts-per-minute limit.
func (h *hookedRelay) put(t *testing.T, alice, bob *identity.Identity, subject string) int64 {
	t.Helper()
	id, err := h.st.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", sealed(t, alice, bob, subject), relay.Quotas{}, relay.Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// putDuring arms the hook to put a note on the relay after the next
// listing with bodies, sealed now, since the hook runs on the relay's
// goroutine; the id it was given is read once the fetch has ended.
func (h *hookedRelay) putDuring(t *testing.T, alice, bob *identity.Identity, subject string) func() int64 {
	t.Helper()
	raw := sealed(t, alice, bob, subject)
	var id atomic.Int64
	var failed atomic.Pointer[error]
	hook := func() {
		got, err := h.st.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", raw, relay.Quotas{}, relay.Forwarded{})
		if err != nil {
			failed.Store(&err)
		}
		id.Store(got)
	}
	h.after.Store(&hook)
	return func() int64 {
		t.Helper()
		if err := failed.Load(); err != nil {
			t.Fatalf("the put during the fetch: %v", *err)
		}
		if h.after.Load() != nil {
			t.Fatal("the fetch listed nothing, and nothing was put during it")
		}
		return id.Load()
	}
}

// An honest relay's mailbox of more than a page is drained by one fetch,
// since the first page's last is the last of all of it, with nothing said
// and no "more". Mail posted while a fetch runs, after its first page, is
// past where it began: the fetch stops before it, says nothing, says
// "more", and the next fetch takes it. The fetches run as inbox --json
// --channel elsewhere, which fetches the whole mailbox and lists none of
// it, so that 250 messages do not fill the pipe the output is read from.
func TestAFetchTakesWhatTheRelayHeldWhenItBegan(t *testing.T) {
	h := startHookedRelay(t)
	alice, bob := watchers(t, h.url)
	_, aliceID, _ := alice.opened()
	_, bobID, _ := bob.opened()
	const n = 250
	if n <= relayapi.MaxListLimit {
		t.Fatalf("%d messages is one page at the listing limit of %d", n, relayapi.MaxListLimit)
	}
	var last int64
	for i := range n {
		last = h.put(t, aliceID, bobID, "first "+strconv.Itoa(i))
	}
	fetch := func() (inboxJSON, *bool, string, int32) {
		t.Helper()
		lists := h.lists.Load()
		var out string
		var err error
		said := stderrWhile(t, func() { out, err = bob.tryRun("inbox", "--json", "--channel", "elsewhere") })
		if err != nil {
			t.Fatalf("inbox: %v\n%s", err, said)
		}
		var in inboxJSON
		if err := json.Unmarshal([]byte(out), &in); err != nil {
			t.Fatal(err)
		}
		more, relayMore := moreOf(t, out)
		if (more == nil) != (relayMore == nil) {
			t.Fatalf("the fetch's more %v and the relay's %v disagree", more, relayMore)
		}
		return in, more, said, h.lists.Load() - lists
	}

	in, more, said, lists := fetch()
	if in.Fetch.Delivered != n || more != nil || said != "" {
		t.Fatalf("the first fetch of %d: %+v, more %v, said %q; want all %d, no more, nothing said", n, in.Fetch, more, said, n)
	}
	if want := int32(n/relayapi.MaxListLimit + 2); lists != want {
		t.Errorf("the fetch listed %d pages; want %d, the last one empty", lists, want)
	}
	if c := cursorOf(t, bob); c != last {
		t.Errorf("the cursor is %d; want %d", c, last)
	}

	// Another mailbox's worth, and one more posted after the first page.
	for i := range n {
		last = h.put(t, aliceID, bobID, "second "+strconv.Itoa(i))
	}
	putDuring := h.putDuring(t, aliceID, bobID, "during")
	in, more, said, lists = fetch()
	during := putDuring()
	if during != last+1 {
		t.Fatalf("the message posted during the fetch is %d; want %d, after what was there", during, last+1)
	}
	if in.Fetch.Delivered != n || more == nil || !*more || said != "" {
		t.Fatalf("the fetch with mail posted during it: %+v, more %v, said %q; want the %d it began with, more, nothing said", in.Fetch, more, said, n)
	}
	if lists != 2 {
		t.Errorf("the fetch listed %d pages; want 2, the second ending at the row past where it began", lists)
	}
	if c := cursorOf(t, bob); c != last {
		t.Errorf("the cursor is %d; want %d, the last row there when the fetch began", c, last)
	}
	if held := inboxSubjects(t, bob); held["during"] || len(held) != 2*n {
		t.Errorf("the inbox holds %d messages, the one posted during the fetch among them %v; want the %d there before it alone", len(held), held["during"], 2*n)
	}

	// The next fetch takes it, and has nothing more.
	in, more, said, _ = fetch()
	if in.Fetch.Delivered != 1 || more != nil || said != "" {
		t.Fatalf("the next fetch: %+v, more %v, said %q; want the one, no more, nothing said", in.Fetch, more, said)
	}
	if c := cursorOf(t, bob); c != during {
		t.Errorf("the cursor is %d; want %d", c, during)
	}
	recordOf(t, bob, store.Inbox, "during")
}

// A re-fetch from the relay's first id runs to its empty page, since a
// reset's accounting is made there: mail posted after the first page, past
// what the relay held when the fetch began, is taken by the reset and not
// left with "more", and the reset is finished. The mailbox is more than a
// page, so the reset spans pages; the reset tests before this one fetch a
// page or less while a reset is in flight.
func TestAResetIsNotCutWhereTheFetchBegan(t *testing.T) {
	h := startHookedRelay(t)
	alice, bob := watchers(t, h.url)
	_, aliceID, _ := alice.opened()
	_, bobID, _ := bob.opened()
	const n = 250
	var first, last int64
	for i := range n {
		id := h.put(t, aliceID, bobID, "kept "+strconv.Itoa(i))
		if i == 0 {
			first = id
		}
		last = id
	}
	name := bob.defaultRelayName()
	past := last + 1000
	bob.setCursor(name, strconv.FormatInt(past, 10)+"\n")
	putDuring := h.putDuring(t, aliceID, bobID, "during")

	var out string
	var err error
	lists := h.lists.Load()
	said := stderrWhile(t, func() { out, err = bob.tryRun("inbox", "--json", "--channel", "elsewhere") })
	if err != nil {
		t.Fatalf("inbox: %v\n%s", err, said)
	}
	during := putDuring()
	var in inboxJSON
	if err := json.Unmarshal([]byte(out), &in); err != nil {
		t.Fatal(err)
	}
	want := name + ": this machine's cursor was " + strconv.FormatInt(past, 10) + " and the relay's mail is numbered " +
		strconv.FormatInt(first, 10) + " to " + strconv.FormatInt(last, 10) +
		", so the cursor was reset and mail is fetched from the beginning; nothing is delivered twice here\n"
	if said != want {
		t.Errorf("the fetch said %q; want %q", said, want)
	}
	if during != last+1 {
		t.Fatalf("the message posted during the fetch is %d; want %d", during, last+1)
	}
	more, relayMore := moreOf(t, out)
	if in.Fetch.Delivered != n+1 || more != nil || relayMore != nil {
		t.Fatalf("the reset: %+v, more %v and %v; want all %d with the one posted during it, and no more", in.Fetch, more, relayMore, n+1)
	}
	// The empty page before the reset, the re-fetch's pages and its empty
	// last page.
	if got, want := h.lists.Load()-lists, int32(1+(n+1+relayapi.MaxListLimit-1)/relayapi.MaxListLimit+1); got != want {
		t.Errorf("the fetch listed %d pages with bodies; want %d", got, want)
	}
	if c := cursorOf(t, bob); c != during {
		t.Errorf("the cursor is %d; want %d, the last row the reset took", c, during)
	}
	if held := inboxSubjects(t, bob); !held["during"] || len(held) != n+1 {
		t.Errorf("the inbox holds %d messages, the one posted during the fetch among them %v; want %d with it", len(held), held["during"], n+1)
	}
	// Finished: the next fetch says nothing and takes nothing.
	said = stderrWhile(t, func() { out, err = bob.tryRun("inbox", "--json", "--channel", "elsewhere") })
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &in); err != nil {
		t.Fatal(err)
	}
	if in.Fetch.Delivered != 0 || said != "" {
		t.Errorf("the fetch after the reset: %+v, said %q", in.Fetch, said)
	}
}

// inboxSubjects is the subjects of what is in a user's inbox.
func inboxSubjects(t *testing.T, u *user) map[string]bool {
	t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(store.Inbox)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range msgs {
		out[m.Inner.Body.Subject] = true
	}
	return out
}

// moreOf is "more" in inbox --json's fetch totals and in its first relay's
// report: nil where the key is absent, which is what a fetch that met the
// end of the mailbox writes.
func moreOf(t *testing.T, out string) (fetch, firstRelay *bool) {
	t.Helper()
	var raw struct {
		Fetch  map[string]json.RawMessage   `json:"fetch"`
		Relays []map[string]json.RawMessage `json:"relays"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	read := func(m map[string]json.RawMessage) *bool {
		v, ok := m["more"]
		if !ok {
			return nil
		}
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			t.Fatalf("more is %s", v)
		}
		return &b
	}
	if len(raw.Relays) == 0 {
		t.Fatalf("inbox --json reports no relay\n%s", out)
	}
	return read(raw.Fetch), read(raw.Relays[0])
}

// stderrWhile runs fn with standard error read as it is written, so that a
// fetch keeping a hundred rows under damaged/, a line each, cannot fill the
// pipe and stop.
func stderrWhile(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		r.Close()
		read <- string(data)
	}()
	real := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = real
	w.Close()
	return <-read
}

// stubsStandIn is a relay for the cursor check: its listings with bodies
// are empty, the mailbox's last at 1<<30, below a cursor of 1<<40, so the
// fetch reckons; its stubs listings answer one row numbered after the id
// asked after, at last 1<<30, while rowsUntil says so, and an empty page
// after. Each listing's kind is counted.
type stubsStandIn struct {
	srv                    *httptest.Server
	stubs, bodies, deletes atomic.Int64
}

const stubsLast = 1 << 30

func startStubsStandIn(t *testing.T, rowsUntil func(stubsPage int64) bool) *stubsStandIn {
	t.Helper()
	p := &stubsStandIn{}
	const enough = 200
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/health":
			io.WriteString(w, listingAdvHealth)
		case r.Method == "DELETE":
			p.deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/queue"):
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && strings.Contains(r.URL.RawQuery, "stubs=1"):
			n := p.stubs.Add(1)
			if n > enough {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"error":"the stand-in gave up","code":""}`)
				return
			}
			after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			if !rowsUntil(n) {
				fmt.Fprintf(w, `{"messages":[],"queued":0,"first":1,"last":%d,"allow":"none","card":"none","directory":"none"}`, stubsLast)
				return
			}
			fmt.Fprintf(w, `{"messages":[{"id":%d,"received":"2026-10-10T00:00:00Z","kind":"envelope","size":2,"channel":"default","via":""}],`+
				`"queued":1,"first":1,"last":%d,"allow":"none","card":"none","directory":"none"}`, after+1, stubsLast)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/"):
			p.bodies.Add(1)
			fmt.Fprintf(w, `{"messages":[],"queued":0,"first":1,"last":%d,"allow":"none","card":"none","directory":"none"}`, stubsLast)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"no","code":""}`)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// homeFiles is every file under a home but the fetch lock, by its path
// relative to the home, with its bytes.
func homeFiles(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(home, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == fetchLockName {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(home, path)
		out[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The cursor check is held to 64 pages as a fetch is: a relay whose stubs
// listing runs on is asked 64 stubs pages and not a 65th, and the fetch
// fails as a transport failure with the sentence, having changed nothing
// here: the cursor, damaged/, the left-behind file and every record as they
// were, and nothing acknowledged. At the edge, a check that ends on its
// 64th page, empty or at the relay's last, is no failure.
func TestLimitTheCursorCheckIsHeldTo64Pages(t *testing.T) {
	const cursor = int64(1) << 40
	run := func(t *testing.T, rowsUntil func(int64) bool) (*user, *stubsStandIn, string, error) {
		t.Helper()
		bob := newUser(t, "bob", startRelay(t))
		p := startStubsStandIn(t, rowsUntil)
		repointRelay(t, bob, p.srv.URL)
		s, err := store.Open(bob.home)
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.DefaultRelay()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetCursorFor(r, cursor); err != nil {
			t.Fatal(err)
		}
		var runErr error
		said := stderrWhile(t, func() { _, runErr = bob.tryRun("inbox", "--json") })
		return bob, p, said, runErr
	}
	const refusal = "the relay listed more than 64 pages while this machine checked its cursor against it; " +
		"nothing was changed, and the next fetch asks again"

	t.Run("a stubs listing that runs on", func(t *testing.T) {
		bob := newUser(t, "bob", startRelay(t))
		p := startStubsStandIn(t, func(int64) bool { return true })
		repointRelay(t, bob, p.srv.URL)
		s, err := store.Open(bob.home)
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.DefaultRelay()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetCursorFor(r, cursor); err != nil {
			t.Fatal(err)
		}
		leftBefore, err := s.LeftBehind(r.Name)
		if err != nil {
			t.Fatal(err)
		}
		before := homeFiles(t, bob.home)
		var runErr error
		said := stderrWhile(t, func() { _, runErr = bob.tryRun("inbox", "--json") })

		var e *exitError
		if !errors.As(runErr, &e) || e.code != exitTransport {
			t.Fatalf("the fetch: %v; want a transport failure, exit %d\n%s", runErr, exitTransport, said)
		}
		if !strings.Contains(runErr.Error(), refusal) {
			t.Errorf("the failure %q does not say %q", runErr, refusal)
		}
		if n := p.stubs.Load(); n != 64 {
			t.Errorf("the check asked %d stubs listings; want 64 and not a 65th", n)
		}
		if n := p.bodies.Load(); n != 1 {
			t.Errorf("%d listings with bodies; want the one that found the cursor past", n)
		}
		if n := p.deletes.Load(); n != 0 {
			t.Errorf("%d acknowledged; want none", n)
		}
		if c := cursorOf(t, bob); c != cursor {
			t.Errorf("the cursor is %d; want it left at %d", c, cursor)
		}
		if n, _, err := s.DamagedKept(); err != nil || n != 0 {
			t.Errorf("damaged/ holds %d (%v); want nothing", n, err)
		}
		if left, err := s.LeftBehind(r.Name); err != nil || !slices.Equal(left, leftBefore) {
			t.Errorf("left behind went from %v to %v (%v)", leftBefore, left, err)
		}
		after := homeFiles(t, bob.home)
		for path, data := range before {
			if got, ok := after[path]; !ok || got != data {
				t.Errorf("%s changed or went", path)
			}
		}
		for path := range after {
			if _, ok := before[path]; !ok {
				t.Errorf("%s was written", path)
			}
		}
	})

	t.Run("a check that ends empty on page 64", func(t *testing.T) {
		_, p, said, err := run(t, func(n int64) bool { return n < 64 })
		if err != nil {
			t.Fatalf("the fetch: %v\n%s", err, said)
		}
		if n := p.stubs.Load(); n != 64 {
			t.Errorf("%d stubs listings; want 63 with a row and the empty 64th", n)
		}
		if strings.Contains(said, "checked its cursor") {
			t.Errorf("said %q", said)
		}
	})

	t.Run("a check that reaches the relay's last on page 64", func(t *testing.T) {
		// 63 rows, then the 64th page's row at the relay's last.
		bob := newUser(t, "bob", startRelay(t))
		var stubs, bodies atomic.Int64
		hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/v1/health":
				io.WriteString(w, listingAdvHealth)
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && !strings.HasSuffix(r.URL.Path, "/queue"):
				stubbed := strings.Contains(r.URL.RawQuery, "stubs=1")
				after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
				if !stubbed || after >= 64 {
					bodies.Add(1)
					io.WriteString(w, `{"messages":[],"queued":0,"first":1,"last":64,"allow":"none","card":"none","directory":"none"}`)
					return
				}
				stubs.Add(1)
				fmt.Fprintf(w, `{"messages":[{"id":%d,"received":"2026-10-10T00:00:00Z","kind":"envelope","size":2,"channel":"default","via":""}],`+
					`"queued":1,"first":1,"last":64,"allow":"none","card":"none","directory":"none"}`, after+1)
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
		if err := s.SetCursorFor(r, cursor); err != nil {
			t.Fatal(err)
		}
		var runErr error
		said := stderrWhile(t, func() { _, runErr = bob.tryRun("inbox", "--json") })
		if runErr != nil {
			t.Fatalf("a check ending at the relay's last on page 64: %v\n%s", runErr, said)
		}
		if strings.Contains(said, "checked its cursor") {
			t.Errorf("said %q", said)
		}
		if n := stubs.Load(); n != 64 {
			t.Errorf("%d stubs listings; want 64, the last at the relay's last", n)
		}
	})
}

// A fetch stopped where it began has met what it took: a message removed
// here alone and served again under a new id is met on the first page, and
// the stop writes the left-behind entry under the new id, as the empty page
// would have, with mail posted during the fetch left for the next one.
func TestAStoppedFetchWritesWhatItMet(t *testing.T) {
	h := startHookedRelay(t)
	alice, bob := watchers(t, h.url)
	_, aliceID, _ := alice.opened()
	_, bobID, _ := bob.opened()
	name := bob.defaultRelayName()
	fp := bobID.Fingerprint()
	first := h.put(t, aliceID, bobID, "removed here")
	rows, err := h.st.List(fp, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the relay holds %d (%v)", len(rows), err)
	}
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "removed here")
	bob.run("rm", "--local-only", m.Inner.ID[:12])
	if ok, err := h.st.Delete(fp, first); err != nil || !ok {
		t.Fatal(err)
	}
	again, err := h.st.Put(fp, "default", relayapi.KindEnvelope, "", rows[0].Envelope, relay.Quotas{}, relay.Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	putDuring := h.putDuring(t, aliceID, bobID, "during")
	var out string
	said := stderrWhile(t, func() { out, err = bob.tryRun("inbox", "--json") })
	if err != nil {
		t.Fatalf("inbox: %v\n%s", err, said)
	}
	during := putDuring()
	if during != again+1 {
		t.Fatalf("posted during the fetch as %d; want %d", during, again+1)
	}
	if more, _ := moreOf(t, out); more == nil || !*more {
		t.Fatalf("the fetch did not stop where it began: more %v\n%s", more, out)
	}
	if held := inboxSubjects(t, bob); held["removed here"] || held["during"] {
		t.Fatalf("the inbox holds %v; want neither the message removed here nor the one posted during the fetch", held)
	}
	s, _, _ := bob.opened()
	if left, err := s.LeftBehind(name); err != nil || len(left) != 1 || left[0].RelayID != again || left[0].ID != m.Inner.ID {
		t.Fatalf("left behind: %v (%v), want %s under %d", left, err, m.Inner.ID, again)
	}
}
