package auu

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// filingGate sits in front of a relay and rewrites what its listing says
// about channels: "old" strips the field from every message, as a relay
// from before channels answers; "relist" lists every message under
// another name while leaving the envelope alone, as a relay that re-files
// would; "reouter" rewrites the outer ch inside the envelope instead.
type filingGate struct {
	inner http.Handler
	mu    sync.Mutex
	mode  string
}

func (g *filingGate) set(mode string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode = mode
}

func (g *filingGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	mode := g.mode
	g.mu.Unlock()
	isList := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") &&
		strings.Count(r.URL.Path, "/") == 3
	if mode == "" || !isList {
		g.inner.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	g.inner.ServeHTTP(rec, r)
	var answer struct {
		Messages []map[string]json.RawMessage `json:"messages"`
		Queued   int64                        `json:"queued"`
	}
	if rec.Code == http.StatusOK && json.Unmarshal(rec.Body.Bytes(), &answer) == nil {
		for _, m := range answer.Messages {
			switch mode {
			case "old":
				delete(m, "channel")
			case "relist":
				m["channel"], _ = json.Marshal("elsewhere")
			case "reouter":
				if raw, ok := m["envelope"]; ok {
					var env map[string]json.RawMessage
					if json.Unmarshal(raw, &env) == nil {
						env["ch"], _ = json.Marshal("elsewhere")
						m["envelope"], _ = json.Marshal(env)
					}
				}
			}
		}
		rec.Body.Reset()
		json.NewEncoder(rec.Body).Encode(answer)
	}
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())
}

func startFilingRelay(t *testing.T) (string, *filingGate, *relay.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	gate := &filingGate{inner: relay.NewServer(st, relay.Config{
		Streams: true,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limits:  relay.DefaultLimits(),
	})}
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)
	return srv.URL, gate, st
}

// Messages are filed under the channel they were sealed for, listed with
// it after the subject when it is not default, filtered by --channel
// without changing the fetch, and read with channel: always.
func TestMailIsFiledAndListedByChannel(t *testing.T) {
	work := startRelay(t)
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "create", "bug reports", "--description", "One bug per message")

	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a bug", "the bug")
	alice.run("send", "--to", "bob", "--subject", "plain", "hello")
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a log", "--attach", big, "the log")

	got := bob.inboxJSON()
	if got.Fetch.Delivered != 3 || len(got.Messages) != 3 || len(got.Fetch.Gone) != 0 {
		t.Fatalf("the fetch: %+v, %d messages", got.Fetch, len(got.Messages))
	}
	byChannel := map[string]int{}
	for _, m := range got.Messages {
		byChannel[m.Channel]++
		s, _, _ := bob.opened()
		_, stored, err := s.Find(m.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Channel != storedChannel(m.Channel) || stored.Inner.Channel != storedChannel(m.Channel) {
			t.Fatalf("message %s is filed under %q with %q sealed, listed as %q", m.ID, stored.Channel, stored.Inner.Channel, m.Channel)
		}
	}
	if byChannel["bug reports"] != 2 || byChannel["default"] != 1 {
		t.Fatalf("filed as %v", byChannel)
	}

	text := bob.run("inbox", "--no-fetch")
	if strings.Count(text, `  in "bug reports"`) != 2 || strings.Contains(text, `in "default"`) {
		t.Fatalf("the listing:\n%s", text)
	}
	// The filter, in text and JSON; the fetch is whole either way.
	filtered := bob.run("inbox", "--no-fetch", "--channel", "bug reports")
	if strings.Count(filtered, `  in "bug reports"`) != 2 || strings.Contains(filtered, "plain") {
		t.Fatalf("the filtered listing:\n%s", filtered)
	}
	var only inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json", "--no-fetch", "--channel", "default")), &only); err != nil {
		t.Fatal(err)
	}
	if len(only.Messages) != 1 || only.Messages[0].Subject != "plain" || only.Messages[0].Channel != "default" {
		t.Fatalf("--channel default: %+v", only.Messages)
	}
	if out := bob.run("inbox", "--no-fetch", "--channel", "nothing"); !strings.Contains(out, "inbox is empty") {
		t.Fatalf("a filter that matches nothing:\n%s", out)
	}
	usageError(t, bob, `--channel "a/b": name contains "/"`, "inbox", "--no-fetch", "--channel", "a/b")
	// A fetch with the filter is still the whole mailbox.
	alice.run("send", "--to", "bob", "--subject", "later", "one more")
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json", "--channel", "bug reports")), &only); err != nil {
		t.Fatal(err)
	}
	if only.Fetch.Delivered != 1 || len(only.Messages) != 2 {
		t.Fatalf("a filtered fetch: %+v, %d listed", only.Fetch, len(only.Messages))
	}

	// read says channel: always.
	for _, m := range got.Messages {
		out := bob.run("read", m.ID)
		if !strings.Contains(out, "channel: "+m.Channel+"\n") {
			t.Fatalf("read %s:\n%s", m.ID, out)
		}
		var one messageJSON
		if err := json.Unmarshal([]byte(bob.run("read", m.ID, "--json")), &one); err != nil {
			t.Fatal(err)
		}
		if one.Channel != m.Channel {
			t.Fatalf("read --json %s: %q", m.ID, one.Channel)
		}
	}
}

// A message the relay lists under a channel it was not sealed for, or
// whose outer name was rewritten, is misfiled: kept under damaged/ with
// the cause word, said to be with the relay's name, and acknowledged so
// the mailbox is not blocked.
func TestAMisfiledMessageIsKeptAndAcknowledged(t *testing.T) {
	for _, mode := range []string{"relist", "reouter"} {
		t.Run(mode, func(t *testing.T) {
			work, gate, workStore := startFilingRelay(t)
			alice := newUser(t, "alice", work)
			bob := newUser(t, "bob", work)
			alice.run("peers", "add", bob.exportLine())
			bob.run("peers", "add", alice.exportLine())
			bob.run("channel", "create", "bug reports")
			_, bobID, _ := bob.opened()
			relayName := bob.defaultRelayName()

			alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a bug", "the bug")
			if mode == "relist" {
				// A stream too, which has no outer name and is found out
				// by the listing alone.
				big := filepath.Join(t.TempDir(), "big.bin")
				if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
					t.Fatal(err)
				}
				alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a log", "--attach", big, "the log")
			}
			gate.set(mode)
			var out string
			warning := captureStderr(t, func() { out = bob.run("inbox", "--json") })
			var got inboxJSON
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			want := 1
			if mode == "relist" {
				want = 2
			}
			if got.Fetch.Delivered != 0 || got.Fetch.Kept != want || got.Fetch.Unreadable != want || len(got.Messages) != 0 {
				t.Fatalf("the fetch: %+v, %d messages", got.Fetch, len(got.Messages))
			}
			filedAs := "elsewhere"
			if !strings.Contains(warning, `warning: relay message 1 was filed under "`+filedAs+`" by `+relayName+
				` but is sealed for "bug reports"; it was kept as `+filepath.Join(bob.home, "damaged", relayName, "1.bin")+"\n") {
				t.Fatalf("the warning:\n%s", warning)
			}
			if strings.Contains(warning, "ask the sender") {
				t.Fatalf("a misfiled message blamed the sender:\n%s", warning)
			}
			s, _, _ := bob.opened()
			for id := int64(1); id <= int64(want); id++ {
				raw, err := os.ReadFile(strings.TrimSuffix(s.DamagedPath(relayName, id), ".bin") + ".json")
				if err != nil {
					t.Fatal(err)
				}
				var rec store.DamagedRecord
				if err := json.Unmarshal(raw, &rec); err != nil {
					t.Fatal(err)
				}
				if rec.Cause != "misfiled" || rec.Relay != relayName || rec.RelayID != id {
					t.Fatalf("the record: %+v", rec)
				}
			}
			// Acknowledged: nothing left on the relay, and the cursor past it.
			if u, _ := workStore.MailboxUsage(bobID.Fingerprint()); u.Messages != 0 {
				t.Fatalf("%d messages still queued after a misfiled fetch", u.Messages)
			}
			gate.set("")
			warning = captureStderr(t, func() { out = bob.run("inbox", "--json") })
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			if !got.Fetch.empty() || warning != "" {
				t.Fatalf("the next fetch was not clean: %+v %q", got.Fetch, warning)
			}
			if !strings.Contains(bob.run("inbox", "--no-fetch"), "damaged message(s) kept under") {
				t.Fatal("the kept messages are not said to be")
			}
		})
	}
}

// A relay from before channels lists no channel: the message is filed by
// the sealed record alone, and nothing is said.
func TestAnOldRelaysListingFilesByTheSealedRecord(t *testing.T) {
	work, gate, _ := startFilingRelay(t)
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "create", "bug reports")
	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a bug", "the bug")
	alice.run("send", "--to", "bob", "--subject", "plain", "hello")
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a log", "--attach", big, "the log")

	gate.set("old")
	var out string
	warning := captureStderr(t, func() { out = bob.run("inbox", "--json") })
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if warning != "" {
		t.Fatalf("an old relay's listing drew a warning:\n%s", warning)
	}
	if got.Fetch.Delivered != 3 || got.Fetch.Kept != 0 || len(got.Messages) != 3 {
		t.Fatalf("the fetch: %+v, %d messages", got.Fetch, len(got.Messages))
	}
	byChannel := map[string]string{}
	for _, m := range got.Messages {
		byChannel[m.Subject] = m.Channel
	}
	if byChannel["a bug"] != "bug reports" || byChannel["plain"] != "default" || byChannel["a log"] != "bug reports" {
		t.Fatalf("filed as %v", byChannel)
	}
}

// Mail queued under a channel that was then deleted arrives as usual,
// filed under that name, and the summary says the channel is no longer in
// the directory; a home with no directory says nothing.
func TestMailForADeletedChannelArrivesAndIsSaidToBe(t *testing.T) {
	work := startRelay(t)
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "create", "bug reports")
	bob.run("channel", "create", "cfp")
	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "one", "x")
	alice.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "two", "y")
	alice.run("send", "--to", "bob", "--channel", "cfp", "--subject", "three", "z")
	alice.run("send", "--to", "bob", "--subject", "four", "w")
	bob.run("channel", "delete", "bug reports")
	bob.run("channel", "delete", "cfp")

	out := bob.run("inbox")
	if !strings.Contains(out, "fetched 4 new message(s)\n") ||
		!strings.Contains(out, `3 message(s) arrived for channels no longer in your directory: "bug reports", "cfp"`+"\n") {
		t.Fatalf("inbox after the deletes:\n%s", out)
	}
	if strings.Count(out, `  in "bug reports"`) != 2 || strings.Count(out, `  in "cfp"`) != 1 {
		t.Fatalf("the deleted channels' mail is not listed under its names:\n%s", out)
	}
	// And in JSON, by name.
	bob.run("channel", "create", "cfp")
	alice.run("send", "--to", "bob", "--channel", "cfp", "--subject", "five", "v")
	bob.run("channel", "delete", "cfp")
	got := bob.inboxJSON()
	if got.Fetch.Gone["cfp"] != 1 || len(got.Fetch.Gone) != 1 {
		t.Fatalf("channels_gone: %v", got.Fetch.Gone)
	}
	// A home with no directory defines nothing and says nothing: the relay
	// still holds the directory this machine pushed, so alice can post to
	// cfp, and the message is filed under it here without a word.
	bob.run("channel", "create", "cfp")
	alice.run("send", "--to", "bob", "--channel", "cfp", "--subject", "six", "u")
	s, _, _ := bob.opened()
	if err := os.Remove(s.ChannelsPath()); err != nil {
		t.Fatal(err)
	}
	out = bob.run("inbox")
	if !strings.Contains(out, "fetched 1 new message(s)\n") || strings.Contains(out, "no longer in your directory") ||
		strings.Count(out, `  in "cfp"`) != 3 {
		t.Fatalf("inbox with no local directory:\n%s", out)
	}
}

// Quarantine files the same way: a stranger's message keeps its channel
// through the hold and the trust, for an envelope and for a stream whose
// payload waited on the relay.
func TestQuarantineFilesByChannelToo(t *testing.T) {
	work := startRelay(t)
	bob := newUser(t, "bob", work)
	carol := newUser(t, "carol", work)
	carol.run("peers", "add", bob.exportLine())
	bob.run("channel", "create", "bug reports")
	carol.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "from a stranger", "hello")
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	carol.run("send", "--to", "bob", "--channel", "bug reports", "--subject", "a stranger's log", "--attach", big, "the log")

	got := bob.inboxJSON()
	if got.Fetch.Quarantined != 2 || got.Fetch.Delivered != 0 || len(got.Fetch.Gone) != 0 {
		t.Fatalf("the fetch: %+v", got.Fetch)
	}
	var held []messageJSON
	if err := json.Unmarshal([]byte(bob.run("quarantine", "ls", "--json")), &held); err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 || held[0].Channel != "bug reports" || held[1].Channel != "bug reports" {
		t.Fatalf("the quarantine: %+v", held)
	}
	for _, m := range held {
		if out := bob.run("quarantine", "show", m.ID); !strings.Contains(out, "channel: bug reports\n") {
			t.Fatalf("quarantine show:\n%s", out)
		}
	}
	bob.run("quarantine", "trust", held[0].ID)
	bob.run("quarantine", "trust", held[1].ID)
	text := bob.run("inbox", "--no-fetch")
	if strings.Count(text, `  in "bug reports"`) != 2 {
		t.Fatalf("the inbox after trusting:\n%s", text)
	}
}
