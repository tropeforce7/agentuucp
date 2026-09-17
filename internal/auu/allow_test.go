package auu

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// startEditableRelay is startRelayOnDisk with a second connection to the
// relay's database, for the tests that edit a row the way an intruder on
// the host would, and the relay's log, for what it says about that.
func startEditableRelay(t *testing.T) (string, *relay.Store, *sql.DB, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	srv, st, msgs := startRelayOnDisk(t, relay.Config{Logger: slog.New(slog.NewTextHandler(logs, nil))})
	db, err := sql.Open("sqlite", filepath.Join(filepath.Dir(msgs), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		t.Fatal(err)
	}
	return srv.URL, st, db, logs
}

// allowPushed reads the file beside the cursor for the default relay.
func (u *user) allowPushed() (time.Time, bool) {
	u.t.Helper()
	s, _, relays := u.opened()
	pushed, found, err := s.AllowPushed(relays[0])
	if err != nil {
		u.t.Fatal(err)
	}
	return pushed, found
}

// relayName is what this home calls its one relay: the host, since
// newUser names none.
func (u *user) relayName() string {
	u.t.Helper()
	_, _, relays := u.opened()
	return relays[0].Name
}

// The three sentences of push, clear and show, the file beside the cursor
// written on push and removed on clear, and what show prints for each
// state, by peer name where the peer list knows the sender.
func TestAllowPushClearAndShow(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	carol := newUser(t, "carol", relayURL)
	alice.run("peers", "add", bob.exportLine())
	carol.run("peers", "add", alice.exportLine())
	rn := alice.relayName()

	// Before anything: none.
	out := alice.run("allow", "show")
	if !strings.Contains(out, rn+": no allow list; any registered sender may post to you there\n") {
		t.Fatalf("show before a push:\n%s", out)
	}
	if _, found := alice.allowPushed(); found {
		t.Fatal("allow_pushed exists before a push")
	}

	before := time.Now().Add(-time.Second)
	out = alice.run("allow", "push")
	if !strings.Contains(out, rn+" will now accept mail for you from 1 peer(s) only\n") {
		t.Fatalf("push:\n%s", out)
	}
	pushed, found := alice.allowPushed()
	if !found || pushed.Before(before) {
		t.Fatalf("allow_pushed after a push: %v %v", pushed, found)
	}
	out = alice.run("allow", "show")
	if !strings.Contains(out, rn+": signed, issued ") || !strings.Contains(out, ", 1 sender\n") ||
		!strings.Contains(out, "  "+bob.exportFingerprint()[:16]+"  bob\n") {
		t.Fatalf("show after a push:\n%s", out)
	}
	if _, err := carol.tryRun("send", "--to", "alice", "hello"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a stranger after the push: %v", err)
	}

	// A peer the list names but the peer list no longer knows is shown by
	// fingerprint.
	alice.run("peers", "rm", "bob")
	out = alice.run("allow", "show")
	if !strings.Contains(out, "\n  "+bob.exportFingerprint()+"\n") {
		t.Fatalf("show with a sender the peer list does not know:\n%s", out)
	}
	var shown []allowShowJSON
	if err := json.Unmarshal([]byte(alice.run("allow", "show", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown) != 1 || shown[0].Relay != rn || shown[0].State != "signed" || shown[0].Issued == nil ||
		len(shown[0].Senders) != 1 || shown[0].Senders[0].Fingerprint != bob.exportFingerprint() || shown[0].Senders[0].Name != "" {
		t.Fatalf("show --json: %+v", shown)
	}

	// Clear: the sentences, the file gone, the relay signed with nobody.
	out = alice.run("allow", "clear")
	for _, want := range []string{
		rn + ": allow list cleared; any registered user there can queue mail for you\n",
		"(messages from senders outside your peer list still land in quarantine)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("clear lacks %q:\n%s", want, out)
		}
	}
	if _, found := alice.allowPushed(); found {
		t.Fatal("allow_pushed survives a clear")
	}
	out = alice.run("allow", "show")
	if !strings.Contains(out, ", 0 senders\n  nobody is named, so any registered sender may post\n") {
		t.Fatalf("show after a clear:\n%s", out)
	}
	carol.run("send", "--to", "alice", "hello again")

	// A push with no peers is the same document, and says so.
	out = alice.run("allow", "push")
	if !strings.Contains(out, "warning: your peer list is empty, so this admits any registered sender; add peers and push again\n") {
		t.Fatalf("push with no peers:\n%s", out)
	}
}

// The owner is told, once per run and after the messages, what the relay
// says about their list: nothing for signed and for none with nothing
// pushed from here; the sentences for legacy, for none or legacy after a
// push from here, and for broken.
func TestInboxWarnsAboutTheAllowListState(t *testing.T) {
	relayURL, st, db, logs := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	fp := alice.exportFingerprint()
	rn := alice.relayName()
	inbox := func() (string, string) {
		var out string
		warning := captureStderr(t, func() { out = alice.run("inbox") })
		return out, warning
	}

	// none, nothing pushed: silence.
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning with no list and no push:\n%s", warning)
	}
	// signed: silence.
	alice.run("allow", "push")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning with a signed list:\n%s", warning)
	}
	// broken: the relay's row edited to add a sender. A message from
	// before the edit is queued, so the fetch has something to list before
	// the warning.
	bob.run("send", "--to", "alice", "before the edit")
	doc, _, _, _, err := st.Allowlist(fp)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(doc), `"senders":[`, `"senders":["`+strings.Repeat("c", 64)+`",`, 1)
	if _, err := db.Exec(`UPDATE allowlists SET doc = ? WHERE fp = ?`, []byte(edited), fp); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.tryRun("send", "--to", "alice", "after the edit"); err == nil {
		t.Fatal("bob reached alice through a broken list")
	}
	if !strings.Contains(logs.String(), "allow list for "+fp+" does not verify; refusing every post to it until the owner pushes again") {
		t.Fatalf("the relay's log has no line about the broken list:\n%s", logs.String())
	}
	out, warning := inbox()
	if warning != "auu: your allow list on "+rn+" does not verify, so nobody can post to you there; run auu allow push, and if you did not change it, tell the relay's operator\n" {
		t.Fatalf("the broken warning:\n%s\n%s", warning, out)
	}
	if !strings.Contains(out, "fetched 1 new message(s)\n") {
		t.Fatalf("the message from before the edit was not fetched:\n%s", out)
	}
	// The warning is after the messages and on stderr; stdout has the
	// message and not the warning.
	if strings.Contains(out, "does not verify") {
		t.Fatalf("the warning is on stdout:\n%s", out)
	}
	// wait says it once per run, and the run's own exit code stands.
	warning = captureStderr(t, func() {
		_, err := alice.tryRun("wait", "--thread", "nothing", "--timeout", "1s", "--interval", "5s")
		var e *exitError
		if !errors.As(err, &e) || e.code != exitTimeout {
			t.Errorf("wait under a broken list: %v", err)
		}
	})
	if strings.Count(warning, "does not verify") != 1 {
		t.Fatalf("wait's warning:\n%s", warning)
	}
	// A push repairs it.
	alice.run("allow", "push")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning after the repair:\n%s", warning)
	}

	// none after a push from here: the relay has lost it.
	if _, err := db.Exec(`DELETE FROM allowlists WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	_, warning = inbox()
	today := time.Now().Format(time.DateOnly)
	if warning != "auu: your allow list on "+rn+" is missing or unsigned, though you pushed one on "+today+"; run auu allow push and tell the relay's operator\n" {
		t.Fatalf("the missing warning:\n%s", warning)
	}
	// legacy after a push from here: the same.
	legacy, _ := json.Marshal(&allowlist.Document{V: 1, Owner: fp, Issued: time.Now().UTC(), Senders: []string{bob.exportFingerprint()}})
	if _, err := db.Exec(`INSERT INTO allowlists (fp, doc, sig, issued, count) VALUES (?, ?, X'', ?, 1)`,
		fp, legacy, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	_, warning = inbox()
	if !strings.Contains(warning, "is missing or unsigned, though you pushed one on "+today) {
		t.Fatalf("the legacy-after-push warning:\n%s", warning)
	}
	// legacy with nothing pushed from here: predates signing.
	alice.run("allow", "clear")
	if _, err := db.Exec(`UPDATE allowlists SET sig = X'', doc = ? WHERE fp = ?`, legacy, fp); err != nil {
		t.Fatal(err)
	}
	_, warning = inbox()
	if warning != "auu: your allow list on "+rn+" predates signing; run auu allow push\n" {
		t.Fatalf("the legacy warning:\n%s", warning)
	}
	out = alice.run("allow", "show")
	if !strings.Contains(out, rn+": legacy, ") || !strings.Contains(out, "  your allow list on "+rn+" predates signing; run auu allow push\n") {
		t.Fatalf("show of a legacy list:\n%s", out)
	}
	// And pushing ends it.
	alice.run("allow", "push")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning after pushing over a legacy list:\n%s", warning)
	}
}

// show verifies the pair with the owner's own key and never trusts the
// relay's word: a relay that alters the document it serves, and still
// says signed, is caught, and show exits 1 with the broken sentence.
func TestAllowShowVerifiesWithTheOwnersKey(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("allow", "push")

	// A relay in the middle that serves the real relay's answers, but
	// with one sender added to the allow list it hands back.
	real := relayURL
	lying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, real+r.URL.RequestURI(), r.Body)
		req.Header = r.Header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var body []byte
		if strings.HasSuffix(r.URL.Path, "/allow") && r.Method == http.MethodGet {
			var out relayapi.AllowResponse
			json.NewDecoder(resp.Body).Decode(&out)
			out.Document = []byte(strings.Replace(string(out.Document), `"senders":[`, `"senders":["`+strings.Repeat("d", 64)+`",`, 1))
			body, _ = json.Marshal(out)
		} else {
			body, _ = io.ReadAll(resp.Body)
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", "")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	}))
	defer lying.Close()
	alice.run("relay", "add", lying.URL, "--name", "liar")

	out, err := alice.tryRun("allow", "show", "--relay", "liar")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage || err.Error() != "an allow list does not verify" {
		t.Fatalf("show through a lying relay: %v\n%s", err, out)
	}
	if !strings.Contains(out, "liar: your allow list on liar does not verify, so nobody can post to you there; run auu allow push, and if you did not change it, tell the relay's operator\n") {
		t.Fatalf("show through a lying relay:\n%s", out)
	}
	var shown []allowShowJSON
	out, _ = alice.tryRun("allow", "show", "--relay", "liar", "--json")
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown) != 1 || shown[0].State != "broken" || shown[0].Error == "" || len(shown[0].Senders) != 0 {
		t.Fatalf("show --json through a lying relay: %+v", shown)
	}
	// The real relay is fine.
	rn := alice.relayName()
	if out := alice.run("allow", "show", "--relay", rn); !strings.Contains(out, rn+": signed, ") {
		t.Fatalf("show through the real relay:\n%s", out)
	}
}
