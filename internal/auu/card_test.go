package auu

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// cardPushed reads the file beside the cursor for the default relay.
func (u *user) cardPushed() (time.Time, bool) {
	u.t.Helper()
	s, _, relays := u.opened()
	pushed, found, err := s.CardPushed(relays[0])
	if err != nil {
		u.t.Fatal(err)
	}
	return pushed, found
}

// localCard reads card.json, the card this machine last pushed.
func (u *user) localCard() (*card.Document, bool) {
	u.t.Helper()
	s, _, _ := u.opened()
	d, found, err := s.Card()
	if err != nil {
		u.t.Fatal(err)
	}
	return d, found
}

// The sentences of push, clear and show; card.json and the marker written
// on push and the marker removed on clear; a bare push saying again what
// the file says, a typed flag the one thing that changes a word, and
// --listed=false the way to turn one off; and what show prints and gives
// as JSON for each state.
func TestCardPushClearAndShow(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	rn := alice.relayName()

	// Before anything: none, no file, no marker.
	out := alice.run("card", "show")
	if !strings.Contains(out, rn+": no card; you are not listed there and your mailbox takes no knocks\n") {
		t.Fatalf("show before a push:\n%s", out)
	}
	if _, found := alice.cardPushed(); found {
		t.Fatal("card_pushed exists before a push")
	}
	if _, found := alice.localCard(); found {
		t.Fatal("card.json exists before a push")
	}

	// A bare push with no file: a card that says neither.
	before := time.Now().Add(-time.Second)
	out = alice.run("card", "push")
	if !strings.Contains(out, rn+": card pushed; you are not listed there and your mailbox takes no knocks\n") {
		t.Fatalf("a bare push with no file:\n%s", out)
	}
	pushed, found := alice.cardPushed()
	if !found || pushed.Before(before) {
		t.Fatalf("card_pushed after a push: %v %v", pushed, found)
	}
	if d, found := alice.localCard(); !found || d.Listed || d.Knocks || d.Name != "alice" || d.Issued.Before(before) {
		t.Fatalf("card.json after a bare push: %+v %v", d, found)
	}

	// --listed, with the flag after nothing in particular: the file and
	// the relay both say so, and knocks stays as it was.
	out = alice.run("card", "push", "--listed")
	if !strings.Contains(out, rn+": card pushed; you are listed there and your mailbox takes no knocks\n") {
		t.Fatalf("push --listed:\n%s", out)
	}
	if d, _ := alice.localCard(); !d.Listed || d.Knocks {
		t.Fatalf("card.json after --listed: %+v", d)
	}
	out = alice.run("card", "show")
	if !strings.Contains(out, rn+": signed, issued ") ||
		!strings.Contains(out, ", name alice; you are listed there and your mailbox takes no knocks\n") {
		t.Fatalf("show after --listed:\n%s", out)
	}

	// A bare push again: the same two words, since the flags default to
	// the file's, which is what the inbox's repair sentence relies on.
	out = alice.run("card", "push")
	if !strings.Contains(out, rn+": card pushed; you are listed there and your mailbox takes no knocks\n") {
		t.Fatalf("a bare push after --listed changed a word:\n%s", out)
	}
	// --knocks adds the other word and keeps listed; --listed=false takes
	// the first away and keeps knocks.
	out = alice.run("card", "push", "--knocks")
	if !strings.Contains(out, rn+": card pushed; you are listed there and your mailbox takes knocks\n") {
		t.Fatalf("push --knocks:\n%s", out)
	}
	out = alice.run("card", "push", "--listed=false")
	if !strings.Contains(out, rn+": card pushed; you are not listed there and your mailbox takes knocks\n") {
		t.Fatalf("push --listed=false:\n%s", out)
	}
	if d, _ := alice.localCard(); d.Listed || !d.Knocks {
		t.Fatalf("card.json after --listed=false: %+v", d)
	}

	var shown []cardShowJSON
	if err := json.Unmarshal([]byte(alice.run("card", "show", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown) != 1 || shown[0].Relay != rn || shown[0].State != "signed" || shown[0].Issued == nil ||
		shown[0].Name != "alice" || shown[0].Listed || !shown[0].Knocks || shown[0].Error != "" {
		t.Fatalf("show --json: %+v", shown)
	}

	// Clear: the sentence, the marker gone, the file saying neither, the
	// relay holding a signed card that says neither.
	out = alice.run("card", "clear")
	if !strings.Contains(out, rn+": card cleared; you are not listed there and your mailbox takes no knocks\n") {
		t.Fatalf("clear:\n%s", out)
	}
	if _, found := alice.cardPushed(); found {
		t.Fatal("card_pushed survives a clear")
	}
	if d, found := alice.localCard(); !found || d.Listed || d.Knocks {
		t.Fatalf("card.json after a clear: %+v %v", d, found)
	}
	out = alice.run("card", "show")
	if !strings.Contains(out, ", name alice; you are not listed there and your mailbox takes no knocks\n") {
		t.Fatalf("show after a clear:\n%s", out)
	}
	if err := json.Unmarshal([]byte(alice.run("card", "show", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if shown[0].State != "signed" || shown[0].Listed || shown[0].Knocks {
		t.Fatalf("show --json after a clear: %+v", shown)
	}
	// clear takes no --relay: it is every relay.
	if _, err := alice.tryRun("card", "clear", "--relay", rn); err == nil || !strings.Contains(err.Error(), "-relay") {
		t.Fatalf("clear with --relay: %v; want the flag refused", err)
	}
}

// The owner is told, once per run and after the messages, what the relay
// says about their card: nothing for signed and for none with nothing
// pushed from here; the sentences for none after a push from here, and
// for broken, which a blanked signature is too.
func TestInboxWarnsAboutTheCardState(t *testing.T) {
	relayURL, st, db, _ := startEditableRelay(t)
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
	const brokenWarning = "auu: your card on %s does not verify, so nobody can knock and you are not listed there; run auu card push, and if you did not change it, tell the relay's operator\n"

	// none, nothing pushed: silence.
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning with no card and no push:\n%s", warning)
	}
	// signed: silence.
	alice.run("card", "push", "--listed")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning with a signed card:\n%s", warning)
	}
	// broken: the relay's row edited to change the name. A message from
	// before the edit is queued, so the fetch has something to list before
	// the warning.
	bob.run("send", "--to", "alice", "before the edit")
	doc, _, _, _, err := st.Card(fp)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(doc), `"name":"alice"`, `"name":"mallory"`, 1)
	if edited == string(doc) {
		t.Fatal("the document has no name to edit")
	}
	if _, err := db.Exec(`UPDATE cards SET doc = ? WHERE fp = ?`, []byte(edited), fp); err != nil {
		t.Fatal(err)
	}
	out, warning := inbox()
	if warning != strings.ReplaceAll(brokenWarning, "%s", rn) {
		t.Fatalf("the broken warning:\n%s\n%s", warning, out)
	}
	if !strings.Contains(out, "fetched 1 new message(s)\n") {
		t.Fatalf("the message from before the edit was not fetched:\n%s", out)
	}
	if strings.Contains(out, "does not verify") {
		t.Fatalf("the warning is on stdout:\n%s", out)
	}
	// wait says it once per run, and the run's own exit code stands.
	warning = captureStderr(t, func() {
		_, err := alice.tryRun("wait", "--thread", "nothing", "--timeout", "1s", "--interval", "5s")
		var e *exitError
		if !errors.As(err, &e) || e.code != exitTimeout {
			t.Errorf("wait under a broken card: %v", err)
		}
	})
	if strings.Count(warning, "your card on") != 1 {
		t.Fatalf("wait's warning:\n%s", warning)
	}
	// A bare push repairs it, and leaves the words as they were.
	out = alice.run("card", "push")
	if !strings.Contains(out, "you are listed there and your mailbox takes no knocks") {
		t.Fatalf("the repair changed a word:\n%s", out)
	}
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning after the repair:\n%s", warning)
	}

	// none after a push from here: the relay has lost it.
	if _, err := db.Exec(`DELETE FROM cards WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	_, warning = inbox()
	today := time.Now().Format(time.DateOnly)
	if warning != "auu: your card on "+rn+" is missing, though you pushed one on "+today+"; run auu card push and tell the relay's operator\n" {
		t.Fatalf("the missing warning:\n%s", warning)
	}
	// The signature blanked on the host: broken, the same sentence,
	// whether or not this machine had pushed; and show says broken and
	// exits 1 rather than reading it.
	alice.run("card", "push")
	if _, err := db.Exec(`UPDATE cards SET sig = X'' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	_, warning = inbox()
	if warning != strings.ReplaceAll(brokenWarning, "%s", rn) {
		t.Fatalf("the blanked-signature warning:\n%s", warning)
	}
	alice.run("card", "clear")
	if _, err := db.Exec(`UPDATE cards SET sig = X'' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	_, warning = inbox()
	if !strings.Contains(warning, " does not verify, so nobody can knock and you are not listed there;") {
		t.Fatalf("the blanked-signature warning with nothing pushed from here:\n%s", warning)
	}
	out, err = alice.tryRun("card", "show")
	if err == nil || !strings.Contains(out, rn+": your card on "+rn+" does not verify, so nobody can knock and you are not listed there") {
		t.Fatalf("show of a blanked row: %v\n%s", err, out)
	}
	// And pushing ends it.
	alice.run("card", "push")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning after pushing over a blanked row:\n%s", warning)
	}
}

// show verifies the pair with the owner's own key and never trusts the
// relay's word: a relay that alters the document it serves, and still
// says signed, is caught, and show exits 1 with the broken sentence.
func TestCardShowVerifiesWithTheOwnersKey(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	alice.run("card", "push", "--listed")

	// A relay in the middle that serves the real relay's answers, but
	// with the card's name changed in the one it hands back.
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
		if strings.HasSuffix(r.URL.Path, "/card") && r.Method == http.MethodGet {
			var out relayapi.CardResponse
			json.NewDecoder(resp.Body).Decode(&out)
			out.Document = []byte(strings.Replace(string(out.Document), `"name":"alice"`, `"name":"mallory"`, 1))
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

	out, err := alice.tryRun("card", "show", "--relay", "liar")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage || err.Error() != "a card does not verify" {
		t.Fatalf("show through a lying relay: %v\n%s", err, out)
	}
	if !strings.Contains(out, "liar: your card on liar does not verify, so nobody can knock and you are not listed there; run auu card push, and if you did not change it, tell the relay's operator\n") {
		t.Fatalf("show through a lying relay:\n%s", out)
	}
	var shown []cardShowJSON
	if out, _ := alice.tryRun("card", "show", "--relay", "liar", "--json"); json.Unmarshal([]byte(out), &shown) != nil ||
		len(shown) != 1 || shown[0].State != "broken" || shown[0].Error == "" || shown[0].Name != "" {
		t.Fatalf("show --json through a lying relay: %+v", shown)
	}
	// The real relay, asked directly, is fine.
	if out := alice.run("card", "show", "--relay", alice.relayName()); !strings.Contains(out, ": signed, issued ") {
		t.Fatalf("show through the real relay:\n%s", out)
	}
}

// A relay whose health answer carries no registration mode, or a fourth
// word, is refused by name through a whole command, with nothing of the
// answer used: the mode is what a listed name rests on, and a command
// that would print it must not guess.
func TestARelayWithoutARegistrationModeIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode any
	}{
		{"without registration", nil},
		{"with a fourth word", "invite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := map[string]any{"ok": true, "max_bytes": relayapi.DefaultMaxBytes, "knock_max_bytes": relayapi.DefaultMaxBytes, "wire_level": 1}
			if tc.mode != nil {
				answer["registration"] = tc.mode
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(answer)
			}))
			defer srv.Close()
			alice := &user{t: t, home: t.TempDir()}
			alice.run("init", "--name", "alice", "--relay", srv.URL)
			_, err := alice.tryRun("register")
			if err == nil || !strings.Contains(err.Error(), "registration is not one of open, token, closed") {
				t.Fatalf("register against the relay: %v; want the refusal naming the field", err)
			}
			// relay show says it could not be asked, on the line, and
			// still prints what the home holds.
			out := alice.run("relay", "show")
			if !strings.Contains(out, "registration: not asked (") || !strings.Contains(out, "registration is not one of open, token, closed") ||
				!strings.Contains(out, "url:        "+srv.URL) {
				t.Fatalf("relay show against the relay:\n%s", out)
			}
		})
	}
}

// relay show and lookup print the relay's registration mode with what it
// means for a name found there, and their JSON carries the word.
func TestRelayShowAndLookupSayWhatARegistrationModeMeans(t *testing.T) {
	relayURL, _, _, _ := startEditableRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)

	out := alice.run("relay", "show")
	if !strings.Contains(out, "registration: open (registers anyone: an identity here proves nothing about who holds it, and its name is its own claim)\n") {
		t.Fatalf("relay show on an open relay:\n%s", out)
	}
	var shown relayJSON
	if err := json.Unmarshal([]byte(alice.run("relay", "show", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Registration != "open" || shown.RegistrationError != "" {
		t.Fatalf("relay show --json: %+v", shown)
	}
	// relay ls reads local files alone and asks nothing.
	if out := alice.run("relay", "ls"); strings.Contains(out, "registration") {
		t.Fatalf("relay ls asks the relay:\n%s", out)
	}

	out = alice.run("lookup", bob.exportFingerprint())
	if !strings.Contains(out, "registration:  open; the relay registers anyone: this identity proves nothing about who holds it, and its name is its own claim\n") ||
		!strings.Contains(out, "name on relay: bob\n") {
		t.Fatalf("lookup on an open relay:\n%s", out)
	}
	var looked lookupJSON
	if err := json.Unmarshal([]byte(alice.run("lookup", bob.exportFingerprint(), "--json")), &looked); err != nil {
		t.Fatal(err)
	}
	if looked.Registration != "open" {
		t.Fatalf("lookup --json: %+v", looked)
	}

	// The token sentence and the closed sentence, from the function the
	// commands share.
	if got := registrationMeans(relayapi.RegistrationToken, "this identity"); got != "invites by token: this identity was let in by an administrator, and its name is its own claim" {
		t.Fatalf("the token sentence: %q", got)
	}
	if got := registrationMeans(relayapi.RegistrationClosed, "this identity"); got != "registers nobody now: this identity was let in before it closed, under whichever rule held then, and its name is its own claim" {
		t.Fatalf("the closed sentence: %q", got)
	}
}

// A push that fails halfway — the first relay takes the card, the second
// cannot be reached — leaves card.json saying what was typed, since the
// first relay holds it: a bare push afterwards retries the typed words
// on both relays rather than putting the old words back on the one that
// took the new ones. A push that reaches no relay leaves the file as it
// was. The second reader found the file written after every relay, which
// re-listed a person who had just unlisted themselves.
func TestACardPushThatFailsHalfwayLeavesTheFileSayingWhatWasPushed(t *testing.T) {
	workURL, _, _, _ := startEditableRelay(t)
	personalURL, _, _, _ := startEditableRelay(t)
	alice := onBothRelays(t, "alice", workURL, personalURL)

	// Listed on both.
	out := alice.run("card", "push", "--listed")
	if !strings.Contains(out, "personal: card pushed; you are listed there") || !strings.Contains(out, "work: card pushed; you are listed there") {
		t.Fatalf("push to both:\n%s", out)
	}
	if d, _ := alice.localCard(); !d.Listed {
		t.Fatalf("card.json after the push: %+v", d)
	}

	// The second relay in the push's order — the relays go by name, so
	// "work" after "personal" — goes away: its URL is rewritten to a port
	// nothing listens on.
	s, _, _ := alice.opened()
	work, err := s.Relay("work")
	if err != nil {
		t.Fatal(err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	work.URL = deadURL
	if err := s.SaveRelay(work); err != nil {
		t.Fatal(err)
	}

	// Unlisting fails at the second relay, exit 2 naming it; the first
	// relay holds the new card, and so does the file.
	_, err = alice.tryRun("card", "push", "--listed=false")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "work:") {
		t.Fatalf("a push with the second relay down: %v; want exit 2 naming it", err)
	}
	if d, _ := alice.localCard(); d.Listed {
		t.Fatalf("card.json after the halfway failure still says listed: %+v", d)
	}
	if out := alice.run("card", "show", "--relay", "personal"); !strings.Contains(out, "you are not listed there") {
		t.Fatalf("the first relay after the halfway failure:\n%s", out)
	}
	// A bare push retries the typed word on the first relay and fails the
	// same way on the second; the first relay still says not listed.
	if _, err := alice.tryRun("card", "push"); err == nil {
		t.Fatal("a bare push with the second relay down succeeded")
	}
	if out := alice.run("card", "show", "--relay", "personal"); !strings.Contains(out, "you are not listed there") {
		t.Fatalf("the first relay after the bare push:\n%s", out)
	}
	if d, _ := alice.localCard(); d.Listed {
		t.Fatalf("card.json after the bare push: %+v", d)
	}

	// A push that reaches no relay leaves the file as it was: both URLs
	// dead, --knocks typed, the file still says neither.
	personal, err := s.Relay("personal")
	if err != nil {
		t.Fatal(err)
	}
	personal.URL = deadURL
	if err := s.SaveRelay(personal); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.tryRun("card", "push", "--knocks"); err == nil {
		t.Fatal("a push with every relay down succeeded")
	}
	if d, _ := alice.localCard(); d.Knocks || d.Listed {
		t.Fatalf("card.json after a push that reached no relay: %+v", d)
	}
}
