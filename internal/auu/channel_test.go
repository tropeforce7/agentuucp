package auu

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// opened is a user's home as the package sees it: the store, the identity
// and the registered relays, for driving the push machinery directly.
func (u *user) opened() (*store.Store, *identity.Identity, []*store.Relay) {
	u.t.Helper()
	u.t.Setenv("AUU_HOME", u.home)
	s, err := store.Open(u.home)
	if err != nil {
		u.t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		u.t.Fatal(err)
	}
	relays, err := selectedRelays(s, "")
	if err != nil {
		u.t.Fatal(err)
	}
	return s, id, relays
}

// named picks a relay out of a home's list by name.
func named(t *testing.T, relays []*store.Relay, name string) []*store.Relay {
	t.Helper()
	for _, r := range relays {
		if r.Name == name {
			return []*store.Relay{r}
		}
	}
	t.Fatalf("no relay called %s", name)
	return nil
}

// captureStdout runs fn with stdout captured.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	real := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	w.Close()
	os.Stdout = real
	data, _ := io.ReadAll(r)
	r.Close()
	return string(data), runErr
}

// heldBy is the directory a relay's store holds for an identity, or nil.
func heldBy(t *testing.T, st *relay.Store, id *identity.Identity) (*channels.Directory, []byte) {
	t.Helper()
	doc, sig, found, err := st.Directory(id.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		return nil, nil
	}
	d, err := channels.Verify(id.Public(), doc, sig)
	if err != nil {
		t.Fatalf("the relay holds a directory that does not verify: %v", err)
	}
	return d, doc
}

// plant puts a directory on a relay as another machine of the same
// identity would, straight into the relay's store.
func plant(t *testing.T, st *relay.Store, id *identity.Identity, issued time.Time, names ...string) {
	t.Helper()
	d := &channels.Directory{Issued: issued}
	for _, n := range names {
		d.Channels = append(d.Channels, channels.Channel{Name: n})
	}
	doc, sig, err := channels.Sign(id, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetDirectory(id.Fingerprint(), d, doc, sig); err != nil {
		t.Fatal(err)
	}
}

// A push signs the directory under its stored issue time: a relay that
// holds that issue answers as if it took it, one that was down takes it, and
// neither ends up with a fresher issue than the other machines saw.
func TestAPushWithTheStoredIssueIsTakenWhereMissingAndANoOpWhereHeld(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	personal, personalStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work, personal)
	s, id, relays := alice.opened()
	issued := time.Date(2026, 9, 13, 1, 19, 29, 500_000_000, time.UTC)
	d := &channels.Directory{Issued: issued, Channels: []channels.Channel{{Name: "default"}, {Name: "bugs", Description: "one per message"}}}

	// To work alone, as if personal had been down.
	out, err := captureStdout(t, func() error {
		res, err := pushDirectory(s, id, named(t, relays, "work"), d)
		if err == nil && (res.Conflict || res.Failed || res.Pushed != 1) {
			return errors.New("the first push did not count as one")
		}
		return err
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "work: directory pushed (2 channels)") {
		t.Fatalf("the first push:\n%s", out)
	}
	first, firstDoc := heldBy(t, workStore, id)
	if first == nil || !first.Issued.Equal(issued) {
		t.Fatalf("work holds %+v", first)
	}
	if held, _ := heldBy(t, personalStore, id); held != nil {
		t.Fatal("personal holds a directory it was never sent")
	}

	// Now to both, with the same directory and the same issue time.
	out, err = captureStdout(t, func() error {
		res, err := pushDirectory(s, id, relays, d)
		if err == nil && (res.Conflict || res.Failed || res.Pushed != 2) {
			return errors.New("the second push did not reach both")
		}
		return err
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "work: directory pushed (2 channels)") || !strings.Contains(out, "personal: directory pushed (2 channels)") {
		t.Fatalf("the second push:\n%s", out)
	}
	if _, doc := heldBy(t, workStore, id); string(doc) != string(firstDoc) {
		t.Fatal("pushing the stored issue again changed what work holds")
	}
	if held, _ := heldBy(t, personalStore, id); held == nil || !held.Issued.Equal(issued) || len(held.Channels) != 2 {
		t.Fatalf("personal holds %+v after the push", held)
	}
}

// Before an edit changes anything, every selected relay is asked what it
// holds: one holding a directory issued later than the local file's — from
// another machine of the same identity — stops the edit, and nothing is
// pushed or written.
func TestAnEditRefusesWhenARelayIsAhead(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	personal, personalStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work, personal)
	s, id, relays := alice.opened()

	// This machine signed at T; the other machine pushed T+1m to work.
	local := &channels.Directory{V: 1, Owner: id.Fingerprint(), Issued: time.Date(2026, 9, 13, 1, 19, 29, 0, time.UTC),
		Channels: []channels.Channel{{Name: "default"}}}
	if err := s.SetDirectory(local); err != nil {
		t.Fatal(err)
	}
	ahead := local.Issued.Add(time.Minute)
	plant(t, workStore, id, ahead, "default", "from the other machine")
	before, _ := os.ReadFile(s.ChannelsPath())

	edited := &channels.Directory{Channels: []channels.Channel{{Name: "default"}, {Name: "bugs"}}}
	out, err := captureStdout(t, func() error { return editAndPush(s, id, relays, edited, local.Issued) })
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport {
		t.Fatalf("an edit with a relay ahead: %v\n%s", err, out)
	}
	want := "work holds a directory issued " + ahead.Local().Format(time.RFC3339) +
		", newer than this machine's; run 'auu channel pull --relay work' to take it first"
	if err.Error() != want {
		t.Fatalf("the refusal:\n%v\nwant\n%s", err, want)
	}
	if strings.Contains(out, "pushed") {
		t.Fatalf("something was pushed:\n%s", out)
	}
	if held, _ := heldBy(t, workStore, id); held == nil || !held.Issued.Equal(ahead) || len(held.Channels) != 2 {
		t.Fatalf("work's directory changed: %+v", held)
	}
	if held, _ := heldBy(t, personalStore, id); held != nil {
		t.Fatal("personal was pushed to")
	}
	if after, _ := os.ReadFile(s.ChannelsPath()); string(after) != string(before) {
		t.Fatal("the local file was written")
	}

	// A home with no local file at all is behind any relay that holds one:
	// the first create on a second machine must take, not overwrite.
	if err := os.Remove(s.ChannelsPath()); err != nil {
		t.Fatal(err)
	}
	out, err = captureStdout(t, func() error { return editAndPush(s, id, relays, edited, time.Time{}) })
	if !errors.As(err, &exit) || err.Error() != want {
		t.Fatalf("a first edit with a relay ahead: %v\n%s", err, out)
	}
	if _, err := os.Stat(s.ChannelsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the local file was written")
	}
}

// A relay serving a directory for this identity that does not verify under
// its key stops the edit too: nothing is pushed on the word of a relay that
// lies.
func TestAnEditRefusesARelayWhoseDirectoryDoesNotVerify(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	s, id, relays := alice.opened()
	other, err := identity.Generate("other")
	if err != nil {
		t.Fatal(err)
	}
	// Signed by another key but named for alice: what a relay would have
	// to store on purpose, since the route refuses it.
	d := &channels.Directory{V: 1, Owner: id.Fingerprint(), Issued: time.Now(), Channels: []channels.Channel{{Name: "default"}}}
	doc, sig, err := channels.Sign(other, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workStore.SetDirectory(id.Fingerprint(), d, doc, sig); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return editAndPush(s, id, relays, &channels.Directory{Channels: []channels.Channel{{Name: "default"}}}, time.Time{})
	})
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport ||
		err.Error() != "the directory "+relays[0].Name+" serves for you does not verify against your key; do not trust it" {
		t.Fatalf("a lying relay: %v\n%s", err, out)
	}
	if _, err := os.Stat(s.ChannelsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the local file was written")
	}
}

// The preflight cannot see a push that lands between its look and this
// machine's push; the relay's 409 catches it, the same advice is printed,
// and the local file is left as it was.
func TestA409AfterThePreflightLeavesTheFileUnwritten(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	personal, personalStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work, personal)
	s, id, relays := alice.opened()
	local := &channels.Directory{V: 1, Owner: id.Fingerprint(), Issued: time.Date(2026, 9, 13, 1, 19, 29, 0, time.UTC),
		Channels: []channels.Channel{{Name: "default"}}}
	if err := s.SetDirectory(local); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.ChannelsPath())

	// The other machine pushes to work in the gap, ahead so that now,
	// which the edit signs under, is behind it, and within the skew, since
	// a row held from beyond it is no bar to the owner's push (R23).
	ahead := time.Now().Add(relayapi.MaxSkew - time.Minute).Truncate(time.Second)
	defer func() { afterPreflight = func() {} }()
	afterPreflight = func() { plant(t, workStore, id, ahead, "default", "from the other machine") }

	edited := &channels.Directory{Channels: []channels.Channel{{Name: "default"}, {Name: "bugs"}}}
	out, err := captureStdout(t, func() error { return editAndPush(s, id, relays, edited, local.Issued) })
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport || err.Error() != s.ChannelsPath()+" was not written" {
		t.Fatalf("an edit that met a 409: %v\n%s", err, out)
	}
	want := "work holds a directory issued " + ahead.Local().Format(time.RFC3339) +
		", newer than this machine's; run 'auu channel pull --relay work' to take it first"
	if !strings.Contains(out, want) {
		t.Fatalf("the 409 advice:\n%s\nwant\n%s", out, want)
	}
	if after, _ := os.ReadFile(s.ChannelsPath()); string(after) != string(before) {
		t.Fatal("the local file was written after a 409")
	}
	if held, _ := heldBy(t, workStore, id); held == nil || !held.Issued.Equal(ahead) {
		t.Fatalf("work's newer directory was overwritten: %+v", held)
	}
	// personal, which had nothing, took the edit: the two relays disagree
	// until the person pulls and pushes, which is what the advice says to
	// do, and the edit is not lost.
	if held, _ := heldBy(t, personalStore, id); held == nil || len(held.Channels) != 2 {
		t.Fatalf("personal did not take the edit: %+v", held)
	}
}

// A relay that cannot be reached, or refuses for a reason of its own, does
// not stop the edit: the local file is written for push to repair from, and
// the command exits 2 naming the relay.
func TestAnUnreachableRelayLeavesTheFileWrittenForPush(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	srv, personalStore := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work, srv.URL)
	s, id, relays := alice.opened()
	srv.Close()

	edited := &channels.Directory{Channels: []channels.Channel{{Name: "default"}, {Name: "bugs"}}}
	out, err := captureStdout(t, func() error { return editAndPush(s, id, relays, edited, time.Time{}) })
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport ||
		err.Error() != s.ChannelsPath()+" is written; run 'auu channel push' once the relay above can be reached" {
		t.Fatalf("an edit with a relay down: %v\n%s", err, out)
	}
	if !strings.Contains(out, "work: directory pushed (2 channels)") || !strings.Contains(out, "personal: could not push the directory:") {
		t.Fatalf("the report:\n%s", out)
	}
	if held, _ := heldBy(t, workStore, id); held == nil || len(held.Channels) != 2 {
		t.Fatalf("work did not take the edit: %+v", held)
	}
	if held, _ := heldBy(t, personalStore, id); held != nil {
		t.Fatal("the closed relay holds a directory")
	}
	got, found, err := s.Directory()
	if err != nil || !found || len(got.Channels) != 2 || got.Issued.IsZero() {
		t.Fatalf("the local file after: %+v %v %v", got, found, err)
	}
}

// Both time forms, and none.
func TestParseWhenTakesBothForms(t *testing.T) {
	at, cleared, err := parseWhen("--not-before", "2026-10-01T09:00:00+10:00")
	if err != nil || cleared || at == nil || !at.Equal(time.Date(2026, 9, 30, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("RFC 3339: %v %v %v", at, cleared, err)
	}
	at, cleared, err = parseWhen("--not-before", "2026-10-01")
	if err != nil || cleared || at == nil || !at.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local)) {
		t.Fatalf("a day: %v %v %v", at, cleared, err)
	}
	at, cleared, err = parseWhen("--not-after", "none")
	if err != nil || !cleared || at != nil {
		t.Fatalf("none: %v %v %v", at, cleared, err)
	}
	_, _, err = parseWhen("--not-after", "next tuesday")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage ||
		err.Error() != `--not-after wants a time as 2026-10-01T09:00:00+10:00 or a day as 2026-10-01, not "next tuesday"` {
		t.Fatalf("a time that is not one: %v", err)
	}
	if _, _, err := parseWhen("--not-after", "2026-10-01T09:00:00"); err == nil {
		t.Fatal("a time without a zone was taken")
	}
}

// Every Cc white-space character folds to one space, a run to one, \r\n as
// one; other white space is kept as given.
func TestFoldLinesFoldsEveryControlWhiteSpace(t *testing.T) {
	cases := []struct{ in, want string }{
		{"one bug\nper message", "one bug per message"},
		{"one bug\r\nper message", "one bug per message"},
		{"one bug\tper message", "one bug per message"},
		{"one bug\vper\fmessage\r", "one bug per message "},
		{"one bug\n\n\nper message", "one bug per message"},
		{"  one bug per message  ", "  one bug per message  "},
		{"one bug　per message", "one bug　per message"},
		{"one bugper message", "one bug per message"},
		{"", ""},
	}
	for _, c := range cases {
		if got := foldLines(c.in); got != c.want {
			t.Errorf("foldLines(%q) = %q, want %q", c.in, got, c.want)
		}
		if err := channels.ValidDescription(foldLines(c.in)); err != nil {
			t.Errorf("foldLines(%q) is still refused: %v", c.in, err)
		}
	}
}

// A relay holding exactly this machine's issue is not ahead: the edit goes
// through, the relays take the new issue, and the local file follows.
func TestAnEditProceedsWhenTheRelaysHoldThisIssue(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	personal, personalStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work, personal)
	s, id, relays := alice.opened()
	local := &channels.Directory{V: 1, Owner: id.Fingerprint(), Issued: time.Date(2026, 9, 13, 1, 19, 29, 0, time.UTC),
		Channels: []channels.Channel{{Name: "default"}}}
	if err := s.SetDirectory(local); err != nil {
		t.Fatal(err)
	}
	plant(t, workStore, id, local.Issued, "default")
	plant(t, personalStore, id, local.Issued.Add(-time.Hour), "default")

	edited := &channels.Directory{Channels: []channels.Channel{{Name: "default"}, {Name: "bugs"}}}
	out, err := captureStdout(t, func() error { return editAndPush(s, id, relays, edited, local.Issued) })
	if err != nil {
		t.Fatalf("an edit with the relays at or behind this issue: %v\n%s", err, out)
	}
	for _, st := range []*relay.Store{workStore, personalStore} {
		if held, _ := heldBy(t, st, id); held == nil || len(held.Channels) != 2 || !held.Issued.After(local.Issued) {
			t.Fatalf("a relay did not take the edit: %+v", held)
		}
	}
	got, found, err := s.Directory()
	if err != nil || !found || len(got.Channels) != 2 || !got.Issued.After(local.Issued) {
		t.Fatalf("the local file after: %+v %v %v", got, found, err)
	}
}

// The owner is told, once per run, when the relay holds a channel
// directory of theirs that no longer verifies: posts to their channels
// are refused there, and they would otherwise learn it from their
// senders' silence. None is silent, since a home that has pushed no
// directory has published no names and nothing is missing; signed is
// silent; broken says what to run. auu wait says it too.
func TestInboxSaysWhenTheDirectoryDoesNotVerify(t *testing.T) {
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
	const broken = "auu: your channel directory on %s does not verify, so every post to you is refused there; " +
		"run auu channel push, and if you did not change it, tell the relay's operator\n"

	// No directory: silence, and no marker to say one is missing.
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning with no directory:\n%s", warning)
	}
	// Pushed and signed: silence.
	alice.run("channel", "create", "bug reports")
	alice.run("channel", "push")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning with a signed directory:\n%s", warning)
	}
	// Broken: the signature blanked on the host. A message queued first,
	// so the fetch has something to list before the warning.
	bob.run("send", "--to", "alice", "before the edit")
	if _, err := db.Exec(`UPDATE directories SET sig = X'' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	out, warning := inbox()
	if warning != fmt.Sprintf(broken, rn) {
		t.Fatalf("the warning:\n%s\nwant\n%s", warning, fmt.Sprintf(broken, rn))
	}
	if !strings.Contains(out, "fetched 1 new message(s)") {
		t.Fatalf("the fetch itself did not report:\n%s", out)
	}
	// Once per run, whatever the fetch found: a second inbox says it
	// again, and a run that fetches nothing still says it. (Nothing new
	// can arrive now: the mailbox is closed until the push.)
	if _, warning := inbox(); warning != fmt.Sprintf(broken, rn) {
		t.Fatalf("the warning on an empty fetch:\n%s", warning)
	}
	// The sender meets it as a channel that is not there, for a named
	// channel and for the default one alike: the mailbox is closed, and
	// what a sender learns is only that there is no such channel.
	bob.run("channel", "ls")
	_, err := bob.tryRun("send", "--to", "alice", "--channel", "bug reports", "after the edit")
	if err == nil || !strings.Contains(err.Error(), `alice has no channel "bug reports"`) {
		t.Fatalf("a post to a named channel under a broken directory: %v", err)
	}
	// For the default channel the sender is told the same thing, under
	// its name rather than an empty pair of quotes, and their own fetch
	// of alice's directory says why it cannot be listed.
	_, err = bob.tryRun("send", "--to", "alice", "to the default channel")
	if err == nil || !strings.Contains(err.Error(), `alice has no channel "default" on `+rn+
		`, and the directory `+rn+` served for alice does not verify against the key you hold; do not trust it`) {
		t.Fatalf("a post to the default channel under a broken directory: %v", err)
	}
	// auu wait says it too, once, before it times out.
	warning = captureStderr(t, func() { alice.tryRun("wait", "--thread", strings.Repeat("ab", 8), "--timeout", "1s") })
	if !strings.Contains(warning, "your channel directory on "+rn+" does not verify") {
		t.Fatalf("auu wait did not say it:\n%s", warning)
	}
	// The push is the repair, and the relay says signed again.
	alice.run("channel", "push")
	if _, warning := inbox(); warning != "" {
		t.Fatalf("a warning after the repair:\n%s", warning)
	}
	if state, err := st.DirectoryState(fp); err != nil || state != relayapi.DirectorySigned {
		t.Fatalf("the relay says %q %v after the repair", state, err)
	}
}
