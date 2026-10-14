package auu

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The owner's side of a channel's rules (PLAN-CHANNEL-POLICY commit 3):
// the flags, the listing, the checks before a push, and what a sender is
// told.

// frontedRelay is a real relay behind a front the test controls: a health
// answer at wire level 1 for a relay older than the rules, a PUT of the
// directory dropped on the floor for one that fails mid-push, and a count
// of the directory PUTs that reached the relay.
type frontedRelay struct {
	url     string
	store   *relay.Store
	level1  atomic.Bool
	unsaid  atomic.Bool
	dropPUT atomic.Bool
	puts    atomic.Int64
}

func startFrontedRelay(t *testing.T, cfg relay.Config) *frontedRelay {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg.Streams = true
	handler := relay.NewServer(st, cfg)
	f := &frontedRelay{store: st}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/health" && f.level1.Load() {
			// A hand-written health answer for a relay below the rules, as
			// the guide allows: level 1, and so no channel-max-bytes.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":20480,"registration":"open","wire_level":1}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/health" && f.unsaid.Load() {
			// Level 2 with no channel-max-bytes: a relay that does not say
			// how large a channel on it may be.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":20480,"registration":"open","wire_level":2}`))
			return
		}
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/channels") {
			if f.dropPUT.Load() {
				// A transport failure: the connection closed with no answer.
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					conn.Close()
				}
				return
			}
			f.puts.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	f.url = srv.URL
	t.Cleanup(func() { srv.Close(); handler.Close() })
	return f
}

// exitOf is a command's error as its exit code, failing when it is none.
func exitOf(t *testing.T, err error) int {
	t.Helper()
	var exit *exitError
	if !errors.As(err, &exit) {
		t.Fatalf("%v: not an exit error", err)
	}
	return exit.code
}

// A rule set with all three flags is listed in the owner's table and JSON
// and a peer's, and the relay holds a version 2 document; clearing all
// three pushes a version 1 document again; and no_forwards alone writes
// version 2 (R13). The flags follow the positional, which parseArgs takes.
func TestAChannelRuleIsSetListedAndPushed(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	_, aliceID, _ := alice.opened()

	alice.run("channel", "create", "logs", "--max-bytes", "65536", "--no-streams", "--no-forwards")
	d, doc := heldBy(t, workStore, aliceID)
	if d == nil || d.V != channels.Version2 || !strings.HasPrefix(string(doc), `{"v":2,`) {
		t.Fatalf("the relay holds %s; want a version 2 document", doc)
	}
	logs := d.Find("logs")
	if logs == nil || logs.MaxBytes != 65536 || !logs.NoStreams || !logs.NoForwards {
		t.Fatalf("the relay's logs channel: %+v", logs)
	}
	if local := alice.channelsOf(); local.V != channels.Version2 {
		t.Fatalf("the local file says v %d; want 2", local.V)
	}

	text := alice.run("channel", "ls")
	for _, want := range []string{"RULE", "≤ 64 KiB, no streams, no forwards"} {
		if !strings.Contains(text, want) {
			t.Errorf("the owner's ls lacks %q:\n%s", want, text)
		}
	}
	ls := alice.lsJSON()
	if len(ls.Channels) != 2 || ls.Channels[1].MaxBytes != 65536 || !ls.Channels[1].NoStreams || !ls.Channels[1].NoForwards ||
		ls.Channels[0].MaxBytes != 0 || ls.Channels[0].NoStreams || ls.Channels[0].NoForwards {
		t.Fatalf("the owner's ls --json: %+v", ls.Channels)
	}
	if peer := bob.run("channel", "ls", "alice"); !strings.Contains(peer, "≤ 64 KiB, no streams, no forwards") {
		t.Fatalf("the peer's ls lacks the rule:\n%s", peer)
	}
	if peer := bob.lsJSON("alice"); len(peer.Channels) != 2 || peer.Channels[1].MaxBytes != 65536 || !peer.Channels[1].NoStreams || !peer.Channels[1].NoForwards {
		t.Fatalf("the peer's ls --json: %+v", peer.Channels)
	}

	// Every rule cleared: a version 1 document, with no rule field in it.
	alice.run("channel", "update", "logs", "--max-bytes", "none", "--streams", "--forwards")
	d, doc = heldBy(t, workStore, aliceID)
	if d.V != channels.Version1 || !strings.HasPrefix(string(doc), `{"v":1,`) {
		t.Fatalf("the relay holds %s after clearing; want version 1", doc)
	}
	for _, field := range []string{"max_bytes", "no_streams", "no_forwards"} {
		if strings.Contains(string(doc), field) {
			t.Fatalf("the version 1 document carries %s: %s", field, doc)
		}
	}
	if text := alice.run("channel", "ls"); !strings.Contains(text, "logs") || strings.Contains(text, "no streams") {
		t.Fatalf("ls after clearing:\n%s", text)
	}

	// no_forwards alone is a rule.
	alice.run("channel", "create", "mine", "--no-forwards")
	if d, doc = heldBy(t, workStore, aliceID); d.V != channels.Version2 || !strings.Contains(string(doc), `"no_forwards":true`) ||
		strings.Contains(string(doc), "max_bytes") || strings.Contains(string(doc), "no_streams") {
		t.Fatalf("no_forwards alone: %s", doc)
	}

	// Both ways at once is refused before anything is asked.
	usageError(t, alice, "--no-streams and --streams say opposite things; give one", "channel", "update", "mine", "--no-streams", "--streams")
	usageError(t, alice, "--no-forwards and --forwards say opposite things; give one", "channel", "update", "mine", "--no-forwards", "--forwards")
	usageError(t, alice, "nothing to change: give --description, --not-before, --not-after, --max-bytes, --no-streams, --streams, --no-forwards or --forwards",
		"channel", "update", "mine")
}

// --max-bytes is a whole number of bytes in digits, or none, held to the
// smallest ceiling the selected relays' health answers give (R19): at the
// ceiling taken, one over refused naming the relay and its number before
// any push, under the three shapes a relay's two caps can take. Its help
// says wire bytes.
func TestLimitChannelMaxBytesFlag(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	addRuleFlags(fs)
	if usage := fs.Lookup("max-bytes").Usage; !strings.Contains(usage, "wire bytes") {
		t.Errorf("the flag's help does not say wire bytes: %q", usage)
	}

	for _, c := range []struct {
		v    string
		want int64
		bad  string
	}{
		{"1", 1, ""},
		{"none", 0, ""},
		{strconv.FormatInt(relayapi.MaxStreamSize, 10), relayapi.MaxStreamSize, ""},
		{"0", 0, "--max-bytes 0: give a number of bytes from 1, or none for the relay's own cap"},
		{"-1", 0, `--max-bytes "-1": give a whole number of bytes, in digits, or none for the relay's own cap`},
		{"+1", 0, `--max-bytes "+1": give a whole number of bytes, in digits, or none for the relay's own cap`},
		{" 1", 0, `--max-bytes " 1": give a whole number of bytes, in digits, or none for the relay's own cap`},
		{"1e3", 0, `--max-bytes "1e3": give a whole number of bytes, in digits, or none for the relay's own cap`},
		{"", 0, `--max-bytes "": give a whole number of bytes, in digits, or none for the relay's own cap`},
		{"9223372036854775808", 0, "--max-bytes 9223372036854775808: more than any relay takes; the most is 4611686018427387904"},
	} {
		got, err := parseMaxBytes(c.v)
		switch {
		case c.bad == "" && (err != nil || got != c.want):
			t.Errorf("%q: %d, %v; want %d", c.v, got, err, c.want)
		case c.bad != "" && (err == nil || err.Error() != c.bad):
			t.Errorf("%q: %v; want %q", c.v, err, c.bad)
		}
	}

	for _, tc := range []struct {
		name    string
		cfg     relay.Config
		ceiling int64
	}{
		{"max_stream_bytes the larger", relay.Config{MaxBytes: 2048, MaxStreamBytes: 100000}, 100000},
		{"max_bytes the larger", relay.Config{MaxBytes: 60000, MaxStreamBytes: 10000}, 60000},
		{"max_stream_bytes unlimited", relay.Config{MaxBytes: 2048}, relayapi.MaxStreamSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Limits = relay.DefaultLimits()
			f := startFrontedRelay(t, tc.cfg)
			alice := newUser(t, "alice", f.url)
			_, aliceID, _ := alice.opened()
			alice.run("channel", "create", "logs", "--max-bytes", strconv.FormatInt(tc.ceiling, 10))
			if d, _ := heldBy(t, f.store, aliceID); d.Find("logs").MaxBytes != tc.ceiling {
				t.Fatalf("at the ceiling: the relay holds %+v", d.Find("logs"))
			}
			before := f.puts.Load()
			_, kept := heldBy(t, f.store, aliceID)
			over := strconv.FormatInt(tc.ceiling+1, 10)
			want := `channel "logs": --max-bytes ` + over + ` is over the ` + strconv.FormatInt(tc.ceiling, 10) +
				` relay ` + alice.defaultRelayName() + ` takes`
			if tc.ceiling == relayapi.MaxStreamSize {
				// One over the protocol's own ceiling is the format's to
				// refuse, before any relay is asked.
				want = `channel "logs": max_bytes is ` + over + `; 0 for the relay's own, or 1 to 4611686018427387904`
			}
			usageError(t, alice, want, "channel", "update", "logs", "--max-bytes", over)
			if f.puts.Load() != before {
				t.Error("a refused --max-bytes was pushed")
			}
			if _, doc := heldBy(t, f.store, aliceID); string(doc) != string(kept) {
				t.Error("the relay's directory changed")
			}
			if alice.channelsOf().Find("logs").MaxBytes != tc.ceiling {
				t.Error("the local directory changed")
			}
		})
	}
}

// A relay whose health says wire level 1 cannot hold a rule: the version 2
// edit is refused naming it before any PUT, the local directory unchanged,
// and a version 1 edit to the same relay goes through.
func TestAVersionTwoDirectoryIsNotPushedToARelayAtLevelOne(t *testing.T) {
	f := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", f.url)
	f.level1.Store(true)
	alice.run("channel", "create", "plain")
	if f.puts.Load() != 1 {
		t.Fatalf("%d PUTs for a version 1 edit; want 1", f.puts.Load())
	}
	before := alice.channelsOf()
	usageError(t, alice, "relay "+alice.defaultRelayName()+" is at wire level 1 and cannot hold a channel rule; "+
		"update it, or drop --max-bytes, --no-streams and --no-forwards", "channel", "create", "logs", "--no-streams")
	if f.puts.Load() != 1 {
		t.Fatalf("%d PUTs after the refused edit; want none more", f.puts.Load())
	}
	if after := alice.channelsOf(); len(after.Channels) != len(before.Channels) || !after.Issued.Equal(before.Issued) {
		t.Fatalf("the local directory changed: %+v", after)
	}
	// Every edit of a directory that keeps a rule asks the same, and so
	// does channel push of a stored one: update, close and delete of
	// another channel each push the rule again.
	f.level1.Store(false)
	alice.run("channel", "create", "logs", "--no-streams")
	f.level1.Store(true)
	puts := f.puts.Load()
	levelOne := "relay " + alice.defaultRelayName() + " is at wire level 1 and cannot hold a channel rule; " +
		"update it, or drop --max-bytes, --no-streams and --no-forwards"
	usageError(t, alice, levelOne, "channel", "push")
	usageError(t, alice, levelOne, "channel", "update", "plain", "--description", "x")
	usageError(t, alice, levelOne, "channel", "close", "plain")
	usageError(t, alice, levelOne, "channel", "delete", "plain")
	if f.puts.Load() != puts {
		t.Fatalf("%d PUTs of a version 2 directory to a level 1 relay", f.puts.Load()-puts)
	}
	// Deleting the channel that carries the rule leaves version 1, which
	// any relay takes.
	alice.run("channel", "delete", "logs")
	if f.puts.Load() != puts+1 {
		t.Fatalf("the version 1 directory was not pushed: %d PUTs", f.puts.Load()-puts)
	}
}

// A relay at wire level 2 whose health answer does not say the largest
// max_bytes a channel on it may name cannot be held to it, and so is not
// asked to hold any rule: the edit is refused naming it, before any PUT.
func TestARelayThatDoesNotSayItsCeilingIsAskedToHoldNoRule(t *testing.T) {
	f := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", f.url)
	f.unsaid.Store(true)
	alice.run("channel", "create", "plain")
	puts := f.puts.Load()
	usageError(t, alice, "relay "+alice.defaultRelayName()+" did not say the largest max_bytes a channel on it may name, "+
		"so it cannot be asked to hold a channel rule; update it", "channel", "create", "logs", "--no-forwards")
	if f.puts.Load() != puts {
		t.Fatal("a rule was pushed to a relay that did not say its ceiling")
	}
}

// The first rule on a directory that carried none says once what older
// peers meet, in their build's words; the second rule says nothing, nor
// does an edit with no rule.
func TestTheFirstRuleSaysWhatOldPeersMeet(t *testing.T) {
	work := startRelay(t)
	alice := newUser(t, "alice", work)
	said := func(args ...string) string {
		t.Helper()
		return captureStderr(t, func() { alice.run(args...) })
	}
	if got := said("channel", "create", "plain"); got != "" {
		t.Fatalf("an edit with no rule said:\n%s", got)
	}
	first := said("channel", "create", "logs", "--max-bytes", "1000")
	for _, want := range []string{"a channel rule makes your directory version 2",
		"'does not verify against the key you hold; do not trust it'", "not a key problem",
		"they still send to your channels", "cannot go back below v0.18.0"} {
		if !strings.Contains(first, want) {
			t.Errorf("the first rule's word lacks %q:\n%s", want, first)
		}
	}
	if strings.Count(first, "version 2") != 1 {
		t.Errorf("said more than once:\n%s", first)
	}
	if got := said("channel", "update", "plain", "--no-streams"); got != "" {
		t.Fatalf("the second rule said:\n%s", got)
	}
}

// A version 2 edit waits for every selected relay to answer: one that
// cannot be reached refuses the edit naming it, with no PUT to the other
// and the local directory unchanged; the same edit with no rule goes to the
// reachable relay and fails on the other as before.
func TestAVersionTwoEditWaitsForEveryRelay(t *testing.T) {
	work := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
	personal, _ := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := onBothRelays(t, "alice", work.url, personal.URL)
	alice.run("channel", "create", "plain")
	putsBefore := work.puts.Load()
	before := alice.channelsOf()
	personal.Close()

	out, err := alice.tryRun("channel", "create", "logs", "--no-streams")
	if err == nil || exitOf(t, err) != exitTransport || !strings.Contains(err.Error(), "relay personal could not be asked whether it can hold a channel rule") {
		t.Fatalf("a version 2 edit with personal down: %v\n%s", err, out)
	}
	if work.puts.Load() != putsBefore {
		t.Fatal("work was pushed to while personal could not confirm")
	}
	if after := alice.channelsOf(); len(after.Channels) != len(before.Channels) {
		t.Fatalf("the local directory changed: %+v", after)
	}

	out, err = alice.tryRun("channel", "create", "other")
	if err == nil || exitOf(t, err) != exitTransport || !strings.Contains(out, "work: directory pushed") ||
		!strings.Contains(out, "personal: could not push the directory") {
		t.Fatalf("a version 1 edit with personal down: %v\n%s", err, out)
	}
	if work.puts.Load() != putsBefore+1 {
		t.Fatalf("work took %d PUTs; want 1", work.puts.Load()-putsBefore)
	}
}

// A push is relay by relay (R11): with both relays passing health and the
// preflight, one takes the PUT and the other fails, by a dropped
// connection or by a 409 with a newer directory; the command names the
// one that failed, channel ls shows each relay's state, and the mend is
// channel push for the failure and channel pull then the edit again for
// the conflict. Nothing claims all or nothing.
func TestAPartialPushIsSaidAndMended(t *testing.T) {
	t.Run("a transport failure", func(t *testing.T) {
		work := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
		personal := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
		alice := onBothRelays(t, "alice", work.url, personal.url)
		alice.run("channel", "create", "plain")
		personal.dropPUT.Store(true)
		out, err := alice.tryRun("channel", "create", "logs", "--no-streams")
		if err == nil || exitOf(t, err) != exitTransport || !strings.Contains(out, "work: directory pushed") ||
			!strings.Contains(out, "personal: could not push the directory") {
			t.Fatalf("the partial push: %v\n%s", err, out)
		}
		if alice.channelsOf().Find("logs") == nil {
			t.Fatal("the local file was not written")
		}
		states := map[string]string{}
		for _, r := range alice.lsJSON().Relays {
			states[r.Name] = r.State
		}
		if states["work"] != "same" || states["personal"] != "older" {
			t.Fatalf("ls after the partial push: %v", states)
		}
		personal.dropPUT.Store(false)
		alice.run("channel", "push", "--relay", "personal")
		for _, r := range alice.lsJSON().Relays {
			if r.State != "same" {
				t.Fatalf("after channel push: %s is %s", r.Name, r.State)
			}
		}
	})

	t.Run("a newer directory on one relay", func(t *testing.T) {
		work := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
		personal := startFrontedRelay(t, relay.Config{Limits: relay.DefaultLimits()})
		alice := onBothRelays(t, "alice", work.url, personal.url)
		alice.run("channel", "create", "plain")
		_, aliceID, _ := alice.opened()
		before := alice.channelsOf()
		// Another machine pushes to personal between the preflight and the
		// push, so personal answers 409 to a push work has already taken.
		// Issued a second ahead, so that it is newer than the edit issued
		// just after; the edit again waits that second out, as a person
		// running the pull and the edit would.
		elsewhere := time.Now().Add(time.Second)
		afterPreflight = func() {
			plant(t, personal.store, aliceID, elsewhere, "default", "plain", "elsewhere")
		}
		t.Cleanup(func() { afterPreflight = func() {} })
		out, err := alice.tryRun("channel", "create", "logs", "--no-streams")
		afterPreflight = func() {}
		if err == nil || exitOf(t, err) != exitTransport || !strings.Contains(out, "work: directory pushed") ||
			!strings.Contains(out, "personal holds a directory issued") {
			t.Fatalf("the conflicting push: %v\n%s", err, out)
		}
		if after := alice.channelsOf(); after.Find("logs") != nil || !after.Issued.Equal(before.Issued) {
			t.Fatal("the local file was written over a newer directory")
		}
		states := map[string]string{}
		for _, r := range alice.lsJSON().Relays {
			states[r.Name] = r.State
		}
		if states["work"] != "newer" || states["personal"] != "newer" {
			t.Fatalf("ls after the conflict: %v", states)
		}
		alice.run("channel", "pull", "--relay", "personal")
		time.Sleep(time.Until(elsewhere) + 10*time.Millisecond)
		alice.run("channel", "create", "logs", "--no-streams")
		for _, r := range alice.lsJSON().Relays {
			if r.State != "same" {
				t.Fatalf("after pull and the edit again: %s is %s", r.Name, r.State)
			}
		}
		if d := alice.channelsOf(); d.Find("elsewhere") == nil || d.Find("logs") == nil {
			t.Fatalf("the mended directory: %+v", d)
		}
	})
}

// A sender refused by a channel's rule sees the relay's sentence with the
// exit a closed channel gives, the outbox left as a closed channel leaves
// it, and the listing for an unknown channel shows each channel's rules.
func TestASenderIsToldAChannelsRule(t *testing.T) {
	alice, bob, workStore := peersAndDirectory(t)
	_, bobID, _ := bob.opened()
	bob.run("channel", "create", "small", "--max-bytes", "2000")
	bob.run("channel", "create", "nostreams", "--no-streams")
	queuedBefore, _ := workStore.MailboxUsage(bobID.Fingerprint())
	refused := func(prefix string, args ...string) {
		t.Helper()
		out, err := alice.tryRun(args...)
		if err == nil || exitOf(t, err) != exitTransport || !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("auu %s: %v\n%s; want exit 2 beginning %q", strings.Join(args, " "), err, out, prefix)
		}
	}
	refused(`channel "small" takes at most 2000 bytes on the wire; this message is `,
		"send", "--to", "bob", "--channel", "small", "--subject", "s", strings.Repeat("x", 3000))
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	refused(`channel "nostreams" takes no streams`,
		"send", "--to", "bob", "--channel", "nostreams", "--subject", "s", "--attach", big, "x")
	if entries, _ := os.ReadDir(filepath.Join(alice.home, "outbox")); len(entries) != 0 {
		t.Fatalf("a stream refused at its open left %d files in the outbox, where a closed channel leaves none", len(entries))
	}
	if queuedAfter, _ := workStore.MailboxUsage(bobID.Fingerprint()); queuedAfter.Messages != queuedBefore.Messages {
		t.Fatal("a refused send queued something")
	}
	// An inline post to the channel that takes no streams is taken.
	alice.run("send", "--to", "bob", "--channel", "nostreams", "--subject", "s", "x")

	out, err := alice.tryRun("send", "--to", "bob", "--channel", "nope", "--subject", "s", "x")
	if err == nil || !strings.Contains(err.Error(), "\n  small (open; ≤ 2000 bytes)") ||
		!strings.Contains(err.Error(), "\n  nostreams (open; no streams)") ||
		!strings.Contains(err.Error(), "\n  default (open)\n") {
		t.Fatalf("the unknown channel's listing: %v\n%s", err, out)
	}
}
