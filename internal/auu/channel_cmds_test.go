package auu

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
)

// channelsOf reads a user's local directory.
func (u *user) channelsOf() *channels.Directory {
	u.t.Helper()
	s, _, _ := u.opened()
	d, found, err := s.Directory()
	if err != nil {
		u.t.Fatal(err)
	}
	if !found {
		return nil
	}
	return d
}

// lsJSON runs channel ls --json for a user.
func (u *user) lsJSON(args ...string) channelLsJSON {
	u.t.Helper()
	var out channelLsJSON
	if err := json.Unmarshal([]byte(u.run(append([]string{"channel", "ls"}, append(args, "--json")...)...)), &out); err != nil {
		u.t.Fatal(err)
	}
	return out
}

// usageError asserts a command failed as a usage error with the sentence.
func usageError(t *testing.T, u *user, want string, args ...string) {
	t.Helper()
	out, err := u.tryRun(args...)
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage {
		t.Fatalf("auu %s: %v (exit %v), want a usage error\n%s", strings.Join(args, " "), err, exit, out)
	}
	if err.Error() != want {
		t.Fatalf("auu %s:\n%v\nwant\n%s", strings.Join(args, " "), err, want)
	}
}

// The first create writes default beside the new channel, so creating a
// channel never takes the default away; the descriptions are folded; both
// time forms are taken; and the relays and the listing agree.
func TestTheFirstCreateKeepsDefault(t *testing.T) {
	work, personalURL := startRelay(t), startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)
	if out := alice.run("channel", "ls"); !strings.HasPrefix(out, "no directory: your mailbox has the one channel, default\n") ||
		!strings.Contains(out, "work: holds no directory\n") {
		t.Fatalf("ls before any channel:\n%s", out)
	}

	out := alice.run("channel", "create", "bug reports", "--description", "One bug\r\nper message;\tattach\nthe log",
		"--not-before", "2026-10-01", "--not-after", "2026-12-31T23:59:59+10:00")
	if !strings.Contains(out, "work: directory pushed (2 channels)\n") || !strings.Contains(out, "personal: directory pushed (2 channels)\n") {
		t.Fatalf("create:\n%s", out)
	}
	d := alice.channelsOf()
	if d == nil || len(d.Channels) != 2 || d.Channels[0].Name != "default" || d.Channels[1].Name != "bug reports" {
		t.Fatalf("the local directory after the first create: %+v", d)
	}
	bugs := d.Channels[1]
	if bugs.Description != "One bug per message; attach the log" {
		t.Fatalf("the description was not folded: %q", bugs.Description)
	}
	if bugs.NotBefore == nil || !bugs.NotBefore.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local)) ||
		bugs.NotAfter == nil || !bugs.NotAfter.Equal(time.Date(2026, 12, 31, 13, 59, 59, 0, time.UTC)) {
		t.Fatalf("the period: %v to %v", bugs.NotBefore, bugs.NotAfter)
	}
	if d.Issued.IsZero() || d.Owner == "" || d.V != 1 {
		t.Fatalf("the file is not a whole signed directory: %+v", d)
	}

	ls := alice.lsJSON()
	if !ls.Directory || len(ls.Channels) != 2 || ls.Channels[1].Open || ls.Channels[1].Why != "opens "+bugs.NotBefore.UTC().Format(time.RFC3339) ||
		!ls.Channels[0].Open || ls.Channels[0].Why != "" {
		t.Fatalf("ls --json: %+v", ls)
	}
	if len(ls.Relays) != 2 || ls.Relays[0].State != "same" || ls.Relays[1].State != "same" ||
		ls.Relays[0].Queued["default"] != 0 || len(ls.Relays[0].Queued) != 2 {
		t.Fatalf("ls --json relays: %+v", ls.Relays)
	}
	text := alice.run("channel", "ls")
	for _, want := range []string{"NAME", "DESCRIPTION", "PERIOD", "STATE", "QUEUED",
		"bug reports  One bug per message; attach the log  ", "opens " + bugs.NotBefore.Local().Format(time.RFC3339),
		"issued " + d.Issued.Local().Format(time.RFC3339) + " by this machine\n", "work: holds this directory\n", "personal: holds this directory\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("ls lacks %q:\n%s", want, text)
		}
	}

	// A second create adds to what is there.
	alice.run("channel", "create", "cfp", "--description", "talks, until the deadline")
	if d := alice.channelsOf(); len(d.Channels) != 3 || d.Channels[2].Name != "cfp" {
		t.Fatalf("the second create: %+v", d)
	}
}

// Each usage error names the channel, and none of them touches the file or
// the relays.
func TestEveryChannelUsageErrorNamesTheChannel(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	_, id, _ := alice.opened()
	alice.run("channel", "create", "bug reports")
	before, _ := os.ReadFile(alice.channelsPath())
	held, _ := heldBy(t, workStore, id)

	usageError(t, alice, `channel "bug reports" already exists; run 'auu channel update bug reports' to change it`,
		"channel", "create", "bug reports")
	usageError(t, alice, `channel "cfp" is not in your directory; run 'auu channel ls'`, "channel", "update", "cfp", "--description", "x")
	usageError(t, alice, `channel "cfp" is not in your directory; run 'auu channel ls'`, "channel", "close", "cfp")
	usageError(t, alice, `channel "cfp" is not in your directory; run 'auu channel ls'`, "channel", "delete", "cfp")
	usageError(t, alice, `channel "bug/reports": name contains "/"`, "channel", "create", "bug/reports")
	usageError(t, alice, `channel " bugs": name begins with white space`, "channel", "create", " bugs")
	usageError(t, alice, `channel "`+strings.Repeat("b", 65)+`": name is 65 bytes; at most 64`, "channel", "create", strings.Repeat("b", 65))
	usageError(t, alice, "description is 1025 bytes; at most 1024", "channel", "create", "cfp", "--description", strings.Repeat("d", 1025))
	usageError(t, alice, "nothing to change: give --description, --not-before or --not-after", "channel", "update", "bug reports")
	usageError(t, alice, `--not-before wants a time as 2026-10-01T09:00:00+10:00 or a day as 2026-10-01, not "soon"`,
		"channel", "create", "cfp", "--not-before", "soon")
	usageError(t, alice, `channel "bug reports": not_before 2026-12-31T00:00:00Z is after not_after 2026-10-01T00:00:00Z`,
		"channel", "update", "bug reports", "--not-before", "2026-12-31T00:00:00Z", "--not-after", "2026-10-01T00:00:00Z")
	usageError(t, alice, "usage: auu channel create NAME [--description TEXT] [--not-before T] [--not-after T]", "channel", "create")
	usageError(t, alice, "usage: auu channel ls|create|update|close|delete|keep|push|pull", "channel")
	usageError(t, alice, `unknown channel subcommand "list-all"`, "channel", "list-all")
	usageError(t, alice, `--at wants a time; to reopen a channel run 'auu channel update bug reports --not-after none'`,
		"channel", "close", "bug reports", "--at", "none")

	if after, _ := os.ReadFile(alice.channelsPath()); string(after) != string(before) {
		t.Fatal("a usage error changed the local file")
	}
	if now, _ := heldBy(t, workStore, id); !now.Issued.Equal(held.Issued) {
		t.Fatal("a usage error pushed something")
	}
}

func (u *user) channelsPath() string {
	s, _, _ := u.opened()
	return s.ChannelsPath()
}

// close sets not_after to now or to the time given, refuses a time before
// not_before, and the relay refuses a post after it.
func TestCloseSetsNotAfterAndRefusesATimeBeforeNotBefore(t *testing.T) {
	work := startRelay(t)
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	bob.run("peers", "add", alice.exportLine())
	alice.run("peers", "add", bob.exportLine())
	alice.run("channel", "create", "cfp", "--not-before", "2026-10-01T00:00:00Z")

	opens := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	usageError(t, alice, `channel "cfp" opens `+opens.Local().Format(time.RFC3339)+`; it cannot close before that`,
		"channel", "close", "cfp", "--at", "2026-09-30T00:00:00Z")
	if d := alice.channelsOf(); d.Channels[1].NotAfter != nil {
		t.Fatal("a refused close set not_after")
	}

	alice.run("channel", "close", "cfp", "--at", "2026-11-01T00:00:00Z")
	d := alice.channelsOf()
	if d.Channels[1].NotAfter == nil || !d.Channels[1].NotAfter.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("close --at: %v", d.Channels[1].NotAfter)
	}
	// Now, for a channel with no not_before: closed from this second, and
	// a post meets the relay's refusal.
	alice.run("channel", "create", "old", "--description", "was open")
	started := time.Now()
	alice.run("channel", "close", "old")
	d = alice.channelsOf()
	old := d.Find("old")
	if old.NotAfter == nil || old.NotAfter.After(time.Now()) || old.NotAfter.Before(started.Add(-time.Second)) {
		t.Fatalf("close without --at: %v", old.NotAfter)
	}
	ls := bob.lsJSON("alice")
	for _, ch := range ls.Channels {
		if ch.Name == "old" && (ch.Open || !strings.HasPrefix(ch.Why, "closed ")) {
			t.Fatalf("a closed channel listed to a sender as %+v", ch)
		}
	}
	if text := bob.run("channel", "ls", "alice"); !strings.Contains(text, "closed "+old.NotAfter.Local().Format(time.RFC3339)) ||
		strings.Contains(text, "QUEUED") {
		t.Fatalf("the sender's listing:\n%s", text)
	}
}

// delete deletes: the rest stays, default may go, and the last one going
// is warned about.
func TestDeleteLeavesTheRestAndWarnsWhenNoneIsLeft(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	_, id, _ := alice.opened()
	alice.run("channel", "create", "bug reports")
	out := alice.run("channel", "delete", "default")
	if strings.Contains(out, "warning") {
		t.Fatalf("a delete that left a channel warned:\n%s", out)
	}
	d := alice.channelsOf()
	if len(d.Channels) != 1 || d.Channels[0].Name != "bug reports" {
		t.Fatalf("after deleting default: %+v", d)
	}
	if held, _ := heldBy(t, workStore, id); len(held.Channels) != 1 || held.Channels[0].Name != "bug reports" {
		t.Fatalf("the relay after deleting default: %+v", held)
	}
	out = alice.run("channel", "delete", "bug reports")
	if !strings.HasSuffix(out, "warning: your directory is empty, so nobody can post to you\n") {
		t.Fatalf("the last delete:\n%s", out)
	}
	if d := alice.channelsOf(); len(d.Channels) != 0 {
		t.Fatalf("after the last delete: %+v", d)
	}
	if text := alice.run("channel", "ls"); !strings.HasPrefix(text, "your directory is empty, so nobody can post to you; issued ") {
		t.Fatalf("ls of an empty directory:\n%s", text)
	}
}

// A relay that refuses the push — here, because the identity is blocked
// there — leaves the local file written and exits 2 naming it; push
// repairs it once the relay will take it.
func TestARelayRefusalLeavesTheFileWrittenAndExitsTwo(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	personalURL := startRelay(t)
	alice := onBothRelays(t, "alice", work, personalURL)
	_, id, _ := alice.opened()
	if err := workStore.SetBlock(id.Fingerprint(), "testing", strings.Repeat("0", 64), time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := alice.tryRun("channel", "create", "bug reports")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport ||
		err.Error() != alice.channelsPath()+" is written; run 'auu channel push' once the relay above can be reached" {
		t.Fatalf("create with work refusing: %v\n%s", err, out)
	}
	if !strings.Contains(out, "work: could not push the directory: ") || !strings.Contains(out, "personal: directory pushed (2 channels)") {
		t.Fatalf("the report:\n%s", out)
	}
	if d := alice.channelsOf(); d == nil || len(d.Channels) != 2 {
		t.Fatalf("the local file after a refusal: %+v", d)
	}
	// push, once work will take it, catches it up under the same issue.
	if _, err := workStore.Deregister(id.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if err := workStore.Register(id.Fingerprint(), id.Public().Bundle(), "alice", relay.RegisterOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := workStore.RemoveBlock(id.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	out = alice.run("channel", "push")
	if !strings.Contains(out, "work: directory pushed (2 channels)") || !strings.Contains(out, "personal: directory pushed (2 channels)") {
		t.Fatalf("push after:\n%s", out)
	}
	local := alice.channelsOf()
	if held, _ := heldBy(t, workStore, id); !held.Issued.Equal(local.Issued) {
		t.Fatalf("push signed under a fresh issue: relay %v, file %v", held.Issued, local.Issued)
	}
	if text := alice.run("channel", "ls"); !strings.Contains(text, "work: holds this directory\n") {
		t.Fatalf("ls after push:\n%s", text)
	}
}

// ls with a peer: a usage error for somebody not on the list, the sender's
// view without counts for one who is, the one-channel sentence for a peer
// with no directory, and the do-not-trust refusal for a directory the relay
// serves that does not verify.
func TestLsOfAPeerIsReadAgainstTheKeyHeld(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	carol := newUser(t, "carol", work)
	_ = carol

	usageError(t, bob, "no peers yet: add one with 'auu peers add'; a peer's channels are verified against the key you hold for them, so add them with 'auu peers add' first",
		"channel", "ls", "alice")
	bob.run("peers", "add", alice.exportLine())
	if _, err := bob.tryRun("channel", "ls", "carol"); err == nil || !strings.Contains(err.Error(), "so add them with 'auu peers add' first") {
		t.Fatalf("ls of a stranger: %v", err)
	}

	if out := bob.run("channel", "ls", "alice"); out != "alice's mailbox has the one channel, default\n" {
		t.Fatalf("ls of a peer with no directory:\n%s", out)
	}
	if ls := bob.lsJSON("alice"); ls.Directory || ls.Peer != "alice" || len(ls.Channels) != 0 || ls.Relays != nil {
		t.Fatalf("ls --json of a peer with no directory: %+v", ls)
	}

	alice.run("channel", "create", "bug reports", "--description", "One bug per message", "--not-before", "2026-10-01T00:00:00Z")
	out := bob.run("channel", "ls", "alice")
	opens := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Local().Format(time.RFC3339)
	for _, want := range []string{"bug reports  One bug per message  from " + opens + "  opens " + opens + "\n", "issued ", " by alice\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("the sender's view lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "QUEUED") || strings.Contains(out, "holds") {
		t.Fatalf("the sender's view has the owner's lines:\n%s", out)
	}
	ls := bob.lsJSON("alice")
	if ls.Peer != "alice" || !ls.Directory || len(ls.Channels) != 2 || ls.Channels[1].Why != "opens 2026-10-01T00:00:00Z" ||
		ls.Channels[1].Open || ls.Relays != nil {
		t.Fatalf("the sender's --json: %+v", ls)
	}

	// The relay serves a directory for alice signed by somebody else: what
	// a relay would have to store on purpose, since its route refuses it.
	_, aliceID, _ := alice.opened()
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	forged := &channels.Directory{V: 1, Owner: aliceID.Fingerprint(), Issued: time.Now().Add(time.Hour),
		Channels: []channels.Channel{{Name: "send your keys here"}}}
	doc, sig, err := channels.Sign(mallory, forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workStore.SetDirectory(aliceID.Fingerprint(), forged, doc, sig); err != nil {
		t.Fatal(err)
	}
	out, err = bob.tryRun("channel", "ls", "alice")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport ||
		err.Error() != "the directory "+bob.defaultRelayName()+" served for alice does not verify against the key you hold; do not trust it" {
		t.Fatalf("a tampered directory: %v\n%s", err, out)
	}
	if strings.Contains(out, "send your keys") {
		t.Fatalf("the tampered directory was printed:\n%s", out)
	}
	// And the owner's own edit refuses it too.
	if _, err := alice.tryRun("channel", "create", "cfp"); err == nil ||
		err.Error() != "the directory "+alice.defaultRelayName()+" serves for you does not verify against your key; do not trust it" {
		t.Fatalf("the owner's edit against a lying relay: %v", err)
	}
	// The owner's own listing says the relay was reached and is not to be
	// trusted, which is not the same as not reached.
	ownLs := alice.lsJSON()
	if len(ownLs.Relays) != 1 || ownLs.Relays[0].State != "untrusted" || ownLs.Relays[0].Error != "" || ownLs.Relays[0].Issued != nil {
		t.Fatalf("the owner's ls --json against a lying relay: %+v", ownLs.Relays)
	}
	if text := alice.run("channel", "ls"); !strings.Contains(text, alice.defaultRelayName()+
		": the directory it serves for you does not verify against your key; do not trust it\n") ||
		strings.Contains(text, "could not be reached") || strings.Contains(text, "send your keys") {
		t.Fatalf("the owner's ls against a lying relay:\n%s", text)
	}
}

// pull's three outcomes: nothing there, a directory that does not verify,
// and one taken with its issue time — which is what a second machine does
// before its first edit.
func TestPullTakesWhatTheRelayHolds(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	_, id, _ := alice.opened()
	relayName := alice.defaultRelayName()

	usageError(t, alice, "no directory on "+relayName+"; nothing to pull", "channel", "pull")
	if _, err := os.Stat(alice.channelsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pull of nothing wrote a file")
	}

	// The other machine pushed; an edit here refuses in favour of pull.
	issued := time.Date(2026, 9, 13, 1, 19, 29, 250_000_000, time.UTC)
	plant(t, workStore, id, issued, "default", "from the other machine")
	if _, err := alice.tryRun("channel", "create", "cfp"); err == nil ||
		!strings.Contains(err.Error(), "run 'auu channel pull --relay "+relayName+"' to take it first") {
		t.Fatalf("an edit with the relay ahead: %v", err)
	}
	if text := alice.run("channel", "ls"); !strings.Contains(text, relayName+": holds a newer directory, issued "+
		issued.Local().Format(time.RFC3339)+", from another machine of yours; run 'auu channel pull --relay "+relayName+"' to take it\n") {
		t.Fatalf("ls with the relay ahead:\n%s", text)
	}
	out := alice.run("channel", "pull")
	if want := relayName + ": directory pulled (2 channels, issued " + issued.Local().Format(time.RFC3339) + ")\n"; out != want {
		t.Fatalf("pull:\n%s\nwant\n%s", out, want)
	}
	d := alice.channelsOf()
	if d == nil || !d.Issued.Equal(issued) || len(d.Channels) != 2 || d.Channels[1].Name != "from the other machine" || d.Owner != id.Fingerprint() {
		t.Fatalf("the local file after pull: %+v", d)
	}
	if text := alice.run("channel", "ls"); !strings.Contains(text, relayName+": holds this directory\n") {
		t.Fatalf("ls after pull:\n%s", text)
	}
	// And the edit goes through now.
	alice.run("channel", "create", "cfp")
	if held, _ := heldBy(t, workStore, id); len(held.Channels) != 3 || !held.Issued.After(issued) {
		t.Fatalf("the relay after the edit: %+v", held)
	}
	before, _ := os.ReadFile(alice.channelsPath())

	// A directory the relay serves that does not verify under alice's key.
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	forged := &channels.Directory{V: 1, Owner: id.Fingerprint(), Issued: time.Now().Add(time.Hour),
		Channels: []channels.Channel{{Name: "send your keys here"}}}
	doc, sig, err := channels.Sign(mallory, forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workStore.SetDirectory(id.Fingerprint(), forged, doc, sig); err != nil {
		t.Fatal(err)
	}
	out, err = alice.tryRun("channel", "pull")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitTransport ||
		err.Error() != "the directory "+relayName+" serves for you does not verify against your key; do not trust it" {
		t.Fatalf("pull of a tampered directory: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(alice.channelsPath()); string(after) != string(before) {
		t.Fatal("a tampered directory was pulled")
	}
}
