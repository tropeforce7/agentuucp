package auu

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// auu channel keep is this machine's own policy for one channel: what a
// fetch does with the mail afterwards. Nothing is signed, nothing is
// pushed, and no relay is told or even contacted.

// keepPath is where the settings live for a user.
func (u *user) keepPath() string {
	s, _, _ := u.opened()
	return s.ChannelSettingsPath()
}

// keepOf reads a user's setting for a channel, through the store.
func (u *user) keepOf(channel string) bool {
	u.t.Helper()
	s, _, _ := u.opened()
	keep, err := s.KeepOnRelay(channel)
	if err != nil {
		u.t.Fatal(err)
	}
	return keep
}

// A channel with no setting keeps: the default is on, and a home that has
// never run the command has no file at all.
func TestAChannelWithNoSettingKeeps(t *testing.T) {
	alice := newUser(t, "alice", startRelay(t))
	if _, err := os.Stat(alice.keepPath()); !os.IsNotExist(err) {
		t.Fatalf("a home that has set nothing has a settings file: %v", err)
	}
	for _, name := range []string{"default", "", "bugs", "never-heard-of"} {
		if !alice.keepOf(name) {
			t.Fatalf("%q does not keep by default", name)
		}
	}
}

// The command writes the file, says what it did, and the setting is read
// back; the file is the shape the plan gives, mode 0600 as the home's
// other files.
func TestChannelKeepWritesTheSettingAndSaysWhatItDid(t *testing.T) {
	alice := newUser(t, "alice", startRelay(t))
	alice.run("channel", "create", "bugs")

	if out := alice.run("channel", "keep", "bugs", "off"); out != "bugs: mail is removed from the relay once it is fetched\n" {
		t.Fatalf("keep off:\n%s", out)
	}
	if alice.keepOf("bugs") {
		t.Fatal("bugs still keeps after keep off")
	}
	if alice.keepOf("default") != true {
		t.Fatal("keep off for one channel changed another")
	}
	info, err := os.Stat(alice.keepPath())
	if err != nil {
		t.Fatal(err)
	}
	// Go's FileMode on Windows says nothing about who can read a file; the
	// mode is Unix's, and the Windows job reported 666 for the store's.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("the settings file is mode %04o, want 0600", perm)
	}
	raw, err := os.ReadFile(alice.keepPath())
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"v\": 1,\n  \"channels\": {\n    \"bugs\": {\n      \"keep\": false\n    }\n  }\n}\n"
	if string(raw) != want {
		t.Fatalf("the file is:\n%s\nwant\n%s", raw, want)
	}
	// On again, and the other words for each.
	if out := alice.run("channel", "keep", "bugs", "on"); out != "bugs: mail is kept on the relay after it is fetched\n" {
		t.Fatalf("keep on:\n%s", out)
	}
	if !alice.keepOf("bugs") {
		t.Fatal("bugs does not keep after keep on")
	}
	alice.run("channel", "keep", "bugs", "false")
	if alice.keepOf("bugs") {
		t.Fatal("false is not off")
	}
	alice.run("channel", "keep", "bugs", "true")
	if !alice.keepOf("bugs") {
		t.Fatal("true is not on")
	}
	// A channel the directory does not hold: mail queued under a channel
	// since deleted still arrives, so the setting must take a name that
	// is not there.
	alice.run("channel", "keep", "since-deleted", "off")
	if alice.keepOf("since-deleted") {
		t.Fatal("a channel outside the directory took no setting")
	}
}

// The arguments: a name no directory could hold, a word that is neither on
// nor off, and the wrong number of them, each a usage error.
func TestChannelKeepChecksItsArguments(t *testing.T) {
	alice := newUser(t, "alice", startRelay(t))
	usageError(t, alice, `channel "with/a/slash": name contains "/"`,
		"channel", "keep", "with/a/slash", "on")
	usageError(t, alice, `channel "": name is empty`, "channel", "keep", "", "on")
	for _, args := range [][]string{
		{"channel", "keep"},
		{"channel", "keep", "bugs"},
		{"channel", "keep", "bugs", "maybe"},
		{"channel", "keep", "bugs", "on", "off"},
	} {
		usageError(t, alice, "usage: auu channel keep NAME on|off", args...)
	}
	if _, err := os.Stat(alice.keepPath()); !os.IsNotExist(err) {
		t.Fatal("a refused command wrote the settings file")
	}
}

// A settings file that will not read is damaged: exit 5, naming itself and
// what to do, as the channels file does. Nothing guesses at it, because a
// guess would acknowledge away mail the owner meant to keep.
func TestADamagedSettingsFileIsExit5(t *testing.T) {
	alice := newUser(t, "alice", startRelay(t))
	alice.run("channel", "create", "bugs")
	advice := "fix it, or delete it and set the channels again with 'auu channel keep NAME on|off'; " +
		"every channel keeps its mail on the relay until then"
	for _, tc := range []struct {
		what, content, want string
	}{
		{"not JSON", "{", alice.keepPath() + " is not valid JSON"},
		{"a version nobody has", `{"v":2,"channels":{}}`, alice.keepPath() + " is version 2, which this build does not know: " + advice},
		{"a name no directory could hold", `{"v":1,"channels":{"with/a/slash":{"keep":false}}}`,
			alice.keepPath() + ` names a channel "with/a/slash" that no directory could hold`},
	} {
		if err := os.WriteFile(alice.keepPath(), []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := alice.tryRun("channel", "ls")
		var exit *exitError
		if !asExit(err, &exit) || exit.code != exitDamaged || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want exit %d and %q", tc.what, err, exitDamaged, tc.want)
		}
	}
	if err := os.Remove(alice.keepPath()); err != nil {
		t.Fatal(err)
	}
	alice.run("channel", "ls")
}

// The owner's listing carries the setting: a KEEP column after QUEUED and
// a keep field per channel in the JSON. A peer's listing carries neither,
// since it is this machine's business and not the sender's.
func TestChannelLsShowsKeepForTheOwnerAndNotForAPeer(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("channel", "create", "bugs", "--description", "one per message")
	bob.run("channel", "keep", "bugs", "off")

	text := bob.run("channel", "ls")
	if !strings.Contains(text, "NAME") || !strings.Contains(text, "QUEUED") || !strings.Contains(text, "KEEP") {
		t.Fatalf("the owner's table has no KEEP column:\n%s", text)
	}
	for _, want := range []string{"default", "bugs"} {
		line := lineWith(t, text, want)
		fields := strings.Fields(line)
		got := fields[len(fields)-1]
		if (want == "bugs") != (got == "off") {
			t.Fatalf("the %s line says keep %q:\n%s", want, got, text)
		}
	}
	ls := bob.lsJSON()
	if len(ls.Channels) != 2 {
		t.Fatalf("channels: %+v", ls.Channels)
	}
	for _, ch := range ls.Channels {
		if ch.Keep == nil {
			t.Fatalf("%s carries no keep field: %+v", ch.Name, ch)
		}
		if (ch.Name == "bugs") == *ch.Keep {
			t.Fatalf("%s says keep %v", ch.Name, *ch.Keep)
		}
	}
	// A peer's listing: no column, no field.
	text = alice.run("channel", "ls", "bob")
	if strings.Contains(text, "KEEP") {
		t.Fatalf("a peer's table has a KEEP column:\n%s", text)
	}
	raw := alice.run("channel", "ls", "bob", "--json")
	if strings.Contains(raw, "keep") {
		t.Fatalf("a peer's JSON carries keep:\n%s", raw)
	}
	var peer channelLsJSON
	if err := json.Unmarshal([]byte(raw), &peer); err != nil {
		t.Fatal(err)
	}
	for _, ch := range peer.Channels {
		if ch.Keep != nil {
			t.Fatalf("a peer's channel carries keep: %+v", ch)
		}
	}
}

// channel pull takes the directory a relay holds and leaves the settings
// alone: they are not in the signed document and never travel.
func TestPullLeavesTheSettingsAlone(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	_, id, _ := alice.opened()
	alice.run("channel", "keep", "bugs", "off")
	before, err := os.ReadFile(alice.keepPath())
	if err != nil {
		t.Fatal(err)
	}
	plant(t, workStore, id, time.Date(2026, 9, 15, 1, 19, 29, 250_000_000, time.UTC), "default", "bugs")
	alice.run("channel", "pull")
	after, err := os.ReadFile(alice.keepPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("pull rewrote the settings:\n%s\nwas\n%s", after, before)
	}
	if alice.keepOf("bugs") {
		t.Fatal("pull changed the setting")
	}
	// The pulled directory is the relay's, so the two files are
	// independent: one names channels, the other what this machine does
	// with their mail.
	if d := alice.channelsOf(); d == nil || len(d.Channels) != 2 {
		t.Fatalf("the directory after pull: %+v", d)
	}
}

// lineWith is the one line of a table holding the word.
func lineWith(t *testing.T, text, word string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, word+" ") || line == word {
			return line
		}
	}
	t.Fatalf("no line for %q in:\n%s", word, text)
	return ""
}
