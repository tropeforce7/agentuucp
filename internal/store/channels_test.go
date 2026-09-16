package store

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
)

// channels.json is read through the damaged-file path: a home with none has
// the one channel, default; one whose file will not read, or reads to a
// directory no relay would take, is said to be, by name, and exits 5.
func TestTheChannelsFileIsReadThroughTheDamagedPath(t *testing.T) {
	s := newStore(t)
	id, err := identity.Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	if d, found, err := s.Directory(); err != nil || found || d != nil {
		t.Fatalf("a home with no file: %+v %v %v", d, found, err)
	}

	opens := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	want := &channels.Directory{V: 1, Owner: id.Fingerprint(), Issued: time.Date(2026, 9, 13, 1, 19, 29, 123456789, time.UTC),
		Channels: []channels.Channel{{Name: "default"}, {Name: "bugs", Description: "one per message", NotBefore: &opens}}}
	if err := s.SetDirectory(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Directory()
	if err != nil || !found {
		t.Fatalf("after writing: %v %v", found, err)
	}
	if got.Owner != want.Owner || !got.Issued.Equal(want.Issued) || len(got.Channels) != 2 ||
		got.Channels[1].Description != "one per message" || !got.Channels[1].NotBefore.Equal(opens) {
		t.Fatalf("the directory did not survive the file: %+v", got)
	}
	// issued is in the file, to the nanosecond, since push signs under it
	// and ls compares it.
	raw, _ := os.ReadFile(s.ChannelsPath())
	if !strings.Contains(string(raw), `"issued": "2026-09-13T01:19:29.123456789Z"`) {
		t.Fatalf("the file does not hold issued as signed:\n%s", raw)
	}
	// Go's FileMode on Windows says nothing about who can read a file; the
	// mode is Unix's, and the Windows job reported 666.
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(s.ChannelsPath()); info.Mode().Perm() != fileMode {
			t.Fatalf("the file is %o, want %o", info.Mode().Perm(), fileMode)
		}
	}

	// A directory that breaks a rule is not written.
	bad := *want
	bad.Channels = append(bad.Channels, channels.Channel{Name: "bug/reports"})
	if err := s.SetDirectory(&bad); err == nil || !strings.Contains(err.Error(), `channel "bug/reports": name contains "/"`) {
		t.Fatalf("an invalid directory was written, or refused without the rule: %v", err)
	}
	if got, _, _ := s.Directory(); len(got.Channels) != 2 {
		t.Fatal("the refused write changed the file")
	}

	// A file that is not JSON.
	if err := os.WriteFile(s.ChannelsPath(), []byte("{not json"), fileMode); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Directory()
	if !errors.Is(err, ErrDamaged) {
		t.Fatalf("a file that is not JSON: %v, want ErrDamaged", err)
	}
	if !strings.HasPrefix(err.Error(), s.ChannelsPath()+" is not valid JSON (") ||
		!strings.Contains(err.Error(), "fix it, or delete it and define your channels again with 'auu channel create NAME'") {
		t.Fatalf("the sentence: %v", err)
	}
	// A file that is JSON and breaks a rule: hand-edited.
	if err := os.WriteFile(s.ChannelsPath(), []byte(`{"v":1,"owner":"`+id.Fingerprint()+`","issued":"2026-09-13T01:19:29Z","channels":[{"name":" bugs","description":""}]}`), fileMode); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Directory()
	if !errors.Is(err, ErrDamaged) {
		t.Fatalf("a file that breaks a rule: %v, want ErrDamaged", err)
	}
	if want := s.ChannelsPath() + ` holds a directory no relay would take (channel " bugs": name begins with white space): fix it`; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("the sentence:\n%v\nwant a prefix of\n%s", err, want)
	}
}
