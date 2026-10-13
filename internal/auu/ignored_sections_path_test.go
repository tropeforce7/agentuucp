package auu

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// S49: a message's own sections were sorted by envelope.Open on the
// message's path, so a non-critical one whose name is known only on a
// manifest was ignored there, and `auu read --json` lists it under
// ignored_sections; it asked whether the name was known on the message's
// path or the manifest's and left it out. A name known on the message's
// path is read there and is not listed.
func TestASectionKnownOnlyOnAManifestIsListedAsIgnoredOnAMessage(t *testing.T) {
	const manifestOnly, messageOnly = "s49-manifest-only", "s49-message-only"
	t.Cleanup(wire.Register(manifestOnly, wire.OnManifest))
	t.Cleanup(wire.Register(messageOnly, wire.OnMessage))
	alice, bob, _ := peered(t)
	postSections(t, alice, bob, "known on a manifest", []wire.Section{
		{Name: manifestOnly, Data: json.RawMessage(`{"n":1}`)},
	})
	postSections(t, alice, bob, "known on a message", []wire.Section{
		{Name: messageOnly, Data: json.RawMessage(`{"n":1}`)},
	})
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Delivered != 2 || in.Fetch.Unreadable != 0 || in.Fetch.Kept != 0 || len(in.Fetch.Newer) != 0 {
		t.Fatalf("fetch: %+v; want both delivered\n%s", in.Fetch, stderr)
	}
	ids := map[string]string{}
	for _, m := range in.Messages {
		ids[m.Subject] = m.ID
	}
	read := func(subject string) messageJSON {
		t.Helper()
		id, ok := ids[subject]
		if !ok {
			t.Fatalf("no message %q in %+v", subject, in.Messages)
		}
		var m messageJSON
		if err := json.Unmarshal([]byte(bob.run("read", id, "--json")), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := read("known on a manifest"); !slices.Equal(m.IgnoredSections, []string{manifestOnly}) {
		t.Errorf("read --json, a section known only on a manifest: ignored_sections %q; want [%s]",
			m.IgnoredSections, manifestOnly)
	}
	if m := read("known on a message"); slices.Contains(m.IgnoredSections, messageOnly) {
		t.Errorf("read --json, a section known on a message: ignored_sections %q; want it not listed",
			m.IgnoredSections)
	}
}

// S49 for a stream: a streamed record's sections are its manifest's, which
// innerFromManifest took after stream.OpenManifest sorted them on the
// manifest's path, so `auu read --json` lists as ignored a name known only
// on a message and leaves out one known on a manifest. The record is
// asserted to be a stream so the test cannot pass on the message's path.
func TestAStreamsSectionsAreListedAsIgnoredOnTheManifestsPath(t *testing.T) {
	const manifestOnly, messageOnly = "s49s-manifest-only", "s49s-message-only"
	t.Cleanup(wire.Register(manifestOnly, wire.OnManifest))
	t.Cleanup(wire.Register(messageOnly, wire.OnMessage))
	alice, bob, _ := peered(t)
	const subject = "a stream with two sections"
	streamSections(t, alice, bob, subject, []wire.Section{
		{Name: manifestOnly, Data: json.RawMessage(`{"n":1}`)},
		{Name: messageOnly, Data: json.RawMessage(`{"n":1}`)},
	})
	in, stderr := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 || in.Fetch.Unreadable != 0 || in.Fetch.Kept != 0 || len(in.Fetch.Newer) != 0 {
		t.Fatalf("fetch: %+v; want the stream delivered\n%s", in.Fetch, stderr)
	}
	rec := recordOf(t, bob, store.Inbox, subject)
	if !rec.Streamed {
		t.Fatalf("the record of %q is not a stream; the test would read it on the message's path", subject)
	}
	var id string
	for _, l := range in.Messages {
		if l.Subject == subject {
			id = l.ID
		}
	}
	if id == "" {
		t.Fatalf("no message %q in %+v", subject, in.Messages)
	}
	var m messageJSON
	if err := json.Unmarshal([]byte(bob.run("read", id, "--json")), &m); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.IgnoredSections, []string{messageOnly}) {
		t.Errorf("read --json, a stream: ignored_sections %q; want [%s], and %s not listed",
			m.IgnoredSections, messageOnly, manifestOnly)
	}
}
