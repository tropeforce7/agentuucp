package auu

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The third adversarial trace, at v0.17.0, on what a message keeps of a
// section this build knows but does not read on the message path:
// recipient-count and max-recipients were registered as known, so a sealed
// message that carried one kept it whole whatever its size, a mebibyte in
// the record and re-read at every listing, where a name nobody registered
// is held to wire.MaxKeptBytes. A section is now known for the paths that
// read it (D76), and on a message one known only for requests and answers
// is held as an unknown one is. Its test is here as the regression test,
// renamed for what it proves, with the trace's inputs as it wrote them.

// The trace's mebibyte max-recipients section on a sealed note is dropped
// and counted by keptSections, not kept; an old record that kept it whole,
// as v0.17 did, still loads and lists it as ignored, while a record holding
// an unregistered name over the kept size is refused at Load by name;
// through a real relay the fetch
// delivers the message with the section dropped and counted, and a
// max-recipients section at the kept size, with a critical recipient-count
// beside it, is delivered, not kept under damaged/ as waiting for a newer
// auu, since Sort asks whether a name is known on any path, and both are
// kept and listed among the ignored sections, which on the message path is
// true (T9).
func TestASectionNotReadOnTheMessagePathIsHeldToTheKeptCap(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	big := wire.Section{Name: recipients.MaxName, Data: json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), 1<<20)) + `"`)}
	body := message.Body{Type: message.TypeNote, Thread: "0123456789abcdef0123456789abcdef", Text: "hi"}
	env, _, err := envelope.SealSections(alice, bob.Public(), "", body, []wire.Section{big})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	inner, _, err := envelope.Open(bob, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	kept, dropped := keptSections(inner.Sections)
	if dropped != 1 || len(kept) != 0 {
		t.Fatalf("kept %d dropped %d; want the %s section of %d bytes dropped and counted", len(kept), dropped, recipients.MaxName, len(big.Data))
	}

	// An old record: v0.16 and v0.17 kept the section whole, and a record
	// any release from v0.15.0 wrote is read by every later one (R13), so
	// one saved by hand as v0.17 would have kept it loads, and lists the
	// section among the ignored ones, which on the message path is true.
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inner.Sections = []wire.Section{big}
	rec := &store.Stored{Relay: "r", Received: time.Now(), Inner: inner}
	if err := s.Save(store.Inbox, rec); err != nil {
		t.Fatal(err)
	}
	back, err := s.Load(store.Inbox, inner.ID)
	if err != nil || len(back.Inner.Sections) != 1 || len(back.Inner.Sections[0].Data) != len(big.Data) {
		t.Fatalf("the old record with a %s section of %d bytes: %+v, %v; want it read as kept", recipients.MaxName, len(big.Data), back, err)
	}
	if ign := toJSON(s, store.Inbox, back, false).IgnoredSections; strings.Join(ign, ",") != recipients.MaxName {
		t.Errorf("the old record's ignored_sections: %q; want [%s]", ign, recipients.MaxName)
	}

	// A record holding a name nobody registered over the kept size was
	// written by no release and is refused at Load by name.
	inner.Sections = []wire.Section{{Name: "nobody-registered", Data: big.Data}}
	if err := s.Save(store.Inbox, rec); err != nil {
		t.Fatal(err)
	}
	_, err = s.Load(store.Inbox, inner.ID)
	if err == nil || !strings.Contains(err.Error(), `the record's section "nobody-registered"`) || !strings.Contains(err.Error(), "over the 16384 kept") {
		t.Fatalf("load: %v; want the record refused naming the section over the kept size", err)
	}

	// At the fetch, through a real relay.
	au, bu, _ := peered(t)
	at := func(n int) json.RawMessage { return json.RawMessage(`"` + strings.Repeat("a", n-2) + `"`) }
	postSections(t, au, bu, "the mebibyte one", []wire.Section{big})
	postSections(t, au, bu, "at the kept size", []wire.Section{
		{Name: recipients.MaxName, Data: at(wire.MaxKeptBytes)},
		{Name: recipients.CountName, Critical: true, Data: json.RawMessage(`3`)},
	})
	in, stderr := fetchJSON(t, bu)
	if in.Fetch.Delivered != 2 || in.Fetch.Unreadable != 0 || in.Fetch.Kept != 0 || len(in.Fetch.Newer) != 0 {
		t.Fatalf("fetch: %+v; want both delivered, nothing kept under damaged/ or left for a newer auu\n%s", in.Fetch, stderr)
	}
	got := map[string]*messageJSON{}
	for i := range in.Messages {
		got[in.Messages[i].Subject] = &in.Messages[i]
	}
	over, under := got["the mebibyte one"], got["at the kept size"]
	if over == nil || over.DroppedSections != 1 || len(over.IgnoredSections) != 0 {
		t.Fatalf("--json for the mebibyte one: %+v; want it dropped and counted, nothing kept", over)
	}
	if under == nil || under.Newer != "" || under.DroppedSections != 0 || strings.Join(under.IgnoredSections, ",") != recipients.MaxName+","+recipients.CountName {
		t.Fatalf("--json for the one at the kept size: %+v; want both kept and listed as ignored", under)
	}
	bs, err := store.Open(bu.home)
	if err != nil {
		t.Fatal(err)
	}
	m, err := bs.Load(store.Inbox, over.ID)
	if err != nil || len(m.Inner.Sections) != 0 || m.DroppedSections != 1 {
		t.Fatalf("the mebibyte one's record: %+v, %v; want no section and one dropped", m, err)
	}
	m, err = bs.Load(store.Inbox, under.ID)
	if err != nil || m.Newer != "" || len(m.Inner.Sections) != 2 || m.Inner.Sections[0].Name != recipients.MaxName || len(m.Inner.Sections[0].Data) != wire.MaxKeptBytes || !m.Inner.Sections[1].Critical || m.DroppedSections != 0 {
		t.Fatalf("the record at the kept size: %+v, %v; want both sections kept, the first at the kept size", m, err)
	}
}
