package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// aSigner is a fingerprint, as a record's signer and a left-behind entry's
// are.
const aSigner = "4c1d0000000000000000000000000000000000000000000000000000000000aa"

// TestLimitStoredRelayID: a message record's relay id is the relay's
// number for it, never negative; Load refuses a record that says otherwise
// before anything orders by it, and zero and the type's maximum load.
func TestLimitStoredRelayID(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	m := stored("00000000000000000000000000000001", now)
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	path := s.msgPath(Inbox, m.Inner.ID)
	write := func(t *testing.T, id int64) {
		t.Helper()
		m.RelayID = id
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []int64{-1, math.MinInt64} {
		write(t, id)
		_, err := s.Load(Inbox, m.Inner.ID)
		if err == nil || !strings.Contains(err.Error(), "relay id "+strconv.FormatInt(id, 10)+" is negative") {
			t.Errorf("relay id %d: %v; want the refusal naming it", id, err)
		}
	}
	for _, id := range []int64{0, 1, math.MaxInt64} {
		write(t, id)
		got, err := s.Load(Inbox, m.Inner.ID)
		if err != nil || got.RelayID != id {
			t.Errorf("relay id %d: %v (got %d)", id, err, got.RelayID)
		}
	}
}

// TestLimitStoredRelaySize: a message record's relay size is the size the
// relay listed it at, never negative; Load refuses a record that says
// otherwise, and zero, a record from before it was kept, one and the
// type's maximum load.
func TestLimitStoredRelaySize(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	m := stored("00000000000000000000000000000001", now)
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	path := s.msgPath(Inbox, m.Inner.ID)
	write := func(t *testing.T, size int64) {
		t.Helper()
		m.RelaySize = size
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int64{-1, math.MinInt64} {
		write(t, size)
		_, err := s.Load(Inbox, m.Inner.ID)
		if err == nil || !strings.Contains(err.Error(), "relay size "+strconv.FormatInt(size, 10)+" is negative") {
			t.Errorf("relay size %d: %v; want the refusal naming it", size, err)
		}
	}
	for _, size := range []int64{0, 1, math.MaxInt64} {
		write(t, size)
		got, err := s.Load(Inbox, m.Inner.ID)
		if err != nil || got.RelaySize != size {
			t.Errorf("relay size %d: %v (got %d)", size, err, got.RelaySize)
		}
	}
}

// TestLimitDamagedRelayID: a damaged message is kept under the relay's
// number for it, and a negative number is refused before it becomes a
// file name; zero and the type's maximum are file names.
func TestLimitDamagedRelayID(t *testing.T) {
	s := newStore(t)
	for _, id := range []int64{-1, math.MinInt64} {
		if _, err := s.DamagedPath("work", id); err == nil || !strings.Contains(err.Error(), "is negative") {
			t.Errorf("DamagedPath with id %d: %v; want the refusal", id, err)
		}
		kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: id, Relay: "work", Received: time.Now(), Cause: "review"}, []byte("bytes"))
		if err == nil || kept {
			t.Errorf("KeepDamaged with id %d: kept=%v err=%v; want the refusal", id, kept, err)
		}
		if entries, _ := os.ReadDir(s.path(damagedDir, "work")); len(entries) != 0 {
			t.Errorf("KeepDamaged with id %d wrote %d files", id, len(entries))
		}
	}
	for _, id := range []int64{0, math.MaxInt64} {
		bin, err := s.DamagedPath("work", id)
		if err != nil || filepath.Base(bin) != strconv.FormatInt(id, 10)+".bin" {
			t.Errorf("DamagedPath with id %d: %q, %v", id, bin, err)
		}
		if kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: id, Relay: "work", Received: time.Now(), Cause: "review"}, []byte("bytes")); err != nil || !kept {
			t.Errorf("KeepDamaged with id %d: kept=%v err=%v", id, kept, err)
		}
	}
}

// TestLimitChannelSettingsV: the channel settings file's v is 1, and
// every other value is a damaged file naming the version, the type's
// extremes among them.
func TestLimitChannelSettingsV(t *testing.T) {
	s := newStore(t)
	path := s.path(channelSettingsFile)
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		if err := os.WriteFile(path, []byte(`{"v":`+strconv.Itoa(v)+`,"channels":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.ChannelSettings()
		if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "is version "+strconv.Itoa(v)+", which this build does not know") {
			t.Errorf("v %d: %v; want ErrDamaged naming the version", v, err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"v":1,"channels":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChannelSettings(); err != nil {
		t.Errorf("v 1: %v", err)
	}
}

// TestLimitLeftBehindIDs: each line of the left-behind file holds a relay
// id, positive, and a size, zero or more. The relay id at zero, a negative,
// the type's minimum, the text one past the type's maximum, a digit outside
// ASCII and a hex form are each a damaged file naming the line, and so is
// the size at a negative, the minimum and one past the maximum; one and the
// type's maximum are relay ids, zero and the maximum are sizes. A leading
// sign is what ParseInt takes.
func TestLimitLeftBehindIDs(t *testing.T) {
	s := newStore(t)
	const name = "work"
	id := strings.Repeat("a", 32)
	if err := s.AddLeftBehind(name, LeftEntry{RelayID: 1, ID: id}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.relayDir(name), leftBehindFile)
	line := func(relayID, size string) string {
		return relayID + " " + id + " 2026-10-01T02:03:04Z " + size + " -\n"
	}
	for _, text := range []string{
		line("0", "1"), line("-1", "1"), line("-0", "1"), line(strconv.FormatInt(math.MinInt64, 10), "1"),
		line("9223372036854775808", "1"), line("\u0661", "1"), line("0x10", "1"),
		line("1", "-1"), line("1", strconv.FormatInt(math.MinInt64, 10)), line("1", "9223372036854775808"),
	} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.LeftBehind(name)
		if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "which is not a message left on the relay") {
			t.Errorf("%q: %v; want ErrDamaged", text, err)
		}
	}
	// A line that is one field is the old shape when it is a relay id
	// above zero, said by name, and a damaged line otherwise: the number
	// picks the sentence and is used for nothing else.
	for _, tc := range []struct{ text, want string }{
		{"7\n", "has a relay id alone on line 1"},
		{strconv.FormatInt(math.MaxInt64, 10) + "\n", "has a relay id alone on line 1"},
		{"0\n", "which is not a message left on the relay"},
		{"-1\n", "which is not a message left on the relay"},
		{"9223372036854775808\n", "which is not a message left on the relay"},
	} {
		if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.LeftBehind(name); !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v; want %q", tc.text, err, tc.want)
		}
	}
	for _, tc := range []struct {
		relayID, size    string
		wantID, wantSize int64
	}{{"1", "0", 1, 0}, {"+1", "+5", 1, 5}, {"9223372036854775807", "9223372036854775807", math.MaxInt64, math.MaxInt64}} {
		if err := os.WriteFile(path, []byte(line(tc.relayID, tc.size)), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := s.LeftBehind(name)
		if err != nil || len(got) != 1 || got[0].RelayID != tc.wantID || got[0].Size != tc.wantSize {
			t.Errorf("%s %s: %v %v; want %d %d", tc.relayID, tc.size, got, err, tc.wantID, tc.wantSize)
		}
	}
}

// TestLimitCursor: the cursor file holds the last relay message id
// delivered, never negative: a negative, the type's minimum, the text one
// past the type's maximum, a sign inside the digits and a digit outside
// ASCII are each a damaged file; zero, a plus sign, and the type's maximum
// are cursors.
func TestLimitCursor(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://relay.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	path := s.relayPath(r, cursorFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"-1", strconv.FormatInt(math.MinInt64, 10), "9223372036854775808", "1-2", "\u0661", ""} {
		if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.CursorFor(r)
		if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "is not a message id") {
			t.Errorf("%q: %v; want ErrDamaged", text, err)
		}
	}
	for _, tc := range []struct {
		text string
		want int64
	}{{"0", 0}, {"-0", 0}, {"+1", 1}, {" 7 ", 7}, {"9223372036854775807", math.MaxInt64}} {
		if err := os.WriteFile(path, []byte(tc.text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		n, err := s.CursorFor(r)
		if err != nil || n != tc.want {
			t.Errorf("%q: %d %v; want %d", tc.text, n, err, tc.want)
		}
	}
}

// TestLimitStoredRecordShapes: a message record read back is held at Load
// to the shapes a print slices and the words a print shows: its id, its
// thread and its reply are message ids, its from and to are fingerprints,
// its relay is a relay name, each attachment's digest is 64 hex
// characters; its type is one the rule knows, its subject one line of
// text, its text lines of text, each attachment's name any text, its
// media type not empty. Each one character short, or with the one rune
// the rule refuses, is refused naming what it is; a record that names no
// relay is refused as a record from before v0.11.0; and the record as
// written loads.
func TestLimitStoredRecordShapes(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	id := strings.Repeat("1", 32)
	write := func(t *testing.T, mutate func(m *Stored)) error {
		t.Helper()
		m := stored(id, now)
		m.Inner.Body.InReplyTo = strings.Repeat("2", 32)
		m.Inner.Body.Attachments = []message.Attachment{{Name: "a.txt", Media: "text/plain", Size: 1, SHA256: strings.Repeat("0", 64), Data: []byte("x")}}
		mutate(m)
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(s.msgPath(Inbox, id)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(Inbox, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = s.Load(Inbox, id)
		return err
	}
	for _, tc := range []struct {
		name   string
		mutate func(m *Stored)
		says   string
	}{
		{"id one short", func(m *Stored) { m.Inner.ID = id[:31] }, "the record's message id"},
		{"from one short", func(m *Stored) { m.Inner.From = m.Inner.From[:63] }, "from or to is not a fingerprint"},
		{"to one short", func(m *Stored) { m.Inner.To = m.Inner.To[:63] }, "from or to is not a fingerprint"},
		{"thread one short", func(m *Stored) { m.Inner.Body.Thread = m.Inner.Body.Thread[:31] }, "thread is not a message id"},
		{"reply one short", func(m *Stored) { m.Inner.Body.InReplyTo = m.Inner.Body.InReplyTo[:31] }, "in_reply_to is not a message id"},
		{"digest one short", func(m *Stored) { m.Inner.Body.Attachments[0].SHA256 = strings.Repeat("0", 63) }, "digest is 63 characters, not 64"},
		{"digest not lowercase hex", func(m *Stored) { m.Inner.Body.Attachments[0].SHA256 = strings.Repeat("G", 64) }, "digest is not lowercase hex"},
		{"size negative", func(m *Stored) { m.Inner.Body.Attachments[0].Size = -1 }, "size -1 is negative"},
		{"no relay", func(m *Stored) { m.Relay = "" }, "the record names no relay, which is how a record from before v0.11.0 was written; delete the file"},
		{"relay not a name", func(m *Stored) { m.Relay = "../x" }, `the record's relay: relay name "../x"`},
		{"type unknown", func(m *Stored) { m.Inner.Body.Type = "asks" }, `unknown type "asks"`},
		{"subject with an escape", func(m *Stored) { m.Inner.Body.Subject = "a\x1bb" }, "subject contains U+001B"},
		{"subject of two lines", func(m *Stored) { m.Inner.Body.Subject = "a\nb" }, "subject contains U+000A"},
		{"text with a carriage return", func(m *Stored) { m.Inner.Body.Text = "a\rb" }, "text contains U+000D"},
		{"text with a bidi override", func(m *Stored) { m.Inner.Body.Text = "a\u202eb" }, "text contains U+202E"},
		{"name of two lines", func(m *Stored) { m.Inner.Body.Attachments[0].Name = "a\nb" }, "name is more than one line"},
		{"name with a NUL", func(m *Stored) { m.Inner.Body.Attachments[0].Name = "a\x00b" }, "name contains a null byte"},
		{"media empty", func(m *Stored) { m.Inner.Body.Attachments[0].Media = "" }, "empty media type"},
		{"a vouch on another type", func(m *Stored) { m.Inner.Body.Vouch = &message.Carried{} }, "vouch is a vouch message's alone"},
		{"an about on another type", func(m *Stored) { m.Inner.Body.About = strings.Repeat("a", 64) }, "about is a vouch question's alone"},
		{"vouches on another type", func(m *Stored) { m.Inner.Body.Vouches = []message.Carried{{}} }, "vouches are a knock's alone"},
		{"a list that does not name the record's to", func(m *Stored) {
			m.Inner.Sections = []wire.Section{recipientsList(t, m.Inner.From, strings.Repeat("e", 64))}
		}, "does not name " + strings.Repeat("b", 16)},
		{"a list that names nobody", func(m *Stored) {
			m.Inner.Sections = []wire.Section{{Name: recipients.Name, Data: json.RawMessage(`{"to":[]}`)}}
		}, "recipients section is malformed: it names nobody"},
		{"a list with a fingerprint one short", func(m *Stored) {
			m.Inner.Sections = []wire.Section{{Name: recipients.Name,
				Data: json.RawMessage(`{"to":["` + m.Inner.To + `","` + strings.Repeat("e", 63) + `"]}`)}}
		}, "entry 2 is not a fingerprint"},
		{"a list on a knock", func(m *Stored) {
			m.Inner.Body = message.Body{Type: message.TypeKnock, Thread: m.Inner.Body.Thread, Name: "alice", Text: "hello"}
			m.Inner.Sections = []wire.Section{recipientsList(t, m.Inner.To, m.Inner.From)}
		}, "one envelope to one person"},
	} {
		err := write(t, tc.mutate)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.says)
		}
	}
	// The list's refusal reads as one sentence: the rule's words after where
	// they were found, never joined to the record's possessive (ruling 77).
	if err := write(t, func(m *Stored) {
		m.Inner.Sections = []wire.Section{{Name: recipients.Name, Data: json.RawMessage(`{"to":[]}`)}}
	}); err == nil || !strings.Contains(err.Error(), "in the record, the recipients section is malformed: it names nobody") ||
		strings.Contains(err.Error(), "record's the") {
		t.Errorf("a list that names nobody: %v; want the rule's sentence after \"in the record,\"", err)
	}
	// A text keeps its lines and its tab; an attachment's name is held to
	// what any text is, and no further: what it would do as a path is
	// SafeName's at the write, and the terminal escapes it.
	if err := write(t, func(m *Stored) { m.Inner.Body.Text = "one\n\ttwo" }); err != nil {
		t.Errorf("a record whose text has a line break and a tab: %v; want it loaded", err)
	}
	for _, name := range []string{"CON", "a/b", "a<b>.txt", "", "a\x1bb"} {
		if err := write(t, func(m *Stored) { m.Inner.Body.Attachments[0].Name = name }); err != nil {
			t.Errorf("a record with an attachment named %q: %v; want it loaded", name, err)
		}
	}
	if err := write(t, func(m *Stored) {}); err != nil {
		t.Errorf("the record as written: %v", err)
	}
	// Arrived: a record v0.15.0 to v0.17.0 wrote has no arrived key and
	// reads its received as its arrival; one that has the key keeps it.
	{
		m := stored(id, now)
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			t.Fatal(err)
		}
		delete(keys, "arrived")
		if data, err = json.Marshal(keys); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(Inbox, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Load(Inbox, id); err != nil {
			t.Errorf("a record with no arrived key: %v", err)
		} else if !got.Arrived.Equal(now) {
			t.Errorf("a record with no arrived key reads arrived %v; want its received, %v", got.Arrived, now)
		}
	}
	arrived := now.Add(-time.Hour)
	if err := write(t, func(m *Stored) { m.Arrived = arrived }); err != nil {
		t.Errorf("a record with an arrival: %v", err)
	} else if got, err := s.Load(Inbox, id); err != nil {
		t.Errorf("a record with an arrival: %v", err)
	} else if !got.Arrived.Equal(arrived) || !got.Received.Equal(now) {
		t.Errorf("a record with an arrival reads arrived %v, received %v; want %v and %v", got.Arrived, got.Received, arrived, now)
	}
	// A message to several keeps its list, which names the record's to.
	if err := write(t, func(m *Stored) {
		m.Inner.Sections = []wire.Section{recipientsList(t, m.Inner.From, m.Inner.To)}
	}); err != nil {
		t.Errorf("a record whose list names its to: %v; want it loaded", err)
	}

	// A sent message to several keeps its copies, one per recipient the
	// list names, each held to what the sender writes: only in sent/, a
	// fingerprint the list names, a name that is a name, a path that is an
	// address, a relay id that is not negative, and a kept refusal a line
	// of at most relayapi.MaxSaid with a code that is a name.
	from, to := strings.Repeat("a", 64), strings.Repeat("b", 64)
	sentCopies := func() []SentCopy {
		return []SentCopy{{Fingerprint: to, Name: "bob", RelayID: 7}, {Fingerprint: from, Name: "alice"}}
	}
	writeSent := func(t *testing.T, box Box, mutate func(m *Stored)) error {
		t.Helper()
		m := stored(id, now)
		m.Inner.Sections = []wire.Section{recipientsList(t, to, from)}
		m.Copies = sentCopies()
		mutate(m)
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(s.msgPath(box, id)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(box, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = s.Load(box, id)
		return err
	}
	for _, tc := range []struct {
		name   string
		box    Box
		mutate func(m *Stored)
		says   string
	}{
		{"copies on a received message", Inbox, func(m *Stored) {}, "only a sent message has copies"},
		{"a copy for nobody the list names", Sent, func(m *Stored) { m.Copies[1].Fingerprint = strings.Repeat("c", 64) }, "copy 2 is not for a recipient the message names"},
		{"a copy one short", Sent, func(m *Stored) { m.Copies[1].Fingerprint = from[:63] }, "copy 2 is not for a recipient"},
		{"a copy twice", Sent, func(m *Stored) { m.Copies[1] = m.Copies[0] }, "copy 2 is not for a recipient"},
		{"a copy too few", Sent, func(m *Stored) { m.Copies = m.Copies[:1] }, "1 copies for a message to 2"},
		{"copies with no list", Sent, func(m *Stored) { m.Inner.Sections = nil }, "2 copies for a message to 0"},
		{"a name that is not a name", Sent, func(m *Stored) { m.Copies[0].Name = "b\x1bob" }, "copy 1's name is not a name"},
		{"a path that is not an address", Sent, func(m *Stored) { m.Copies[0].Path = "bar!!baz" }, "copy 1's path is not an address"},
		{"a relay id below zero", Sent, func(m *Stored) { m.Copies[0].RelayID = -1 }, "copy 1's relay id -1 is negative"},
		{"a relay id at the type's minimum", Sent, func(m *Stored) { m.Copies[0].RelayID = math.MinInt64 }, "is negative"},
		{"a copy given up and placed both", Sent, func(m *Stored) { m.Copies[0].Dropped = true }, "copy 1 is given up and placed both"},
		{"a code that is not a name", Sent, func(m *Stored) { m.Copies[1].RefusedCode = "Not A Code" }, "copy 2's refusal code is not a name"},
		{"a refusal of two lines", Sent, func(m *Stored) { m.Copies[1].Refused = "one\ntwo" }, "copy 2's refusal is not one line"},
		{"a refusal one byte over", Sent, func(m *Stored) { m.Copies[1].Refused = strings.Repeat("a", relayapi.MaxSaid+1) }, "copy 2's refusal is not one line"},
	} {
		if err := writeSent(t, tc.box, tc.mutate); err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.says)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(m *Stored)
	}{
		{"as written", func(m *Stored) {}},
		{"by a path, refused at the edge, at the type's maximum", func(m *Stored) {
			m.Copies[0].Path = "bar!baz"
			m.Copies[0].RelayID = math.MaxInt64
			m.Copies[1].RefusedCode = relayapi.CodeMailboxFull
			m.Copies[1].Refused = strings.Repeat("a", relayapi.MaxSaid)
		}},
	} {
		if err := writeSent(t, Sent, tc.mutate); err != nil {
			t.Errorf("%s: %v; want it loaded", tc.name, err)
		}
	}
	os.Remove(s.msgPath(Inbox, id))
	// The relay's key is always written, even for the zero value, since
	// Load requires it: a record with none is from before, not a record
	// with the default.
	data, err := json.Marshal(&Stored{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"relay":""`)) {
		t.Errorf("the zero record marshals without its relay key: %s", data)
	}
	// The home's files beside the record are read strictly too (R24), and
	// each has its shape here: strictFileShapes, in strictread_test.go.
	t.Run("the home's files read strictly", strictFileShapes)
	// And so is the record itself (R24a): strictRecordShapes, in
	// loadstrict_test.go.
	t.Run("a record read strictly", strictRecordShapes)
}

// TestLimitRelayRecordHashes: a relay record's two hashes, the pinned
// anchor's and the last signing intermediate's, are 64 hex characters or
// absent, held at readRelay before a print slices sixteen; one character
// short is a damaged file naming the hash.
func TestLimitRelayRecordHashes(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://relay.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"trust_anchor_spki", "server_int_spki"} {
		for _, v := range []string{strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64)} {
			r.TrustAnchorSPKI, r.ServerIntSPKI = "", ""
			if key == "trust_anchor_spki" {
				r.TrustAnchorSPKI = v
			} else {
				r.ServerIntSPKI = v
			}
			if err := s.SaveRelay(r); err != nil {
				t.Fatal(err)
			}
			_, err := s.Relay("work")
			if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "has a "+key+" that is not a hash") {
				t.Errorf("%s %q: %v; want ErrDamaged naming it", key, v, err)
			}
		}
	}
	r.TrustAnchorSPKI, r.ServerIntSPKI = strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := s.SaveRelay(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Relay("work"); err != nil {
		t.Errorf("both hashes as written: %v", err)
	}
	r.TrustAnchorSPKI, r.ServerIntSPKI = "", ""
	if err := s.SaveRelay(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Relay("work"); err != nil {
		t.Errorf("both hashes absent: %v", err)
	}
}

// TestLimitCertRecordSerial: a certificate record's serial is a
// certificate serial, held at CertFor before a print slices sixteen; one
// character short, one long, and uppercase are each a damaged file.
func TestLimitCertRecordSerial(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://relay.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	for _, serial := range []string{strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), ""} {
		if err := s.SaveCertFor(r, &CertRecord{Relay: r.URL, Serial: serial}); err != nil {
			t.Fatal(err)
		}
		_, err := s.CertFor(r)
		if err == nil || !strings.Contains(err.Error(), "its serial is not a certificate serial") {
			t.Errorf("serial %q: %v; want the damaged file naming the serial", serial, err)
		}
	}
	if err := s.SaveCertFor(r, &CertRecord{Relay: r.URL, Serial: strings.Repeat("a", 32)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertFor(r); err != nil {
		t.Errorf("a serial as written: %v", err)
	}
}

// traversalSet is the limit guide's set for a value that becomes part of
// a path: `..`, `../x`, `x/../../y`, `a/b`, an absolute path, a backslash
// form, a drive letter, a Windows device name, a NUL, the empty string,
// `.`, and a name longer than a filesystem allows.
func traversalSet() []string {
	return []string{"..", "../x", "x/../../y", "a/b", "/etc/passwd", `..\x`, `C:\x`, "C:x", "CON", "com1.txt", "\x00", "", ".", strings.Repeat("a", 300)}
}

// outsideUntouched fails the test when anything appeared outside the
// home: the scratch directory beside it holds one witness file and
// nothing else.
func outsideUntouched(t *testing.T, outside, witness string, what string) {
	t.Helper()
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(witness) {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("%s reached outside the home: %v", what, names)
	}
	if _, err := os.Stat(witness); err != nil {
		t.Errorf("%s removed the witness outside the home: %v", what, err)
	}
}

// TestLimitMessageIDIsNotAPathAtTheStoresEdges: a message id names the
// record's file, and every edge of the store that takes one runs
// message.ValidID before the join: Save, Load, Remove, RemoveByID, and the damaged
// box's DamagedPath and KeepDamaged through the relay's number. Each is
// fed the traversal set and refuses it, and nothing appears outside the
// home.
func TestLimitMessageIDIsNotAPathAtTheStoresEdges(t *testing.T) {
	s, outside, witness := reviewHome(t)
	now := time.Now().UTC().Truncate(time.Second)
	for _, v := range traversalSet() {
		if err := s.Save(Inbox, stored(v, now)); err == nil {
			t.Errorf("Save took the id %q", v)
		}
		if _, err := s.Load(Inbox, v); err == nil {
			t.Errorf("Load took the id %q", v)
		}
		if err := s.Remove(Inbox, v); err == nil {
			t.Errorf("Remove took the id %q", v)
		}
		if _, _, _, _, err := s.RemoveByID(v); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("RemoveByID took the id %q: %v", v, err)
		}
	}
	outsideUntouched(t, outside, witness, "an id from the traversal set")
	for _, box := range []Box{Inbox, Sent, Quarantine} {
		if entries, _ := os.ReadDir(s.path(string(box))); len(entries) != 0 {
			t.Errorf("%s holds %d entries after ids from the traversal set", box, len(entries))
		}
	}
}

// TestLimitRelayNameIsNotAPath: a relay name is a directory under the
// home, and ValidRelayName runs at AddRelay, at RenameRelay, and at the
// store's own edges that take a name — SetLeftBehind, LeftBehind,
// DamagedPath, KeepDamaged and CertKey — before the join. Each is fed the
// traversal set and refuses it, and nothing appears outside the home.
func TestLimitRelayNameIsNotAPath(t *testing.T) {
	s, outside, witness := reviewHome(t)
	r, err := s.AddRelay("work", "https://relay.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range traversalSet() {
		if v == "" {
			// An empty name at AddRelay is "derive one from the host".
			continue
		}
		if _, err := s.AddRelay(v, "https://other.example:9443"); err == nil {
			t.Errorf("AddRelay took the name %q", v)
		}
		if err := s.RenameRelay(r.Name, v); err == nil {
			t.Errorf("RenameRelay took the name %q", v)
		}
		if err := s.SetLeftBehind(v, []LeftEntry{{RelayID: 1, ID: strings.Repeat("a", 32)}}); err == nil {
			t.Errorf("SetLeftBehind took the name %q", v)
		}
		if _, err := s.LeftBehind(v); err == nil {
			t.Errorf("LeftBehind took the name %q", v)
		}
		// The couriers file is under the same relay directory and reached by
		// the same kind of name, so it is held to the same rule at each of
		// its three doors. RemoveCourier and AddCourier reach it through
		// Couriers, which is where the check is, and are driven here anyway
		// because the ledger names the function and not the path.
		if err := s.SetCouriers(v, []AdmittedCourier{{FP: strings.Repeat("a", 64), Name: "bar"}}); err == nil {
			t.Errorf("SetCouriers took the name %q", v)
		}
		if _, err := s.Couriers(v); err == nil {
			t.Errorf("Couriers took the name %q", v)
		}
		if err := s.AddCourier(v, strings.Repeat("a", 64), "bar"); err == nil {
			t.Errorf("AddCourier took the name %q", v)
		}
		if _, err := s.RemoveCourier(v, "bar"); err == nil {
			t.Errorf("RemoveCourier took the name %q", v)
		}
		if _, err := s.DamagedPath(v, 1); err == nil {
			t.Errorf("DamagedPath took the name %q", v)
		}
		if kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: 1, Relay: v, Received: time.Now(), Cause: "review"}, []byte("x")); err == nil || kept {
			t.Errorf("KeepDamaged took the name %q (kept=%v, err=%v)", v, kept, err)
		}
		if _, err := s.CertKey(v); err == nil {
			t.Errorf("CertKey took the name %q", v)
		}
		// And the name read back from this home's own config.
		if err := s.SaveConfig(Config{DefaultRelay: v}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DefaultRelay(); err == nil || !strings.Contains(err.Error(), "not a relay name") {
			t.Errorf("DefaultRelay took the name %q from the config: %v", v, err)
		}
	}
	outsideUntouched(t, outside, witness, "a relay name from the traversal set")
	entries, err := os.ReadDir(s.path(relaysDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "work" {
		t.Errorf("relays/ holds %d entries after names from the traversal set", len(entries))
	}
}

// TestLimitDamagedDirectoryEntries: the damaged box is read back by
// damagedEntries, which joins each entry's name onto the directory, and the
// budget, the counts and auu damaged ls all read it by that one rule. An
// entry that is not a kept message's — a file where a relay's directory
// belongs, a directory whose name is no relay's, a .bin whose stem is no id
// as the store writes one, a directory where a .bin belongs, a record with
// no bytes — is a stray: not counted, not evicted, and still there after a
// keep that evicts. A .bin with an id's name in a relay's directory is a
// kept message's whatever is beside it, and is counted and evicted: one
// whose keep was cut off before its record was written, and one beside a
// record that names another id, which is listed as a record that does not
// read. Nothing outside the directory is touched.
func TestLimitDamagedDirectoryEntries(t *testing.T) {
	s, outside, witness := reviewHome(t)
	restore := DamagedBudget
	DamagedBudget = 1000
	t.Cleanup(func() { DamagedBudget = restore })
	old := time.Now().Add(-time.Hour)
	if kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: 7, Relay: "work", Received: old, Cause: "review"}, []byte("bytes")); err != nil || !kept {
		t.Fatal(err)
	}
	dir := s.path(damagedDir)
	var strays []string
	plant := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		strays = append(strays, path)
	}
	// Stray entries beside the relay's directory and inside it.
	for _, name := range []string{"stray.txt", "..x", "CON"} {
		plant(filepath.Join(dir, name), []byte("x"))
		plant(filepath.Join(dir, "work", name+".bin"), []byte("x"))
	}
	if err := os.MkdirAll(filepath.Join(dir, "work", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	strays = append(strays, filepath.Join(dir, "work", "nested"))
	// A directory whose name is no relay's, holding what would otherwise
	// be a kept message: said once, by the directory.
	if err := os.MkdirAll(filepath.Join(dir, "a b"), 0o700); err != nil {
		t.Fatal(err)
	}
	strays = append(strays, filepath.Join(dir, "a b"))
	for _, f := range []string{"3.bin", "3.json"} {
		if err := os.WriteFile(filepath.Join(dir, "a b", f), []byte(`{"relay_id":3,"relay":"a b","received":"2026-10-01T00:00:00Z","cause":"review"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Stems that are not an id as the store writes one, each with a
	// record that would otherwise name it. The record is not said on its
	// own, since the .bin beside it is.
	for _, stem := range []string{"07", "-1", "+7", "9223372036854775808"} {
		plant(filepath.Join(dir, "work", stem+".bin"), []byte("xx"))
		if err := os.WriteFile(filepath.Join(dir, "work", stem+".json"), []byte(`{"relay_id":7,"relay":"work","received":"2026-10-01T00:00:00Z","cause":"review"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A record with no bytes: a stray.
	plant(filepath.Join(dir, "work", "12.json"), []byte(`{"relay_id":12,"relay":"work","received":"2026-10-01T00:00:00Z","cause":"review"}`))
	// Bytes whose record was never written, and bytes beside a record
	// naming another id than the file it is beside: both a kept message's,
	// counted, each at its file's own time, set here so that the order is
	// the test's.
	cutOff := filepath.Join(dir, "work", "9.bin")
	misnamed := filepath.Join(dir, "work", "10.bin")
	for i, f := range []struct{ path, data string }{{cutOff, "bytes"}, {misnamed, "xx"}} {
		if err := os.WriteFile(f.path, []byte(f.data), 0o600); err != nil {
			t.Fatal(err)
		}
		when := old.Add(time.Duration(i+1) * time.Minute)
		if err := os.Chtimes(f.path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(recordPath(misnamed), []byte(`{"relay_id":11,"relay":"work","received":"2026-10-01T00:00:00Z","cause":"review"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	have, err := s.keptMessages()
	if err != nil {
		t.Fatalf("keptMessages over stray entries: %v", err)
	}
	for _, k := range have {
		if rel, err := filepath.Rel(dir, k.bin); err != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("a kept entry outside the damaged box: %s", k.bin)
		}
	}
	n, size, err := s.DamagedKept()
	if err != nil || n != 3 || size != 12 {
		t.Fatalf("DamagedKept counts %d messages of %d bytes (%v); want 7, the record-less 9 and the misnamed 10, 12 bytes, and no stray", n, size, err)
	}
	entries, listed, err := s.DamagedEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].RelayID != 7 || entries[0].NoRecord || entries[0].BadRecord ||
		entries[1].RelayID != 9 || !entries[1].NoRecord || entries[1].BadRecord {
		t.Fatalf("DamagedEntries: %+v; want 7 with its record, 9 without and 10 beside a record that does not read", entries)
	}
	bad := entries[2]
	if bad.RelayID != 10 || bad.Relay != "work" || !bad.BadRecord || bad.NoRecord || bad.Bytes != 2 ||
		!bad.Received.Equal(old.Add(2*time.Minute)) || bad.Cause != `the record names relay "work" and id 11` {
		t.Fatalf("the misnamed record's entry: %+v; want 10 of 2 bytes at its file's time, said by what its record names", bad)
	}
	sort.Strings(strays)
	if strings.Join(listed, "\n") != strings.Join(strays, "\n") {
		t.Errorf("the strays said:\n%s\nwant:\n%s", strings.Join(listed, "\n"), strings.Join(strays, "\n"))
	}
	// A keep over budget evicts all three kept messages, by their own
	// paths, the misnamed record with its bytes, and no stray, which was
	// never counted.
	_, evicted, err := s.KeepDamaged(DamagedRecord{RelayID: 8, Relay: "work", Received: time.Now(), Cause: "review"}, bytes.Repeat([]byte{1}, 999))
	if err != nil || evicted != 3 {
		t.Fatalf("the keep over budget evicted %d (%v); want 7, 9 and 10", evicted, err)
	}
	for _, gone := range []string{filepath.Join(dir, "work", "7.bin"), filepath.Join(dir, "work", "7.json"), cutOff, misnamed, recordPath(misnamed)} {
		if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was not evicted: %v", gone, err)
		}
	}
	for _, p := range strays {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("the stray %s was evicted: %v", p, err)
		}
	}
	outsideUntouched(t, outside, witness, "the damaged box's reader")
}

// writeDamagedPair writes a kept message's bytes and a record as given, by
// hand, for a test of what the reader makes of a record the store would
// not write.
func writeDamagedPair(t *testing.T, s *Store, relay string, id int64, record string, data []byte) string {
	t.Helper()
	bin, err := s.DamagedPath(relay, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath(bin), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestLimitDamagedRecordFields: what the listing said of a kept row is held
// at the read to the listing's own rules again: a size of 0 or more, to the
// type's maximum; a kind that is envelope or knock; a channel's name; and a
// via that is an address. A record that breaks one does not read:
// ReadDamaged refuses it naming the field, which is what keeps reopen from
// it, and damagedEntries lists its pair as a record that does not read,
// at its bytes' own time and with the reason, counted against the budget
// and never a stray, so that no record can put bytes beyond the budget.
// The type's extremes and the empty forms are fed.
func TestLimitDamagedRecordFields(t *testing.T) {
	s := newStore(t)
	const head = `"relay":"work","received":"2026-10-01T00:00:00Z","cause":"newer: section \"x\""`
	cases := []struct {
		field string
		ok    bool
		want  string
	}{
		{`"size":-1`, false, "the record's size -1 is below zero"},
		{`"size":-9223372036854775808`, false, "the record's size -9223372036854775808 is below zero"},
		{`"size":0`, true, ""},
		{`"size":9223372036854775807`, true, ""},
		{`"kind":"envelope"`, true, ""},
		{`"kind":"knock"`, true, ""},
		{`"kind":"stream"`, false, `the record's kind "stream" is not one a kept row is listed under`},
		{`"kind":"Envelope"`, false, `the record's kind "Envelope" is not one a kept row is listed under`},
		{`"kind":""`, true, ""},
		{`"channel":"default"`, true, ""},
		{`"channel":"a/b"`, false, `the record's channel: name contains "/"`},
		{`"channel":" x"`, false, "the record's channel: name begins with white space"},
		{`"channel":"` + strings.Repeat("a", relayapi.MaxChannelNameBytes+1) + `"`, false, "the record's channel: name is "},
		{`"channel":"` + strings.Repeat("a", relayapi.MaxChannelNameBytes) + `"`, true, ""},
		{`"via":"other"`, true, ""},
		{`"via":"other!more"`, true, ""},
		{`"via":"../x"`, false, "the record's via: relay name "},
		{`"via":"other!other"`, false, "the record's via: address repeats "},
		{`"via":"` + strings.Repeat("r!", relayapi.MaxHops) + `r"`, false, "the record's via: an address names 33 relays"},
	}
	mtime := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for i, tc := range cases {
		id := int64(i)
		bin := writeDamagedPair(t, s, "work", id, `{"relay_id":`+strconv.FormatInt(id, 10)+`,`+head+`,`+tc.field+`}`, []byte("bytes"))
		if err := os.Chtimes(bin, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.ReadDamaged("work", id)
		if tc.ok != (err == nil) || (!tc.ok && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: ReadDamaged said %v; want ok=%v and %q", tc.field, err, tc.ok, tc.want)
		}
	}
	entries, strays, err := s.DamagedEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(strays) != 0 {
		t.Errorf("strays %v; want none, every pair a kept message's", strays)
	}
	listed := map[int64]DamagedEntry{}
	for _, e := range entries {
		listed[e.RelayID] = e
	}
	recorded := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, tc := range cases {
		e, ok := listed[int64(i)]
		switch {
		case !ok:
			t.Errorf("%s: not listed; want it listed and counted", tc.field)
		case e.NoRecord || e.Bytes != int64(len("bytes")) || e.Relay != "work":
			t.Errorf("%s: listed as %+v", tc.field, e)
		case tc.ok && (e.BadRecord || !e.Received.Equal(recorded) || e.Cause != `newer: section "x"`):
			t.Errorf("%s: listed as %+v; want its record as it reads", tc.field, e)
		case !tc.ok && (!e.BadRecord || !e.Received.Equal(mtime) || !strings.HasPrefix(e.Cause, tc.want)):
			t.Errorf("%s: listed as %+v; want a record that does not read, at its bytes' time, said by %q", tc.field, e, tc.want)
		}
	}
	if n, size, err := s.DamagedKept(); err != nil || n != len(cases) || size != int64(len(cases)*len("bytes")) {
		t.Errorf("DamagedKept counts %d of %d bytes (%v); want all %d, those that do not read with those that do", n, size, err, len(cases))
	}
}

// TestAZeroReceivedTimeIsKeptWithinTheBudget: a relay that says no received
// time cannot put bytes beyond the budget. KeepDamaged gives such a record
// this machine's time, so every keep reads back, counts and is evicted
// oldest first, and the box stays within the budget however many come. A
// record on disk with a zero received time, which no keep writes now, does
// not read: its pair is listed as a record that does not read, at its
// bytes' own time, counted, and evicted by a later keep that needs room.
func TestAZeroReceivedTimeIsKeptWithinTheBudget(t *testing.T) {
	restore := DamagedBudget
	DamagedBudget = 100
	t.Cleanup(func() { DamagedBudget = restore })
	data := bytes.Repeat([]byte{'z'}, 10)

	s := newStore(t)
	// Ids of two digits, so that the paths sort as the keeps were made.
	const first, last = 10, 24
	for id := int64(first); id <= last; id++ {
		before := time.Now()
		kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: id, Relay: "work", Cause: "malformed"}, data)
		after := time.Now()
		if err != nil || !kept {
			t.Fatalf("keep %d with no received time: kept=%v err=%v", id, kept, err)
		}
		e, _, err := s.ReadDamaged("work", id)
		if err != nil {
			t.Fatalf("keep %d does not read back: %v", id, err)
		}
		if e.Received.IsZero() || e.Received.Before(before.Truncate(time.Microsecond)) || e.Received.After(after) || e.Received.Location() != time.UTC {
			t.Errorf("keep %d was given the received time %v; want this machine's, in UTC, between %v and %v", id, e.Received, before, after)
		}
		n, size, err := s.DamagedKept()
		if err != nil || size > DamagedBudget || n != int(min(id-first+1, 10)) {
			t.Fatalf("after keep %d: %d kept of %d bytes (%v); want within the budget of %d", id, n, size, err, DamagedBudget)
		}
	}
	entries, strays, err := s.DamagedEntries()
	if err != nil || len(strays) != 0 || len(entries) != 10 {
		t.Fatalf("DamagedEntries: %d entries, strays %v (%v); want the ten newest", len(entries), strays, err)
	}
	for i, e := range entries {
		if want := int64(last - 9 + i); e.RelayID != want || e.BadRecord || e.NoRecord {
			t.Errorf("entry %d: %+v; want %d, the oldest five evicted", i, e, want)
		}
	}
	for id := int64(first); id < last-9; id++ {
		if _, _, err := s.ReadDamaged("work", id); !errors.Is(err, ErrNotDamaged) {
			t.Errorf("the oldest, %d, was not evicted: %v", id, err)
		}
	}

	// A record on disk that says no received time.
	s = newStore(t)
	for id := int64(1); id <= 9; id++ {
		if kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: id, Relay: "work", Received: time.Now(), Cause: "malformed"}, data); err != nil || !kept {
			t.Fatalf("keep %d: kept=%v err=%v", id, kept, err)
		}
	}
	bin := writeDamagedPair(t, s, "work", 50, `{"relay_id":50,"relay":"work","received":"0001-01-01T00:00:00Z","cause":"malformed"}`, data)
	mtime := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(bin, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadDamaged("work", 50); err == nil || !strings.HasSuffix(err.Error(), "the record has no received time") {
		t.Errorf("ReadDamaged of a zero received time: %v; want it refused", err)
	}
	entries, strays, err = s.DamagedEntries()
	if err != nil || len(strays) != 0 || len(entries) != 10 {
		t.Fatalf("DamagedEntries: %d entries, strays %v (%v); want nine kept and the zero time's pair", len(entries), strays, err)
	}
	if e := entries[0]; e.RelayID != 50 || !e.BadRecord || e.NoRecord || !e.Received.Equal(mtime) ||
		e.Bytes != int64(len(data)) || e.Cause != "the record has no received time" {
		t.Errorf("the zero time's pair: %+v; want the oldest, a record that does not read at its bytes' time", e)
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 10 || size != DamagedBudget {
		t.Errorf("DamagedKept: %d of %d bytes (%v); want the zero time's pair counted, ten at the budget", n, size, err)
	}
	_, evicted, err := s.KeepDamaged(DamagedRecord{RelayID: 60, Relay: "work", Received: time.Now(), Cause: "malformed"}, data)
	if err != nil || evicted != 1 {
		t.Fatalf("the keep that needs room evicted %d (%v); want the zero time's pair alone", evicted, err)
	}
	for _, p := range []string{bin, recordPath(bin)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was not evicted: %v", p, err)
		}
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 10 || size != DamagedBudget {
		t.Errorf("after the eviction: %d of %d bytes (%v); want ten at the budget", n, size, err)
	}
}

// TestLimitDamagedReadIsBounded: ReadDamaged reads the kept bytes through a
// reader bounded one over DamagedBudget, the most a keep ever writes: bytes
// at the budget read whole, and one byte over is refused by name, never
// cut to the budget and handed on.
func TestLimitDamagedReadIsBounded(t *testing.T) {
	s := newStore(t)
	restore := DamagedBudget
	DamagedBudget = 1000
	t.Cleanup(func() { DamagedBudget = restore })
	record := func(id int64) string {
		return `{"relay_id":` + strconv.FormatInt(id, 10) + `,"relay":"work","received":"2026-10-01T00:00:00Z","cause":"newer"}`
	}
	at := bytes.Repeat([]byte{'a'}, int(DamagedBudget))
	writeDamagedPair(t, s, "work", 1, record(1), at)
	e, data, err := s.ReadDamaged("work", 1)
	if err != nil || !bytes.Equal(data, at) || e.Bytes != DamagedBudget {
		t.Fatalf("bytes at the budget: %d bytes, %v; want all %d", len(data), err, DamagedBudget)
	}
	bin := writeDamagedPair(t, s, "work", 2, record(2), append(at, 'b'))
	_, data, err = s.ReadDamaged("work", 2)
	if err == nil || data != nil || err.Error() != bin+" is over 1 KiB, more than a keep ever writes" {
		t.Fatalf("bytes one over the budget: %d bytes, %v; want the refusal by name", len(data), err)
	}
	// Nothing kept is not the same as nothing read.
	writeDamagedPair(t, s, "work", 3, record(3), nil)
	if _, data, err := s.ReadDamaged("work", 3); err != nil || len(data) != 0 {
		t.Fatalf("empty bytes: %d, %v", len(data), err)
	}
}

// TestLimitDefaultRelayNameFromURL: the name the store derives from a
// relay's host when none is given is made of the characters the name rule
// allows, so a host from the traversal set, an IPv6 literal or a long one
// yields a name that is one segment under relays/ and never a path.
func TestLimitDefaultRelayNameFromURL(t *testing.T) {
	s, outside, witness := reviewHome(t)
	for _, host := range []string{"..", "x/../../y", "[::1]", "CON", "com1.example", strings.Repeat("a", 300), "a.b-c_d"} {
		r, err := s.AddRelay("", "https://"+host+":9443")
		if err != nil {
			if strings.Contains(err.Error(), "--name") || strings.Contains(err.Error(), "not a URL") || strings.Contains(err.Error(), "invalid") {
				continue
			}
			t.Errorf("host %q: %v", host, err)
			continue
		}
		if err := ValidRelayName(r.Name); err != nil {
			t.Errorf("host %q got the name %q, which is not a relay name: %v", host, r.Name, err)
		}
		if rel, err := filepath.Rel(s.path(relaysDir), s.RelayDir(r)); err != nil || strings.Contains(rel, "..") || strings.ContainsAny(rel, `/\`) {
			t.Errorf("host %q: the relay directory %q is not one segment under relays/", host, s.RelayDir(r))
		}
	}
	outsideUntouched(t, outside, witness, "a relay name derived from a host")
}

// TestLimitRelaysDirectoryEntries: Relays reads relays/ by its entries and
// joins each onto the directory to read its record; an entry that is not
// a directory, or is a directory this store could not have made — one
// ValidRelayName refuses, a Windows device, a dot-dot form, a name with a
// space — is skipped without being joined and said once on stderr by its
// path, one with no record is a half-finished add and skipped as before,
// the relay this store wrote is listed, and nothing outside the home is
// touched.
func TestLimitRelaysDirectoryEntries(t *testing.T) {
	s, outside, witness := reviewHome(t)
	if _, err := s.AddRelay("work", "https://relay.example:9443"); err != nil {
		t.Fatal(err)
	}
	dir := s.path(relaysDir)
	for _, name := range []string{"CON", "..x", "a b", strings.Repeat("a", 200), "half"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"CON", "..x"} {
		if err := os.WriteFile(filepath.Join(dir, name, relayFile), []byte(`{"url":"https://x"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var relays []*Relay
	stderr := captureStderr(t, func() {
		var err error
		if relays, err = s.Relays(); err != nil {
			t.Fatalf("Relays failed on a stray entry: %v", err)
		}
	})
	if len(relays) != 1 || relays[0].Name != "work" {
		var names []string
		for _, r := range relays {
			names = append(names, r.Name)
		}
		t.Errorf("Relays listed %v; want work alone", names)
	}
	// Each directory that is not a relay name is said once, by its path,
	// so that a person who can see it in the directory is told why it is
	// not in the listing, and what to do is the shell's move — a name the
	// rule refuses is one 'auu relay rename' cannot resolve either — and
	// then the listing; the half-finished add and the file are not said.
	for _, name := range []string{"CON", "..x", "a b", strings.Repeat("a", 200)} {
		path := filepath.Join(dir, name)
		if !strings.Contains(stderr, "warning: "+path+" is not a relay directory (") {
			t.Errorf("no warning names %q:\n%s", name, stderr)
		}
		if !strings.Contains(stderr, "move it to a relay name by hand, as in: mv "+path+" "+filepath.Join(dir, "NAME")+", then run 'auu relay list'; or remove it") {
			t.Errorf("the warning for %q does not give the shell's move:\n%s", name, stderr)
		}
	}
	if strings.Contains(stderr, "rename it to a relay name") {
		t.Errorf("the warning names a rename the tool refuses:\n%s", stderr)
	}
	if strings.Contains(stderr, "half") || strings.Contains(stderr, "stray") {
		t.Errorf("the warning speaks of an entry the rule takes:\n%s", stderr)
	}
	if again := captureStderr(t, func() { s.Relays() }); again != "" {
		t.Errorf("the second listing warned again:\n%s", again)
	}
	outsideUntouched(t, outside, witness, "an entry of relays/")
}

// TestLimitRemoveByIDRelayFields: RemoveByID reads two fields of a record
// it does not otherwise trust, the relay name and the relay's number, so
// the relay's copy can be remembered as left behind; each is held to its
// rule alone — ValidRelayName, and a positive int64 — and a record whose
// fields fail (a negative, zero, the type's minimum, a name that is not
// a relay name, JSON that is not a record) is removed all the same with
// nothing to remember. The type's maximum is taken.
func TestLimitRemoveByIDRelayFields(t *testing.T) {
	s, outside, witness := reviewHome(t)
	id := strings.Repeat("a", 32)
	write := func(t *testing.T, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(s.msgPath(Inbox, id)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(Inbox, id), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(s.AttachmentDir(Inbox, id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		body        string
		relay       string
		relayID     int64
		description string
		from        string
	}{
		{`{"relay":"work","relay_id":7}`, "work", 7, "as written", ""},
		{`{"relay":"work","relay_id":7,"inner":{"from":"` + aSigner + `"}}`, "work", 7, "with its signer", aSigner},
		{`{"relay":"work","relay_id":7,"inner":{"from":"../` + aSigner[3:] + `"}}`, "work", 7, "a signer that is not a fingerprint", ""},
		{`{"relay":"work","relay_id":7,"inner":{"from":"` + strings.ToUpper(aSigner) + `"}}`, "work", 7, "a signer in capitals", ""},
		{`{"relay":"work","relay_id":9223372036854775807}`, "work", math.MaxInt64, "the type's maximum", ""},
		{`{"relay":"work","relay_id":0}`, "", 0, "zero", ""},
		{`{"relay":"work","relay_id":-1}`, "", 0, "negative", ""},
		{`{"relay":"work","relay_id":-9223372036854775808}`, "", 0, "the type's minimum", ""},
		{`{"relay":"work","relay_id":9223372036854775808}`, "", 0, "one past the maximum", ""},
		{`{"relay":"../x","relay_id":7}`, "", 0, "a relay name that is a path", ""},
		{`{"relay":"","relay_id":7}`, "", 0, "no relay name", ""},
		{`{"relay":"CON","relay_id":7}`, "", 0, "a device as a relay name", ""},
		{`not json`, "", 0, "not a record", ""},
		{`{"relay":"work","relay_id":"7"}`, "", 0, "a number written as text", ""},
	} {
		write(t, tc.body)
		box, relay, relayID, from, err := s.RemoveByID(id)
		if err != nil || box != Inbox {
			t.Errorf("%s: %v, %q; want removed from the inbox", tc.description, err, box)
			continue
		}
		if relay != tc.relay || relayID != tc.relayID || from != tc.from {
			t.Errorf("%s: relay %q id %d from %q; want %q %d %q", tc.description, relay, relayID, from, tc.relay, tc.relayID, tc.from)
		}
		if _, err := os.Stat(s.msgPath(Inbox, id)); !os.IsNotExist(err) {
			t.Errorf("%s: the record is still there", tc.description)
		}
		if _, err := os.Stat(s.AttachmentDir(Inbox, id)); !os.IsNotExist(err) {
			t.Errorf("%s: the attachment directory is still there", tc.description)
		}
	}
	if _, _, _, _, err := s.RemoveByID(id); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("RemoveByID of an id no box holds: %v; want ErrNotExist", err)
	}
	outsideUntouched(t, outside, witness, "RemoveByID")
}

// TestLimitStoredDroppedSections: the count of sections a message lost for
// being over the kept size is zero or more, and a record saying otherwise
// was not written by this program.
func TestLimitStoredDroppedSections(t *testing.T) {
	s := newStore(t)
	m := stored("00000000000000000000000000000002", time.Now().UTC().Truncate(time.Second))
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	path := s.msgPath(Inbox, m.Inner.ID)
	write := func(t *testing.T, n int) {
		t.Helper()
		m.DroppedSections = n
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int{-1, math.MinInt} {
		write(t, n)
		if _, err := s.Load(Inbox, m.Inner.ID); err == nil || !strings.Contains(err.Error(), "dropped section count "+strconv.Itoa(n)+" is negative") {
			t.Errorf("dropped %d: %v; want the refusal naming it", n, err)
		}
	}
	for _, n := range []int{0, 1, math.MaxInt} {
		write(t, n)
		if got, err := s.Load(Inbox, m.Inner.ID); err != nil || got.DroppedSections != n {
			t.Errorf("dropped %d: %v", n, err)
		}
	}
}

// TestAStoredRecordsSectionsAreHeldAtLoad: what a record kept of its
// sections is held at Load to the rule Open and the fetch held it to: the
// list's shape, each section at or under the kept size, and a stream's
// newer mark a name beside a payload on the relay.
func TestAStoredRecordsSectionsAreHeldAtLoad(t *testing.T) {
	s := newStore(t)
	m := stored("00000000000000000000000000000003", time.Now().UTC().Truncate(time.Second))
	if err := s.Save(Inbox, m); err != nil {
		t.Fatal(err)
	}
	path := s.msgPath(Inbox, m.Inner.ID)
	at := func(n int) json.RawMessage { return json.RawMessage(`"` + strings.Repeat("a", n-2) + `"`) }
	for _, tc := range []struct {
		name     string
		sections []wire.Section
		newer    string
		payload  bool
		want     string
	}{
		{"a section at the kept size", []wire.Section{{Name: "later", Data: at(wire.MaxKeptBytes)}}, "", false, ""},
		{"one over it", []wire.Section{{Name: "later", Data: at(wire.MaxKeptBytes + 1)}}, "", false, "over the 16384 kept"},
		{"a name that is not one", []wire.Section{{Name: "Later", Data: json.RawMessage(`1`)}}, "", false, "the record's sections"},
		{"a name twice", []wire.Section{{Name: "a", Data: json.RawMessage(`1`)}, {Name: "a", Data: json.RawMessage(`2`)}}, "", false, "appears twice"},
		{"a newer mark beside its payload", nil, "must-know", true, ""},
		{"a newer mark with no payload on the relay", nil, "must-know", false, "says its payload is not on the relay"},
		{"a newer mark that is not a name", nil, "Must Know", true, "the record's newer section"},
	} {
		m.Inner.Sections, m.Newer, m.PayloadOnRelay = tc.sections, tc.newer, tc.payload
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = s.Load(Inbox, m.Inner.ID)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v; want it read", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.want)
		}
	}
}

// recipientsList is the recipients section naming fps, as the sealer writes
// it.
func recipientsList(t *testing.T, fps ...string) wire.Section {
	t.Helper()
	sec, err := recipients.Section(fps)
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

// TestADamagedRecordIsReadStrictly: a record is read by the wire's strict
// rule, the file this program wrote and nothing that only resembles it. A
// record with a field this build does not know, a key given twice, a key
// that matches a field only by case, or data after the object does not
// read, though each would decode under encoding/json's own rule: its pair
// is listed as a record that does not read, at its bytes' own time and
// with the decoder's reason, counted against the budget, refused by
// ReadDamaged naming the record, and evicted by a keep that needs room.
func TestADamagedRecordIsReadStrictly(t *testing.T) {
	restore := DamagedBudget
	DamagedBudget = 20
	t.Cleanup(func() { DamagedBudget = restore })
	s := newStore(t)
	const fields = `"relay":"work","received":"2026-10-01T00:00:00Z"`
	cases := []struct {
		name, record, want string
	}{
		{"an unknown field", `{"relay_id":1,` + fields + `,"cause":"newer","future":1}`, `json: unknown field "future"`},
		{"a key twice", `{"relay_id":2,` + fields + `,"cause":"malformed","cause":"newer"}`, `key "cause" appears twice in an object at depth 1`},
		{"a key by case", `{"relay_id":3,` + fields + `,"Cause":"newer"}`, `key "Cause" matches the field "cause" only by case, in an object at depth 1`},
		{"trailing data", `{"relay_id":4,` + fields + `,"cause":"newer"} {}`, "trailing data after the value"},
	}
	mtime := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for i, tc := range cases {
		id := int64(i + 1)
		bin := writeDamagedPair(t, s, "work", id, tc.record, []byte("bytes"))
		if err := os.Chtimes(bin, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.ReadDamaged("work", id)
		if want := recordPath(bin) + ": " + tc.want; err == nil || err.Error() != want {
			t.Errorf("%s: ReadDamaged said %v; want %q", tc.name, err, want)
		}
	}
	entries, strays, err := s.DamagedEntries()
	if err != nil || len(strays) != 0 || len(entries) != len(cases) {
		t.Fatalf("DamagedEntries: %+v, strays %v (%v); want the %d pairs and no strays", entries, strays, err, len(cases))
	}
	for i, tc := range cases {
		e := entries[i]
		if e.RelayID != int64(i+1) || e.Relay != "work" || !e.BadRecord || e.NoRecord || !e.Received.Equal(mtime) ||
			e.Bytes != int64(len("bytes")) || e.Cause != tc.want {
			t.Errorf("%s: listed as %+v; want a record that does not read, at its bytes' time, said by %q", tc.name, e, tc.want)
		}
	}
	if n, size, err := s.DamagedKept(); err != nil || n != len(cases) || size != int64(len(cases)*len("bytes")) {
		t.Errorf("DamagedKept counts %d of %d bytes (%v); want all %d", n, size, err, len(cases))
	}
	// A keep the size of the whole budget evicts every one of them.
	kept, evicted, err := s.KeepDamaged(DamagedRecord{RelayID: 9, Relay: "work", Received: time.Now(), Cause: "malformed"},
		bytes.Repeat([]byte{'k'}, int(DamagedBudget)))
	if err != nil || !kept || evicted != len(cases) {
		t.Fatalf("a keep over the budget: kept=%v evicted=%d (%v); want kept, the %d evicted", kept, evicted, err, len(cases))
	}
	for i := range cases {
		if _, _, err := s.ReadDamaged("work", int64(i+1)); !errors.Is(err, ErrNotDamaged) {
			t.Errorf("%s: not evicted: %v", cases[i].name, err)
		}
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 1 || size != DamagedBudget {
		t.Errorf("DamagedKept after the keep: %d of %d bytes (%v); want the new keep alone", n, size, err)
	}
}
