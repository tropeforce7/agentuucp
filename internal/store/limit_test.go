package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
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
	} {
		err := write(t, tc.mutate)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.says)
		}
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
// keptMessages, which joins each entry's name onto the directory; an
// entry that is not a kept message's pair of files — a stray directory,
// a record with no bytes, a name that is no relay's — is listed for
// eviction by its name or skipped, and nothing outside the directory is
// touched.
func TestLimitDamagedDirectoryEntries(t *testing.T) {
	s, outside, witness := reviewHome(t)
	restore := DamagedBudget
	DamagedBudget = 1000
	t.Cleanup(func() { DamagedBudget = restore })
	if kept, _, err := s.KeepDamaged(DamagedRecord{RelayID: 7, Relay: "work", Received: time.Now(), Cause: "review"}, []byte("bytes")); err != nil || !kept {
		t.Fatal(err)
	}
	dir := s.path(damagedDir)
	// Stray entries beside the relay's directory and inside it.
	for _, name := range []string{"stray.txt", "..x", "CON"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "work", name+".bin"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "work", "nested"), 0o700); err != nil {
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
	// A second keep, over budget, evicts by the entries' own paths and
	// stays inside the box.
	if _, _, err := s.KeepDamaged(DamagedRecord{RelayID: 8, Relay: "work", Received: time.Now(), Cause: "review"}, bytes.Repeat([]byte{1}, 990)); err != nil {
		t.Fatal(err)
	}
	outsideUntouched(t, outside, witness, "the damaged box's reader")
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
