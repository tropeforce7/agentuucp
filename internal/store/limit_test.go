package store

import (
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

// TestLimitLeftBehindIDs: the left-behind file holds relay message ids,
// one per line, each positive: zero, a negative, the type's minimum, the
// text one past the type's maximum, a sign, a leading space that TrimSpace
// does not take, and a digit outside ASCII are each a damaged file naming
// the line; one and the type's maximum are ids.
func TestLimitLeftBehindIDs(t *testing.T) {
	s := newStore(t)
	const name = "work"
	if err := s.AddLeftBehind(name, 1); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.relayDir(name), leftBehindFile)
	for _, text := range []string{"0", "-1", "-0", strconv.FormatInt(math.MinInt64, 10), "9223372036854775808", "1 2", "\u0661", "0x10"} {
		if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.LeftBehind(name)
		if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "which is not a message id") {
			t.Errorf("%q: %v; want ErrDamaged", text, err)
		}
	}
	// A leading sign and surrounding space are what ParseInt and TrimSpace
	// take: the number is the number.
	for _, tc := range []struct {
		text string
		want int64
	}{{"1", 1}, {"+1", 1}, {" 7 ", 7}, {"9223372036854775807", math.MaxInt64}} {
		if err := os.WriteFile(path, []byte(tc.text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ids, err := s.LeftBehind(name)
		if err != nil || len(ids) != 1 || ids[0] != tc.want {
			t.Errorf("%q: %v %v; want [%d]", tc.text, ids, err, tc.want)
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
// to the shapes a print slices: its id, its thread and its reply are
// message ids, its from and to are fingerprints, and each attachment's
// digest is 64 hex characters; each one character short is refused
// naming what it is, and the record as written loads.
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
	} {
		err := write(t, tc.mutate)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.says)
		}
	}
	if err := write(t, func(m *Stored) {}); err != nil {
		t.Errorf("the record as written: %v", err)
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
