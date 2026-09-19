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
