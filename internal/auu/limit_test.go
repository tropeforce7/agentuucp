package auu

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// serveFileWith writes a serve.json with one channel over a fresh git
// repository, the channel's fields as given, and loads and checks it.
func serveFileWith(t *testing.T, fields string) error {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the PATH")
	}
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	path := filepath.Join(t.TempDir(), "serve.json")
	file := `{"v":1,"channels":{"work":{"dir":"` + jsonPath(repo) + `","exec":"cat"` + fields + `}}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadServeConfig(path)
	if err != nil {
		return err
	}
	return cfg.check()
}

// TestLimitServeChannelIntegers: a served channel's max_turns is one or
// more and its retries zero or more, with zero meaning the default for
// both; its timeout and thread_ttl are lengths of time more than nothing,
// read from text. A negative, the type's minimum, and for the durations
// zero, a negative, the text one past the type's maximum and a bare
// number are refused naming the field; the type's maximum is taken.
func TestLimitServeChannelIntegers(t *testing.T) {
	for _, tc := range []struct {
		fields string
		want   string
	}{
		{`,"max_turns":-1`, "max_turns is -1"},
		{`,"max_turns":` + strconv.Itoa(math.MinInt), "max_turns is " + strconv.Itoa(math.MinInt)},
		{`,"max_turns":9223372036854775808`, "max_turns"},
		{`,"retries":-1`, "retries is -1"},
		{`,"retries":` + strconv.Itoa(math.MinInt), "retries is " + strconv.Itoa(math.MinInt)},
		{`,"timeout":"0s"`, "timeout is 0s; it must be more than nothing"},
		{`,"timeout":"-1s"`, "timeout is -1s; it must be more than nothing"},
		{`,"timeout":"9223372036854775808ns"`, `timeout "9223372036854775808ns" is not a length of time`},
		{`,"timeout":"30"`, `timeout "30" is not a length of time`},
		{`,"thread_ttl":"0s"`, "thread_ttl is 0s; it must be more than nothing"},
		{`,"thread_ttl":"-1h"`, "thread_ttl is -1h; it must be more than nothing"},
		{`,"thread_ttl":"9223372036854775808ns"`, `thread_ttl "9223372036854775808ns" is not a length of time`},
	} {
		err := serveFileWith(t, tc.fields)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want %q", tc.fields, err, tc.want)
		}
	}
	for _, fields := range []string{
		``, `,"max_turns":1`, `,"max_turns":` + strconv.Itoa(math.MaxInt), `,"retries":0`, `,"retries":` + strconv.Itoa(math.MaxInt),
		`,"timeout":"1ns"`, `,"timeout":"9223372036854775807ns"`, `,"thread_ttl":"1ns"`, `,"thread_ttl":"9223372036854775807ns"`,
	} {
		if err := serveFileWith(t, fields); err != nil {
			t.Errorf("%s: %v; want it taken", fields, err)
		}
	}
}

// TestLimitServeConfigV: a serve file's v is 1, and every other value is
// refused naming the version this build understands, the type's extremes
// among them.
func TestLimitServeConfigV(t *testing.T) {
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		path := filepath.Join(t.TempDir(), "serve.json")
		if err := os.WriteFile(path, []byte(`{"v":`+strconv.Itoa(v)+`,"channels":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadServeConfig(path)
		if err == nil || !strings.Contains(err.Error(), "v is "+strconv.Itoa(v)+"; this auu understands version 1") {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}
}

// TestLimitServeLedgerIntegers: the serve ledger's v is 1 and each
// entry's failures is a count; a negative count, the type's minimum, and
// a v that is not 1 are each refused naming the file, and zero and the
// type's maximum are read.
func TestLimitServeLedgerIntegers(t *testing.T) {
	path := filepath.Join(t.TempDir(), ledgerFile)
	write := func(t *testing.T, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id := strings.Repeat("a", 32)
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		write(t, `{"v":`+strconv.Itoa(v)+`,"messages":{}}`)
		_, err := loadLedger(path)
		if err == nil || !strings.Contains(err.Error(), "is version "+strconv.Itoa(v)+"; this auu writes version 1") {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}
	for _, n := range []int{-1, math.MinInt} {
		write(t, `{"v":1,"messages":{"`+id+`":{"thread":"`+id+`","failures":`+strconv.Itoa(n)+`}}}`)
		_, err := loadLedger(path)
		if err == nil || !strings.Contains(err.Error(), "counts "+strconv.Itoa(n)+" failures for "+id+", which is not a count") {
			t.Errorf("failures %d: %v; want the refusal naming the count", n, err)
		}
	}
	for _, n := range []int{0, 1, math.MaxInt} {
		write(t, `{"v":1,"messages":{"`+id+`":{"thread":"`+id+`","failures":`+strconv.Itoa(n)+`,"tried":"2026-09-20T10:00:00Z"}}}`)
		l, err := loadLedger(path)
		if err != nil || l.Messages[id] == nil || l.Messages[id].Failures != n {
			t.Errorf("failures %d: %v; want it read", n, err)
		}
	}
	write(t, `{"v":1,"messages":{"`+id+`":null}}`)
	if _, err := loadLedger(path); err == nil || !strings.Contains(err.Error(), "has no entry under") {
		t.Errorf("a null entry: %v; want the refusal", err)
	}
	// An attempt has a time: an entry that counts one, or gave up, with
	// no tried is from before there were timestamps, and is refused
	// naming the entry and the fix; a skipped entry has none and is
	// read, as is one whose attempt is timed, and every attempt this
	// program records writes the key.
	fromBefore := "has an attempt with no time for " + id + ", which is how a ledger from before v0.11.0 was written"
	for _, entry := range []string{
		`{"thread":"` + id + `","failures":1}`,
		`{"thread":"` + id + `","gave_up":true}`,
		`{"thread":"` + id + `","failures":1,"tried":"0001-01-01T00:00:00Z"}`,
	} {
		write(t, `{"v":1,"messages":{"`+id+`":`+entry+`}}`)
		_, err := loadLedger(path)
		if err == nil || !strings.Contains(err.Error(), fromBefore) {
			t.Errorf("%s: %v; want the refusal naming the entry", entry, err)
		}
	}
	for _, entry := range []string{
		`{"thread":"` + id + `","skipped":true}`,
		`{"thread":"` + id + `","failures":1,"tried":"2026-09-20T10:00:00Z"}`,
		`{"thread":"` + id + `","gave_up":true,"failures":3,"tried":"2026-09-20T10:00:00Z"}`,
	} {
		write(t, `{"v":1,"messages":{"`+id+`":`+entry+`}}`)
		if _, err := loadLedger(path); err != nil {
			t.Errorf("%s: %v; want it read", entry, err)
		}
	}
	data, err := json.Marshal(&ledgerEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tried":`) {
		t.Errorf("the zero entry marshals without its tried key: %s", data)
	}
}

// TestLimitProxyFileV: the proxy file's v is 1, and every other value is
// refused naming the version this build understands, the type's extremes
// among them.
func TestLimitProxyFileV(t *testing.T) {
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		path := filepath.Join(t.TempDir(), "proxy.json")
		if err := os.WriteFile(path, []byte(`{"v":`+strconv.Itoa(v)+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadProxyFile(path)
		if err == nil || !strings.Contains(err.Error(), "v is "+strconv.Itoa(v)+"; this auu understands version 1") {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}
}

// TestLimitPendingRecordIntegers: an outbox record's bytes and chunks are
// counts and its chunk_size is within [MinChunkSize, MaxChunkSize], as the
// sender wrote them; a record that says otherwise is broken, listed by its
// id and not resumed, before any number is a seek or a count. Zero, the
// bounds and the type's maximum are read. A record from before this wire,
// carrying max_request, is broken by the strict decode: it names an
// upload of a protocol the relay no longer has.
func TestLimitPendingRecordIntegers(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(streamPath(s, id), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, p pending) {
		t.Helper()
		p.MessageID = id
		p.To = strings.Repeat("c", 64)
		p.Relay = "relay"
		p.Started = time.Now()
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pendingPath(s, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := pending{Bytes: 5000, Chunks: 2, ChunkSize: stream.DefaultChunkSize}
	for _, tc := range []struct {
		name string
		p    pending
	}{
		{"bytes -1", pending{Bytes: -1, Chunks: 2, ChunkSize: stream.DefaultChunkSize}},
		{"bytes MinInt64", pending{Bytes: math.MinInt64, Chunks: 2, ChunkSize: stream.DefaultChunkSize}},
		{"chunks -1", pending{Bytes: 5000, Chunks: -1, ChunkSize: stream.DefaultChunkSize}},
		{"chunks MinInt64", pending{Bytes: 5000, Chunks: math.MinInt64, ChunkSize: stream.DefaultChunkSize}},
		{"chunk_size 0", pending{Bytes: 5000, Chunks: 2, ChunkSize: 0}},
		{"chunk_size one under", pending{Bytes: 5000, Chunks: 2, ChunkSize: stream.MinChunkSize - 1}},
		{"chunk_size one over", pending{Bytes: 5000, Chunks: 2, ChunkSize: stream.MaxChunkSize + 1}},
		{"chunk_size MinInt", pending{Bytes: 5000, Chunks: 2, ChunkSize: math.MinInt}},
		{"chunk_size MaxInt", pending{Bytes: 5000, Chunks: 2, ChunkSize: math.MaxInt}},
	} {
		write(t, tc.p)
		waiting, broken, err := listPending(s)
		if err != nil || len(waiting) != 0 || len(broken) != 1 || broken[0] != id {
			t.Errorf("%s: waiting %d, broken %v, %v; want the record broken", tc.name, len(waiting), broken, err)
		}
	}
	for _, tc := range []struct {
		name string
		p    pending
	}{
		{"as written", good},
		{"zero bytes and chunks", pending{ChunkSize: stream.MinChunkSize}},
		{"the type's maximum", pending{Bytes: math.MaxInt64, Chunks: math.MaxInt64, ChunkSize: stream.MaxChunkSize}},
	} {
		write(t, tc.p)
		waiting, broken, err := listPending(s)
		if err != nil || len(waiting) != 1 || len(broken) != 0 {
			t.Errorf("%s: waiting %d, broken %v, %v; want the record read", tc.name, len(waiting), broken, err)
		}
	}
	// A record from before: the old wire's max_request in it.
	old := `{"message_id":"` + id + `","to":"` + strings.Repeat("c", 64) + `","started":"2026-09-19T00:00:00Z","time":"2026-09-19T00:00:00Z","body":{"type":"note","thread":"` + id + `","text":"x"},"bytes":5000,"chunks":2,"chunk_size":` + strconv.Itoa(stream.DefaultChunkSize) + `,"max_request":1048576,"upload":"u"}`
	if err := os.WriteFile(pendingPath(s, id), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 0 || len(broken) != 1 || broken[0] != id {
		t.Errorf("a record from before the wire: waiting %d, broken %v, %v; want it broken by name", len(waiting), broken, err)
	}
}

// TestLimitStreamSettings: the home's stream_threshold is at least
// MinChunkSize and its chunk_size within [MinChunkSize, MaxChunkSize],
// zero meaning the default for each: a negative, the type's minimum, one
// under and, for chunk_size, one over and the type's maximum are refused
// naming the setting; the bounds are taken.
func TestLimitStreamSettings(t *testing.T) {
	for _, tc := range []struct {
		cfg  store.Config
		want string
	}{
		{store.Config{StreamThreshold: stream.MinChunkSize - 1}, "stream_threshold must be at least " + strconv.Itoa(stream.MinChunkSize)},
		{store.Config{StreamThreshold: -1}, "stream_threshold must be at least"},
		{store.Config{StreamThreshold: math.MinInt64}, "stream_threshold must be at least"},
		{store.Config{ChunkSize: stream.MinChunkSize - 1}, "chunk_size must be between"},
		{store.Config{ChunkSize: stream.MaxChunkSize + 1}, "chunk_size must be between"},
		{store.Config{ChunkSize: -1}, "chunk_size must be between"},
		{store.Config{ChunkSize: math.MinInt}, "chunk_size must be between"},
		{store.Config{ChunkSize: math.MaxInt}, "chunk_size must be between"},
	} {
		_, err := settingsFrom(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v; want %q", tc.cfg, err, tc.want)
		}
	}
	for _, cfg := range []store.Config{
		{}, {StreamThreshold: stream.MinChunkSize}, {StreamThreshold: math.MaxInt64},
		{ChunkSize: stream.MinChunkSize}, {ChunkSize: stream.MaxChunkSize},
	} {
		if _, err := settingsFrom(cfg); err != nil {
			t.Errorf("%+v: %v; want it taken", cfg, err)
		}
	}
	s, err := settingsFrom(store.Config{})
	if err != nil || s.threshold != stream.DefaultThreshold || s.chunkSize != stream.DefaultChunkSize {
		t.Errorf("zero is not the default: %+v %v", s, err)
	}
}

// TestLimitWaitAndWatchFlags: auu wait's --interval is at least 5s and
// its --timeout more than nothing; auu watch's --interval is at least 5s
// and its --timeout zero or more; auu unlock's --ttl is zero or more. Each
// is read from text by the flag package: a negative, zero where zero is
// not allowed, one under the floor, a bare number, the text one past the
// type's maximum and a digit outside ASCII are each a usage error before
// anything runs; the floor is taken.
func TestLimitWaitAndWatchFlags(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice := newUser(t, "alice", relayURL)
	gate.lists.Store(0)
	usage := func(t *testing.T, want string, args ...string) {
		t.Helper()
		_, err := alice.tryRun(args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitUsage {
			t.Errorf("%v: %v; want a usage error", args, err)
			return
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %q; want %q in it", args, err.Error(), want)
		}
	}
	thread := strings.Repeat("c", 32)
	// wait
	for _, v := range []string{"4s", "4999999999ns", "0s", "-5s", "-9223372036854775808ns"} {
		usage(t, "--interval must be at least 5s", "wait", "--thread", thread, "--timeout", "1s", "--interval", v)
	}
	for _, v := range []string{"5", "9223372036854775808ns", "\u0665s", "", "x"} {
		usage(t, `invalid value "`+v+`" for flag -interval`, "wait", "--thread", thread, "--timeout", "1s", "--interval", v)
	}
	for _, v := range []string{"0s", "-1s", "-9223372036854775808ns"} {
		usage(t, "--timeout must be more than nothing", "wait", "--thread", thread, "--timeout", v)
	}
	// watch
	for _, v := range []string{"4s", "0s", "-5s"} {
		usage(t, "--interval must be at least 5s", "watch", "--timeout", "1s", "--interval", v)
	}
	for _, v := range []string{"-1s", "-9223372036854775808ns"} {
		usage(t, "--timeout must not be negative", "watch", "--timeout", v)
	}
	usage(t, `invalid value "10" for flag -timeout`, "watch", "--timeout", "10")
	// unlock
	for _, v := range []string{"-1s", "-9223372036854775808ns"} {
		usage(t, "--ttl must not be negative", "unlock", "--ttl", v)
	}
	usage(t, `invalid value "8" for flag -ttl`, "unlock", "--ttl", "8")
	if gate.lists.Load() != 0 {
		t.Fatalf("%d listings were made by commands refused for their flags", gate.lists.Load())
	}
	// The floors are taken: a wait and a watch at them run, and end with
	// their timeouts rather than a usage error.
	for _, args := range [][]string{
		{"watch", "--timeout", "1s", "--interval", "5s"},
		{"wait", "--thread", thread, "--timeout", "1s", "--interval", "5s"},
	} {
		_, err := alice.tryRun(args...)
		var e *exitError
		if asExit(err, &e) && e.code == exitUsage {
			t.Errorf("%v at the floor: %v; want it run", args, err)
		}
	}
}

// TestLimitGroupID: a group id from os/user is digits, zero or more: a
// negative, the type's minimum, the text one past the type's maximum, a
// sign inside the digits, a leading space and a digit outside ASCII are
// refused; zero, a plus sign and the type's maximum are taken.
func TestLimitGroupID(t *testing.T) {
	for _, text := range []string{"-1", strconv.Itoa(math.MinInt), "9223372036854775808", "1-2", " 1", "\u0661", "", "x"} {
		if _, err := parseGid(text); err == nil || !strings.Contains(err.Error(), "is not a group id") {
			t.Errorf("%q: %v; want the refusal", text, err)
		}
	}
	for _, tc := range []struct {
		text string
		want int
	}{{"0", 0}, {"+1", 1}, {"20", 20}, {strconv.Itoa(math.MaxInt), math.MaxInt}} {
		if got, err := parseGid(tc.text); err != nil || got != tc.want {
			t.Errorf("%q: %d %v; want %d", tc.text, got, err, tc.want)
		}
	}
}

// TestLimitProxyAllowUIDs: the uids a proxy file allows are zero or more:
// a negative and the type's minimum are refused naming the uid; zero and
// the type's maximum are taken.
func TestLimitProxyAllowUIDs(t *testing.T) {
	write := func(t *testing.T, uids string) (*proxyFile, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "proxy.json")
		key := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"v":1,"key_file":"`+jsonPath(key)+`","control":"/tmp/x","allow_uids":[`+uids+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadProxyFile(path)
	}
	for _, uids := range []string{"-1", strconv.Itoa(math.MinInt), "1000, -1"} {
		if _, err := write(t, uids); err == nil || !strings.Contains(err.Error(), "which is not a uid") {
			t.Errorf("allow_uids [%s]: %v; want the refusal naming the uid", uids, err)
		}
	}
	for _, uids := range []string{"0", strconv.Itoa(math.MaxInt), "1000, 1001"} {
		if _, err := write(t, uids); err != nil {
			t.Errorf("allow_uids [%s]: %v; want it taken", uids, err)
		}
	}
}

// TestLimitPendingRecordShapes: an outbox record's id and recipient are a
// message id and a fingerprint, held at listPending before a label slices
// twelve of each, and its relay is a relay name; one character short is a
// broken record, and so is a record that names no relay, which is how a
// record from before a home could know more than one was written. The
// relay's key is written for the zero value, so a record without it is
// not one with the default.
func TestLimitPendingRecordShapes(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, id, to string, relay ...string) {
		t.Helper()
		if err := os.WriteFile(streamPath(s, id), []byte("sealed"), 0o600); err != nil {
			t.Fatal(err)
		}
		p := pending{MessageID: id, To: to, Relay: "relay", Started: time.Now(), ChunkSize: stream.DefaultChunkSize}
		if len(relay) > 0 {
			p.Relay = relay[0]
		}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pendingPath(s, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	shortID, fullID := strings.Repeat("b", 31), strings.Repeat("b", 32)
	write(t, shortID, strings.Repeat("c", 64))
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 0 || len(broken) != 1 || broken[0] != shortID {
		t.Errorf("an id one short: waiting %d, broken %v, %v; want the record broken", len(waiting), broken, err)
	}
	os.Remove(pendingPath(s, shortID))
	os.Remove(streamPath(s, shortID))
	write(t, fullID, strings.Repeat("c", 63))
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 0 || len(broken) != 1 || broken[0] != fullID {
		t.Errorf("a recipient one short: waiting %d, broken %v, %v; want the record broken", len(waiting), broken, err)
	}
	for _, relay := range []string{"", "../x"} {
		write(t, fullID, strings.Repeat("c", 64), relay)
		if waiting, broken, err := listPending(s); err != nil || len(waiting) != 0 || len(broken) != 1 || broken[0] != fullID {
			t.Errorf("relay %q: waiting %d, broken %v, %v; want the record broken", relay, len(waiting), broken, err)
		}
	}
	write(t, fullID, strings.Repeat("c", 64))
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 1 || len(broken) != 0 {
		t.Errorf("as written: waiting %d, broken %v, %v; want the record read", len(waiting), broken, err)
	}
	data, err := json.Marshal(&pending{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"relay":""`) {
		t.Errorf("the zero record marshals without its relay key: %s", data)
	}
}

// TestLimitAnchorArgsOneShort: the anchor hash auu init, auu relay add and
// auu anchor pin take is a fingerprint's shape, held before the command
// prints its first sixteen characters; one character short is a usage
// error naming the shape, and no relay is asked.
func TestLimitAnchorArgsOneShort(t *testing.T) {
	relayURL, gate := startGatedRelay(t)
	alice := newUser(t, "alice", relayURL)
	gate.lists.Store(0)
	short := strings.Repeat("a", 63)
	for _, args := range [][]string{
		{"relay", "add", relayURL, "--name", "other", "--anchor", short},
		{"anchor", "pin", short},
	} {
		_, err := alice.tryRun(args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "64 lowercase hex characters") {
			t.Errorf("%v: %v; want a usage error naming the shape", args, err)
		}
	}
	fresh := &user{t: t, home: t.TempDir()}
	_, err := fresh.tryRun("init", "--name", "carol", "--relay", relayURL, "--anchor", short)
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "64 lowercase hex characters") {
		t.Errorf("init --anchor one short: %v; want a usage error naming the shape", err)
	}
	if gate.lists.Load() != 0 {
		t.Errorf("%d listings were made for anchors refused for their shape", gate.lists.Load())
	}
}

// TestLimitServeAndProxyPathsResolveAgainstTheirFile: a relative path in
// serve.json — a channel's dir, the proxy's key_file and control — or in
// proxy.json — key_file and control — is resolved against the file's own
// directory, never the working directory a wrapper started the command
// in; an absolute one is left as it is.
func TestLimitServeAndProxyPathsResolveAgainstTheirFile(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the PATH")
	}
	fileDir := t.TempDir()
	elsewhere := t.TempDir()
	t.Chdir(elsewhere)
	// A checkout beside the file, named relatively.
	repo := filepath.Join(fileDir, "checkout")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	key := filepath.Join(fileDir, "key")
	if err := os.WriteFile(key, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(t.TempDir(), "control.sock")
	serve := filepath.Join(fileDir, "serve.json")
	if err := os.WriteFile(serve, []byte(`{"v":1,"channels":{"work":{"dir":"checkout","exec":"cat"}},"proxy":{"key_file":"key","control":`+strconv.Quote(abs)+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadServeConfig(serve)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Channels["work"].Dir; got != repo {
		t.Errorf("dir resolved to %q, want %q", got, repo)
	}
	if got := cfg.Proxy.KeyFile; got != key {
		t.Errorf("proxy key_file resolved to %q, want %q", got, key)
	}
	if got := cfg.Proxy.Control; got != abs {
		t.Errorf("proxy control, absolute, became %q", got)
	}
	// key_file and control are one or the other; the resolution of each is
	// what is shown here, and check is run over a file with the key alone.
	if err := os.WriteFile(serve, []byte(`{"v":1,"channels":{"work":{"dir":"checkout","exec":"cat"}},"proxy":{"key_file":"key"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if only, err := loadServeConfig(serve); err != nil {
		t.Fatal(err)
	} else if err := only.check(); err != nil {
		t.Errorf("the file checked from another directory: %v", err)
	}
	for _, got := range []string{cfg.Channels["work"].Dir, cfg.Proxy.KeyFile} {
		if rel, err := filepath.Rel(elsewhere, got); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("%q resolved under the working directory", got)
		}
	}

	proxy := filepath.Join(fileDir, "proxy.json")
	if err := os.WriteFile(proxy, []byte(`{"v":1,"key_file":"key","control":"run/control.sock"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := loadProxyFile(proxy)
	if err != nil {
		t.Fatal(err)
	}
	if f.KeyFile != key {
		t.Errorf("proxy.json key_file resolved to %q, want %q", f.KeyFile, key)
	}
	if want := filepath.Join(fileDir, "run", "control.sock"); f.Control != want {
		t.Errorf("proxy.json control resolved to %q, want %q", f.Control, want)
	}
}

// pathSet is the limit guide's traversal set, as the store's tests have it.
func pathSet() []string {
	return []string{"..", "../x", "x/../../y", "a/b", "/etc/passwd", `..\x`, `C:\x`, "C:x", "CON", "com1.txt", "\x00", "", ".", strings.Repeat("a", 300)}
}

// TestLimitThreadIDIsNotAPathAtServe: a thread id names a directory and a
// worktree under the serve directory, and worktreeFor runs message.ValidID
// before the join, as handle does before it; threadName quotes one that
// is not an id rather than print it as a path. Each is fed the traversal
// set, worktreeFor refuses it, and nothing appears beside the serve
// directory.
func TestLimitThreadIDIsNotAPathAtServe(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the PATH")
	}
	scratch := t.TempDir()
	root := filepath.Join(scratch, "serve")
	repo := filepath.Join(scratch, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	ch := &serveChannel{name: "c", Dir: repo, Exec: "cat", Mode: modeSideCopy}
	for _, v := range pathSet() {
		if _, _, err := worktreeFor(root, ch, v, filepath.Join(root, "state"), true); err == nil || !strings.Contains(err.Error(), "not a message id") {
			t.Errorf("worktreeFor took the thread id %q: %v", v, err)
		}
		if name := threadName(v); !strings.HasPrefix(name, `"`) {
			t.Errorf("threadName printed %q as a thread: %q", v, name)
		}
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "serve" && e.Name() != "repo" {
			t.Errorf("a thread id from the traversal set made %q beside the serve directory", e.Name())
		}
	}
	if _, err := os.Stat(root); err == nil {
		if under, _ := os.ReadDir(root); len(under) != 0 {
			t.Errorf("a refused thread id left %d entries under the serve directory", len(under))
		}
	}
}

// TestLimitAttachmentNameIsNotAPathAtExtract: an attachment's name becomes
// a file under the directory extract was given, through message.SafeName
// and the unique loop at the write; a record carrying a name from the
// traversal set is not refused but written under the safe name, one file
// per record, under the directory and nowhere else, and the line extract
// prints says the sender's name differs.
func TestLimitAttachmentNameIsNotAPathAtExtract(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range pathSet() {
		if v == "\x00" || len(v) > 255 {
			// Refused as text at Open, never a record; the sender's rule
			// refuses them too (TestLimitNamesAreNotPathsAtValidate).
			continue
		}
		scratch := t.TempDir()
		out := filepath.Join(scratch, "out")
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		m := &store.Stored{Relay: "relay", Inner: &envelope.Inner{
			ID: strings.Repeat("a", 32), Time: time.Now(),
			Body: message.Body{Type: message.TypeNote, Thread: strings.Repeat("a", 32), Text: "hi",
				Attachments: []message.Attachment{rawAttachment(v, []byte("hi"))}},
		}}
		written, err := extractInto(s, store.Inbox, m, out)
		if err != nil || len(written) != 1 {
			t.Errorf("extractInto with the name %q: %v, %v; want one file written", v, written, err)
			continue
		}
		want := filepath.Join(out, message.SafeName(v))
		if written[0] != want {
			t.Errorf("the name %q was written as %q, want %q", v, written[0], want)
		}
		if data, err := os.ReadFile(want); err != nil || string(data) != "hi" {
			t.Errorf("the name %q: %q, %v", v, data, err)
		}
		entries, err := os.ReadDir(scratch)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != "out" {
			t.Errorf("the name %q reached beside its directory: %v", v, entries)
		}
		if under, _ := os.ReadDir(out); len(under) != 1 {
			t.Errorf("the name %q left %d entries in the directory", v, len(under))
		}
		if line := wroteLine(written[0], m.Inner.Body.Attachments[0]); v != message.SafeName(v) && !strings.Contains(line, "the sender named it") {
			t.Errorf("the line for %q does not say the sender's name differs: %s", v, line)
		}
	}
}

// TestLimitThreadsDirectoryEntries: the sweep reads the threads directory
// back and lets go of what has gone idle by each entry's name; an entry
// that is not a thread id — a file, a stray directory, a name with a
// separator's cousin in it — is not serve's, is never joined onto the
// worktrees directory, and survives the sweep.
func TestLimitThreadsDirectoryEntries(t *testing.T) {
	alice, bob := newExpert(t, modeSideCopy)
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.serve(t)
	threads := filepath.Join(bob.home, "serve", "threads")
	strays := []string{"stray", "..x", "CON", strings.Repeat("b", 31)}
	for _, name := range strays {
		if err := os.MkdirAll(filepath.Join(threads, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(threads, "a-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bob.row.ThreadTTL = "1ms"
	bob.write(t)
	time.Sleep(5 * time.Millisecond)
	stderr := captureStderr(t, func() { bob.serve(t) })
	if !strings.Contains(stderr, "thread "+shortID(sent.Thread)+" has been idle") {
		t.Fatalf("the sweep did not let go of the real thread:\n%s", stderr)
	}
	for _, name := range append(strays, "a-file") {
		if _, err := os.Stat(filepath.Join(threads, name)); err != nil {
			t.Errorf("the sweep touched %q, which is not a thread: %v", name, err)
		}
		if strings.Contains(stderr, name) {
			t.Errorf("the sweep spoke of %q, which is not a thread:\n%s", name, stderr)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(bob.home, "serve", "worktrees")); len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("worktrees holds %v after the sweep", names)
	}
}

// TestLimitOutboxDirectoryEntries: listPending reads the outbox by its
// entries and joins each onto the directory; a directory, a file that is
// not a record, and a record whose id is not its file's name or not a
// message id — a Windows device, a dot-dot form — are skipped or listed
// as broken by the name alone, the record this program wrote is read,
// and nothing beside the home is touched.
func TestLimitOutboxDirectoryEntries(t *testing.T) {
	scratch := t.TempDir()
	witness := filepath.Join(scratch, "witness")
	if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(scratch, "home"))
	if err != nil {
		t.Fatal(err)
	}
	dir := outboxDir(s)
	if err := os.MkdirAll(filepath.Join(dir, "x.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	good := strings.Repeat("b", 32)
	record := func(name, id string) {
		t.Helper()
		data, err := json.Marshal(pending{MessageID: id, To: strings.Repeat("c", 64), Relay: "relay", Started: time.Now(), ChunkSize: stream.DefaultChunkSize})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	record(good+".json", good)
	if err := os.WriteFile(streamPath(s, good), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	record("CON.json", "CON")
	record("com1.json", "../x")
	record(strings.Repeat("a", 32)+".json", "..")
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	waiting, broken, err := listPending(s)
	if err != nil {
		t.Fatalf("listPending failed on a stray entry: %v", err)
	}
	if len(waiting) != 1 || waiting[0].MessageID != good {
		t.Errorf("waiting %d; want the one record this program wrote", len(waiting))
	}
	sort.Strings(broken)
	if want := []string{"CON", strings.Repeat("a", 32), "com1"}; strings.Join(broken, ",") != strings.Join(want, ",") {
		t.Errorf("broken %q; want %q, each by its file's name", broken, want)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("an outbox entry reached beside the home: %v", names)
	}
	if _, err := os.Stat(witness); err != nil {
		t.Errorf("the witness beside the home is gone: %v", err)
	}
}

// TestLimitThreadIDIsNotAPathAtServeLs: serve ls prints the threads the
// ledger holds and joins one onto the worktrees directory to say whether
// its worktree is there; a ledger written by hand with threads from the
// traversal set lists each quoted, with no worktree, and makes nothing.
func TestLimitThreadIDIsNotAPathAtServeLs(t *testing.T) {
	_, bob := newExpert(t, modeSideCopy)
	root := filepath.Join(bob.home, "serve")
	led, err := loadLedger(filepath.Join(root, ledgerFile))
	if err != nil {
		t.Fatal(err)
	}
	set := pathSet()
	for i, v := range set {
		led.Messages[fmt.Sprintf("%032x", i)] = &ledgerEntry{Thread: v, Channel: "jostle", Handled: time.Now()}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := led.save(); err != nil {
		t.Fatal(err)
	}
	var out serveLsJSON
	if err := json.Unmarshal([]byte(bob.run("serve", "ls", "--json")), &out); err != nil {
		t.Fatal(err)
	}
	listed := 0
	for _, ch := range out.Channels {
		for _, th := range ch.Threads {
			listed++
			if th.Worktree != "" {
				t.Errorf("thread %q was joined onto the worktrees directory: %q", th.Thread, th.Worktree)
			}
		}
	}
	if listed != len(set) {
		t.Errorf("listed %d threads; want %d", listed, len(set))
	}
	text := bob.run("serve", "ls")
	for _, v := range set {
		if v == "" || v == "." || v == ".." {
			continue
		}
		if strings.Contains(text, "  "+shortID(v)+"  ") {
			t.Errorf("serve ls printed %q as a thread, not quoted:\n%s", v, text)
		}
	}
	if _, err := os.Stat(filepath.Join(bob.home, "serve", "worktrees")); err == nil {
		t.Errorf("serve ls made the worktrees directory")
	}
}

// TestLimitProxyListenIsAnAddressNotAPath: the proxy's listen is a
// loopback host:port, held by the proxy config's check; a value from the
// traversal set is refused as not host:port or not loopback, and the
// proxy is never started on it.
func TestLimitProxyListenIsAnAddressNotAPath(t *testing.T) {
	for _, v := range pathSet() {
		if v == "" {
			// Empty is the default, 127.0.0.1:0.
			continue
		}
		p := &proxyConfig{Listen: v, KeyFile: "key"}
		p.fill()
		if err := p.check(&serveConfig{path: "serve.json"}); err == nil {
			t.Errorf("listen %q was taken", v)
		}
	}
}

// TestLimitExtractionWritesSafeUniqueNames: a message with attachments
// named `../x`, `CON`, `a<b>.txt`, `.bashrc`, `A.txt`, `a.txt`, an empty
// name, a 250-byte name and a 200-byte name twice — every one but the
// last a name the sender's rule refuses,
// carried past it here as a stranger's client would — is opened, saved,
// listed and extracted into a directory that already holds A.txt. Every
// file is written under its safe name, made unique at the write: x, _CON,
// a_b_.txt, _bashrc, A-2.txt (A.txt stood there), attachment, and the
// long name cut; a.txt is a.txt where the disk tells it from A.txt and
// a-3.txt where it does not (a.txt being A.txt and a-2.txt the A-2.txt
// just made), which the test asks the disk. The contents
// are by digest, the report lines say the sender's name where it
// differs, a witness outside is untouched, the existing A.txt is as it
// was, and nothing else is in the directory — no temporary left behind.
// Shown on both write paths: the link, and the copy a filesystem that
// refuses links gets.
func TestLimitExtractionWritesSafeUniqueNames(t *testing.T) {
	onEachWritePath(t, extractionWritesSafeUniqueNames)
}

// onEachWritePath runs body with the name taken by the link and then by
// the exclusive create and copy, the path a filesystem that refuses hard
// links takes.
func onEachWritePath(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	for _, links := range []bool{true, false} {
		name := "by the link"
		if !links {
			name = "by the create and the copy"
		}
		t.Run(name, func(t *testing.T) {
			hardLinks = links
			t.Cleanup(func() { hardLinks = true })
			body(t)
		})
	}
}

func extractionWritesSafeUniqueNames(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	out := filepath.Join(scratch, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	witness := filepath.Join(scratch, "witness")
	if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "A.txt"), []byte("already here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Does this disk tell a.txt from A.txt?
	folds := false
	if _, err := os.Stat(filepath.Join(out, "a.txt")); err == nil {
		folds = true
	}
	// 250 bytes: over the 200 SafeName keeps, under the 255 a name may be
	// as text (300 would be refused at Open and at the write alike).
	long := strings.Repeat("n", 250)
	// A 200-byte name whose extension is 199 bytes, twice: a fixed point
	// the sender may ship, and the second copy takes the numbered name,
	// which the first draft of Numbered panicked on (the second reader's
	// finding: a slice bound below zero).
	wide := "x." + strings.Repeat("a", 198)
	names := []string{"../x", "CON", "a<b>.txt", ".bashrc", "A.txt", "a.txt", "", long, wide, wide}
	var atts []message.Attachment
	for i, name := range names {
		atts = append(atts, rawAttachment(name, []byte(fmt.Sprintf("file %d\n", i))))
	}
	id := strings.Repeat("d", 32)
	m := &store.Stored{Relay: "relay", Inner: &envelope.Inner{
		ID: id, Time: time.Now().UTC(), From: strings.Repeat("e", 64), To: strings.Repeat("f", 64),
		Body: message.Body{Type: message.TypeNote, Thread: id, Text: "odd names", Attachments: atts},
	}}
	if err := s.Save(store.Inbox, m); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(store.Inbox, id); err != nil {
		t.Fatalf("Load refused a record for its attachment names: %v", err)
	}
	written, err := extractInto(s, store.Inbox, m, out)
	if err != nil {
		t.Fatalf("extractInto: %v", err)
	}
	want := []string{"x", "_CON", "a_b_.txt", "_bashrc", "A-2.txt", "a.txt", "attachment", long[:200], wide, "x." + strings.Repeat("a", 196) + "-2"}
	if folds {
		// a.txt is A.txt, which stood there, and a-2.txt is A-2.txt, which
		// the attachment before it just made.
		want[5] = "a-3.txt"
	}
	if len(written) != len(want) {
		t.Fatalf("wrote %v, want %d files", written, len(want))
	}
	for i, path := range written {
		if filepath.Base(path) != want[i] || filepath.Dir(path) != out {
			t.Errorf("attachment %d (%q) was written as %q, want %q under %s", i, names[i], path, want[i], out)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != fmt.Sprintf("file %d\n", i) {
			t.Errorf("attachment %d: %q, %v", i, data, err)
		}
		line := wroteLine(path, atts[i])
		if differs := want[i] != names[i]; differs != strings.Contains(line, "the sender named it") {
			t.Errorf("attachment %d: the line %q; the name differs: %v", i, line, differs)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(out, "A.txt")); string(data) != "already here\n" {
		t.Errorf("the A.txt that stood there was touched: %q", data)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want)+1 {
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		t.Errorf("the directory holds %v; want the %d files and A.txt", got, len(want))
	}
	if beside, _ := os.ReadDir(scratch); len(beside) != 2 {
		t.Errorf("something appeared beside the directory: %d entries", len(beside))
	}
	if data, _ := os.ReadFile(witness); string(data) != "keep me\n" {
		t.Errorf("the witness was touched: %q", data)
	}
}

// rawAttachment is an inline attachment exactly as given, name and all,
// with its size and digest right: what a client that is not auu's might
// send, past the sender's rule.
func rawAttachment(name string, data []byte) message.Attachment {
	sum := sha256.Sum256(data)
	return message.Attachment{Name: name, Media: "application/octet-stream", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Data: data}
}

// TestLimitAStreamExtractsUnderSafeUniqueNames: the stream form of the
// same. A manifest built with plain names and changed under the seal to
// `../x`, `CON`, `A.txt`, `a.txt` and an empty name — past the sender's
// rule, as a client that is not auu's could — is opened and delivered
// into a home's spool by position, saved as a streamed record with the
// sender's names, and extracted into a directory that already holds
// A.txt: every file under its safe name, unique at the write, with the
// bytes the sender sent, and nothing beside the directory. On both write
// paths.
func TestLimitAStreamExtractsUnderSafeUniqueNames(t *testing.T) {
	onEachWritePath(t, aStreamExtractsUnderSafeUniqueNames)
}

func aStreamExtractsUnderSafeUniqueNames(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"../x", "CON", "A.txt", "a.txt", ""}
	var sources []stream.Source
	for i := range names {
		data := []byte(fmt.Sprintf("stream file %d\n", i))
		sources = append(sources, stream.Source{Name: fmt.Sprintf("plain%d.bin", i), Media: "application/octet-stream", Size: int64(len(data)),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }})
	}
	id := strings.Repeat("e", 32)
	m, err := stream.BuildManifest(alice, bob.Public(), id, stream.Body{Type: "note", Thread: id, Text: "odd names"}, sources, stream.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		m.Attachments[i].Name = name
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, alice, bob.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	full := blob.Bytes()
	n, err := stream.ManifestLength(full[:stream.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	opened, err := stream.OpenManifest(bob, full[:stream.HeaderSize], full[stream.HeaderSize:stream.HeaderSize+n])
	if err != nil {
		t.Fatalf("a received manifest with odd names: %v", err)
	}
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.AttachmentDir(store.Inbox, id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := opened.ToDirectory(bytes.NewReader(full[stream.HeaderSize+n:]), dir); err != nil {
		t.Fatalf("ToDirectory: %v", err)
	}
	inner := &envelope.Inner{From: alice.Fingerprint(), To: bob.Fingerprint(), ID: id, Time: time.Now().UTC(),
		Body: message.Body{Type: message.TypeNote, Thread: id, Text: "odd names"}}
	for _, a := range opened.Manifest.Attachments {
		inner.Body.Attachments = append(inner.Body.Attachments, message.Attachment{Name: a.Name, Media: a.Media, Size: a.Size, SHA256: a.SHA256})
	}
	rec := &store.Stored{Relay: "relay", Inner: inner, Streamed: true, Received: time.Now().UTC()}
	if err := s.Save(store.Inbox, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(store.Inbox, id); err != nil {
		t.Fatalf("Load refused the streamed record for its names: %v", err)
	}
	scratch := t.TempDir()
	out := filepath.Join(scratch, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "A.txt"), []byte("already here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	folds := false
	if _, err := os.Stat(filepath.Join(out, "a.txt")); err == nil {
		folds = true
	}
	written, err := extractInto(s, store.Inbox, rec, out)
	if err != nil {
		t.Fatalf("extractInto: %v", err)
	}
	want := []string{"x", "_CON", "A-2.txt", "a.txt", "attachment"}
	if folds {
		want[3] = "a-3.txt"
	}
	if len(written) != len(want) {
		t.Fatalf("wrote %v, want %d files", written, len(want))
	}
	for i, path := range written {
		if filepath.Base(path) != want[i] || filepath.Dir(path) != out {
			t.Errorf("attachment %d (%q) was written as %q, want %q", i, names[i], path, want[i])
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != fmt.Sprintf("stream file %d\n", i) {
			t.Errorf("attachment %d: %q, %v", i, data, err)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(out, "A.txt")); string(data) != "already here\n" {
		t.Errorf("the A.txt that stood there was touched: %q", data)
	}
	if entries, _ := os.ReadDir(out); len(entries) != len(want)+1 {
		t.Errorf("the directory holds %d entries; want %d", len(entries), len(want)+1)
	}
	if beside, _ := os.ReadDir(scratch); len(beside) != 1 {
		t.Errorf("something appeared beside the directory: %d entries", len(beside))
	}
}

// TestLimitTheNumberedSuffixHasACeiling: the loop that makes an
// attachment's name unique at the write tries the name and then
// name-2, name-3, … up to maxNameTries, a thousand, and then refuses the
// directory by name with the count, rather than trying for ever in a
// directory somebody keeps full. With 999 names standing — the name and
// name-2 … name-999 — the extract writes name-1000, the last the loop
// tries; with the thousandth standing too it is refused naming the
// directory and the count, writes nothing under the name, and leaves no
// temporary, the thousand files as they were. On both write paths, the
// link and the copy a filesystem that refuses links gets.
func TestLimitTheNumberedSuffixHasACeiling(t *testing.T) {
	onEachWritePath(t, theNumberedSuffixHasACeiling)
}

func theNumberedSuffixHasACeiling(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 32)
	m := &store.Stored{Relay: "relay", Inner: &envelope.Inner{
		ID: id, Time: time.Now().UTC(), From: strings.Repeat("e", 64), To: strings.Repeat("f", 64),
		Body: message.Body{Type: message.TypeNote, Thread: id, Text: "full", Attachments: []message.Attachment{rawAttachment("report.txt", []byte("the bytes\n"))}},
	}}
	if err := s.Save(store.Inbox, m); err != nil {
		t.Fatal(err)
	}
	plant := func(t *testing.T, dir string, upTo int) {
		t.Helper()
		for n := 1; n <= upTo; n++ {
			if err := os.WriteFile(filepath.Join(dir, message.Numbered("report.txt", n)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// One under the ceiling: the thousandth name is the one written.
	under := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(under, 0o700); err != nil {
		t.Fatal(err)
	}
	plant(t, under, maxNameTries-1)
	written, err := extractInto(s, store.Inbox, m, under)
	if err != nil || len(written) != 1 || written[0] != filepath.Join(under, "report-1000.txt") {
		t.Fatalf("with %d names standing: wrote %v, %v; want report-1000.txt", maxNameTries-1, written, err)
	}
	if data, err := os.ReadFile(written[0]); err != nil || string(data) != "the bytes\n" {
		t.Fatalf("report-1000.txt holds %q, %v", data, err)
	}
	if entries, _ := os.ReadDir(under); len(entries) != maxNameTries {
		t.Errorf("the directory holds %d entries after the write, want %d", len(entries), maxNameTries)
	}
	// At the ceiling: refused by name, and nothing written or left.
	at := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(at, 0o700); err != nil {
		t.Fatal(err)
	}
	plant(t, at, maxNameTries)
	written, err = extractInto(s, store.Inbox, m, at)
	want := fmt.Sprintf("%s holds %d files named like %q already; choose another --out directory", at, maxNameTries, "report.txt")
	if err == nil || err.Error() != want {
		t.Fatalf("with %d names standing: %v\nwant %s", maxNameTries, err, want)
	}
	if len(written) != 0 {
		t.Errorf("the refusal reported %v written", written)
	}
	entries, err := os.ReadDir(at)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxNameTries {
		t.Errorf("the directory holds %d entries after the refusal, want the %d planted and no temporary", len(entries), maxNameTries)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if info.Size() != 0 || strings.HasPrefix(e.Name(), tempPrefix) {
			t.Errorf("%s: size %d; want the empty file planted", e.Name(), info.Size())
		}
	}
}

// TestLimitASenderDoesNotShipANameTheReceiverWouldChange: auu send
// --attach of a file whose name a receiver would write differently is
// refused as a usage error naming the step, inline and as a stream, and
// nothing is posted; the same names are what the receiver's tests above
// write safely, so an honest sender is told and a dishonest one changes
// nothing.
func TestLimitASenderDoesNotShipANameTheReceiverWouldChange(t *testing.T) {
	alice, bob := twoPeers(t)
	dir := t.TempDir()
	for _, tc := range []struct{ name, says string }{
		{".bashrc", "begins with a dot"},
		{"a<b>.txt", "Windows forbids"},
		{"CON", "device name on Windows"},
		{"report.txt.", "Windows strips"},
		{"x ", "Windows strips"},
		{"file‮.txt", "format character"},
		{strings.Repeat("n", 201) + ".txt", "over 200"},
	} {
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("%q: this disk cannot hold the name: %v", tc.name, err)
		}
		for _, form := range [][]string{
			{"send", "--to", "bob", "--attach", path, "an odd name"},
			{"send", "--to", "bob", "--stream", "--attach", path, "an odd name"},
		} {
			out, err := alice.tryRun(form...)
			var exit *exitError
			if !errors.As(err, &exit) || exit.code != exitUsage || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("%v: %v\n%s\nwant a usage error saying %q", form, err, out, tc.says)
			}
		}
		os.Remove(path)
	}
	var got inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 0 {
		t.Errorf("bob received %d messages from refused sends", len(got.Messages))
	}
}

// TestLimitRmWholeIDOneShort: rm removes a record Load refuses by its
// whole id and nothing shorter: an id one character short is a prefix,
// which cannot name an unreadable record, so rm says no message matches
// and the record stays; the whole id removes it. The id is held to
// ValidID at cmdRm before rmUnreadable prints its first twelve.
func TestLimitRmWholeIDOneShort(t *testing.T) {
	alice, bob := twoPeers(t)
	alice.run("send", "--to", "bob", "--subject", "kept", "one")
	bob.run("inbox")
	m := recordOf(t, bob, store.Inbox, "kept")
	path := filepath.Join(bob.home, "inbox", m.Inner.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"thread": "`, `"thread": "zz`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.tryRun("rm", m.Inner.ID[:31]); err == nil || !strings.Contains(err.Error(), "no message matches") {
		t.Errorf("rm of an id one short: %v; want no match", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("an id one short removed the record: %v", err)
	}
	if out := bob.run("rm", m.Inner.ID); !strings.Contains(out, "removed here (the record could not be read)") {
		t.Errorf("rm of the whole id: %s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the record is still there: %v", err)
	}
}
