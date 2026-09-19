package auu

import (
	"encoding/json"
	"fmt"
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
		write(t, `{"v":1,"messages":{"`+id+`":{"thread":"`+id+`","failures":`+strconv.Itoa(n)+`}}}`)
		l, err := loadLedger(path)
		if err != nil || l.Messages[id] == nil || l.Messages[id].Failures != n {
			t.Errorf("failures %d: %v; want it read", n, err)
		}
	}
	write(t, `{"v":1,"messages":{"`+id+`":null}}`)
	if _, err := loadLedger(path); err == nil || !strings.Contains(err.Error(), "has no entry under") {
		t.Errorf("a null entry: %v; want the refusal", err)
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

// TestLimitPendingRecordIntegers: an outbox record's bytes, chunks and
// max_request are counts and its chunk_size is within [MinChunkSize,
// MaxChunkSize], as the sender wrote them; a record that says otherwise is
// broken, listed by its id and not resumed, before any number is a seek,
// a piece or a count. Zero, the bounds and the type's maximum are read.
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
		p.Started = time.Now()
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pendingPath(s, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := pending{Bytes: 5000, Chunks: 2, ChunkSize: stream.DefaultChunkSize, MaxRequest: 1 << 20}
	for _, tc := range []struct {
		name string
		p    pending
	}{
		{"bytes -1", pending{Bytes: -1, Chunks: 2, ChunkSize: stream.DefaultChunkSize}},
		{"bytes MinInt64", pending{Bytes: math.MinInt64, Chunks: 2, ChunkSize: stream.DefaultChunkSize}},
		{"chunks -1", pending{Bytes: 5000, Chunks: -1, ChunkSize: stream.DefaultChunkSize}},
		{"chunks MinInt64", pending{Bytes: 5000, Chunks: math.MinInt64, ChunkSize: stream.DefaultChunkSize}},
		{"max_request -1", pending{Bytes: 5000, Chunks: 2, ChunkSize: stream.DefaultChunkSize, MaxRequest: -1}},
		{"max_request MinInt64", pending{Bytes: 5000, Chunks: 2, ChunkSize: stream.DefaultChunkSize, MaxRequest: math.MinInt64}},
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
		{"zero bytes, chunks and max_request", pending{ChunkSize: stream.MinChunkSize}},
		{"the type's maximum", pending{Bytes: math.MaxInt64, Chunks: math.MaxInt64, ChunkSize: stream.MaxChunkSize, MaxRequest: math.MaxInt64}},
	} {
		write(t, tc.p)
		waiting, broken, err := listPending(s)
		if err != nil || len(waiting) != 1 || len(broken) != 0 {
			t.Errorf("%s: waiting %d, broken %v, %v; want the record read", tc.name, len(waiting), broken, err)
		}
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
// twelve of each; one character short is a broken record.
func TestLimitPendingRecordShapes(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, id, to string) {
		t.Helper()
		if err := os.WriteFile(streamPath(s, id), []byte("sealed"), 0o600); err != nil {
			t.Fatal(err)
		}
		p := pending{MessageID: id, To: to, Started: time.Now(), ChunkSize: stream.DefaultChunkSize}
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
	write(t, fullID, strings.Repeat("c", 64))
	if waiting, broken, err := listPending(s); err != nil || len(waiting) != 1 || len(broken) != 0 {
		t.Errorf("as written: waiting %d, broken %v, %v; want the record read", len(waiting), broken, err)
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
// a file under the directory extract was given, through
// ValidAttachmentName at Validate and filepath.Base at the write; a record
// carrying a name from the traversal set is refused at the write, and
// nothing appears outside the directory.
func TestLimitAttachmentNameIsNotAPathAtExtract(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	out := filepath.Join(scratch, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, v := range pathSet() {
		m := &store.Stored{Inner: &envelope.Inner{
			ID: strings.Repeat("a", 32), Time: time.Now(),
			Body: message.Body{Type: message.TypeNote, Thread: strings.Repeat("a", 32), Text: "hi",
				Attachments: []message.Attachment{{Name: v, Media: "text/plain", Size: 2, SHA256: strings.Repeat("0", 64), Data: []byte("hi")}}},
		}}
		written, err := extractInto(s, store.Inbox, m, out)
		if err == nil {
			t.Errorf("extractInto took the name %q and wrote %v", v, written)
		}
		for _, w := range written {
			if rel, err := filepath.Rel(out, w); err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				t.Errorf("extractInto wrote %q outside %s for the name %q", w, out, v)
			}
		}
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out" {
		t.Errorf("extract reached beside its directory: %v", entries)
	}
	if under, _ := os.ReadDir(out); len(under) != 0 {
		t.Errorf("a refused name left %d entries in the directory", len(under))
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
		data, err := json.Marshal(pending{MessageID: id, To: strings.Repeat("c", 64), Started: time.Now(), ChunkSize: stream.DefaultChunkSize})
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
