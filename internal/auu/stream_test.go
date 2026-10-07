package auu

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// A message large enough becomes a stream without anybody asking, and arrives
// byte for byte.
func TestStreamEndToEnd(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// Comfortably over the 64 KiB threshold and several chunks long.
	payload := make([]byte, 400<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	file := filepath.Join(t.TempDir(), "dump.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	out := alice.run("send", "--to", "bob", "--subject", "a big one",
		"--attach", file, "--json", "look at this")
	var sent sentJSON
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("send --json unparseable: %v\n%s", err, out)
	}
	if sent.Kind != "stream" {
		t.Fatalf("a %d byte message was sent as %q", len(payload), sent.Kind)
	}
	if sent.ChunkSize != stream.DefaultChunkSize {
		t.Fatalf("chunk size %d, want the default %d", sent.ChunkSize, stream.DefaultChunkSize)
	}
	if want := stream.ChunkCount(int64(len(payload)), stream.DefaultChunkSize); sent.Chunks != want {
		t.Fatalf("chunks %d, want %d", sent.Chunks, want)
	}

	// The outbox is empty again: the sealed copy is removed once it is sent.
	if entries, err := os.ReadDir(filepath.Join(alice.home, "outbox")); err == nil && len(entries) != 0 {
		t.Fatalf("%d files left in the outbox", len(entries))
	}

	inbox := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(inbox), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, inbox)
	}
	if got.Fetch.Delivered != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	if len(got.Messages) != 1 || got.Messages[0].Subject != "a big one" {
		t.Fatalf("unexpected inbox: %+v", got.Messages)
	}

	// The bytes are on disk, verified against the manifest's digest.
	dir := t.TempDir()
	bob.run("extract", got.Messages[0].ID, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "dump.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("the payload did not survive: %d bytes back, %d sent", len(back), len(payload))
	}
	want := sha256.Sum256(payload)
	back2 := sha256.Sum256(back)
	if hex.EncodeToString(want[:]) != hex.EncodeToString(back2[:]) {
		t.Fatal("digest mismatch after a round trip")
	}

	// And the relay is empty: a delivered stream is acknowledged.
	second := bob.run("inbox", "--json")
	var again inboxJSON
	if err := json.Unmarshal([]byte(second), &again); err != nil {
		t.Fatal(err)
	}
	if again.Fetch.Delivered != 0 {
		t.Fatalf("a delivered stream was fetched twice: %+v", again.Fetch)
	}
}

// The threshold decides, and both sides of it are tested.
func TestStreamThresholdBoundary(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// The estimate is raw + raw/3, so a payload of n weighs n + n/3.
	kind := func(t *testing.T, n int, extra ...string) string {
		t.Helper()
		file := filepath.Join(t.TempDir(), "f.bin")
		if err := os.WriteFile(file, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"send", "--to", "bob", "--subject", "s",
			"--attach", file, "--json", "t"}, extra...)
		var sent sentJSON
		if err := json.Unmarshal([]byte(alice.run(args...)), &sent); err != nil {
			t.Fatal(err)
		}
		return sent.Kind
	}

	// Well under: an envelope. Well over: a stream.
	if k := kind(t, 1<<10); k != "envelope" {
		t.Fatalf("a 1 KiB message went as %q", k)
	}
	if k := kind(t, 200<<10); k != "stream" {
		t.Fatalf("a 200 KiB message went as %q", k)
	}
	// The flags override the size in both directions.
	if k := kind(t, 1<<10, "--stream"); k != "stream" {
		t.Fatalf("--stream on a small message gave %q", k)
	}
	if k := kind(t, 200<<10, "--inline"); k != "envelope" {
		t.Fatalf("--inline on a large message gave %q", k)
	}
}

func TestStreamFlagsContradict(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	if _, err := alice.tryRun("send", "--to", "bob", "--stream", "--inline", "x"); err == nil {
		t.Fatal("--stream and --inline together were accepted")
	}
}

// A stream from somebody unknown is recorded from its manifest alone. The
// payload stays on the relay, so a stranger cannot make anybody download it.
func TestStreamFromAStrangerIsNotDownloaded(t *testing.T) {
	relayURL := startRelay(t)
	bob := newUser(t, "bob", relayURL)
	stranger := newUser(t, "stranger", relayURL)
	stranger.run("peers", "add", bob.exportLine())

	payload := make([]byte, 300<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	file := filepath.Join(t.TempDir(), "unsolicited.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	stranger.run("send", "--to", bob.exportFingerprint(), "--subject", "hello", "--attach", file, "unasked")

	out := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Fetch.Quarantined != 1 || got.Fetch.Delivered != 0 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}

	// Nothing of the payload is on disk.
	var found []string
	filepath.Walk(bob.home, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && info.Size() > 64<<10 {
			found = append(found, path)
		}
		return nil
	})
	if len(found) != 0 {
		t.Fatalf("a stranger's payload was downloaded: %v", found)
	}

	// Quarantine shows it, with its size, and extract says where it is.
	listed := bob.run("quarantine", "ls")
	if !strings.Contains(listed, "hello") {
		t.Fatalf("quarantine ls does not show it:\n%s", listed)
	}
	var q []messageJSON
	if err := json.Unmarshal([]byte(bob.run("quarantine", "ls", "--json")), &q); err != nil {
		t.Fatal(err)
	}
	if len(q) != 1 {
		t.Fatalf("quarantine has %d messages", len(q))
	}
	if _, err := bob.tryRun("extract", q[0].ID); err == nil {
		t.Fatal("extract worked on a payload that is still on the relay")
	}

	// Trusting the sender fetches it and delivers it.
	if _, err := bob.answer("bob-peer", "quarantine", "trust", q[0].ID); err != nil {
		t.Fatalf("trust: %v", err)
	}
	dir := t.TempDir()
	bob.run("extract", q[0].ID, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "unsolicited.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("the payload did not survive being trusted")
	}
}

// The settings are validated wherever they come from.
func TestStreamSettingsValidation(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("allow", "push")

	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		threshold int64
		chunk     int
		accept    bool
	}{
		{"defaults", 0, 0, true},
		{"chunk at the minimum", 0, stream.MinChunkSize, true},
		{"chunk below the minimum", 0, stream.MinChunkSize - 1, false},
		{"chunk at the maximum", 0, stream.MaxChunkSize, true},
		{"chunk above the maximum", 0, stream.MaxChunkSize + 1, false},
		{"threshold at the minimum", stream.MinChunkSize, 0, true},
		{"threshold below the minimum", stream.MinChunkSize - 1, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := s.Config()
			if err != nil {
				t.Fatal(err)
			}
			cfg.StreamThreshold, cfg.ChunkSize = c.threshold, c.chunk
			if err := s.SaveConfig(cfg); err != nil {
				t.Fatal(err)
			}
			_, err = alice.tryRun("send", "--to", "bob", "a short message")
			mentions := err != nil && (strings.Contains(err.Error(), "chunk_size") ||
				strings.Contains(err.Error(), "stream_threshold"))
			if c.accept {
				if err != nil {
					t.Fatalf("valid settings were refused: %v", err)
				}
				return
			}
			if !mentions {
				t.Fatalf("invalid settings were accepted: %v", err)
			}
		})
	}
	cfg, _ := s.Config()
	cfg.StreamThreshold, cfg.ChunkSize = 0, 0
	s.SaveConfig(cfg)
	_ = relay.Config{}
}

// A stream the relay finds damaged when asked to serve it is dropped there
// and answered with a 410. That is permanent and none of this machine's
// doing, so the fetch says so, names the message, advances past it, and goes
// on to the next one; nothing is acknowledged, since the relay has already
// dropped it. The container suite's M06 found a 416 instead, reported as a
// transport failure, and every inbox after it failing the same way.
func TestAGoneStreamDoesNotBlockTheInbox(t *testing.T) {
	// The relay's own log is the one place a wasted acknowledgement of the
	// dropped message could be seen: the client swallows the 404 it would
	// get, as it should for a message already gone.
	relayLog := &syncBuffer{}
	srv, st, messages := startRelayOnDisk(t, relay.Config{
		Limits: relay.DefaultLimits(),
		Logger: slog.New(slog.NewTextHandler(relayLog, nil)),
	})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	payload := make([]byte, 200<<10)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	file := filepath.Join(t.TempDir(), "dump.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"the damaged one", "the good one"} {
		var sent sentJSON
		out := alice.run("send", "--to", "bob", "--subject", subject, "--attach", file, "--json", "streamed")
		if err := json.Unmarshal([]byte(out), &sent); err != nil || sent.Kind != "stream" {
			t.Fatalf("send: %v %s", err, out)
		}
	}
	bobFP := bob.exportFingerprint()
	queued, err := st.List(bobFP, 0, 10)
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued %d (%v), want 2", len(queued), err)
	}
	first := queued[0].ID
	path := filepath.Join(messages, bobFP[:2], bobFP, strconv.FormatInt(first, 10))
	if err := os.Truncate(path, queued[0].Size-4096); err != nil {
		t.Fatal(err)
	}

	var inbox inboxJSON
	var out string
	warning := captureStderr(t, func() { out = bob.run("inbox", "--json") })
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, out)
	}
	if inbox.Fetch.Delivered != 1 || inbox.Fetch.Unreadable != 1 || inbox.Fetch.Quarantined != 0 {
		t.Fatalf("fetch: %+v, want one delivered and one unreadable", inbox.Fetch)
	}
	if len(inbox.Messages) != 1 || inbox.Messages[0].Subject != "the good one" {
		t.Fatalf("inbox: %+v", inbox.Messages)
	}
	want := fmt.Sprintf("warning: relay message %d was damaged on the relay and has been dropped there; "+
		"ask the sender to send it again\n", first)
	if warning != want {
		t.Fatalf("stderr %q, want %q", warning, want)
	}

	// The dropped stream is gone from the relay, which dropped it itself,
	// and the good message is kept there, since default keeps: the cursor
	// moved past both.
	left, err := st.List(bobFP, 0, 10)
	if err != nil || len(left) != 1 || left[0].ID != queued[1].ID {
		t.Fatalf("the relay holds %v (%v), want the good message alone", left, err)
	}
	// Neither was acknowledged: the relay dropped the damaged one itself,
	// and the good one is kept where it is.
	for _, id := range []int64{first, queued[1].ID} {
		ack := fmt.Sprintf("method=DELETE path=/v1/mailbox/%s/%d ", bobFP, id)
		if logs := relayLog.String(); strings.Contains(logs, ack) {
			t.Fatalf("message %d was acknowledged:\n%s", id, logs)
		}
	}
	var again inboxJSON
	warning = captureStderr(t, func() { out = bob.run("inbox", "--json") })
	if err := json.Unmarshal([]byte(out), &again); err != nil {
		t.Fatal(err)
	}
	if !again.Fetch.empty() || warning != "" {
		t.Fatalf("the next inbox was not clean: %+v %q", again.Fetch, warning)
	}
}

// The relay's storage 500 says nothing to the client, since nothing the
// client can do would help; auu's sentence says whose problem it is and where
// they look. Only that 500 gets it: a 507 has its own sentences. The container
// suite's R17 and R24 found "relay returned 500: storage error" and exit 2.
func TestAStorageFaultIsSaidToBeTheRelays(t *testing.T) {
	srv, _, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	const want = "the relay could not store or read a message (storage error); whoever runs it needs to look at its log"

	// A post, with nowhere on the relay to write.
	if err := os.RemoveAll(filepath.Join(messages, "tmp")); err != nil {
		t.Fatal(err)
	}
	_, err := alice.tryRun("send", "--to", "bob", "--subject", "nowhere", "does this get stored")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("send against a relay that cannot write: %v, want exit %d", err, exitTransport)
	}
	if err.Error() != want {
		t.Fatalf("send said %q, want %q", err, want)
	}

	// A fetch, with the message's file gone from under its row: the list
	// skips it, and the blob route, which a stream is fetched by, is a 500.
	if err := os.MkdirAll(filepath.Join(messages, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 100<<10)
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "then lost", "--attach", file, "stream")
	bobFP := bob.exportFingerprint()
	if err := os.RemoveAll(filepath.Join(messages, bobFP[:2])); err != nil {
		t.Fatal(err)
	}
	_, err = bob.tryRun("inbox")
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("inbox against a relay that cannot read: %v, want exit %d", err, exitTransport)
	}
	if err.Error() != want {
		t.Fatalf("inbox said %q, want %q", err, want)
	}
}

// The storage sentence is for the relay's storage 500 alone: a 507 has its
// own sentences, and the relay's other 500 names what it could not do.
func TestStorageFaultHintIsOnlyForTheStorage500(t *testing.T) {
	const want = "the relay could not store or read a message (storage error); whoever runs it needs to look at its log"
	for _, tc := range []struct {
		name   string
		err    error
		hinted bool
	}{
		{"the storage 500", &client.HTTPError{Status: 500, Message: relayapi.MsgStorageError, Code: relayapi.CodeStorageError}, true},
		{"a 507 for the relay", &client.HTTPError{Status: 507, Message: relayapi.MsgRelayFull, Code: relayapi.CodeRelayFull}, false},
		{"a 507 for the mailbox", &client.HTTPError{Status: 507, Message: relayapi.MsgMailboxFull, Code: relayapi.CodeMailboxFull}, false},
		{"the other 500", &client.HTTPError{Status: 500, Message: "could not issue a certificate"}, false},
		{"a 404", &client.HTTPError{Status: 404, Message: "no such mailbox"}, false},
		{"not the relay's at all", errors.New("dial tcp: connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := storageFaultHint(tc.err)
			if tc.hinted && got.Error() != want {
				t.Fatalf("got %q, want the storage sentence", got)
			}
			if !tc.hinted && got != tc.err {
				t.Fatalf("got %q, want the error unchanged: %q", got, tc.err)
			}
		})
	}
}
