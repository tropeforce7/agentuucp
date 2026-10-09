package auu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// attachment writes n bytes, each a function of its offset, to a file of
// that name in a fresh directory.
func attachment(t *testing.T, name string, n int) (string, []byte) {
	t.Helper()
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*13 + 5)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, payload
}

// extracted is the one file a recipient extracts from a message.
func extracted(t *testing.T, u *user, id, name string) []byte {
	t.Helper()
	dir := t.TempDir()
	u.run("extract", id, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return back
}

// outboxFiles is every name in a home's outbox.
func outboxFiles(t *testing.T, u *user) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(u.home, "outbox"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A message to several big enough to be a stream goes as one stream to each
// (D49): --json says stream with its chunks once and every recipient
// placed, the outbox is empty after, the one sent record is a stream with a
// copy for each, each recipient has the payload byte for byte and the list
// of who else has it, and reply --all answers everyone.
func TestAStreamToSeveralGoesToEach(t *testing.T) {
	us := peersOn(t, startRelay(t), "alice", "bob", "carol", "dave")
	alice, bob, carol, dave := us[0], us[1], us[2], us[3]
	file, payload := attachment(t, "build.bin", 200<<10)

	got := sentMany(t, alice.run("send", "--to", "bob,carol,dave", "--subject", "the build",
		"--attach", file, "--json", "here it is"))
	if got.Kind != kindStream || got.Bytes != int64(len(payload)) || got.ChunkSize != stream.DefaultChunkSize ||
		got.Chunks != stream.ChunkCount(int64(len(payload)), stream.DefaultChunkSize) {
		t.Fatalf("--json: kind %q, bytes %d, chunks %d, chunk_size %d; want a stream of %d", got.Kind, got.Bytes,
			got.Chunks, got.ChunkSize, len(payload))
	}
	if len(got.Recipients) != 3 {
		t.Fatalf("--json recipients: %+v", got.Recipients)
	}
	for _, r := range got.Recipients {
		if r.RelayID <= 0 || r.Error != "" || r.Waiting {
			t.Errorf("recipient %s: %+v; want placed", r.Name, r)
		}
	}
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Errorf("the outbox after every stream was uploaded: %v", left)
	}
	m := alice.stored(store.Sent, got.ID)
	if !m.Streamed || len(m.Copies) != 3 {
		t.Fatalf("the sent record: streamed %v, %d copies", m.Streamed, len(m.Copies))
	}
	for _, c := range m.Copies {
		if c.RelayID <= 0 {
			t.Errorf("the sent record's copy for %s is not placed: %+v", c.Name, c)
		}
	}
	if list := recipientsOf(m); len(list) != 3 || list[0] != bob.exportFingerprint() {
		t.Errorf("the sent record's list: %v", list)
	}
	if read := alice.run("read", got.ID); !strings.Contains(read, "sent as a stream") {
		t.Errorf("read of the sent stream:\n%s", read)
	}

	for _, u := range []*user{bob, carol, dave} {
		u.run("inbox")
		if back := extracted(t, u, got.ID, "build.bin"); !bytes.Equal(back, payload) {
			t.Errorf("a recipient's payload: %d bytes back, %d sent", len(back), len(payload))
		}
		if read := u.run("read", got.ID); !strings.Contains(read, "to:") || !strings.Contains(read, "you") {
			t.Errorf("read of the stream to several does not say who has it:\n%s", read)
		}
		var again inboxJSON
		if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &again); err != nil || again.Fetch.Delivered != 0 {
			t.Errorf("a delivered stream copy was fetched again: %+v, %v", again.Fetch, err)
		}
	}

	reply := sentMany(t, bob.run("reply", got.ID, "--all", "--json", "thanks, all"))
	if len(reply.Recipients) != 3 || reply.Recipients[0].Name != "alice" {
		t.Errorf("reply --all to a stream went to %+v; want alice, carol and dave", reply.Recipients)
	}

	// The plain form says each recipient, as an envelope to several does.
	small, _ := attachment(t, "small.bin", 100<<10)
	out := alice.run("send", "--to", "bob,carol", "--attach", small, "again")
	for _, want := range []string{"sent to 2 recipients via", "  bob: sent", "  carol: sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("the send says:\n%s\nwant %q", out, want)
		}
	}
}

// An upload cut part way stops the send, the copies after it wait, and
// --resume finishes every one: each lands in the message's one sent record,
// which keeps its three copies, and each recipient has the message once,
// byte for byte.
func TestAStreamToSeveralInterruptedIsFinishedByResume(t *testing.T) {
	relayURL, gate := startInterruptibleRelay(t, 2, 64<<10)
	us := peersOn(t, relayURL, "alice", "bob", "carol", "dave")
	alice := us[0]
	file, payload := attachment(t, "long.bin", 400<<10)

	out, err := alice.tryRun("send", "--to", "bob,carol,dave", "--attach", file, "--json", "the long one")
	if err == nil {
		t.Fatalf("the send should have failed with the relay cut off part way:\n%s", out)
	}
	if _, cut := gate.counts(); cut == 0 {
		t.Fatal("the gate cut nothing; the test proves nothing")
	}
	got := sentMany(t, out)
	waiting, broken := outboxOf(t, alice)
	if len(waiting) != 3 || len(broken) != 0 {
		t.Fatalf("the outbox after the cut: %d waiting, broken %v; want all three", len(waiting), broken)
	}
	for _, p := range waiting {
		if p.kind != kindStream || p.RecipientCount != 3 || p.name() != copyStem(got.ID, p.To) {
			t.Errorf("a waiting stream copy: kind %s, count %d, name %s", p.kind, p.RecipientCount, p.name())
		}
	}

	gate.open()
	alice.run("send", "--resume")
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Fatalf("the outbox after --resume: %v", left)
	}
	m := alice.stored(store.Sent, got.ID)
	if !m.Streamed || len(m.Copies) != 3 {
		t.Fatalf("the sent record after --resume: streamed %v, %d copies; want the message's one record kept", m.Streamed, len(m.Copies))
	}
	for _, c := range m.Copies {
		if c.RelayID <= 0 {
			t.Errorf("copy for %s not placed after --resume: %+v", c.Name, c)
		}
	}
	for _, u := range us[1:] {
		var box inboxJSON
		if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &box); err != nil {
			t.Fatal(err)
		}
		if box.Fetch.Delivered != 1 {
			t.Errorf("a recipient fetched %+v; want the message once", box.Fetch)
		}
		if back := extracted(t, u, got.ID, "long.bin"); !bytes.Equal(back, payload) {
			t.Errorf("a resumed payload: %d bytes back, %d sent", len(back), len(payload))
		}
	}
}

// streamFront is a relay behind a proxy that keeps every stream open's body
// and answers an open for refuse's mailbox, while it names one, as a full
// mailbox, and every upload attempt, while busy is set, as a relay asking
// for an hour.
type streamFront struct {
	mu     sync.Mutex
	opens  [][]byte
	refuse atomic.Value
	busy   atomic.Bool
}

func (f *streamFront) openBodies() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.opens...)
}

func frontStreams(t *testing.T) (*streamFront, []*user) {
	t.Helper()
	backend, err := url.Parse(startRelay(t))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	f := &streamFront{}
	f.refuse.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") && strings.HasSuffix(r.URL.Path, "/streams") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			f.mu.Lock()
			f.opens = append(f.opens, body)
			f.mu.Unlock()
			if fp := f.refuse.Load().(string); fp != "" && strings.Contains(r.URL.Path, fp) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInsufficientStorage)
				_, _ = w.Write([]byte(`{"error":"the mailbox is full","code":"` + relayapi.CodeMailboxFull + `"}`))
				return
			}
		}
		if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v1/uploads/") && f.busy.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"busy"}`))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, peersOn(t, srv.URL, "alice", "bob", "carol", "dave")
}

// countOf is the recipient count an open request's body says, zero for none.
func countOf(t *testing.T, body []byte) int {
	t.Helper()
	var req struct {
		Sections []struct {
			Name string          `json:"name"`
			Data json.RawMessage `json:"data"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("an open request: %v\n%s", err, body)
	}
	for _, s := range req.Sections {
		if s.Name == recipients.CountName {
			var c recipients.Count
			if err := json.Unmarshal(s.Data, &c); err != nil {
				t.Fatal(err)
			}
			return c.N
		}
	}
	return 0
}

// A stream copy the relay refuses at its open stays in the outbox with the
// relay's code and words, in its record and the sent record's copy, as an
// envelope copy does (ruling 78, point 3), and the rest go on; the command
// names --resume and the drop; every open says how many the message went
// to, and so does the resumed one, which lands in the one sent record.
func TestAStreamCopyRefusedAtItsOpenIsKeptAndResumed(t *testing.T) {
	f, us := frontStreams(t)
	alice, carol := us[0], us[2]
	f.refuse.Store(carol.exportFingerprint())

	out, err := alice.tryRun("send", "--to", "bob,carol,dave", "--stream", "--json", "the plan")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("a refused stream copy: %v; want exit 2", err)
	}
	got := sentMany(t, out)
	if !strings.Contains(err.Error(), "1 of 3 copies were not sent") ||
		!strings.Contains(err.Error(), "finish them with 'auu send --resume'") ||
		!strings.Contains(err.Error(), "or give one up with 'auu outbox drop "+got.ID[:12]+" PEER'") {
		t.Errorf("the closing sentence: %v", err)
	}
	if got.Recipients[0].RelayID <= 0 || got.Recipients[1].Code != relayapi.CodeMailboxFull || got.Recipients[2].RelayID <= 0 {
		t.Fatalf("recipients: %+v; want bob and dave placed, carol refused as full", got.Recipients)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || waiting[0].kind != kindStream || waiting[0].ToName != "carol" ||
		waiting[0].RefusedCode != relayapi.CodeMailboxFull || waiting[0].Refused == "" ||
		waiting[0].name() != copyStem(got.ID, carol.exportFingerprint()) {
		t.Fatalf("the outbox: %+v; want carol's stream copy with the relay's refusal", waiting)
	}
	if m := alice.stored(store.Sent, got.ID); m.Copies[1].RefusedCode != relayapi.CodeMailboxFull || m.Copies[1].RelayID != 0 {
		t.Errorf("the sent record's copy for carol: %+v", m.Copies[1])
	}
	if listing := alice.run("outbox"); !strings.Contains(listing, "stream") || !strings.Contains(listing, "refused, "+relayapi.CodeMailboxFull) {
		t.Errorf("auu outbox:\n%s", listing)
	}
	for i, body := range f.openBodies() {
		if n := countOf(t, body); n != 3 {
			t.Errorf("open %d said %d recipients; want 3", i+1, n)
		}
	}

	f.refuse.Store("")
	before := len(f.openBodies())
	alice.run("send", "--resume")
	opens := f.openBodies()
	if len(opens) != before+1 || countOf(t, opens[before]) != 3 {
		t.Fatalf("the resumed open: %d opens after %d; want one more, saying 3", len(opens), before)
	}
	m := alice.stored(store.Sent, got.ID)
	if !m.Streamed || len(m.Copies) != 3 || m.Copies[1].RelayID <= 0 || m.Copies[1].Refused != "" {
		t.Fatalf("the sent record after --resume: streamed %v, copies %+v", m.Streamed, m.Copies)
	}
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Errorf("the outbox after --resume: %v", left)
	}
	carol.run("inbox")
	if read := carol.run("read", got.ID); !strings.Contains(read, "the plan") || !strings.Contains(read, "to:") {
		t.Errorf("carol's copy:\n%s", read)
	}
}

// A refused stream copy given up by auu outbox drop is given up in the sent
// record too, and its sealed stream and record go.
func TestADroppedStreamCopyIsGivenUpInTheSentRecord(t *testing.T) {
	f, us := frontStreams(t)
	alice, carol := us[0], us[2]
	f.refuse.Store(carol.exportFingerprint())
	out, _ := alice.tryRun("send", "--to", "bob,carol", "--stream", "--json", "the plan")
	id := sentMany(t, out).ID
	if dropped := alice.run("outbox", "drop", id[:8], "carol"); !strings.Contains(dropped, "dropped the stream of") {
		t.Errorf("the drop says:\n%s", dropped)
	}
	if m := alice.stored(store.Sent, id); !m.Copies[1].Dropped || m.Copies[0].Dropped {
		t.Errorf("the sent record after dropping carol's stream copy: %+v", m.Copies)
	}
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Errorf("the outbox after the drop: %v", left)
	}
}

// A relay that asks the sender to wait over a minute at a stream's open
// stops the posting (R7), on a relay whose byte budget takes two copies and
// a half: the third waits in the outbox with no refusal kept, and the send
// does not sit through the wait.
func TestAStreamToSeveralStopsOnALongWaitAtItsOpen(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 250 << 10
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol", "dave")
	alice := us[0]
	file, _ := attachment(t, "part.bin", 100<<10)
	started := time.Now()
	out, err := alice.tryRun("send", "--to", "bob,carol,dave", "--attach", file, "--json", "three parts")
	if took := time.Since(started); took > 30*time.Second {
		t.Errorf("the send took %s; it waited on the relay instead of stopping", took)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "the relay is limiting this sender and asked for") {
		t.Fatalf("a long wait at the open: %v", err)
	}
	got := sentMany(t, out)
	if got.Recipients[0].RelayID == 0 || got.Recipients[1].RelayID == 0 || !got.Recipients[2].Waiting {
		t.Fatalf("recipients: %+v; want two sent and dave's waiting", got.Recipients)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || waiting[0].ToName != "dave" || waiting[0].Refused != "" || waiting[0].kind != kindStream {
		t.Errorf("the outbox after the stop: %+v; want dave's stream copy, no refusal kept", waiting)
	}
}

// A relay that asks for an hour in the middle of an upload stops a stream
// copy at once (ruling 78, point 5), where a stream to one waits thirty
// seconds at a time: the copy and the rest wait in the outbox, the first
// with its upload, and the command says how long the relay asked for.
func TestAStreamCopyDoesNotSitThroughALongWaitInItsUpload(t *testing.T) {
	f, us := frontStreams(t)
	alice := us[0]
	f.busy.Store(true)
	started := time.Now()
	out, err := alice.tryRun("send", "--to", "bob,carol,dave", "--stream", "--json", "later")
	if took := time.Since(started); took > 20*time.Second {
		t.Errorf("the send took %s; it sat through the relay's wait", took)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "the relay is busy and asked for 3600 seconds") {
		t.Fatalf("a long wait in the upload: %v", err)
	}
	got := sentMany(t, out)
	for _, r := range got.Recipients {
		if !r.Waiting {
			t.Errorf("recipient %s: %+v; want waiting", r.Name, r)
		}
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 3 {
		t.Fatalf("%d waiting; want all three", len(waiting))
	}
	for _, p := range waiting {
		if p.Refused != "" || (p.ToName == "bob") != (p.Upload != "") {
			t.Errorf("%s's copy: upload %q, refused %q; want bob's alone opened and no refusal kept", p.ToName, p.Upload, p.Refused)
		}
	}
}

// A recipient by bang path among several refuses a stream to several whole,
// before anything is read or written, since a stream does not cross a relay.
func TestAStreamToSeveralByAPathIsRefusedWhole(t *testing.T) {
	alice, _, _ := threePeers(t)
	_, err := alice.tryRun("send", "--to", "bob,elsewhere!carol", "--stream", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "a large message does not cross a relay yet") ||
		!strings.Contains(err.Error(), "carol") {
		t.Fatalf("a stream to several with a path: %v", err)
	}
	if left := outboxFiles(t, alice); len(left) != 0 || len(sentBox(t, alice)) != 0 {
		t.Errorf("a refused stream to several wrote something: %v", left)
	}
}

// failingSigner signs as its identity does and, at its nth signature, runs
// a fault first: answers as a locked agent does, or does something to the
// disk and signs.
type failingSigner struct {
	inner *identity.Identity
	n     atomic.Int64
	at    int64
	fault func() error
}

func (f *failingSigner) Public() []byte { return f.inner.Public().SignPublic() }
func (f *failingSigner) Sign(msg []byte) ([]byte, error) {
	if f.n.Add(1) == f.at {
		if err := f.fault(); err != nil {
			return nil, err
		}
	}
	return f.inner.Sign(msg)
}

// A seal of several streams that fails part way takes every stream and
// record of the message with it and says so (R9): a key that locks at the
// second signature, and a record that cannot be written for the second
// copy, as a full disk leaves it. Nothing is left that --resume would post.
func TestSealingStreamsThatFailsPartWayLeavesNothing(t *testing.T) {
	alice, _, _ := threePeers(t)
	t.Setenv("AUU_HOME", alice.home)
	s, me, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := selectRelay(s, "")
	if err != nil {
		t.Fatal(err)
	}
	var to []addressed
	for _, name := range []string{"bob", "carol"} {
		pub, err := s.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		to = append(to, addressed{pub: pub})
	}
	file, _ := attachment(t, "x.bin", 10<<10)
	body := message.Body{Type: message.TypeAsk, Thread: strings.Repeat("a", 32), Text: "x"}
	set := streamSettings{threshold: stream.DefaultThreshold, chunkSize: stream.MinChunkSize}
	signer := func(t *testing.T, fault func() error) *identity.Identity {
		t.Helper()
		f := &failingSigner{inner: me, at: 2, fault: fault}
		id, err := identity.FromRemote(me.Suite(), me.Name, me.Public().Bundle(), f, me.KEM())
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	locked := signer(t, func() error { return identity.ErrLocked })
	_, _, err = sealStreams(s, locked, r, to, body, []string{file}, set, "")
	if !isLocked(err) || !strings.Contains(err.Error(), "sealing the copy for carol") ||
		!strings.Contains(err.Error(), "nothing was sent, and the outbox keeps none of this message") {
		t.Errorf("a key locked at the second copy: %v", err)
	}
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Errorf("the outbox after a lock part way: %v", left)
	}

	// At the second signature the first copy is written whole: its record
	// names the message, and a directory where the second copy's record
	// goes makes that record's write fail, as a full disk would.
	var blocker string
	full := signer(t, func() error {
		for _, name := range outboxFiles(t, alice) {
			if stem, ok := strings.CutSuffix(name, ".json"); ok {
				id, _, _ := strings.Cut(stem, "-")
				blocker = pendingPath(s, copyStem(id, to[1].pub.Fingerprint()))
				if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
					return err
				}
				return nil
			}
		}
		return fmt.Errorf("the first copy's record is not in the outbox at the second signature")
	})
	_, _, err = sealStreams(s, full, r, to, body, []string{file}, set, "")
	if err == nil || !strings.Contains(err.Error(), "nothing was sent, and the outbox keeps none of this message") {
		t.Fatalf("a record that cannot be written for the second copy: %v", err)
	}
	if blocker == "" {
		t.Fatal("the fault never ran; the test proves nothing")
	}
	os.RemoveAll(blocker)
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Errorf("the outbox after a write failed part way: %v", left)
	}
}

// A stream to several on a channel carries it in every manifest, under the
// signature, and on every row, as a stream to one does, so each recipient
// files it where the relay did.
func TestAStreamToSeveralCarriesItsChannel(t *testing.T) {
	work, workStore := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", work)
	bob := newUser(t, "bob", work)
	carol := newUser(t, "carol", work)
	for _, u := range []*user{bob, carol} {
		alice.run("peers", "add", u.exportLine())
		u.run("peers", "add", alice.exportLine())
		u.run("channel", "create", "bug reports", "--description", "One bug per message")
	}
	file, _ := attachment(t, "log.bin", 200<<10)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--channel", "bug reports", "--attach", file, "--json", "the log"))
	if got.Kind != kindStream || got.Channel != "bug reports" {
		t.Fatalf("--json: kind %q, channel %q", got.Kind, got.Channel)
	}
	for _, u := range []*user{bob, carol} {
		_, id, _ := u.opened()
		row, blob := storedOnRelay(t, workStore, id.Fingerprint())
		if row.Kind != relayapi.KindStream || row.Channel != "bug reports" {
			t.Fatalf("the relay filed a copy as %s under %q", row.Kind, row.Channel)
		}
		n, err := stream.ManifestLength(blob[:stream.HeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		opened, err := stream.OpenManifest(id, blob[:stream.HeaderSize], blob[stream.HeaderSize:stream.HeaderSize+n])
		if err != nil {
			t.Fatal(err)
		}
		if opened.Manifest.Channel != "bug reports" {
			t.Errorf("a copy's manifest carries %q", opened.Manifest.Channel)
		}
	}
	if m := alice.stored(store.Sent, got.ID); m.Channel != "bug reports" || m.Inner.Channel != "bug reports" {
		t.Errorf("the sent record's channel: %q, %q", m.Channel, m.Inner.Channel)
	}
}

// A stream copy refused at its open during --resume is kept as one refused
// at the first send is (D48, ruling 78 point 3): its record and the sent
// record's copy keep the relay's code and words, the sentence names
// --resume and the drop, the other copies finish, and the refused one goes
// once the refusal is lifted.
func TestAStreamCopyRefusedOnResumeIsKept(t *testing.T) {
	f, us := frontStreams(t)
	alice, carol := us[0], us[2]
	// The first send stops at bob's upload, every copy left waiting.
	f.busy.Store(true)
	out, _ := alice.tryRun("send", "--to", "bob,carol,dave", "--stream", "--json", "the plan")
	got := sentMany(t, out)
	if waiting, _ := outboxOf(t, alice); len(waiting) != 3 {
		t.Fatalf("%d waiting after the first send; want all three", len(waiting))
	}
	f.busy.Store(false)
	f.refuse.Store(carol.exportFingerprint())

	var err error
	said := captureStderr(t, func() { _, err = alice.tryRun("send", "--resume") })
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "1 of 3 unfinished messages did not finish") {
		t.Fatalf("--resume with carol's copy refused: %v", err)
	}
	if !strings.Contains(said, "carol's mailbox on the relay is full") ||
		!strings.Contains(said, "finish it with 'auu send --resume', or give it up with 'auu outbox drop "+got.ID[:12]+" carol'") {
		t.Errorf("--resume says:\n%s", said)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || waiting[0].kind != kindStream || waiting[0].ToName != "carol" ||
		waiting[0].RefusedCode != relayapi.CodeMailboxFull || waiting[0].Refused != "the mailbox is full" {
		t.Fatalf("the outbox after --resume: %+v; want carol's stream copy with the relay's code and words", waiting)
	}
	m := alice.stored(store.Sent, got.ID)
	if m.Copies[1].RefusedCode != relayapi.CodeMailboxFull || m.Copies[1].Refused != "the mailbox is full" ||
		m.Copies[0].RelayID <= 0 || m.Copies[2].RelayID <= 0 {
		t.Fatalf("the sent record after --resume: %+v", m.Copies)
	}

	f.refuse.Store("")
	alice.run("send", "--resume")
	m = alice.stored(store.Sent, got.ID)
	if len(m.Copies) != 3 || m.Copies[1].RelayID <= 0 || m.Copies[1].Refused != "" {
		t.Fatalf("the sent record once the refusal was lifted: %+v", m.Copies)
	}
	if left := outboxFiles(t, alice); len(left) != 0 {
		t.Errorf("the outbox after the last --resume: %v", left)
	}
	carol.run("inbox")
	if read := carol.run("read", got.ID); !strings.Contains(read, "the plan") {
		t.Errorf("carol's copy:\n%s", read)
	}
}
