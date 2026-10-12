package auu

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// adv2UploadCorruptStream seals a whole stream from u for to, flips one
// byte of the first payload chunk (after the manifest), and uploads all of
// it: the manifest verifies, its size is the size the relay lists, and the
// payload will not open. Only the sender can make this; the relay cannot
// tell it from any other stream. It hands back the bytes uploaded.
func adv2UploadCorruptStream(t *testing.T, u, to *user, subject string) []byte {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(s, id, r)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := store.Open(to.home)
	if err != nil {
		t.Fatal(err)
	}
	toID, err := ts.Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := toID.Public()
	payload := make([]byte, 200<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sources := []stream.Source{{
		Name: "big.bin", Media: "application/octet-stream", Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
	}}
	messageID, err := envelope.NewID()
	if err != nil {
		t.Fatal(err)
	}
	m, err := stream.BuildManifest(id, pub, messageID,
		stream.Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: subject, Text: "streamed"},
		sources, stream.DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, id, pub, m, sources); err != nil {
		t.Fatal(err)
	}
	full := append([]byte{}, blob.Bytes()...)
	n := adv2ManifestLength(full)
	full[stream.HeaderSize+n+100] ^= 0xff // inside chunk 1
	ctx := context.Background()
	opened, err := c.OpenStream(ctx, to.exportFingerprint(), "", int64(len(full)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(full), int64(len(full))); err != nil {
		t.Fatal(err)
	}
	return full
}

// adv2ManifestLength is the sealed manifest chunk's length, as the
// stream's header states it.
func adv2ManifestLength(full []byte) int {
	return int(binary.BigEndian.Uint32(full[stream.EncSize:stream.HeaderSize]))
}

// The control: from a sender bob holds, the fetch keeps such a stream as
// damaged and acknowledges it (streamrecv.go fetchOneStream, isPermanent).
func TestAPeersStreamWhosePayloadWillNotOpenIsKeptAsDamaged(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	alice := newUser(t, "alice", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	adv2UploadCorruptStream(t, alice, bob, "corrupt")
	got := bob.inboxJSON()
	t.Logf("fetch: %+v", got.Fetch)
	if got.Fetch.Kept != 1 || got.Fetch.Unreadable != 1 {
		t.Fatalf("a peer's stream whose payload will not open: %+v; want it kept as damaged", got.Fetch)
	}
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("the relay still holds %v; want it acknowledged", left)
	}
}

// adv2CountingFront is a reverse proxy in front of srv that counts every
// byte it serves; while drop is set, an open-ended range (the payload, never
// the manifest, which is asked for by a closed range) is cut after its first
// kilobyte, as a connection that drops mid-payload is.
func adv2CountingFront(t *testing.T, srv *httptest.Server, served, cuts *atomic.Int64, drop *atomic.Bool) *httptest.Server {
	t.Helper()
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &adv2CountingWriter{ResponseWriter: w, n: served}
		if rg := r.Header.Get("Range"); drop.Load() && strings.HasSuffix(rg, "-") {
			cw.cutAfter, cw.cuts = 1024, cuts
		}
		proxy.ServeHTTP(cw, r)
	}))
	t.Cleanup(front.Close)
	return front
}

// F4 residual, closed (G8): the same stream from a stranger is quarantined
// (its manifest and size are right), and `quarantine trust` downloads the
// payload and meets the AEAD failure. That is the sender's fault, and trust
// settles it as the fetch settles a peer's: the manifest chunk kept under
// damaged/ with the stream's cause, in the fetch's own sentence, the stream
// acknowledged, the quarantine record gone, exit 0 with a line saying so,
// and nobody added. A second trust finds nothing to trust and pulls nothing
// of the payload again; before the fix it reported a transport failure at
// every attempt and downloaded the whole payload each time.
func TestTrustOfAStreamThatWillNotOpenKeepsItAsDamagedAndAddsNobody(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	full := adv2UploadCorruptStream(t, stranger, bob, "corrupt")
	manifestEnd := stream.HeaderSize + adv2ManifestLength(full)
	payloadBytes := int64(len(full) - manifestEnd)

	// Count the payload bytes each trust pulls through a proxy.
	var served, cuts atomic.Int64
	var drop atomic.Bool
	front := adv2CountingFront(t, srv, &served, &cuts, &drop)
	relayName := repointRelay(t, bob, front.URL)

	if got := bob.inboxJSON(); got.Fetch.Quarantined != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	rec := recordOf(t, bob, store.Quarantine, "corrupt")
	if !rec.PayloadOnRelay {
		t.Fatalf("the quarantined stream: %+v", rec)
	}

	// The first trust: settled, said, exit 0.
	before := served.Load()
	var out string
	var err error
	stderr := captureStderr(t, func() { out, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID) })
	pulled := served.Load() - before
	t.Logf("trust 1: %d bytes pulled: %v\n%s%s", pulled, err, out, stderr)
	if err != nil {
		t.Fatalf("trust of a stream whose payload will not open: %v; want exit 0", err)
	}
	// The payload was asked for: the byte flipped 100 into chunk 1 was
	// read, since that is what would not open. How much more of the
	// payload's payloadBytes came before the reader stopped is the
	// transport's buffering, not this test's to fix (it failed under -race
	// asking for the whole payload).
	if pulled <= int64(manifestEnd)+100 {
		t.Fatalf("trust pulled %d bytes, not past the flipped byte at %d of a payload of %d: the payload was never asked for",
			pulled, manifestEnd+100, payloadBytes)
	}
	settled := fmt.Sprintf("%s: its payload will not open; it was settled as damaged and acknowledged, and nobody was added\n", rec.Inner.ID[:12])
	if !strings.HasSuffix(out, settled) {
		t.Fatalf("trust said:\n%s\nwant it to end %q", out, settled)
	}

	// Kept under damaged/ with the manifest chunk and the stream's cause,
	// in the fetch's own sentence.
	s, _, _ := bob.opened()
	path := damagedPathOf(t, s, relayName, rec.RelayID)
	cause := streamCause(stream.ErrOpenFailed)
	sentence := fmt.Sprintf("warning: relay message %d could not be opened (%s) and was kept as %s; ask the sender to send it again\n",
		rec.RelayID, cause, path)
	if stderr != sentence {
		t.Fatalf("trust's standard error:\n%q\nwant\n%q", stderr, sentence)
	}
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("nothing kept under damaged/: %v", err)
	}
	if !bytes.Equal(kept, full[:manifestEnd]) {
		t.Fatalf("damaged/ holds %d bytes, want the manifest chunk's %d", len(kept), manifestEnd)
	}
	if got := damagedRecord(t, s, relayName, rec.RelayID); got.Cause != cause || got.RelayID != rec.RelayID || got.Relay != relayName {
		t.Fatalf("the damaged record: %+v; want cause %q for relay message %d on %s", got, cause, rec.RelayID, relayName)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 { // the bytes and the record, one message
		t.Fatalf("damaged/%s holds %d files, want one message's two", relayName, len(entries))
	}

	// Acknowledged, out of the quarantine, and nobody added.
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("the relay still holds %v; want the stream acknowledged", left)
	}
	if box, _, err := s.Find(rec.Inner.ID); err == nil {
		t.Fatalf("after trust the message is still in %s", box)
	}
	strangerFP := stranger.exportFingerprint()
	for _, p := range adv2PeersOf(t, bob) {
		if p.Fingerprint == strangerFP {
			t.Fatalf("trust of a stream kept as damaged added the stranger as %q", p.Name)
		}
	}
	if peers := adv2PeersOf(t, bob); len(peers) != 0 {
		t.Fatalf("trust of a stream kept as damaged added peers: %+v", peers)
	}

	// A second trust finds nothing to trust and downloads nothing again.
	before = served.Load()
	stderr = captureStderr(t, func() { out, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID) })
	again := served.Load() - before
	t.Logf("trust 2: %d bytes pulled: %v\n%s%s", again, err, out, stderr)
	var e *exitError
	want := fmt.Sprintf("no message matches %q", rec.Inner.ID)
	if !asExit(err, &e) || e.code != exitUsage || err.Error() != want {
		t.Fatalf("a second trust: %v; want exit %d and %q", err, exitUsage, want)
	}
	if again != 0 {
		t.Fatalf("a second trust pulled %d bytes from the relay; want none", again)
	}
	if out != "" || stderr != "" {
		t.Fatalf("a second trust printed %q and %q; want nothing beyond its refusal", out, stderr)
	}
	if peers := adv2PeersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a second trust added peers: %+v", peers)
	}
	if cuts.Load() != 0 {
		t.Fatalf("the proxy cut %d answers with nothing asking it to", cuts.Load())
	}
}

// The other side of the line: a stream whose payload is honest and whose
// connection drops part way through it is the relay's failure, not the
// sender's. Trust exits 2 as a transport failure, keeps nothing under
// damaged/, acknowledges nothing, leaves the record in quarantine with its
// payload on the relay and adds nobody; with the connection whole again,
// the same trust delivers the stream and names the peer.
func TestATrustWhosePayloadConnectionDropsIsATransportFailure(t *testing.T) {
	srv, st, bob, rec, payload := strangersStream(t)
	var served, cuts atomic.Int64
	var drop atomic.Bool
	front := adv2CountingFront(t, srv, &served, &cuts, &drop)
	relayName := repointRelay(t, bob, front.URL)

	drop.Store(true)
	var err error
	stderr := captureStderr(t, func() { _, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID) })
	t.Logf("trust with the payload cut: %v (%d cuts)\n%s", err, cuts.Load(), stderr)
	if cuts.Load() == 0 {
		t.Fatal("the proxy cut nothing: the payload was never asked for")
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), errDownloadInterrupted.Error()) {
		t.Fatalf("trust over a connection that drops mid-payload: %v; want exit %d naming the interruption", err, exitTransport)
	}
	if strings.Contains(stderr, "could not be opened") {
		t.Fatalf("a dropped connection was said to be a stream that will not open:\n%s", stderr)
	}
	s, _, _ := bob.opened()
	box, still, err := s.Find(rec.Inner.ID)
	if err != nil || box != store.Quarantine || !still.PayloadOnRelay {
		t.Fatalf("after a dropped trust the record is in %s (payload_on_relay=%v, %v); want it in quarantine with its payload on the relay",
			box, still != nil && still.PayloadOnRelay, err)
	}
	path := damagedPathOf(t, s, relayName, rec.RelayID)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a dropped trust kept something under damaged/: %v", err)
	}
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 1 || left[0] != rec.RelayID {
		t.Fatalf("after a dropped trust the relay holds %v; want [%d], unacknowledged", left, rec.RelayID)
	}
	if peers := adv2PeersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a dropped trust added peers: %+v", peers)
	}

	drop.Store(false)
	if _, err := bob.answer("mallory", "quarantine", "trust", rec.Inner.ID); err != nil {
		t.Fatalf("trust with the connection whole: %v", err)
	}
	trusted(t, bob, rec.Inner.ID, "mallory", payload)
}

// adv2CountingWriter counts what it writes into n. With cutAfter set it
// aborts the answer once that many body bytes have gone, counting the cut.
type adv2CountingWriter struct {
	http.ResponseWriter
	n        *atomic.Int64
	cutAfter int64
	cuts     *atomic.Int64
	written  int64
}

func (w *adv2CountingWriter) Write(p []byte) (int, error) {
	if w.cutAfter > 0 && w.written+int64(len(p)) > w.cutAfter {
		p = p[:w.cutAfter-w.written]
		n, _ := w.ResponseWriter.Write(p)
		w.n.Add(int64(n))
		w.Flush()
		w.cuts.Add(1)
		panic(http.ErrAbortHandler)
	}
	n, err := w.ResponseWriter.Write(p)
	w.n.Add(int64(n))
	w.written += int64(n)
	return n, err
}

func (w *adv2CountingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func adv2PeersOf(t *testing.T, u *user) []peerJSON {
	t.Helper()
	var peers []peerJSON
	if err := json.Unmarshal([]byte(u.run("peers", "ls", "--json")), &peers); err != nil {
		t.Fatal(err)
	}
	return peers
}

func adv2RowIDs(t *testing.T, st *relay.Store, fp string) []int64 {
	t.Helper()
	rows, err := st.List(fp, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// A relay that answers 410 to the payload has found its stored file
// damaged and dropped it: that is the relay's doing, never the sender's,
// as the fetch reads it (droppedOnRelay). Trust says the body is no longer
// on the relay and exits 2; it keeps nothing under damaged/, acknowledges
// nothing, leaves the record in quarantine and adds nobody. Read as a
// payload that will not open, it would have settled an honest sender's
// stream as damaged and blamed them for the relay's loss.
func TestATrustWhosePayloadTheRelayDroppedBlamesTheRelay(t *testing.T) {
	srv, st, bob, rec, _ := strangersStream(t)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var gone atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The payload is asked for by an open-ended range; the manifest
		// by a closed one, which goes through.
		if rg := r.Header.Get("Range"); strings.HasSuffix(rg, "-") {
			gone.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			io.WriteString(w, `{"error":"message is damaged on the relay and has been dropped"}`)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	relayName := repointRelay(t, bob, front.URL)

	var out string
	stderr := captureStderr(t, func() { out, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID) })
	t.Logf("trust with the payload gone: %v (%d answered 410)\n%s%s", err, gone.Load(), out, stderr)
	if gone.Load() == 0 {
		t.Fatal("the proxy answered no 410: the payload was never asked for")
	}
	var e *exitError
	want := fmt.Sprintf("%s: its body is no longer on the relay; ask the sender to send it again", rec.Inner.ID[:12])
	if !asExit(err, &e) || e.code != exitTransport || err.Error() != want {
		t.Fatalf("trust of a payload the relay dropped: %v; want exit %d and %q", err, exitTransport, want)
	}
	for _, said := range []string{out, stderr} {
		if strings.Contains(said, "could not be opened") || strings.Contains(said, "will not open") {
			t.Fatalf("a payload the relay dropped was blamed on the sender:\n%s", said)
		}
	}
	s, _, _ := bob.opened()
	path := damagedPathOf(t, s, relayName, rec.RelayID)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a payload the relay dropped was kept under damaged/: %v", err)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err == nil && len(entries) != 0 {
		t.Fatalf("damaged/%s holds %d files; want none", relayName, len(entries))
	}
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 1 || left[0] != rec.RelayID {
		t.Fatalf("after the trust the relay holds %v; want [%d], unacknowledged", left, rec.RelayID)
	}
	box, still, err := s.Find(rec.Inner.ID)
	if err != nil || box != store.Quarantine || !still.PayloadOnRelay {
		t.Fatalf("after the trust the record is in %s (%v); want it kept in quarantine with its payload on the relay", box, err)
	}
	if peers := adv2PeersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a trust of a payload the relay dropped added peers: %+v", peers)
	}
}

// The settle's order (G8): a trust whose payload will not open keeps the
// stream under damaged/, acknowledges it, and only then removes the
// quarantine record, since a one-way move writes the thing that says it
// happened last. While the relay refuses the acknowledgement the trust
// exits 2 as a transport failure and the record stays, the row on the relay
// with it, so the next trust finds the message and settles it then. Were the
// record removed first, the refused acknowledgement would leave a row on
// the relay that no trust could reach.
func TestATrustWhoseAcknowledgementFailsKeepsTheRecordForTheNextTrust(t *testing.T) {
	srv, st := startRelayServer(t, relay.Config{Limits: relay.DefaultLimits()})
	bob := newUser(t, "bob", srv.URL)
	stranger := newUser(t, "stranger", srv.URL)
	stranger.run("peers", "add", bob.exportLine())
	adv2UploadCorruptStream(t, stranger, bob, "corrupt")

	// While refuse is set, every acknowledgement (client.Ack: a DELETE on
	// the message in the mailbox) is answered 503, the client's retries
	// among them, in the body the relay writes when it is busy.
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var refuse atomic.Bool
	var refused atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			refused.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":"relay is busy","code":""}`)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	relayName := repointRelay(t, bob, front.URL)

	if got := bob.inboxJSON(); got.Fetch.Quarantined != 1 {
		t.Fatalf("fetch: %+v", got.Fetch)
	}
	rec := recordOf(t, bob, store.Quarantine, "corrupt")
	if !rec.PayloadOnRelay {
		t.Fatalf("the quarantined stream: %+v", rec)
	}
	s, _, _ := bob.opened()
	path := damagedPathOf(t, s, relayName, rec.RelayID)
	cause := streamCause(stream.ErrOpenFailed)
	sentence := fmt.Sprintf("warning: relay message %d could not be opened (%s) and was kept as %s; ask the sender to send it again\n",
		rec.RelayID, cause, path)
	strangerFP := stranger.exportFingerprint()

	// The first trust, its acknowledgement refused: exit 2, the payload
	// read and kept as damaged, the record and the row both still there.
	refuse.Store(true)
	var out string
	stderr := captureStderr(t, func() { out, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID) })
	t.Logf("trust 1, its acknowledgement refused %d times: %v\n%s%s", refused.Load(), err, out, stderr)
	if refused.Load() == 0 {
		t.Fatal("the proxy refused no acknowledgement: none was asked for")
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || err.Error() != "relay returned 503: relay is busy" {
		t.Fatalf("trust with its acknowledgement refused: %v; want exit %d and the relay's 503", err, exitTransport)
	}
	if stderr != sentence {
		t.Fatalf("trust's standard error:\n%q\nwant\n%q", stderr, sentence)
	}
	if strings.Contains(out, "settled as damaged") {
		t.Fatalf("a trust whose acknowledgement was refused said it settled:\n%s", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nothing kept under damaged/ before the acknowledgement: %v", err)
	}
	box, still, err := s.Find(rec.Inner.ID)
	if err != nil || box != store.Quarantine || !still.PayloadOnRelay {
		t.Fatalf("after a refused acknowledgement the record is in %s (%v); want it kept in quarantine with its payload on the relay", box, err)
	}
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 1 || left[0] != rec.RelayID {
		t.Fatalf("after a refused acknowledgement the relay holds %v; want [%d]", left, rec.RelayID)
	}
	if peers := adv2PeersOf(t, bob); len(peers) != 0 {
		t.Fatalf("a trust whose acknowledgement was refused added peers: %+v", peers)
	}

	// The relay answers again: the same trust finds the record and settles.
	refuse.Store(false)
	refusedBefore := refused.Load()
	stderr = captureStderr(t, func() { out, err = bob.answer("mallory", "quarantine", "trust", rec.Inner.ID) })
	t.Logf("trust 2: %v\n%s%s", err, out, stderr)
	if err != nil {
		t.Fatalf("trust with the relay answering again: %v; want exit 0", err)
	}
	if refused.Load() != refusedBefore {
		t.Fatalf("the proxy refused %d acknowledgements with refuse clear", refused.Load()-refusedBefore)
	}
	settled := fmt.Sprintf("%s: its payload will not open; it was settled as damaged and acknowledged, and nobody was added\n", rec.Inner.ID[:12])
	if !strings.HasSuffix(out, settled) {
		t.Fatalf("trust said:\n%s\nwant it to end %q", out, settled)
	}
	if stderr != sentence {
		t.Fatalf("the second trust's standard error:\n%q\nwant\n%q", stderr, sentence)
	}
	if box, _, err := s.Find(rec.Inner.ID); err == nil {
		t.Fatalf("after the second trust the message is still in %s", box)
	}
	if left := adv2RowIDs(t, st, bob.exportFingerprint()); len(left) != 0 {
		t.Fatalf("after the second trust the relay still holds %v; want the stream acknowledged", left)
	}
	for _, p := range adv2PeersOf(t, bob) {
		if p.Fingerprint == strangerFP {
			t.Fatalf("the second trust added the stranger as %q", p.Name)
		}
	}
	if peers := adv2PeersOf(t, bob); len(peers) != 0 {
		t.Fatalf("the second trust added peers: %+v", peers)
	}
	// One message under damaged/, rewritten in place: its bytes and its
	// record, nothing else.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("damaged/%s holds %d files, want one message's two", relayName, len(entries))
	}
	if got := damagedRecord(t, s, relayName, rec.RelayID); got.Cause != cause || got.RelayID != rec.RelayID || got.Relay != relayName {
		t.Fatalf("the damaged record: %+v; want cause %q for relay message %d on %s", got, cause, rec.RelayID, relayName)
	}
}
