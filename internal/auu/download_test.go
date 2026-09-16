package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// dropper cuts the payload download short after a number of bytes, as many
// times as it is told to. Only the open-ended range is cut: the two small
// requests that fetch a manifest are left alone, so a test can be sure it is
// interrupting the download and not the look at who sent it.
type dropper struct {
	inner http.Handler

	mu       sync.Mutex
	drops    int   // downloads still to cut short
	after    int64 // bytes to serve before cutting
	manifest bool  // cut the small manifest ranges instead of the payload
	full     int   // downloads served whole
	cut      int   // downloads cut short
}

func (d *dropper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rng := r.Header.Get("Range")
	blob := r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blob") &&
		strings.HasPrefix(rng, "bytes=")
	openEnded := strings.HasSuffix(rng, "-")
	payload := blob && openEnded != d.manifest
	if !payload {
		d.inner.ServeHTTP(w, r)
		return
	}

	d.mu.Lock()
	cut := d.drops > 0
	if cut {
		d.drops--
		d.cut++
	} else {
		d.full++
	}
	after := d.after
	d.mu.Unlock()

	if !cut {
		d.inner.ServeHTTP(w, r)
		return
	}
	// Writing fewer bytes than the declared Content-Length and returning makes
	// the server close the connection without finishing the body, which is
	// what the client sees when a download is interrupted.
	d.inner.ServeHTTP(&shortWriter{ResponseWriter: w, left: after}, r)
}

func (d *dropper) counts() (full, cut int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.full, d.cut
}

type shortWriter struct {
	http.ResponseWriter
	left int64
}

var errCut = errors.New("connection cut")

func (s *shortWriter) Write(p []byte) (int, error) {
	if s.left <= 0 {
		return 0, errCut
	}
	if int64(len(p)) > s.left {
		p = p[:s.left]
	}
	n, err := s.ResponseWriter.Write(p)
	s.left -= int64(n)
	if s.left <= 0 && err == nil {
		err = errCut
	}
	return n, err
}

func startDroppingRelay(t *testing.T, drops int, after int64) (string, *dropper) {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := &dropper{
		inner: relay.NewServer(st, relay.Config{
			Streams: true,
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			Limits:  relay.DefaultLimits(),
		}),
		drops: drops,
		after: after,
	}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return srv.URL, d
}

// A payload takes several attachments so that a cut lands in the middle of one.
func downloadPayload() []byte {
	p := make([]byte, 400<<10)
	for i := range p {
		p[i] = byte(i*13 + 5)
	}
	return p
}

func sendOneStream(t *testing.T, alice, bob *user, payload []byte, name string) {
	t.Helper()
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	file := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	alice.run("send", "--to", "bob", "--subject", "a long download", "--attach", file, "here")
}

// One dropped download is picked up with a Range from where it stopped, inside
// the same fetch: the HPKE context is still open, so the bytes already
// decrypted are not thrown away.
func TestDownloadResumesWithinOneFetch(t *testing.T) {
	relayURL, gate := startDroppingRelay(t, 1, 100<<10)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	payload := downloadPayload()
	sendOneStream(t, alice, bob, payload, "long.bin")

	out := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, out)
	}
	if got.Fetch.Delivered != 1 {
		t.Fatalf("a download that dropped once did not deliver: %+v", got.Fetch)
	}
	full, cut := gate.counts()
	if cut != 1 {
		t.Fatalf("the harness cut %d downloads, want 1", cut)
	}
	if full != 1 {
		t.Fatalf("the client made %d whole download requests after the cut, want 1", full)
	}

	dir := t.TempDir()
	bob.run("extract", got.Messages[0].ID, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "long.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("the resumed download differs: %d bytes back, %d sent", len(back), len(payload))
	}
}

// A download that keeps dropping past the budget is a transport failure:
// nothing is delivered, nothing is acknowledged, nothing is left half written,
// and the next fetch gets it.
func TestDownloadThatKeepsDroppingIsNotAcknowledged(t *testing.T) {
	relayURL, gate := startDroppingRelay(t, maxStalledReconnects, 0)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	payload := downloadPayload()
	sendOneStream(t, alice, bob, payload, "stubborn.bin")

	out, err := bob.tryRun("inbox", "--json")
	if err == nil {
		t.Fatalf("a download that never completed was reported as success:\n%s", out)
	}

	// Nothing under AUU_HOME claims to hold it.
	var partial []string
	filepath.WalkDir(bob.home, func(path string, e os.DirEntry, err error) error {
		if err == nil && strings.Contains(e.Name(), ".d") {
			partial = append(partial, path)
		}
		return nil
	})
	if len(partial) != 0 {
		t.Fatalf("a failed download left files behind: %v", partial)
	}

	if _, cut := gate.counts(); cut != maxStalledReconnects {
		t.Fatalf("the client gave up after %d attempts, want %d", cut, maxStalledReconnects)
	}

	// The relay still holds it, so the next fetch gets it whole.
	second := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(second), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, second)
	}
	if got.Fetch.Delivered != 1 {
		t.Fatalf("the second fetch delivered %+v", got.Fetch)
	}
	if full, cut := gate.counts(); full != 1 || cut != maxStalledReconnects {
		t.Fatalf("the second fetch: %d whole downloads and %d cut, want 1 and %d",
			full, cut, maxStalledReconnects)
	}

	dir := t.TempDir()
	bob.run("extract", got.Messages[0].ID, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "stubborn.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("the payload did not survive a retried download")
	}

	// And it is acknowledged exactly once: a third fetch finds nothing.
	third := bob.run("inbox", "--json")
	var again inboxJSON
	if err := json.Unmarshal([]byte(third), &again); err != nil {
		t.Fatal(err)
	}
	if again.Fetch.Delivered != 0 {
		t.Fatalf("the message was delivered twice: %+v", again.Fetch)
	}
}

// A manifest read that is cut short is a transport failure too. It must not be
// taken for a manifest nobody can open, because that answer acknowledges the
// message and throws it away.
func TestInterruptedManifestIsNotDiscarded(t *testing.T) {
	relayURL, gate := startDroppingRelay(t, 1, 8)
	gate.manifest = true
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	payload := downloadPayload()
	sendOneStream(t, alice, bob, payload, "manifest.bin")

	if out, err := bob.tryRun("inbox", "--json"); err == nil {
		t.Fatalf("a cut-off manifest read was reported as success:\n%s", out)
	}

	// Nothing was acknowledged, so the message is still there.
	out := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, out)
	}
	if got.Fetch.Delivered != 1 || got.Fetch.Unreadable != 0 {
		t.Fatalf("after an interrupted manifest read: %+v", got.Fetch)
	}
	dir := t.TempDir()
	bob.run("extract", got.Messages[0].ID, "--out", dir)
	back, err := os.ReadFile(filepath.Join(dir, "manifest.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("the payload did not survive an interrupted manifest read")
	}
}
