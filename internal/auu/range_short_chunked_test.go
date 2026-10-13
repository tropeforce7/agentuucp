package auu

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// The second review's F3 sibling, kept: a proxy that answers every range
// with the right 206 and the right Content-Range, but chunked and cut to
// half the span with a clean end of the chunked body (no Content-Length to
// betray it). Blob accepts the answer (it holds the header, not the body's
// length when none is given) and its LimitReader ends in a clean EOF. The
// callers must still take that as a cut: the manifest read
// (readBlobRange's ReadFull) and the payload read (resumingReader's until)
// both do, so the fetch is a transport failure, nothing is kept under
// damaged/, and the stream waits on the relay. It is here because Blob
// alone does not hold it (TestBlobRangeEdges in internal/client).
func TestAShortChunkedRangeIsATransportFailure(t *testing.T) {
	for _, cutManifest := range []bool{true, false} {
		name := "payload ranges cut"
		if cutManifest {
			name = "every range cut"
		}
		t.Run(name, func(t *testing.T) {
			relayURL := startRelay(t)
			alice := newUser(t, "alice", relayURL)
			bob := newUser(t, "bob", relayURL)
			alice.run("peers", "add", bob.exportLine())
			bob.run("peers", "add", alice.exportLine())
			var cut atomic.Int64
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req, _ := http.NewRequestWithContext(r.Context(), r.Method, relayURL+r.URL.RequestURI(), r.Body)
				req.Header = r.Header.Clone()
				resp, err := http.DefaultTransport.RoundTrip(req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				rng := r.Header.Get("Range")
				open := strings.HasSuffix(rng, "-")
				for k, v := range resp.Header {
					if k == "Content-Length" && resp.StatusCode == http.StatusPartialContent && (cutManifest || open) {
						continue
					}
					w.Header()[k] = v
				}
				w.WriteHeader(resp.StatusCode)
				if resp.StatusCode == http.StatusPartialContent && (cutManifest || open) {
					body, _ := io.ReadAll(resp.Body)
					cut.Add(1)
					w.(http.Flusher).Flush() // chunked, so no length is given
					w.Write(body[:len(body)/2])
					return // a clean end of the chunked body
				}
				io.Copy(w, resp.Body)
			}))
			defer front.Close()
			repointRelay(t, bob, front.URL)
			payload := make([]byte, 300<<10)
			for i := range payload {
				payload[i] = byte(i * 13)
			}
			file := filepath.Join(t.TempDir(), "big.bin")
			if err := os.WriteFile(file, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			alice.run("send", "--to", "bob", "--attach", file, "x")
			_, err := bob.tryRun("inbox", "--json")
			var e *exitError
			t.Logf("fetch through the cutting proxy (%d answers cut): %v", cut.Load(), err)
			if cut.Load() == 0 {
				t.Fatal("nothing was cut")
			}
			if !errors.As(err, &e) || e.code != exitTransport {
				t.Errorf("a range cut short with a clean chunked end: %v; want a transport failure", err)
			}
			s, err := store.Open(bob.home)
			if err != nil {
				t.Fatal(err)
			}
			if kept, err := os.ReadDir(s.DamagedDir()); err == nil && len(kept) > 0 {
				t.Errorf("kept %d entries under damaged/", len(kept))
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			repointRelay(t, bob, relayURL)
			if got := bob.inboxJSON(); got.Fetch.Delivered != 1 {
				t.Errorf("straight to the relay afterwards: %+v; want the stream delivered", got.Fetch)
			}
		})
	}
}
