package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/mldsa"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A listing held open for a watcher is answered before the listener drains,
// so a shutdown with twenty seconds of grace never waits on a hold of a
// minute: the hold ends as one more request that finished, and Shutdown
// returns at once. Without Close first, Shutdown waits out the grace and
// reports the drain as a failure.
func TestStopAnswersHeldListingsBeforeTheListenerDrains(t *testing.T) {
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	handler := relay.NewServer(st, relay.Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := newHTTPServer("127.0.0.1:0", handler, nil, DefaultTimeouts())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	url := "http://" + ln.Addr().String()

	id, err := identity.Generate("watcher")
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(url, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A registration carries a certificate request whether or not the
	// relay issues certificates; the key is not kept.
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "test-machine", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(context.Background(), csr); err != nil {
		t.Fatal(err)
	}

	// A listing held for longer than the grace below, in flight.
	req, err := http.NewRequest("GET", url+"/v1/mailbox/"+id.Fingerprint()+"?wait=30s", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(id, req, nil); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		status int
		body   []byte
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			answered <- answer{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		answered <- answer{status: resp.StatusCode, body: body}
	}()
	// Observed on the relay: the hold is under way before it is stopped.
	deadline := time.Now().Add(15 * time.Second)
	for handler.Held() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the relay holds %d listings, want 1", handler.Held())
		}
		time.Sleep(5 * time.Millisecond)
	}

	started := time.Now()
	if err := stopServing(handler, srv, 5*time.Second); err != nil {
		t.Fatalf("stopping with a listing held: %v", err)
	}
	if took := time.Since(started); took >= 5*time.Second {
		t.Fatalf("stopping took %s: the grace ran out, so the held listing was waited on", took)
	}
	select {
	case a := <-answered:
		if a.err != nil || a.status != http.StatusOK || !bytes.Contains(a.body, []byte(`"messages":[]`)) {
			t.Fatalf("the held listing at shutdown: %d %s (%v)", a.status, a.body, a.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the held listing was never answered")
	}
	// The listener is gone.
	if _, err := http.Get(url + "/v1/health"); err == nil {
		t.Fatal("the relay still answers after stopServing")
	}
}

// The startup line states the policy, max_waiting beside max_inflight.
func TestTheStartupLineNamesMaxWaiting(t *testing.T) {
	cfg, err := resolve(t, "", "--max-waiting", "7", "--max-inflight", "40")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logLimits(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	line := logs.String()
	if !strings.Contains(line, "max_inflight=40 max_waiting=7") {
		t.Fatalf("the limits line does not name max_waiting beside max_inflight:\n%s", line)
	}
}
