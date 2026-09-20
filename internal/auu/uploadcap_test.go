package auu

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// A sender at the relay's cap on open uploads waits the Retry-After the
// 429 carries and then opens: the client's loop treats the refusal as one
// to wait out, since it does not say waiting will not help, and the open
// it retries meets the sender's expired upload and lets it go. The relay
// runs on a clock the test moves: the upload already open expires a
// second on, so the refusal asks for a second, and the clock passes the
// expiry while the client waits.
func TestASenderAtTheCapWaitsAndThenOpens(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	logs := &syncBuffer{}
	limits := relay.DefaultLimits()
	limits.MaxOpenUploads = 1
	relayURL, st := startRelayConfig(t, relay.Config{
		Limits: limits,
		Now:    clock,
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
	})
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")

	// The one upload the cap allows, planted as the relay's own row for
	// alice, expiring a second on.
	id, err := relay.NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.OpenUpload(id, bob.exportFingerprint(), alice.exportFingerprint(), "default", 1<<20,
		clock(), clock().Add(time.Second), relay.Quotas{}, 0); err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 100<<10)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	file := filepath.Join(t.TempDir(), "waited.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	// The clock passes the planted upload's expiry while the client is
	// waiting out the refusal.
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		now = now.Add(2 * time.Second)
		mu.Unlock()
	}()
	alice.run("send", "--to", "bob", "--subject", "after the wait", "--attach", file, "here it is")
	<-done

	// The relay saw the open refused at the cap and then taken.
	log := logs.String()
	refused := strings.Index(log, `limit="open uploads"`)
	taken := strings.LastIndex(log, "/streams status=201")
	if refused < 0 || taken < 0 || taken < refused {
		t.Fatalf("the relay's log does not show the open refused at the cap and then taken:\n%s", log)
	}
	if !strings.Contains(log, "abandoned uploads removed") {
		t.Fatalf("the open after the wait did not let the expired upload go:\n%s", log)
	}
	if _, err := st.Upload(id); err == nil {
		t.Fatal("the planted upload is still there after the open that met it expired")
	}

	inbox := bob.run("inbox", "--json")
	var got inboxJSON
	if err := json.Unmarshal([]byte(inbox), &got); err != nil {
		t.Fatalf("inbox --json unparseable: %v\n%s", err, inbox)
	}
	var found int
	for _, m := range got.Messages {
		if m.Subject == "after the wait" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("the message arrived %d times, want once: %+v", found, got.Messages)
	}
}
