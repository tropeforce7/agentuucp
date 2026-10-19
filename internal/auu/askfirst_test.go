package auu

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// An inline send over a relay's max_bytes, which a raised stream threshold
// or --inline makes, is refused in the relay's words at a transport
// failure's exit code, not as a dropped link (57d): the post asks before
// its body goes, so the relay's 413 arrives where its reset used to.
func TestAnInlineSendOverTheRelaysCapSaysTheRelaysRefusal(t *testing.T) {
	url, _ := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits(), MaxBytes: 1 << 20})
	alice := newUser(t, "alice", url)
	bob := newUser(t, "bob", url)
	alice.run("peers", "add", bob.exportLine())
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := alice.tryRun("send", "--to", "bob", "--subject", "big", "--inline", "--attach", file, "text")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("an inline send over the relay's cap: %v; want exit %d", err, exitTransport)
	}
	if !strings.Contains(err.Error(), "relay returned 413") || strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("an inline send over the relay's cap said %q; want the relay's 413, not a dropped link", err)
	}
}
