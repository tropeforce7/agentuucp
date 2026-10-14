package relay

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A relay at wire level 2 takes an owner's directory of version 2 and
// holds it: the push is taken, the document and its signature come back
// to a sender byte for byte, a post to a channel that carries every rule
// is routed by it, and the owner's listing says the directory is signed.
// What the rules refuse is the next change's; this is the taking.
func TestARelayTakesAndHoldsAVersionTwoDirectory(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()

	ruled := channels.Channel{Name: "bug reports", MaxBytes: relayapi.MaxStreamSize, NoStreams: true, NoForwards: true}
	status, body, pushed := h.pushDirectory(bob, bob, time.Now(), dflt, ruled)
	if status != http.StatusNoContent {
		t.Fatalf("the push of a version 2 directory: %d %s", status, body)
	}
	if !bytes.HasPrefix(pushed.Document, []byte(`{"v":2,`)) {
		t.Fatalf("the directory was not signed as version 2: %s", pushed.Document)
	}
	for _, field := range []string{`"max_bytes":`, `"no_streams":true`, `"no_forwards":true`} {
		if strings.Count(string(pushed.Document), field) != 1 {
			t.Fatalf("the pushed document carries %s other than once: %s", field, pushed.Document)
		}
	}

	status, body, got := h.getDirectory(alice, fp)
	if status != http.StatusOK {
		t.Fatalf("a sender's read of the directory: %d %s", status, body)
	}
	if !bytes.Equal(got.Document, pushed.Document) || !bytes.Equal(got.Signature, pushed.Signature) {
		t.Fatalf("the directory came back changed:\n got %s\nwant %s", got.Document, pushed.Document)
	}

	env := sealedTo(t, alice, bob.Public(), "x", "bug reports")
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, env, nil); status != http.StatusOK {
		t.Fatalf("a post to the ruled channel: %d %s", status, body)
	}
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, sealedTo(t, alice, bob.Public(), "x", "invented"), nil); status != http.StatusNotFound {
		t.Fatalf("a post to a channel the version 2 directory does not carry: %d %s", status, body)
	}
	if got := h.listedDirectory(bob); got != relayapi.DirectorySigned {
		t.Fatalf("the listing says %q, want signed", got)
	}
}
