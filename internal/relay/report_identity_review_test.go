package relay

import (
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestARetriedReportIsAnswered409AndLeavesTheOlderGeneration is Codex's
// TestReviewRetriedReportCannotFailAnotherGeneration under its name (G22,
// R26). A relay may reuse its numeric IDs after database recreation.
// Retrying a report whose 204 was lost must not apply it to an older message
// sharing ID: HandedTo reads the newest row sharing the pair whatever its
// state, and when that row is final the answer is 409 already reported,
// never an older row still handed.
func TestARetriedReportIsAnswered409AndLeavesTheOlderGeneration(t *testing.T) {
	courier := neighbourID(t, "bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice := h.user(t, "alice")

	t.Run("a retry after a lost answer", func(t *testing.T) {
		older := h.handedRow(t, alice, h.fpOf(t, "bob"), "old generation", 5)
		newer := h.handedRow(t, alice, h.fpOf(t, "carol"), "new generation", 5)
		report := failedReq(5, relayapi.CodeRefused, "new generation recipient refused")
		status, body := h.do(courier, "POST", "/v1/forward/failed", report, nil)
		if status != 204 {
			t.Fatalf("first report: %d %s", status, body)
		}
		if h.outbound(t, newer).State != OutFinal || h.outbound(t, older).State != OutHanded {
			t.Fatal("first report did not select newest handed row")
		}
		// Fresh HTTP signature/nonce, identical application report, as a retry
		// after a lost response would send. Transport replay protection is intact.
		status, body = h.do(courier, "POST", "/v1/forward/failed", report, nil)
		t.Logf("retry: %d %s", status, body)
		if row := h.outbound(t, older); row.State != OutHanded {
			t.Errorf("unrelated older message became %s: %q", row.State, row.Said)
		}
		if status != 409 {
			t.Errorf("retry status=%d; want already-reported 409", status)
		}
	})

	// The other order is unchanged: an older row already told about beside
	// a newer one still handed, and the report is the newer one's.
	t.Run("an older final row beside a newer handed row", func(t *testing.T) {
		done := h.handedRow(t, alice, h.fpOf(t, "dave"), "told already", 8)
		if err := h.store.Failed(done, relayapi.CodeRefused, "bar: told already", h.clock.Now()); err != nil {
			t.Fatal(err)
		}
		live := h.handedRow(t, alice, h.fpOf(t, "erin"), "live", 8)
		status, body := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(8, relayapi.CodeRefused, "gone"), nil)
		if status != 204 {
			t.Fatalf("report: %d %s", status, body)
		}
		if got := h.outbound(t, live); got.State != OutFinal || got.Said != "bar: gone" {
			t.Errorf("the newer row is %q saying %q, want final with the report's sentence", got.State, got.Said)
		}
		if got := h.outbound(t, done); got.State != OutFinal || got.Said != "bar: told already" {
			t.Errorf("the older row is %q saying %q, want as it was", got.State, got.Said)
		}
	})
}
