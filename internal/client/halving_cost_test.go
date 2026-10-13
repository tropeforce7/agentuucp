package client

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The second review's F6 halving, kept: a relay over the hold on every ask
// costs one listing eight asks (200, 100, 50, 25, 12, 6, 3, 1), each read
// to the hold and a byte before it is refused. This records what that
// costs and holds the count of asks. The page is chunked with its padding
// before the closing brace, as the review's was: pageCostRelay with lead
// and declared false, and pageCostMeasure, are the review's own helpers as
// they landed with commit 5.
func TestTheHalvingCostsEightReadsOfTheHold(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation is measured without the race detector")
	}
	var asks atomic.Int64
	srv := pageCostRelay(t, relayapi.MaxListingHold+1, false, false, &asks)
	c, err := New(srv.URL, testIdentity(t, "tester"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.listingCap(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	var listErr error
	total, peak := pageCostMeasure(func() { _, listErr = c.List(t.Context(), 0, relayapi.MaxListLimit) })
	hold := uint64(relayapi.MaxListingHold)
	t.Logf("pages of hold+1 bytes on every ask: asks=%d; err=%v; TotalAlloc +%d MiB (%.1fx the hold); peak live heap +%d MiB (%.1fx)",
		asks.Load(), listErr, total>>20, float64(total)/float64(hold), peak>>20, float64(peak)/float64(hold))
	if !errors.Is(listErr, ErrMalformedAnswer) {
		t.Fatalf("want the malformed answer, got %v", listErr)
	}
	if asks.Load() != 8 {
		t.Errorf("asks = %d; the commit says at most seven more than the first", asks.Load())
	}
}
