package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// couriers fetches the courier listing as the caller.
func (h *harness) couriers(caller *identity.Identity) (int, []byte, relayapi.CouriersResponse) {
	h.t.Helper()
	status, body := h.do(caller, "GET", "/v1/couriers", nil, nil)
	var resp relayapi.CouriersResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			h.t.Fatalf("the courier listing is not JSON: %s", body)
		}
	}
	return status, body, resp
}

// TestTheCourierListingIsForThisRelaysOwnUsers: ruling 32's disclosure, tested
// at both edges.
//
// Any registered identity here may read it, and nobody else. Its own users must
// know these names and fingerprints to be reachable from off this relay at all
// — delivery of a forwarded message asks the recipient's allow list about the
// courier that handed the envelope over — so an operator could not withhold it
// and still have forwarding work for them. A stranger with no mailbox here is
// refused as every mailbox route refuses one, which is the answer that keeps
// this from being an oracle: somebody who merely holds a courier's fingerprint
// learns nothing, because they have no mailbox to ask with.
func TestTheCourierListingIsForThisRelaysOwnUsers(t *testing.T) {
	bar := neighbourID(t, "bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{bar}, nil)
	alice := h.user(t, "alice")
	stranger := ids(t, "stranger")[0]

	// An identity no mailbox has, signing a well-formed request: 401, the one
	// word every authentication failure gets.
	status, body, _ := h.couriers(stranger)
	if status != http.StatusUnauthorized || errorText(t, body) != "unauthorized" {
		t.Fatalf("a stranger with no mailbox: %d %s", status, body)
	}
	// No signature at all.
	if status, body, _ := h.couriers(nil); status != http.StatusUnauthorized {
		t.Fatalf("no signature: %d %s", status, body)
	}
	// A blocked user of this relay, refused as they are everywhere else.
	blocked := h.user(t, "blocked")
	if err := h.store.SetBlock(blocked.Fingerprint(), "gone", alice.Fingerprint(), h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := h.couriers(blocked); status != http.StatusForbidden {
		t.Fatalf("a blocked caller: %d %s", status, body)
	}
	// And a registered one is answered, with the neighbour this relay accepts
	// from and the fingerprint its file admits.
	status, body, resp := h.couriers(alice)
	if status != http.StatusOK {
		t.Fatalf("a registered user: %d %s", status, body)
	}
	if len(resp.Couriers) != 1 {
		t.Fatalf("%d couriers, want the one: %s", len(resp.Couriers), body)
	}
	if resp.Couriers[0].Name != "bar" {
		t.Errorf("name %q, want this relay's own name for the neighbour", resp.Couriers[0].Name)
	}
	if resp.Couriers[0].FP != bar.Fingerprint() {
		t.Errorf("fp %q, want the fingerprint the couriers file admits", resp.Couriers[0].FP)
	}
	// The courier's own mailbox still answers exactly as any refusing mailbox
	// does, which is what the route must not have changed: 10b closed an
	// oracle to anybody holding a fingerprint, and this route answers nobody
	// without a mailbox here.
	h.enroll(bar)
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+bar.Fingerprint(),
		sealed(t, alice, bar.Public(), "hello"), nil); status != http.StatusForbidden ||
		errorText(t, body) != msgNotAllowed {
		t.Errorf("a post to the courier's mailbox: %d %s; want the refusal every unadmitted sender gets",
			status, body)
	}
}

// TestACourierListingIsAListEvenWhenItIsEmpty: a relay that forwards nothing
// says so, and says it with [] rather than with an absent key.
//
// Absent and empty are one value after a decode, so a reader that had to tell
// them apart would be guessing about whether it may address mail through here.
// A relay with no courier block at all is the case: it has no file to read, and
// it answers the same shape as one whose file is empty.
func TestACourierListingIsAListEvenWhenItIsEmpty(t *testing.T) {
	// No courier block: this relay forwards nothing.
	h := newHarness(t, Config{})
	alice := h.user(t, "alice")
	status, body, resp := h.couriers(alice)
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	if resp.Couriers == nil || len(resp.Couriers) != 0 {
		t.Errorf("couriers is %v; want an empty list", resp.Couriers)
	}
	// On the wire and not only in the struct, since a decode makes absent and
	// empty one value and the claim is about the key.
	if !strings.Contains(string(body), `"couriers":[]`) {
		t.Errorf("the answer is %s; want couriers as an empty list", body)
	}
}

// TestTheCourierListingIsInNameOrderAndFollowsTheFile: the order is the name's,
// and the answer follows the file without a restart.
//
// Name order and not fingerprint order because the name is what a person reads
// and types; the reload matters because the couriers file is the operator's and
// is re-read when it changes, so a neighbour added while the relay runs is
// addressable without bouncing it.
func TestTheCourierListingIsInNameOrderAndFollowsTheFile(t *testing.T) {
	// Deliberately not in name order in the file.
	zed := neighbourID(t, "zed")
	abe := neighbourID(t, "abe")
	mid := neighbourID(t, "mid")
	h := peered(t, []string{"zed", "abe", "mid"}, []*identity.Identity{zed, abe, mid}, nil)
	alice := h.user(t, "alice")

	_, body, resp := h.couriers(alice)
	got := make([]string, 0, len(resp.Couriers))
	for _, c := range resp.Couriers {
		got = append(got, c.Name)
	}
	if strings.Join(got, ",") != "abe,mid,zed" {
		t.Errorf("order is %v; want name order: %s", got, body)
	}
	// One removed from the file is gone from the answer, with no restart.
	writeCouriers(h.t, h.server.courier.couriers.path, zed, abe)
	_, _, resp = h.couriers(alice)
	got = got[:0]
	for _, c := range resp.Couriers {
		got = append(got, c.Name)
	}
	if strings.Join(got, ",") != "abe,zed" {
		t.Errorf("after the file changed the answer is %v; want abe,zed", got)
	}
}

// TestLimitTheCourierListingIsHeldToItsBytes: the hold MaxCouriersBytes is,
// measured rather than estimated.
//
// The worst answer a relay that loaded its file could send is MaxCouriers
// entries with every name at identity.MaxNameBytes and every fingerprint full
// length. The constant's comment gives the measurement and this is where it
// comes from, so a name bound or a fingerprint length that changed would fail
// here rather than leaving a hold that is too small to read an honest answer.
func TestLimitTheCourierListingIsHeldToItsBytes(t *testing.T) {
	list := make([]relayapi.Courier, 0, relayapi.MaxCouriers)
	for i := range relayapi.MaxCouriers {
		list = append(list, relayapi.Courier{
			Name: "r" + strings.Repeat("x", identity.MaxNameBytes-1),
			FP:   strings.Repeat(string("0123456789abcdef"[i%16]), 64),
		})
	}
	worst, err := json.Marshal(relayapi.CouriersResponse{Couriers: list})
	if err != nil {
		t.Fatal(err)
	}
	if len(worst) > relayapi.MaxCouriersBytes {
		t.Fatalf("the worst courier listing is %d bytes, over the %d hold: an honest answer from a "+
			"relay at its own file's cap would be refused by name", len(worst), relayapi.MaxCouriersBytes)
	}
	// The comment's two measurements, so that the prose is held to the encoder.
	if len(worst) != 148014 {
		t.Errorf("the worst listing is %d bytes; MaxCouriersBytes' comment says 148,014", len(worst))
	}
	one, err := json.Marshal(list[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 147 {
		t.Errorf("one entry at every bound is %d bytes; the comment says 147", len(one))
	}
	empty, err := json.Marshal(relayapi.CouriersResponse{Couriers: []relayapi.Courier{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 15 {
		t.Errorf("the empty answer is %d bytes; the comment says 15", len(empty))
	}
}
