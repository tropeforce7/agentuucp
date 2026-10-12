package envelope

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The review's TestDTwoClocksTheRelayAcceptsDisagreeOnAnInnerStamp (G5,
// D83), renamed for what it now proves. The relay holds each party to its
// own clock within relayapi.MaxSkew, so a sender four minutes ahead of the
// relay and a recipient four behind it are both served, and the sender's
// inner stamp is eight minutes ahead of the recipient's clock. Open took
// MaxSkew as its bound and refused that message as malformed, so the
// receiver filed it under damaged and acknowledged it; it now takes a
// stamp up to the chain's bound, relayapi.MaxStampAhead, and opens it.
func TestTwoPeersOneRelayAcceptsReadEachOther(t *testing.T) {
	alice, bob := pair(t)
	bobNow := time.Now()                      // the recipient's clock (Open reads time.Now())
	relayNow := bobNow.Add(4 * time.Minute)   // bob is 4 min behind the relay
	aliceNow := relayNow.Add(4 * time.Minute) // alice is 4 min ahead of it

	for who, now := range map[string]time.Time{"alice": aliceNow, "bob": bobNow} {
		a := relayapi.Auth{TS: now.Unix()}
		if !a.FreshAt(relayNow) {
			t.Fatalf("precondition: the relay refuses %s's requests", who)
		}
	}

	in := &Inner{V: Version, From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
		ID: "0123456789abcdef0123456789abcdef", Time: aliceNow, Body: body(t)}
	innerBytes, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := append(append([]byte{}, mustSign(t, alice, sigInput(bob.Fingerprint(), innerBytes))...), innerBytes...)
	if _, _, err := Open(bob, sealPlaintext(t, bob.Public(), plaintext)); err != nil {
		t.Errorf("a message sealed by a sender the relay accepts, opened by a recipient the relay accepts: %v (cause %v; beneath: %v)", err, Cause(err), errors.Unwrap(err))
	}
}

// TestTwoPeersTwoRelaysAMinuteApartReadEachOther is the twin through two
// relays. A relay's clock is not injected (R11: freshness stays on the
// real clock), so the chain is built as the relays judge it, in whole
// seconds: alice at the edge of MaxSkew ahead of her relay, her relay at
// the edge of CourierSkew ahead of bob's, which bob's relay takes from
// its courier (TestACouriersRequestIsHeldToTheMinute shows that edge
// through a real relay), and bob at the edge of MaxSkew behind his. Her
// stamp is then 2*MaxSkew + CourierSkew, eleven minutes, ahead of bob's
// clock, and Open takes it.
func TestTwoPeersTwoRelaysAMinuteApartReadEachOther(t *testing.T) {
	alice, bob := pair(t)
	bobNow := time.Unix(time.Now().Unix(), 0)        // bob's clock, at its whole second
	bobRelay := bobNow.Add(relayapi.MaxSkew)         // bob is MaxSkew behind his relay
	aliceRelay := bobRelay.Add(relayapi.CourierSkew) // her relay is a minute ahead of his
	aliceNow := aliceRelay.Add(relayapi.MaxSkew)     // alice is MaxSkew ahead of hers

	if !(&relayapi.Auth{TS: aliceNow.Unix()}).FreshAt(aliceRelay) {
		t.Fatal("precondition: alice's relay refuses her requests")
	}
	if !(&relayapi.Auth{TS: aliceRelay.Unix()}).FreshWithin(bobRelay, relayapi.CourierSkew) {
		t.Fatal("precondition: bob's relay refuses the courier of alice's")
	}
	if !(&relayapi.Auth{TS: bobNow.Unix()}).FreshAt(bobRelay) {
		t.Fatal("precondition: bob's relay refuses his requests")
	}
	if got, want := aliceNow.Sub(bobNow), 2*relayapi.MaxSkew+relayapi.CourierSkew; got != want || want != 11*time.Minute {
		t.Fatalf("the chain over one hop is %s; want %s, eleven minutes", got, want)
	}

	in := &Inner{V: Version, From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
		ID: "0123456789abcdef0123456789abcdef", Time: aliceNow, Body: body(t)}
	innerBytes, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := append(append([]byte{}, mustSign(t, alice, sigInput(bob.Fingerprint(), innerBytes))...), innerBytes...)
	if _, _, err := Open(bob, sealPlaintext(t, bob.Public(), plaintext)); err != nil {
		t.Errorf("a message across two relays a minute apart, each party within its relay's skew: %v (cause %v; beneath: %v)", err, Cause(err), errors.Unwrap(err))
	}
}
