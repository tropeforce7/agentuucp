package token

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

func TestIssueVerifyRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	id := admin(t)
	now := time.Now()

	for i := range 200 {
		noteLen := 1 + r.IntN(MaxNoteBytes)
		c := Claims{
			Relay:     "https://relay.example.com",
			Use:       UseRegister,
			Note:      testutil.Text(r, noteLen),
			NotBefore: now.Unix() - int64(r.IntN(1000)),
			NotAfter:  now.Unix() + 1 + int64(r.IntN(100000)),
			Uses:      1 + r.IntN(MaxUses),
		}
		if r.IntN(2) == 0 {
			subject := admin(t)
			c.Subject = subject.Fingerprint()
		}

		raw, err := Issue(id, c)
		if err != nil {
			t.Fatalf("seed %d: iteration %d, note of %d bytes: %v", seed, i, noteLen, err)
		}
		u, err := Parse(raw)
		if err != nil {
			t.Fatalf("seed %d: iteration %d: %v", seed, i, err)
		}
		got, err := u.Verify(id.Public(), now, relayapi.MaxSkew)
		if err != nil {
			t.Fatalf("seed %d: iteration %d: %v", seed, i, err)
		}
		if got.Note != c.Note || got.Uses != c.Uses || got.Subject != c.Subject {
			t.Fatalf("seed %d: claims did not survive: %+v", seed, got)
		}

		// One flipped bit of the payload must break the signature.
		parts := strings.Split(raw, ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		bad := Prefix + "." +
			base64.RawURLEncoding.EncodeToString(testutil.FlipBit(payload, r.IntN(len(payload)*8))) +
			"." + parts[2]
		if u2, err := Parse(bad); err == nil {
			if _, err := u2.Verify(id.Public(), now, relayapi.MaxSkew); !errors.Is(err, ErrSignature) &&
				!errors.Is(err, ErrForm) && !errors.Is(err, ErrIssuer) {
				t.Fatalf("seed %d: a flipped payload bit gave %v", seed, err)
			}
		}
	}
}

// Every token id must be distinct: it is the relay's primary key, and a
// collision would let one token displace another.
func TestTokenIDsAreDistinct(t *testing.T) {
	id := admin(t)
	seen := map[string]bool{}
	for range 500 {
		raw, err := Issue(id, base(time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		u, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if seen[u.Claims.ID] {
			t.Fatalf("token id %s was issued twice", u.Claims.ID)
		}
		seen[u.Claims.ID] = true
	}
}

// The signature is vandalised rather than replaced, so length and encoding
// stay valid and only the cryptography can refuse it.
func TestTokenSignatureVandalism(t *testing.T) {
	r, seed := testutil.Seed(t)
	id := admin(t)
	now := time.Now()
	raw, err := Issue(id, base(now))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	for i := range 32 {
		bit := r.IntN(len(sig) * 8)
		bad := parts[0] + "." + parts[1] + "." +
			base64.RawURLEncoding.EncodeToString(testutil.FlipBit(sig, bit))
		u, err := Parse(bad)
		if err != nil {
			t.Fatalf("seed %d: a flipped signature bit broke parsing: %v", seed, err)
		}
		if _, err := u.Verify(id.Public(), now, relayapi.MaxSkew); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d, bit %d gave %v, want ErrSignature", seed, i, bit, err)
		}
	}
}

// The fingerprint check passes and only the signature stands: the issuer field
// names A, the key is A's, but B did the signing.
func TestRightIssuerFieldWrongSigningKey(t *testing.T) {
	a, b := admin(t), admin(t)
	now := time.Now()

	// B signs a payload that claims A as the issuer.
	fromB, err := Issue(b, base(now))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(fromB, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	claimed := strings.Replace(string(payload), b.Fingerprint(), a.Fingerprint(), 1)
	forged := Prefix + "." + base64.RawURLEncoding.EncodeToString([]byte(claimed)) + "." + parts[2]

	u, err := Parse(forged)
	if err != nil {
		t.Fatal(err)
	}
	if u.Claims.Issuer != a.Fingerprint() {
		t.Fatal("the forged token does not name A as issuer")
	}
	// Verified with A's key, which matches the claim, so ErrIssuer cannot
	// fire: only the signature check stands between this and acceptance.
	if _, err := u.Verify(a.Public(), now, relayapi.MaxSkew); !errors.Is(err, ErrSignature) {
		t.Fatalf("gave %v, want ErrSignature", err)
	}
}

func TestSignatureLengthVandalism(t *testing.T) {
	id := admin(t)
	raw, err := Issue(id, base(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string][]byte{
		"truncated by one": sig[:len(sig)-1],
		"extended by one":  append(append([]byte{}, sig...), 0),
		"empty":            nil,
	} {
		bad := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(s)
		if _, err := Parse(bad); !errors.Is(err, ErrForm) {
			t.Errorf("%s: Parse gave %v, want ErrForm", name, err)
		}
	}
}

// A fixed identity and fixed claims must always produce the same token, or the
// wire format has drifted. Random tests find the edge; this pins the format.
func TestKnownAnswer(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	id, err := identity.FromSeeds("fixed", seed, seed)
	if err != nil {
		t.Fatal(err)
	}
	c := Claims{
		ID:        "000102030405060708090a0b0c0d0e0f",
		Relay:     "https://relay.example.com",
		Use:       UseRegister,
		Note:      "known answer",
		NotBefore: 1700000000,
		NotAfter:  1700086400,
		Uses:      1,
	}
	raw, err := Issue(id, c)
	if err != nil {
		t.Fatal(err)
	}
	// Updated deliberately on 2026-09-08, when ccxt2 added the anchor field:
	// the whole point of this test is that the format cannot change by
	// accident, so a change here is a change somebody meant. The ccxt1
	// vector below is the form before it, refused by name.
	const want = "ccxt2.eyJpZCI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIiwiaXNzdWVyIjoi"
	if !strings.HasPrefix(raw, want) {
		t.Fatalf("the token format has changed.\n got %s\nwant it to start %s", raw, want)
	}
	// The anchor is present and empty rather than absent: every field is
	// always on the wire, so two implementations cannot disagree about a
	// missing one.
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"anchor":""`) {
		t.Errorf("the payload omits an empty anchor: %s", payload)
	}
	// And it round-trips through the verifier that will see it.
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Verify(id.Public(), time.Unix(1700000001, 0), relayapi.MaxSkew); err != nil {
		t.Fatalf("the known-answer token does not verify: %v", err)
	}
}

// TestAnOlderKnownAnswerIsRefused pins a ccxt1 token exactly as one was
// handed out before the anchor, and shows it refused by name: nothing on
// the wire is from before, and the sentence tells its holder to ask for a
// new one.
func TestAnOlderKnownAnswerIsRefused(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	id, err := identity.FromSeeds("fixed", seed, seed)
	if err != nil {
		t.Fatal(err)
	}
	// Built by hand, because Issue only writes ccxt2 now.
	payload := []byte(`{"id":"000102030405060708090a0b0c0d0e0f",` +
		`"issuer":"` + id.Fingerprint() + `",` +
		`"relay":"https://relay.example.com","use":"register","subject":"",` +
		`"note":"known answer","not_before":1700000000,"not_after":1700086400,"uses":1}`)
	raw := "ccxt1." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mustSign(t, id, signingBytes(payload)))

	_, err = Parse(raw)
	if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "this token is of an older form, ccxt1, which pins no trust anchor; ask for a new one to be issued") {
		t.Fatalf("a ccxt1 token: %v; want it refused by name", err)
	}
}
