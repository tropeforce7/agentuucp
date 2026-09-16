package relayapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

func TestSignThenVerifyRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	for _, n := range append(testutil.Lengths(1<<16, 16), 7, 4095, 4096) {
		method := methods[r.IntN(len(methods))]
		path := "/v1/mailbox/" + testutil.Text(r, 1+r.IntN(60))
		body := testutil.Bytes(r, n)
		ts := time.Now().Unix() - int64(r.IntN(int(MaxSkew/time.Second)))
		nonce := base64.StdEncoding.EncodeToString(testutil.Bytes(r, nonceBytes))

		signing := SigningString(method, path, ts, nonce, body)
		sig := mustSign(t, id, signing)
		auth := &Auth{FP: id.Fingerprint(), TS: ts, Nonce: nonce, Sig: sig}

		if !auth.Verify(id.Public(), method, path, body) {
			t.Fatalf("seed %d: a freshly signed request of %d bytes did not verify", seed, n)
		}
		if !auth.FreshAt(time.Now()) {
			t.Fatalf("seed %d: a request stamped inside the window was stale", seed)
		}

		// One flipped bit in one randomly chosen component must break it.
		switch r.IntN(4) {
		case 0:
			bad := *auth
			bad.Sig = testutil.FlipBit(sig, r.IntN(len(sig)*8))
			if bad.Verify(id.Public(), method, path, body) {
				t.Fatalf("seed %d: a flipped signature bit verified", seed)
			}
		case 1:
			if len(body) > 0 {
				if auth.Verify(id.Public(), method, path, testutil.FlipBit(body, r.IntN(len(body)*8))) {
					t.Fatalf("seed %d: a flipped body bit verified", seed)
				}
			}
		case 2:
			if auth.Verify(id.Public(), method, path+"x", body) {
				t.Fatalf("seed %d: a changed path verified", seed)
			}
		case 3:
			bad := *auth
			bad.TS = ts + 1
			if bad.Verify(id.Public(), method, path, body) {
				t.Fatalf("seed %d: a changed timestamp verified", seed)
			}
		}
	}
}

// TestVerifyFailsOnChanges alters the inputs; these alter the signature itself,
// which keeps every input intact so only the cryptography can refuse it.
func TestSignatureVandalism(t *testing.T) {
	r, seed := testutil.Seed(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	const method, path = "POST", "/v1/mailbox/abc"
	body := []byte("payload")
	ts := time.Now().Unix()
	nonce := base64.StdEncoding.EncodeToString(make([]byte, nonceBytes))
	sig := mustSign(t, id, SigningString(method, path, ts, nonce, body))

	base := &Auth{FP: id.Fingerprint(), TS: ts, Nonce: nonce, Sig: sig}
	if !base.Verify(id.Public(), method, path, body) {
		t.Fatal("the control signature did not verify")
	}

	t.Run("one flipped bit", func(t *testing.T) {
		for i := range 32 {
			bit := r.IntN(ed25519.SignatureSize * 8)
			bad := &Auth{FP: base.FP, TS: ts, Nonce: nonce, Sig: testutil.FlipBit(sig, bit)}
			if bad.Verify(id.Public(), method, path, body) {
				t.Fatalf("seed %d: iteration %d, bit %d verified", seed, i, bit)
			}
		}
	})
	t.Run("truncated by one", func(t *testing.T) {
		bad := &Auth{FP: base.FP, TS: ts, Nonce: nonce, Sig: sig[:len(sig)-1]}
		if bad.Verify(id.Public(), method, path, body) {
			t.Fatal("a signature one byte short verified")
		}
	})
	t.Run("extended by one", func(t *testing.T) {
		bad := &Auth{FP: base.FP, TS: ts, Nonce: nonce, Sig: append(append([]byte{}, sig...), 0)}
		if bad.Verify(id.Public(), method, path, body) {
			t.Fatal("a signature one byte long verified")
		}
	})
	t.Run("empty", func(t *testing.T) {
		bad := &Auth{FP: base.FP, TS: ts, Nonce: nonce, Sig: nil}
		if bad.Verify(id.Public(), method, path, body) {
			t.Fatal("an empty signature verified")
		}
	})
	t.Run("right message, wrong key", func(t *testing.T) {
		other, err := identity.Generate("mallory")
		if err != nil {
			t.Fatal(err)
		}
		if base.Verify(other.Public(), method, path, body) {
			t.Fatal("verified against the wrong key")
		}
	})
}

// The nonce is a fixed width; both neighbours of it must be refused.
func TestNonceLengthBoundaries(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	for _, n := range []int{0, nonceBytes - 1, nonceBytes + 1, 64} {
		nonce := base64.StdEncoding.EncodeToString(make([]byte, n))
		header := fmt.Sprintf("v1 %s 1 %s %s", id.Fingerprint(), nonce, sig)
		if _, err := ParseAuth(header); err == nil {
			t.Errorf("a nonce of %d bytes was accepted", n)
		}
	}
	nonce := base64.StdEncoding.EncodeToString(make([]byte, nonceBytes))
	header := fmt.Sprintf("v1 %s 1 %s %s", id.Fingerprint(), nonce, sig)
	if _, err := ParseAuth(header); err != nil {
		t.Fatalf("a nonce of exactly %d bytes was refused: %v", nonceBytes, err)
	}
}
