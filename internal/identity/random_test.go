package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

func TestSignVerifyRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	other, err := Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range append(testutil.Lengths(1<<20, 64), 31, 32, 33, 4096) {
		msg := testutil.Bytes(r, n)
		sig := mustSign(t, id, msg)
		if !id.Public().Verify(msg, sig) {
			t.Fatalf("seed %d: a %d byte message did not verify", seed, n)
		}
		// Right message, wrong key.
		if other.Public().Verify(msg, sig) {
			t.Fatalf("seed %d: verified against the wrong key at %d bytes", seed, n)
		}
		// Wrong message, right key.
		if n > 0 && id.Public().Verify(testutil.FlipBit(msg, r.IntN(n*8)), sig) {
			t.Fatalf("seed %d: a flipped message bit verified at %d bytes", seed, n)
		}
		// Vandalised signature.
		if id.Public().Verify(msg, testutil.FlipBit(sig, r.IntN(ed25519.SignatureSize*8))) {
			t.Fatalf("seed %d: a flipped signature bit verified at %d bytes", seed, n)
		}
		// Length vandalism.
		if id.Public().Verify(msg, sig[:len(sig)-1]) {
			t.Fatalf("seed %d: a short signature verified", seed)
		}
		if id.Public().Verify(msg, append(append([]byte{}, sig...), 0)) {
			t.Fatalf("seed %d: a long signature verified", seed)
		}
	}
}

// A vandalised export line must never yield the original identity.
//
// The assertion is per region, because a bundle is sign_pub || kem_pub and the
// two halves are guarded by different things. Changing the KEM half leaves the
// Ed25519 key intact, so it still verifies the original's signatures — which
// is correct — while the fingerprint, taken over the whole bundle, differs.
// Only a change to the Ed25519 half may break signature verification. An
// earlier version of this test asserted the stronger claim and failed, and the
// code was right.
func TestExportLineBitFlip(t *testing.T) {
	r, seed := testutil.Seed(t)
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	line := id.Public().ExportLine()
	prefix, rest, _ := strings.Cut(line, exportSep)
	field, name, _ := strings.Cut(rest, exportSep)
	original, err := base64.RawURLEncoding.DecodeString(field)
	if err != nil {
		t.Fatal(err)
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	signChanged, kemChanged := 0, 0
	for range 256 {
		encoded := []byte(field)
		i := r.IntN(len(encoded))
		next := alphabet[r.IntN(len(alphabet))]
		if next == encoded[i] {
			continue
		}
		encoded[i] = next

		pub, err := ParseExportLine(prefix + exportSep + string(encoded) + exportSep + name)
		if err != nil {
			continue // refused, which is the usual and correct outcome
		}
		raw, err := base64.RawURLEncoding.DecodeString(string(encoded))
		if err != nil {
			t.Fatalf("seed %d: a parsed line did not decode: %v", seed, err)
		}

		// Whatever changed, this is no longer the same identity.
		if pub.Fingerprint() == id.Fingerprint() {
			t.Fatalf("seed %d: a vandalised export line produced the original fingerprint", seed)
		}

		msg := testutil.Bytes(r, 32)
		if bytes.Equal(raw[:ed25519.PublicKeySize], original[:ed25519.PublicKeySize]) {
			kemChanged++
			// The signing half is untouched, so signatures must still verify.
			if !pub.Verify(msg, mustSign(t, id, msg)) {
				t.Fatalf("seed %d: an untouched Ed25519 half stopped verifying", seed)
			}
		} else {
			signChanged++
			if pub.Verify(msg, mustSign(t, id, msg)) {
				t.Fatalf("seed %d: a vandalised Ed25519 key verified the original's signature", seed)
			}
		}
	}
	if kemChanged == 0 {
		t.Fatalf("seed %d: no flip landed in the KEM half; the test proved little", seed)
	}
	t.Logf("flips that parsed: %d in the KEM half, %d in the Ed25519 half", kemChanged, signChanged)
}

// Fingerprints must be stable and distinct across many generated identities.
func TestFingerprintsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		id, err := Generate("x")
		if err != nil {
			t.Fatal(err)
		}
		fp := id.Fingerprint()
		if seen[fp] {
			t.Fatalf("fingerprint %s was generated twice", fp)
		}
		seen[fp] = true
		if len(fp) != 64 || !ValidFingerprint(fp) {
			t.Fatalf("generated an invalid fingerprint %q", fp)
		}
	}
}
