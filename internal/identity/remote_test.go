package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// inProcessSigner is a Signer over the local key, standing in for the
// agent: the seam is the interface, and a test of the seam needs no socket.
type inProcessSigner struct{ id *Identity }

func (s inProcessSigner) Public() []byte                  { return s.id.sign.Public() }
func (s inProcessSigner) Sign(msg []byte) ([]byte, error) { return s.id.sign.Sign(msg) }

// lockedSigner is what the agent looks like when it is locked.
type lockedSigner struct{ pub []byte }

func (s lockedSigner) Public() []byte              { return s.pub }
func (s lockedSigner) Sign([]byte) ([]byte, error) { return nil, ErrLocked }

// composedKEM builds the hpke.PrivateKey a client composes from the agent's
// two halves, here from the seed directly.
func composedKEM(t *testing.T, kemSeed []byte) hpke.PrivateKey {
	t.Helper()
	pq, x, err := SplitKEMSeed(kemSeed)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.NewDecapsulationKey768(pq)
	if err != nil {
		t.Fatal(err)
	}
	xk, err := ecdh.X25519().NewPrivateKey(x)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := hpke.NewHybridPrivateKey(dk, xk)
	if err != nil {
		t.Fatal(err)
	}
	return kem
}

// TestTheXWingHalvesComposeToTheSeedKey is the check that fails if
// crypto/hpke ever changes how it expands an X-Wing seed: the public key of
// the key composed from the halves must equal the seed-derived one, and a
// message sealed to the seed-derived key must open with the composed one.
func TestTheXWingHalvesComposeToTheSeedKey(t *testing.T) {
	r, seed := testutil.Seed(t)
	for i := 0; i < 8; i++ {
		kemSeed := testutil.Bytes(r, KEMPrivateKeySize)
		fromSeed, err := hpke.MLKEM768X25519().NewPrivateKey(kemSeed)
		if err != nil {
			t.Fatal(err)
		}
		composed := composedKEM(t, kemSeed)
		if !bytes.Equal(fromSeed.PublicKey().Bytes(), composed.PublicKey().Bytes()) {
			t.Fatalf("the composed key's public key is not the seed's (seed %d)", seed)
		}
		msg := testutil.Bytes(r, 1+r.IntN(200))
		ct, err := hpke.Seal(fromSeed.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"), msg)
		if err != nil {
			t.Fatal(err)
		}
		back, err := hpke.Open(composed, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"), ct)
		if err != nil {
			t.Fatalf("the composed key did not open what was sealed to the seed key: %v (seed %d)", err, seed)
		}
		if !bytes.Equal(back, msg) {
			t.Fatalf("the plaintext came back changed (seed %d)", seed)
		}
		// And the other way, which is what a message sent by a client
		// holding a remote identity looks like to a recipient with the seed.
		ct, err = hpke.Seal(composed.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"), msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hpke.Open(fromSeed, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"), ct); err != nil {
			t.Fatalf("the seed key did not open what was sealed to the composed key: %v (seed %d)", err, seed)
		}
	}
	// The public split agrees with the private one.
	id, err := Generate("x")
	if err != nil {
		t.Fatal(err)
	}
	ek, x, err := SplitKEMPublic(id.Public().KEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(ek.Bytes(), x.Bytes()...), id.Public().KEM.Bytes()) {
		t.Error("SplitKEMPublic does not reassemble to the public key")
	}
	if _, _, err := SplitKEMSeed(make([]byte, KEMPrivateKeySize-1)); err == nil {
		t.Error("a short seed was split")
	}
	if _, _, err := SplitKEMPublic(make([]byte, KEMPublicKeySize+1)); err == nil {
		t.Error("a long public key was split")
	}
}

// TestARemoteIdentitySignsAndOpensLikeALocalOne: a fake in-process Signer
// and hpke.PrivateKey built from the local seeds through FromRemote;
// signatures verify under the same Public, an envelope sealed to the public
// half opens, and MarshalJSON refuses.
func TestARemoteIdentitySignsAndOpensLikeALocalOne(t *testing.T) {
	local, err := Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := FromRemote(local.Suite(), "ada", local.Public().Bundle(),
		inProcessSigner{local}, composedKEM(t, local.kemSeed))
	if err != nil {
		t.Fatal(err)
	}
	if !remote.Remote() || local.Remote() {
		t.Error("Remote does not tell the two apart")
	}
	if remote.Fingerprint() != local.Fingerprint() {
		t.Fatal("the remote identity has a different fingerprint")
	}
	if remote.Public().ExportLine() != local.Public().ExportLine() {
		t.Fatal("the remote identity has a different export line")
	}
	r, seed := testutil.Seed(t)
	msg := testutil.Bytes(r, 1+r.IntN(300))
	sig, err := remote.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !local.Public().Verify(msg, sig) {
		t.Errorf("a remote signature does not verify under the local public key (seed %d)", seed)
	}
	sig, err = local.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !remote.Public().Verify(msg, sig) {
		t.Errorf("a local signature does not verify under the remote public key (seed %d)", seed)
	}
	ct, err := hpke.Seal(local.Public().KEM, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("to ada"), msg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := hpke.Open(remote.KEM(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("to ada"), ct)
	if err != nil {
		t.Fatalf("the remote KEM did not open a message sealed to the public half: %v (seed %d)", err, seed)
	}
	if !bytes.Equal(back, msg) {
		t.Error("the plaintext came back changed")
	}
	if _, err := json.Marshal(remote); err == nil {
		t.Error("a remote identity was written as JSON, which would be a file with no keys in it")
	}
	if _, err := remote.Secrets(); err == nil {
		t.Error("a remote identity gave up secrets it does not have")
	}

	// A locked agent is an error, not a signature.
	locked, err := FromRemote(local.Suite(), "ada", local.Public().Bundle(),
		lockedSigner{local.sign.Public()}, composedKEM(t, local.kemSeed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locked.Sign(msg); !errors.Is(err, ErrLocked) {
		t.Errorf("a locked signer gave %v, want ErrLocked", err)
	}

	// The halves are checked against the bundle.
	other, _ := Generate("eve")
	if _, err := FromRemote(local.Suite(), "ada", local.Public().Bundle(),
		inProcessSigner{other}, composedKEM(t, local.kemSeed)); err == nil ||
		!strings.Contains(err.Error(), "signer's public key") {
		t.Errorf("a signer for another identity gave %v", err)
	}
	if _, err := FromRemote(local.Suite(), "ada", local.Public().Bundle(),
		inProcessSigner{local}, composedKEM(t, other.kemSeed)); err == nil ||
		!strings.Contains(err.Error(), "KEM's public key") {
		t.Errorf("a KEM for another identity gave %v", err)
	}
	if _, err := FromRemote(local.Suite(), "ada", local.Public().Bundle(), nil, nil); err == nil {
		t.Error("no halves at all was accepted")
	}
}

// TestSecretsRoundTrip: identity.key's plaintext is the two seeds in DER,
// and reading it back gives the same identity.
func TestSecretsRoundTrip(t *testing.T) {
	id, err := Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	der, err := id.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	// SEQUENCE { OCTET STRING(32) OCTET STRING(32) }: 2 + (2+32) + (2+32).
	if len(der) != 2+2+32+2+32 {
		t.Errorf("secrets DER is %d bytes, want 70", len(der))
	}
	back, err := FromSecrets(DefaultSuite(), "ada", der)
	if err != nil {
		t.Fatal(err)
	}
	if back.Fingerprint() != id.Fingerprint() {
		t.Error("the identity from secrets has a different fingerprint")
	}
	if _, _, err := ParseSecrets(append(der, 0)); err == nil {
		t.Error("trailing data was accepted")
	}
	if _, _, err := ParseSecrets(der[:len(der)-1]); err == nil {
		t.Error("a truncated encoding was accepted")
	}
}

// TestLockedRoundTrip: identity.json's encrypted form carries the public
// half and nothing else, and reads back to the same public key.
func TestLockedRoundTrip(t *testing.T) {
	id, err := Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(NewLocked(id))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sign_seed", "kem_seed"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the locked form mentions %s", secret)
		}
	}
	if strings.Contains(string(data), `"suite"`) {
		t.Error("the default suite is written, which the plain form omits")
	}
	var back Locked
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	pub, err := back.Public()
	if err != nil {
		t.Fatal(err)
	}
	if pub.Fingerprint() != id.Fingerprint() || pub.Name != "ada" {
		t.Error("the locked form does not read back to the same public key")
	}
	// A bad bundle is refused on the way in, not on first use.
	if err := json.Unmarshal([]byte(`{"name":"x","bundle":"AAAA"}`), &back); err == nil {
		t.Error("a bundle of no known suite was accepted")
	}
	if err := json.Unmarshal([]byte(`{"name":"x","suite":200,"bundle":""}`), &back); err == nil ||
		!strings.Contains(err.Error(), "upgrade auu") {
		t.Errorf("an unknown suite gave %v", err)
	}
}
