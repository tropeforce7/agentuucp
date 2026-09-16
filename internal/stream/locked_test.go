package stream

import (
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// lockedKEM is what an identity's KEM looks like when the agent holding it
// has locked: the public halves are known, and every private operation
// answers identity.ErrLocked.
type lockedDecapsulator struct{ ek crypto.Encapsulator }

func (d lockedDecapsulator) Encapsulator() crypto.Encapsulator { return d.ek }
func (d lockedDecapsulator) Decapsulate([]byte) ([]byte, error) {
	return nil, identity.ErrLocked
}

type lockedExchanger struct{ pub *ecdh.PublicKey }

func (e lockedExchanger) PublicKey() *ecdh.PublicKey           { return e.pub }
func (e lockedExchanger) Curve() ecdh.Curve                    { return ecdh.X25519() }
func (e lockedExchanger) ECDH(*ecdh.PublicKey) ([]byte, error) { return nil, identity.ErrLocked }

type localSigner struct{ id *identity.Identity }

func (l localSigner) Public() []byte                  { return l.id.Public().SignPublic() }
func (l localSigner) Sign(msg []byte) ([]byte, error) { return l.id.Sign(msg) }

// TestALockedKeyIsNotAnUnopenableManifest: a manifest that fails to open
// because the recipient's key is not here is returned with
// identity.ErrLocked in its chain and without ErrOpenFailed, so that the
// receiver leaves the stream on the relay instead of acknowledging it as
// something nobody will ever read.
func TestALockedKeyIsNotAnUnopenableManifest(t *testing.T) {
	from, to := pair(t)
	blob, _ := build(t, from, to, MinChunkSize, map[string][]byte{"a": []byte("payload")})
	ek, x, err := identity.SplitKEMPublic(to.Public().KEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kem, err := hpke.NewHybridPrivateKey(lockedDecapsulator{ek}, lockedExchanger{x})
	if err != nil {
		t.Fatal(err)
	}
	locked, err := identity.FromRemote(to.Suite(), to.Name, to.Public().Bundle(), localSigner{to}, kem)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ManifestLength(blob[:HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenManifest(locked, blob[:HeaderSize], blob[HeaderSize:HeaderSize+n])
	if err == nil {
		t.Fatal("a locked key opened the manifest")
	}
	if !errors.Is(err, identity.ErrLocked) {
		t.Errorf("the error does not carry identity.ErrLocked: %v", err)
	}
	if errors.Is(err, ErrOpenFailed) {
		t.Errorf("a locked key was reported as an unopenable manifest, which is what gets a stream discarded: %v", err)
	}
	// The same key, unlocked, opens it: the manifest was fine.
	if _, err := OpenManifest(to, blob[:HeaderSize], blob[HeaderSize:HeaderSize+n]); err != nil {
		t.Errorf("the manifest does not open with the real key either: %v", err)
	}
}
