package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/sha3"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/wire"
)

// An identity whose secrets are elsewhere.
//
// When a home is under a passphrase, identity.json keeps the name, the
// suite and the public bundle, and the two seeds are in identity.key,
// sealed under the home key. The agent holds the unsealed halves and
// performs every private operation over a socket; what this process holds
// is an Identity built by FromRemote, whose Signer and hpke.PrivateKey ask
// the agent. Nothing above them — envelopes, streams, request signing,
// tokens — can tell the difference, which is the point of the seam.

// ErrLocked is what a remote identity's private operations return when the
// agent is locked or not running. Every command turns it into the same
// advice, and nothing that receives it may treat the message it was working
// on as unreadable: the key is not wrong, it is not here.
var ErrLocked = errors.New("the identity is locked")

// Locked is identity.json's form in an encrypted home: everything but the
// secrets. Store.Self reads it, so that every command which needs only the
// public half never touches the agent.
type Locked struct {
	Name   string
	Suite  *Suite
	Bundle []byte
}

type lockedJSON struct {
	Name string `json:"name"`
	// Suite is omitted for the original one, as identityJSON omits it, so
	// the two files say the same thing the same way.
	Suite  SuiteID `json:"suite,omitempty"`
	Bundle string  `json:"bundle"`
}

// NewLocked is the public form of an identity, for writing identity.json
// when the secrets move to identity.key.
func NewLocked(id *Identity) *Locked {
	return &Locked{Name: id.Name, Suite: id.suite, Bundle: id.pub.Bundle()}
}

// Public is the bundle with the name.
func (l *Locked) Public() (*Public, error) {
	pub, err := ParseBundle(l.Bundle)
	if err != nil {
		return nil, err
	}
	if pub.suite != l.Suite {
		return nil, fmt.Errorf("identity: the file says suite %d but the bundle is suite %d",
			l.Suite.ID, pub.suite.ID)
	}
	pub.Name = l.Name
	return pub, nil
}

func (l *Locked) MarshalJSON() ([]byte, error) {
	out := lockedJSON{Name: l.Name, Bundle: base64.StdEncoding.EncodeToString(l.Bundle)}
	if l.Suite.ID != SuiteEd25519XWing {
		out.Suite = l.Suite.ID
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads a locked identity strictly, through wire.Decode, for
// the reason Identity.UnmarshalJSON does (R24).
func (l *Locked) UnmarshalJSON(b []byte) error {
	var j lockedJSON
	if err := wire.Decode(b, &j); err != nil {
		return err
	}
	bundle, err := base64.StdEncoding.DecodeString(j.Bundle)
	if err != nil {
		return fmt.Errorf("identity: bad bundle: %w", err)
	}
	suiteID := j.Suite
	if suiteID == 0 {
		suiteID = SuiteEd25519XWing
	}
	suite, ok := SuiteByID(suiteID)
	if !ok {
		return fmt.Errorf("identity: this key uses suite %d, which this build does not know; "+
			"upgrade auu", suiteID)
	}
	*l = Locked{Name: j.Name, Suite: suite, Bundle: bundle}
	if _, err := l.Public(); err != nil {
		return err
	}
	return nil
}

// FromRemote builds an identity whose private operations are performed
// elsewhere: sign over the signing half, kem over the KEM half, with the
// public bundle as it appears in identity.json.
//
// Both halves are checked against the bundle, so a signer or a KEM that
// does not belong to this identity is refused here rather than producing
// signatures nobody can verify and messages nobody can open.
func FromRemote(suite *Suite, name string, bundle []byte, sign Signer, kem hpke.PrivateKey) (*Identity, error) {
	if suite == nil {
		return nil, errors.New("identity: no suite")
	}
	if sign == nil || kem == nil {
		return nil, errors.New("identity: a remote identity needs both halves")
	}
	pub, err := ParseBundle(bundle)
	if err != nil {
		return nil, err
	}
	if pub.suite != suite {
		return nil, fmt.Errorf("identity: bundle is suite %d, not suite %d", pub.suite.ID, suite.ID)
	}
	if !bytes.Equal(sign.Public(), pub.signPub) {
		return nil, errors.New("identity: the remote signer's public key is not the bundle's")
	}
	if !bytes.Equal(kem.PublicKey().Bytes(), pub.KEM.Bytes()) {
		return nil, errors.New("identity: the remote KEM's public key is not the bundle's")
	}
	return &Identity{
		Name:   name,
		suite:  suite,
		sign:   sign,
		kem:    kem,
		pub:    newPublic(suite, name, pub.signPub, pub.KEM),
		remote: true,
	}, nil
}

// secrets is identity.key's plaintext: the two seeds, in the order the
// identity file has always kept them.
type secrets struct {
	SignSeed []byte
	KEMSeed  []byte
}

// Secrets is the DER an encrypted home seals as identity.key: a SEQUENCE of
// two OCTET STRINGs, the signing seed then the KEM seed. A remote identity
// has none.
func (id *Identity) Secrets() ([]byte, error) {
	if id.remote {
		return nil, errors.New("identity: a remote identity has no secrets")
	}
	return asn1.Marshal(secrets{SignSeed: id.signSeed, KEMSeed: id.kemSeed})
}

// ParseSecrets reverses Secrets.
func ParseSecrets(der []byte) (signSeed, kemSeed []byte, err error) {
	var s secrets
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: secrets: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("identity: secrets: trailing data")
	}
	return s.SignSeed, s.KEMSeed, nil
}

// FromSecrets rebuilds an identity from Secrets' DER.
func FromSecrets(suite *Suite, name string, der []byte) (*Identity, error) {
	signSeed, kemSeed, err := ParseSecrets(der)
	if err != nil {
		return nil, err
	}
	return FromSeedsSuite(suite, name, signSeed, kemSeed)
}

// The X-Wing seed and its halves.
//
// crypto/hpke's MLKEM768X25519 private key is a 32-byte seed, expanded with
// SHAKE256 into a 64-byte ML-KEM-768 seed and then a 32-byte X25519 key,
// which is what draft-connolly-cfrg-xwing-kem specifies. The agent holds
// the two halves rather than the seed so that it can decapsulate and
// exchange separately, which is what hpke.NewHybridPrivateKey composes a
// key from; TestTheXWingHalvesComposeToTheSeedKey is what fails if
// crypto/hpke ever derives them differently.
const (
	// MLKEMSeedSize is the ML-KEM-768 half: d || z.
	MLKEMSeedSize = mlkem.SeedSize
	// X25519KeySize is the X25519 half.
	X25519KeySize = 32
)

// SplitKEMSeed expands an MLKEM768X25519 seed into its ML-KEM-768 seed and
// its X25519 private key.
func SplitKEMSeed(seed []byte) (mlkemSeed, x25519Key []byte, err error) {
	if len(seed) != KEMPrivateKeySize {
		return nil, nil, fmt.Errorf("identity: an X-Wing seed is %d bytes, got %d", KEMPrivateKeySize, len(seed))
	}
	s := sha3.NewSHAKE256()
	s.Write(seed)
	mlkemSeed = make([]byte, MLKEMSeedSize)
	s.Read(mlkemSeed)
	x25519Key = make([]byte, X25519KeySize)
	s.Read(x25519Key)
	return mlkemSeed, x25519Key, nil
}

// SplitKEMPublic separates an MLKEM768X25519 public key into the ML-KEM-768
// encapsulation key and the X25519 point, which is how a remote KEM is
// composed on the client side.
func SplitKEMPublic(pub []byte) (*mlkem.EncapsulationKey768, *ecdh.PublicKey, error) {
	if len(pub) != KEMPublicKeySize {
		return nil, nil, fmt.Errorf("identity: an X-Wing public key is %d bytes, got %d", KEMPublicKeySize, len(pub))
	}
	ek, err := mlkem.NewEncapsulationKey768(pub[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, nil, fmt.Errorf("identity: ML-KEM half: %w", err)
	}
	x, err := ecdh.X25519().NewPublicKey(pub[mlkem.EncapsulationKeySize768:])
	if err != nil {
		return nil, nil, fmt.Errorf("identity: X25519 half: %w", err)
	}
	return ek, x, nil
}
