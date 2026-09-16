package identity

import (
	"crypto/ed25519"
	"crypto/hpke"
	"fmt"
	"sort"
)

// A SuiteID names one set of algorithms an identity can be built from. It is
// on the wire, in the first byte of every bundle but the original one, so the
// numbers here are permanent.
type SuiteID uint8

const (
	// SuiteEd25519XWing is the identity every deployed key uses: Ed25519 for
	// signing, MLKEM768-X25519 (X-Wing) for receiving mail. Its bundle is the
	// bare concatenation with no leading suite byte, because it predates
	// there being a suite byte at all, and retro-fitting one would change
	// every fingerprint in existence.
	SuiteEd25519XWing SuiteID = 1

	// FirstTestSuite begins the range reserved for tests and experiments.
	// Nothing in this range may ever be written to the wire by a release: it
	// exists so a test can prove the registry works without spending a real
	// identifier on a suite nobody ships.
	FirstTestSuite SuiteID = 128
)

// Signer is a suite's private signing key.
//
// Sign can fail. A key held in this process never does; a key held by the
// agent (see FromRemote) is a connection away, and a locked agent is an
// error every caller has to carry out rather than a signature that is not
// one.
type Signer interface {
	// Public is the serialised public key, as it appears in a bundle.
	Public() []byte
	// Sign returns a signature over msg.
	Sign(msg []byte) ([]byte, error)
}

// A Suite is one set of algorithms, with everything the rest of the package
// needs in order to build, parse and check an identity without naming a
// primitive itself.
//
// There is one registered suite. The machinery is here so that a second can
// be added without touching anything that reads a bundle, and so that the few
// places which genuinely cannot yet be extended — see the note on the stream
// format in the package documentation — are visible rather than discovered.
type Suite struct {
	ID   SuiteID
	Name string

	// PQCategory is the NIST post-quantum security category of the signing
	// half: 1, 3 or 5, and zero for a signature that is classical only.
	//
	// It exists so that a receiver can have a policy about what it will
	// accept rather than only a fact about what it got. A downgrade of the
	// identity suite is not possible — the fingerprint commits to the bundle
	// and the bundle carries the suite, so a weaker suite is a different
	// address, not the same one weakened — but when a second suite exists,
	// somebody may still want to refuse peers who are on the older one, and
	// that is a comparison rather than a check.
	PQCategory int

	// SignSeedSize is the stored secret a signing key is derived from.
	SignSeedSize int
	// SignPublicSize is that key's public half, inside the bundle.
	SignPublicSize int
	// SignatureSize is what Sign produces. Fixed per suite: several formats
	// depend on a signature having one length.
	SignatureSize int

	// KEM is the HPKE KEM this suite receives mail with.
	KEM func() hpke.KEM
	// KEMPublicSize is the serialised public key, the rest of the bundle.
	KEMPublicSize int

	// NewSigner derives the signing key from a seed of SignSeedSize bytes.
	NewSigner func(seed []byte) (Signer, error)
	// Verify checks sig over msg against a public key of this suite. It must
	// return false rather than panic on a key of the wrong length.
	Verify func(pub, msg, sig []byte) bool
}

// BundleSize is the length of this suite's bundle, not counting the leading
// suite byte that every suite but the first carries.
func (s *Suite) BundleSize() int { return s.SignPublicSize + s.KEMPublicSize }

// wireSize is the length a bundle of this suite occupies, including its tag.
func (s *Suite) wireSize() int {
	if s.tagged() {
		return 1 + s.BundleSize()
	}
	return s.BundleSize()
}

// tagged reports whether this suite's bundle begins with its identifier.
// Only the original suite does not.
func (s *Suite) tagged() bool { return s.ID != SuiteEd25519XWing }

var (
	suites    = map[SuiteID]*Suite{}
	byWireLen = map[int]*Suite{}
)

// Register adds a suite. It panics rather than returning an error: a suite is
// registered at init, a clash is a programming mistake, and a program that
// cannot agree with itself about what a bundle means must not start.
func Register(s *Suite) {
	if s == nil || s.ID == 0 {
		panic("identity: suite must have a non-zero id")
	}
	if _, dup := suites[s.ID]; dup {
		panic(fmt.Sprintf("identity: suite %d is already registered", s.ID))
	}
	if s.SignSeedSize <= 0 || s.SignPublicSize <= 0 || s.SignatureSize <= 0 || s.KEMPublicSize <= 0 {
		panic(fmt.Sprintf("identity: suite %d has a zero size", s.ID))
	}
	if s.NewSigner == nil || s.Verify == nil || s.KEM == nil {
		panic(fmt.Sprintf("identity: suite %d is missing a function", s.ID))
	}
	// Bundles are told apart by length before anything reads a tag, because
	// the original suite has no tag to read. Two suites of the same wire
	// length would be indistinguishable, so the collision is refused here
	// rather than discovered by somebody whose key stops parsing.
	if other, clash := byWireLen[s.wireSize()]; clash {
		panic(fmt.Sprintf("identity: suite %d and suite %d are both %d bytes on the wire",
			s.ID, other.ID, s.wireSize()))
	}
	suites[s.ID] = s
	byWireLen[s.wireSize()] = s
}

// SuiteByID returns a registered suite.
func SuiteByID(id SuiteID) (*Suite, bool) {
	s, ok := suites[id]
	return s, ok
}

// suiteForWire picks the suite a bundle of this length must be, and reports
// whether the first byte is its tag.
func suiteForWire(b []byte) (*Suite, error) {
	s, ok := byWireLen[len(b)]
	if !ok {
		return nil, fmt.Errorf("identity: bundle is %d bytes, which is no known suite (%s)",
			len(b), knownSizes())
	}
	if s.tagged() && SuiteID(b[0]) != s.ID {
		return nil, fmt.Errorf("identity: bundle is %d bytes, which is suite %d, but it is tagged %d",
			len(b), s.ID, b[0])
	}
	return s, nil
}

// knownSizes lists the bundle lengths this build understands, for a refusal
// somebody has to act on.
func knownSizes() string {
	sizes := make([]int, 0, len(byWireLen))
	for n := range byWireLen {
		sizes = append(sizes, n)
	}
	sort.Ints(sizes)
	out := "want "
	for i, n := range sizes {
		if i > 0 {
			out += " or "
		}
		out += fmt.Sprintf("%d", n)
	}
	return out
}

// MaxSignatureSize is the largest signature any registered suite produces. It
// is what a format bounds an encoded signature by before decoding one.
func MaxSignatureSize() int {
	max := 0
	for _, s := range suites {
		if s.SignatureSize > max {
			max = s.SignatureSize
		}
	}
	return max
}

// SignatureSizes lists, in order, every length a signature by a registered
// suite can be. A format that carries a signature checks the encoded length
// against these before decoding one: a size no suite produces cannot verify,
// so refusing it early costs an attacker the allocation.
func SignatureSizes() []int {
	out := make([]int, 0, len(suites))
	for _, s := range suites {
		out = append(out, s.SignatureSize)
	}
	sort.Ints(out)
	return out
}

// IsSignatureSize reports whether n is a length some registered suite signs
// with.
func IsSignatureSize(n int) bool {
	for _, s := range suites {
		if s.SignatureSize == n {
			return true
		}
	}
	return false
}

// ed25519Signer adapts crypto/ed25519 to the Signer interface.
type ed25519Signer struct{ key ed25519.PrivateKey }

func (s ed25519Signer) Public() []byte {
	return append([]byte{}, s.key.Public().(ed25519.PublicKey)...)
}

func (s ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.key, msg), nil }

func init() {
	Register(&Suite{
		ID:   SuiteEd25519XWing,
		Name: "Ed25519+MLKEM768X25519",
		// The KEM is post-quantum; the signature is not. That asymmetry is
		// deliberate and is the whole of what a future suite would change:
		// confidentiality has to survive a recording made today, whereas a
		// signature only has to hold until it is checked.
		PQCategory:     0,
		SignSeedSize:   ed25519.SeedSize,
		SignPublicSize: ed25519.PublicKeySize,
		SignatureSize:  ed25519.SignatureSize,
		KEM:            hpke.MLKEM768X25519,
		KEMPublicSize:  KEMPublicKeySize,
		NewSigner: func(seed []byte) (Signer, error) {
			if len(seed) != ed25519.SeedSize {
				return nil, fmt.Errorf("identity: signing seed must be %d bytes", ed25519.SeedSize)
			}
			return ed25519Signer{key: ed25519.NewKeyFromSeed(seed)}, nil
		},
		Verify: func(pub, msg, sig []byte) bool {
			// Length-checked rather than left to ed25519.Verify, which
			// panics on a public key of the wrong size.
			if len(pub) != ed25519.PublicKeySize {
				return false
			}
			return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
		},
	})
}

// AtLeast reports whether this suite's signing half meets a post-quantum
// category. A policy that refuses anything below a floor uses it.
func (s *Suite) AtLeast(category int) bool { return s.PQCategory >= category }

// Describe names a suite for a person: what it is, and whether its signatures
// are post-quantum.
func (s *Suite) Describe() string {
	if s.PQCategory == 0 {
		return s.Name + " (signatures are classical)"
	}
	return fmt.Sprintf("%s (signatures are post-quantum, NIST category %d)", s.Name, s.PQCategory)
}
