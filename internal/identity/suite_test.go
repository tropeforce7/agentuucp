package identity

import (
	"bytes"
	"crypto/hpke"
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// testSuiteID is in the range reserved for tests. Nothing in a release may
// ever write it, which is why a second suite can be exercised here without
// spending a real identifier on one nobody ships.
const testSuiteID = FirstTestSuite

// mldsaSigner adapts crypto/mldsa to the Signer interface.
type mldsaSigner struct{ key *mldsa.PrivateKey }

func (s mldsaSigner) Public() []byte                  { return s.key.PublicKey().Bytes() }
func (s mldsaSigner) Sign(msg []byte) ([]byte, error) { return s.key.Sign(nil, msg, nil) }

// registerTestSuite adds a second, genuinely different suite for one test and
// removes it afterwards.
//
// It is ML-DSA-65 rather than a stub, deliberately: a fake suite with
// Ed25519's sizes would prove nothing, because every size that matters would
// be the same. This one has a 1952-byte public key and a 3309-byte signature,
// so anything that assumed 32 and 64 fails.
func registerTestSuite(t *testing.T) *Suite {
	t.Helper()
	s := &Suite{
		ID:             testSuiteID,
		Name:           "ML-DSA-65+MLKEM768X25519 (test only)",
		SignSeedSize:   mldsa.PrivateKeySize,
		SignPublicSize: mldsa.MLDSA65PublicKeySize,
		SignatureSize:  mldsa.MLDSA65SignatureSize,
		KEM:            hpke.MLKEM768X25519,
		KEMPublicSize:  KEMPublicKeySize,
		NewSigner: func(seed []byte) (Signer, error) {
			key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
			if err != nil {
				return nil, err
			}
			return mldsaSigner{key: key}, nil
		},
		Verify: func(pub, msg, sig []byte) bool {
			key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
			if err != nil {
				return false
			}
			return mldsa.Verify(key, msg, sig, nil) == nil
		},
	}
	Register(s)
	t.Cleanup(func() {
		delete(suites, s.ID)
		delete(byWireLen, s.wireSize())
	})
	return s
}

func TestASecondSuiteWorksEndToEnd(t *testing.T) {
	// The whole point of the registry. If this passes, adding a suite is a
	// matter of registering one; if it fails, the scheme is not extensible
	// whatever the machinery looks like.
	suite := registerTestSuite(t)

	id, err := GenerateSuite(suite, "bunty")
	if err != nil {
		t.Fatalf("generating under a second suite: %v", err)
	}
	if id.Suite().ID != testSuiteID {
		t.Fatalf("identity reports suite %d, want %d", id.Suite().ID, testSuiteID)
	}

	// A fingerprint is a fingerprint whatever made it: 64 hex characters, so
	// every path, database key and command-line argument is unaffected.
	if !ValidFingerprint(id.Fingerprint()) {
		t.Errorf("fingerprint %q is not the shape everything else expects", id.Fingerprint())
	}

	// Signing and verifying, through the interface rather than a primitive.
	msg := []byte("a message to sign")
	sig := mustSign(t, id, msg)
	if len(sig) != mldsa.MLDSA65SignatureSize {
		t.Errorf("signature is %d bytes, want %d", len(sig), mldsa.MLDSA65SignatureSize)
	}
	if !id.Public().Verify(msg, sig) {
		t.Fatal("a signature by the second suite does not verify")
	}
	if id.Public().Verify([]byte("a different message"), sig) {
		t.Fatal("a signature verified over the wrong message")
	}

	// The bundle round-trips, and says which suite it is.
	back, err := ParseBundle(id.Public().Bundle())
	if err != nil {
		t.Fatalf("parsing a second-suite bundle: %v", err)
	}
	if back.Suite().ID != testSuiteID {
		t.Errorf("parsed bundle reports suite %d", back.Suite().ID)
	}
	if back.Fingerprint() != id.Fingerprint() {
		t.Error("the fingerprint changed across a bundle round trip")
	}
	if !back.Verify(msg, sig) {
		t.Error("a signature does not verify against the parsed bundle")
	}

	// And so does an export line, which is where a person meets it.
	line := id.Public().ExportLine()
	parsed, err := ParseExportLine(line)
	if err != nil {
		t.Fatalf("parsing a second-suite export line: %v", err)
	}
	if parsed.Fingerprint() != id.Fingerprint() || parsed.Name != "bunty" {
		t.Error("the export line did not survive the round trip")
	}

	// And the key file, which records the suite because it is not the default.
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"suite":128`)) {
		t.Errorf("the key file does not record the suite: %s", data)
	}
	var restored Identity
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("reloading a second-suite identity: %v", err)
	}
	if restored.Fingerprint() != id.Fingerprint() {
		t.Error("the identity changed across a save and load")
	}
}

func TestTheOriginalSuiteIsUntaggedAndUnchanged(t *testing.T) {
	// Everything above must cost the existing format nothing. A bundle of the
	// original suite is still the bare concatenation, still 1248 bytes, and
	// its fingerprint is still over exactly those bytes — so every key,
	// export line and stored bundle in existence is unaffected.
	id, err := Generate("bunty")
	if err != nil {
		t.Fatal(err)
	}
	bundle := id.Public().Bundle()
	if len(bundle) != BundleSize {
		t.Fatalf("bundle is %d bytes, want %d", len(bundle), BundleSize)
	}
	if id.Suite().tagged() {
		t.Fatal("the original suite carries a tag byte; every fingerprint would change")
	}
	// The first 32 bytes are the signing key itself, not a tag in front of it.
	if !bytes.Equal(bundle[:32], id.Public().signPub) {
		t.Error("the bundle no longer begins with the signing key")
	}

	// The key file records no suite, so a file this build writes is one an
	// older build still reads.
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"suite"`)) {
		t.Errorf("the default suite is written into the key file: %s", data)
	}
	// And a file with no suite loads as the default.
	var restored Identity
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Suite().ID != SuiteEd25519XWing {
		t.Errorf("a file with no suite loaded as suite %d", restored.Suite().ID)
	}
}

func TestABundleOfAnUnknownSuiteIsRefused(t *testing.T) {
	// A key from a newer release, or nonsense. Either way the refusal names
	// the lengths this build does understand, so somebody can tell the two
	// apart.
	for _, n := range []int{0, 1, BundleSize - 1, BundleSize + 1, 4096} {
		_, err := ParseBundle(make([]byte, n))
		if err == nil {
			t.Fatalf("a %d-byte bundle was accepted", n)
		}
		if !strings.Contains(err.Error(), "no known suite") && n != BundleSize {
			t.Errorf("a %d-byte bundle: %q does not say it is an unknown suite", n, err)
		}
	}
}

func TestATaggedBundleMustCarryItsOwnTag(t *testing.T) {
	// The length says which suite a bundle is; the tag must agree. A bundle
	// of the right length claiming to be something else is refused rather
	// than read as the suite its length implies.
	suite := registerTestSuite(t)
	id, err := GenerateSuite(suite, "bunty")
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte{}, id.Public().Bundle()...)
	bad[0] ^= 0xff
	_, err = ParseBundle(bad)
	if err == nil {
		t.Fatal("a bundle with the wrong suite tag was accepted")
	}
	if !strings.Contains(err.Error(), "tagged") {
		t.Errorf("error %q does not say the tag is wrong", err)
	}
}

func TestRegisterRefusesACollision(t *testing.T) {
	// Two suites the same length on the wire would be indistinguishable,
	// because the original one has no tag to tell them apart by. Refused
	// when the second is registered rather than when somebody's key stops
	// parsing.
	defer func() {
		if recover() == nil {
			t.Fatal("registering a suite of a colliding length did not panic")
		}
	}()
	// A tagged suite whose wire size is one more than its body, chosen to
	// collide with the original 1248-byte bundle.
	Register(&Suite{
		ID: FirstTestSuite + 1, Name: "collides",
		SignSeedSize: 32, SignPublicSize: 31, SignatureSize: 64,
		KEM: hpke.MLKEM768X25519, KEMPublicSize: KEMPublicKeySize,
		NewSigner: func([]byte) (Signer, error) { return nil, nil },
		Verify:    func(pub, msg, sig []byte) bool { return false },
	})
}

func TestSignatureSizesCoverEverySuite(t *testing.T) {
	// Formats that carry a signature bound its length by these before
	// decoding one, so a suite missing from the list would have every
	// signature refused.
	before := len(SignatureSizes())
	suite := registerTestSuite(t)
	after := SignatureSizes()
	if len(after) != before+1 {
		t.Fatalf("registering a suite added %d sizes, want 1", len(after)-before)
	}
	if !IsSignatureSize(suite.SignatureSize) {
		t.Error("the new suite's signature size is not reported")
	}
	if MaxSignatureSize() != mldsa.MLDSA65SignatureSize {
		t.Errorf("MaxSignatureSize is %d, want the largest registered", MaxSignatureSize())
	}
	// Sorted, because a refusal lists them and an unstable order would make
	// the message differ between runs.
	for i := 1; i < len(after); i++ {
		if after[i-1] > after[i] {
			t.Fatalf("SignatureSizes is not sorted: %v", after)
		}
	}
}

// TestGoldenVectorFromBeforeSuitesExisted holds this build to what the one
// before it produced.
//
// The values were taken from commit e8d8a40, the last before the suite
// registry existed, by running the same seeds through it. If any of them
// changes, every identity, export line, authorized_peers entry, stored bundle
// and relay mailbox in existence has been invalidated — which is the one thing
// making the scheme extensible was not allowed to cost.
func TestGoldenVectorFromBeforeSuitesExisted(t *testing.T) {
	signSeed := make([]byte, 32)
	kemSeed := make([]byte, 32)
	for i := range signSeed {
		signSeed[i] = byte(i)
		kemSeed[i] = byte(0xa0 + i)
	}
	id, err := FromSeeds("bunty", signSeed, kemSeed)
	if err != nil {
		t.Fatal(err)
	}

	const (
		wantFP     = "c35dc68748a36521d80067ccc0a8f051c51af44e547d6e4b32897256d9e9c28d"
		wantHead   = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8d3e23930213480e960360b7ec8c45911"
		wantTail   = "cc2d8f70f401065ceb75a8c2e409cf5a"
		wantExport = "ccx2.A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbjT4jkwITSA6WA"
		wantSig    = "8a47f0e5fa7b426466e57ecd2c32433d6bae097efa5b50e1edf72018f2fc668c" +
			"4be04a1b19d30e5185361367c8b745af6616f35e54f414d6be7dc3f11aa57309"
	)

	if got := id.Fingerprint(); got != wantFP {
		t.Errorf("fingerprint changed:\n got %s\nwant %s", got, wantFP)
	}
	b := id.Public().Bundle()
	if len(b) != 1248 {
		t.Errorf("bundle is %d bytes, want 1248", len(b))
	}
	if got := hex.EncodeToString(b[:48]); got != wantHead {
		t.Errorf("bundle head changed:\n got %s\nwant %s", got, wantHead)
	}
	if got := hex.EncodeToString(b[len(b)-16:]); got != wantTail {
		t.Errorf("bundle tail changed:\n got %s\nwant %s", got, wantTail)
	}
	if got := id.Public().ExportLine(); !strings.HasPrefix(got, wantExport) {
		t.Errorf("export line changed:\n got %s\nwant a line beginning %s", got[:60], wantExport)
	}
	// Ed25519 signing is deterministic, so the signature is a constant too.
	if got := hex.EncodeToString(mustSign(t, id, []byte("golden"))); got != wantSig {
		t.Errorf("signature changed:\n got %s\nwant %s", got, wantSig)
	}

	// And the bundle still parses back to the same identity, which is what a
	// peer with this line in authorized_peers does on every message.
	back, err := ParseBundle(b)
	if err != nil {
		t.Fatalf("the bundle no longer parses: %v", err)
	}
	if back.Fingerprint() != wantFP {
		t.Error("a parsed bundle no longer produces the same fingerprint")
	}
	if !back.Verify([]byte("golden"), mustSign(t, id, []byte("golden"))) {
		t.Error("a signature no longer verifies against a parsed bundle")
	}
}
