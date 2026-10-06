package stream

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

func later(critical bool) wire.Section {
	return wire.Section{Name: "something-later", Critical: critical, Data: json.RawMessage(`{"n":1}`)}
}

// sealedWith builds and seals a stream carrying sections, through the
// sender's own path, and returns its header and chunk 0.
func sealedWith(t *testing.T, from, to *identity.Identity, sections []wire.Section) (*Manifest, []byte, []byte) {
	t.Helper()
	src := source("a.txt", []byte("payload"))
	m, err := BuildManifestSections(from, to.Public(), strings.Repeat("a", 32), body(), []Source{src}, MinChunkSize, sections)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Seal(&buf, from, to.Public(), m, []Source{src}); err != nil {
		t.Fatal(err)
	}
	blob := buf.Bytes()
	n, err := ManifestLength(blob[:HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	return m, blob[:HeaderSize], blob[HeaderSize : HeaderSize+n]
}

// sealManifestByHand seals chunk 0 for a manifest as given, signed by
// signer, past every rule BuildManifest and Seal would hold it to.
func sealManifestByHand(t *testing.T, signer, to *identity.Identity, m *Manifest) ([]byte, []byte) {
	t.Helper()
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := senderContext(to.Public())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(sigInput(m.To, manifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sender.Seal(aadManifest, append(sig, manifestJSON...))
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{}, enc...), putPrefix(len(sealed))...), sealed
}

// A section the reader does not know and is not told it must is ignored:
// the manifest is version 2, since any section makes it so (D30), and it
// opens as the manifest it would be without the section.
func TestAStreamWithAnUnknownSectionNotCriticalOpens(t *testing.T) {
	from, to := pair(t)
	m, header, chunk0 := sealedWith(t, from, to, []wire.Section{later(false)})
	if m.V != VersionSections {
		t.Fatalf("a manifest with a section built as version %d; want %d", m.V, VersionSections)
	}
	opened, err := OpenManifest(to, header, chunk0)
	if err != nil {
		t.Fatalf("an unknown section, not critical: %v; want it opened", err)
	}
	got, want := *opened.Manifest, *m
	got.Sections, want.Sections = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("opened %+v; want the manifest as built, without the section, %+v", got, want)
	}
	if plain, _, _ := sealedWith(t, from, to, nil); plain.V != Version {
		t.Errorf("a manifest with no section built as version %d; want %d", plain.V, Version)
	}
}

// A critical section the reader does not know stops it, once the signature
// has verified: the verified manifest and its sender come back with an
// error that needs a newer auu and is not ErrForm.
func TestAStreamWithAnUnknownCriticalSectionNeedsANewerAuu(t *testing.T) {
	from, to := pair(t)
	m, header, chunk0 := sealedWith(t, from, to, []wire.Section{later(true)})
	opened, err := OpenManifest(to, header, chunk0)
	var nn *wire.NeedsNewerError
	if !errors.Is(err, wire.ErrNeedsNewer) || !errors.As(err, &nn) || nn.Name != "something-later" {
		t.Fatalf("an unknown critical section: %v; want it named as needing a newer auu", err)
	}
	if errors.Is(err, ErrForm) || errors.Is(err, ErrSignature) {
		t.Errorf("an unknown critical section was called malformed or unsigned: %v", err)
	}
	if opened == nil || opened.Manifest.ID != m.ID || opened.Sender.Fingerprint() != from.Fingerprint() {
		t.Fatalf("the manifest and its sender were not handed back: %+v", opened)
	}
}

// Nothing unsigned is ever one that needs a newer auu (R7): a manifest with
// a critical section under a signature that is not its sender's is refused
// for the signature, and nothing of it is handed back.
func TestAnUnsignedManifestWithACriticalSectionIsRefusedForItsSignature(t *testing.T) {
	from, to := pair(t)
	mallory, _ := pair(t)
	m, _, _ := sealedWith(t, from, to, []wire.Section{later(true)})
	header, chunk0 := sealManifestByHand(t, mallory, to, m)
	opened, err := OpenManifest(to, header, chunk0)
	if !errors.Is(err, ErrSignature) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("signed by mallory with a critical section: %v; want the signature refused and never needs-newer", err)
	}
	if opened != nil {
		t.Fatalf("a manifest that failed its signature was handed back: %+v", opened)
	}
}

// The writer's rule is checked by the reader both ways (P4, R6), on a
// manifest signed and sealed past the builder's rule: version 1 with a
// section and version 2 with none are malformed.
func TestTheManifestVersionRuleIsCheckedBothWays(t *testing.T) {
	from, to := pair(t)
	m, _, _ := sealedWith(t, from, to, nil)
	for _, tc := range []struct {
		name     string
		v        int
		sections []wire.Section
		want     string
	}{
		{"version 1 with a section", Version, []wire.Section{later(false)}, "manifest version 1 with 1 sections"},
		{"version 2 with none", VersionSections, nil, "manifest version 2 with 0 sections"},
	} {
		bad := *m
		bad.V, bad.Sections = tc.v, tc.sections
		header, chunk0 := sealManifestByHand(t, from, to, &bad)
		if _, err := OpenManifest(to, header, chunk0); !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want ErrForm, %q", tc.name, err, tc.want)
		}
	}
	bad := *m
	bad.V, bad.Sections = VersionSections, []wire.Section{{Name: "Not-A-Name", Data: json.RawMessage(`1`)}}
	header, chunk0 := sealManifestByHand(t, from, to, &bad)
	if _, err := OpenManifest(to, header, chunk0); !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "sections are malformed") {
		t.Errorf("a section whose name is not a name: %v; want ErrForm", err)
	}
	if _, err := BuildManifestSections(from, to.Public(), strings.Repeat("a", 32), body(), nil, MinChunkSize, bad.Sections); !errors.Is(err, ErrForm) {
		t.Errorf("the builder took a section whose name is not a name: %v", err)
	}
}

// The list is left out when there is none, and the version is always
// written.
func TestTheManifestLeavesOutNoSections(t *testing.T) {
	out, err := json.Marshal(Manifest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"v":0`) || strings.Contains(string(out), "sections") {
		t.Fatalf("the zero manifest marshals as %s", out)
	}
}

// A key that is not here is not a stream that needs a newer auu: the
// manifest with a critical section, opened with a locked key, answers
// ErrLocked and never reaches the section.
func TestALockedKeyIsNotAStreamThatNeedsANewerAuu(t *testing.T) {
	from, to := pair(t)
	_, header, chunk0 := sealedWith(t, from, to, []wire.Section{later(true)})
	ek, x, err := identity.SplitKEMPublic(to.Public().KEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	locked, err := identity.FromRemote(to.Suite(), to.Name, to.Public().Bundle(), localSigner{to}, mustLockedKEM(t, ek, x))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenManifest(locked, header, chunk0); !errors.Is(err, identity.ErrLocked) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("a locked key: %v; want ErrLocked and never needs-newer", err)
	}
}

// mustLockedKEM is the recipient's KEM as a locked agent presents it.
func mustLockedKEM(t *testing.T, ek crypto.Encapsulator, x *ecdh.PublicKey) hpke.PrivateKey {
	t.Helper()
	kem, err := hpke.NewHybridPrivateKey(lockedDecapsulator{ek}, lockedExchanger{x})
	if err != nil {
		t.Fatal(err)
	}
	return kem
}
