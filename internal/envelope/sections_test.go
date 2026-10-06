package envelope

import (
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

func later(critical bool) wire.Section {
	return wire.Section{Name: "something-later", Critical: critical, Data: json.RawMessage(`{"n":1}`)}
}

// sealRecord seals inner bytes as given, signed by signer, under the outer
// version given: what a sender of another build, or one past this build's
// own rule, would put on the wire.
func sealRecord(t *testing.T, signer *identity.Identity, to *identity.Public, outerV int, innerBytes []byte) *Envelope {
	t.Helper()
	plaintext := append(append([]byte{}, mustSign(t, signer, sigInput(to.Fingerprint(), innerBytes))...), innerBytes...)
	env := sealPlaintext(t, to, plaintext)
	env.V = outerV
	return env
}

// record is an inner record from alice to bob as raw JSON, with whatever
// version and sections the test wants and nothing held to Seal's rules.
func record(t *testing.T, alice, bob *identity.Identity, v int, sections []wire.Section) []byte {
	t.Helper()
	raw, err := json.Marshal(&Inner{
		V: v, From: alice.Fingerprint(), FromBundle: alice.Public().Bundle(), To: bob.Fingerprint(),
		ID: "0123456789abcdef0123456789abcdef", Time: time.Now().UTC().Truncate(time.Second),
		Body: body(t), Sections: sections,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A section a reader does not know and is not told it must is ignored: the
// message is read, version 1, and is the message it would be without it.
func TestAnUnknownSectionNotCriticalIsRead(t *testing.T) {
	alice, bob := pair(t)
	env, sealed, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{later(false)})
	if err != nil {
		t.Fatal(err)
	}
	if env.V != Version || sealed.V != Version {
		t.Fatalf("a message with no critical section sealed as %d outside and %d inside; want %d", env.V, sealed.V, Version)
	}
	inner, sender, err := Open(bob, env)
	if err != nil {
		t.Fatalf("an unknown section, not critical: %v; want it read", err)
	}
	if sender.Fingerprint() != alice.Fingerprint() || len(inner.Sections) != 1 || inner.Sections[0].Name != "something-later" {
		t.Fatalf("opened %+v from %s", inner, sender.Fingerprint())
	}
	without := *inner
	without.Sections = nil
	plain := *sealed
	plain.Sections = nil
	if !reflect.DeepEqual(without, plain) {
		t.Errorf("read with the section ignored: %+v; want the message as sealed without it, %+v", without, plain)
	}
}

// A critical section a reader does not know stops it: the envelope is
// version 2 inside and out, Open says the message needs a newer auu and is
// not malformed, and hands back the record and its verified sender, so the
// receiver can say whose it is and keep it.
func TestAnUnknownCriticalSectionNeedsANewerAuu(t *testing.T) {
	alice, bob := pair(t)
	env, sealed, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{later(false), later(true)})
	if err == nil {
		t.Fatal("two sections of one name were sealed")
	}
	other := later(true)
	other.Name = "must-know"
	env, sealed, err = SealSections(alice, bob.Public(), "", body(t), []wire.Section{later(false), other})
	if err != nil {
		t.Fatal(err)
	}
	if env.V != VersionCritical || sealed.V != VersionCritical {
		t.Fatalf("a message with a critical section sealed as %d outside and %d inside; want %d", env.V, sealed.V, VersionCritical)
	}
	inner, sender, err := Open(bob, env)
	var nn *wire.NeedsNewerError
	if !errors.Is(err, wire.ErrNeedsNewer) || !errors.As(err, &nn) || nn.Name != "must-know" {
		t.Fatalf("an unknown critical section: %v; want it named as needing a newer auu", err)
	}
	if errors.Is(err, ErrMalformed) || errors.Is(err, ErrBadSender) {
		t.Errorf("an unknown critical section was called malformed or badly sent: %v", err)
	}
	if inner == nil || inner.ID != sealed.ID || sender == nil || sender.Fingerprint() != alice.Fingerprint() {
		t.Fatalf("the record and its sender were not handed back: %+v, %v", inner, sender)
	}
}

// Nothing unsigned is ever one that needs a newer auu (R7): a record with a
// critical section under a signature that is not its sender's is refused
// for the signature, and nothing of it is handed back.
func TestAnUnsignedCriticalSectionIsRefusedForItsSignature(t *testing.T) {
	alice, bob := pair(t)
	mallory, _ := pair(t)
	env := sealRecord(t, mallory, bob.Public(), VersionCritical, record(t, alice, bob, VersionCritical, []wire.Section{later(true)}))
	inner, sender, err := Open(bob, env)
	if !errors.Is(err, ErrBadSender) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("signed by mallory under alice's name, with a critical section: %v; want the signature refused and never needs-newer", err)
	}
	if inner != nil || sender != nil {
		t.Fatalf("a record that failed its signature was handed back: %+v, %v", inner, sender)
	}
}

// The writer's rule is checked by the reader, both ways (P4, R6), on a
// record signed and sealed past Seal's own rule: version 1 with a critical
// section, and version 2 with none, are malformed.
func TestTheVersionRuleIsCheckedBothWays(t *testing.T) {
	alice, bob := pair(t)
	for _, tc := range []struct {
		name     string
		v        int
		sections []wire.Section
		want     string
	}{
		{"version 1 with a critical section", Version, []wire.Section{later(true)}, "version 1 with critical sections true"},
		{"version 2 with no section", VersionCritical, nil, "version 2 with critical sections false"},
		{"version 2 with a section not critical", VersionCritical, []wire.Section{later(false)}, "version 2 with critical sections false"},
	} {
		_, _, err := Open(bob, sealRecord(t, alice, bob.Public(), tc.v, record(t, alice, bob, tc.v, tc.sections)))
		if !errors.Is(err, ErrMalformed) || !strings.Contains(errors.Unwrap(err).Error(), tc.want) {
			t.Errorf("%s: %v; want malformed, %q", tc.name, causeOf(err), tc.want)
		}
	}
}

// The outer version is signed by nobody, so the inner one under the
// signature must agree with it (ruling 60); a record from a build before
// the inner version carries none, and is said so (D43).
func TestTheOuterVersionMustBeTheInnerOne(t *testing.T) {
	alice, bob := pair(t)
	for _, tc := range []struct {
		name         string
		outer, inner int
		sections     []wire.Section
		want         string
	}{
		{"outer 2 over inner 1", VersionCritical, Version, nil, "the envelope says version 2 and the sealed record 1"},
		{"outer 1 over inner 2", Version, VersionCritical, []wire.Section{later(true)}, "the envelope says version 1 and the sealed record 2"},
		{"no inner version", Version, 0, nil, "the sealed record carries no version; the envelope says 1"},
	} {
		_, _, err := Open(bob, sealRecord(t, alice, bob.Public(), tc.outer, record(t, alice, bob, tc.inner, tc.sections)))
		if !errors.Is(err, ErrMalformed) || causeOf(err) != "malformed: "+tc.want {
			t.Errorf("%s: %v; want malformed: %q", tc.name, causeOf(err), tc.want)
		}
	}
	// A relay rewriting the outer version of an honest message buys a
	// message the recipient refuses, no more.
	env, _, err := Seal(alice, bob.Public(), body(t))
	if err != nil {
		t.Fatal(err)
	}
	env.V = VersionCritical
	if _, _, err := Open(bob, env); !errors.Is(err, ErrMalformed) {
		t.Errorf("an honest message with its outer version rewritten: %v; want malformed", err)
	}
}

// P1: outside the sections a field the record does not have is refused, so
// the list is the only place something new may go; and the list itself is
// held to its shape before the signature.
func TestAFieldOutsideTheSectionsIsMalformed(t *testing.T) {
	alice, bob := pair(t)
	raw := record(t, alice, bob, Version, nil)
	with := append([]byte(`{"colour":"blue",`), raw[1:]...)
	if _, _, err := Open(bob, sealRecord(t, alice, bob.Public(), Version, with)); !errors.Is(err, ErrMalformed) ||
		!strings.Contains(causeOf(err), `unknown field "colour"`) {
		t.Errorf("an unknown field: %v; want malformed, naming it", causeOf(err))
	}
	bad := []wire.Section{{Name: "Not-A-Name", Data: json.RawMessage(`1`)}}
	if _, _, err := Open(bob, sealRecord(t, alice, bob.Public(), Version, record(t, alice, bob, Version, bad))); !errors.Is(err, ErrMalformed) ||
		!strings.Contains(causeOf(err), "sections are malformed") {
		t.Errorf("a section whose name is not a name: %v; want malformed", causeOf(err))
	}
	many := make([]wire.Section, wire.MaxSections+1)
	for i := range many {
		many[i] = wire.Section{Name: "s" + strings.Repeat("a", i), Data: json.RawMessage(`1`)}
	}
	if _, _, err := Open(bob, sealRecord(t, alice, bob.Public(), Version, record(t, alice, bob, Version, many))); !errors.Is(err, ErrMalformed) ||
		!strings.Contains(causeOf(err), "33 sections, at most 32") {
		t.Errorf("33 sections: %v; want malformed", causeOf(err))
	}
	if _, _, err := SealSections(alice, bob.Public(), "", body(t), bad); !errors.Is(err, wire.ErrForm) {
		t.Errorf("Seal took a section whose name is not a name: %v", err)
	}
}

// The list is left out when there is none, as a default channel is, and the
// version is always written.
func TestTheInnerRecordWritesItsVersionAndLeavesOutNoSections(t *testing.T) {
	out, err := json.Marshal(Inner{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"v":0`) || strings.Contains(string(out), "sections") {
		t.Fatalf("the zero inner record marshals as %s", out)
	}
}

type lockedDecapsulator struct{ ek crypto.Encapsulator }

func (d lockedDecapsulator) Encapsulator() crypto.Encapsulator  { return d.ek }
func (d lockedDecapsulator) Decapsulate([]byte) ([]byte, error) { return nil, identity.ErrLocked }

type lockedExchanger struct{ pub *ecdh.PublicKey }

func (e lockedExchanger) PublicKey() *ecdh.PublicKey           { return e.pub }
func (e lockedExchanger) Curve() ecdh.Curve                    { return ecdh.X25519() }
func (e lockedExchanger) ECDH(*ecdh.PublicKey) ([]byte, error) { return nil, identity.ErrLocked }

type localSigner struct{ id *identity.Identity }

func (l localSigner) Public() []byte                  { return l.id.Public().SignPublic() }
func (l localSigner) Sign(msg []byte) ([]byte, error) { return l.id.Sign(msg) }

// A key that is not here is not a message that needs a newer auu: locked
// after the message was signed, the receiver gets ErrLocked, and the
// critical section inside is never reached.
func TestALockedKeyIsNotACriticalSection(t *testing.T) {
	alice, bob := pair(t)
	env, _, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{later(true)})
	if err != nil {
		t.Fatal(err)
	}
	ek, x, err := identity.SplitKEMPublic(bob.Public().KEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kem, err := hpke.NewHybridPrivateKey(lockedDecapsulator{ek}, lockedExchanger{x})
	if err != nil {
		t.Fatal(err)
	}
	locked, err := identity.FromRemote(bob.Suite(), bob.Name, bob.Public().Bundle(), localSigner{bob}, kem)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(locked, env); !errors.Is(err, identity.ErrLocked) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("a locked key: %v; want ErrLocked and never needs-newer", err)
	}
}

// causeOf is the sentence beneath Open's one-word error.
func causeOf(err error) string {
	if err == nil {
		return "<nil>"
	}
	if c := errors.Unwrap(err); c != nil {
		return c.Error()
	}
	return err.Error()
}
