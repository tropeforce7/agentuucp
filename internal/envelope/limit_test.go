package envelope

import (
	"errors"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"math"
	"strconv"
	"testing"
)

// TestLimitEnvelopeV: an envelope's v is 1, and Open refuses every other
// value as malformed, the type's extremes among them, before it looks at
// the addressee or the seal.
func TestLimitEnvelopeV(t *testing.T) {
	alice, bob := pair(t)
	// Outside the two versions this build writes, refused before anything
	// is decrypted.
	for _, v := range []int{0, -1, VersionCritical + 1, math.MinInt, math.MaxInt} {
		env := mustSeal(t, alice, bob, body(t))
		env.V = v
		_, _, err := Open(bob, env)
		if !errors.Is(err, ErrMalformed) || causeOf(err) != "malformed: unsupported version "+strconv.Itoa(v) {
			t.Errorf("v %d: %v; want malformed, unsupported version", v, causeOf(err))
		}
	}
	// 1, the version of a message with no critical section, opens.
	env := mustSeal(t, alice, bob, body(t))
	if env.V != Version {
		t.Fatalf("Seal wrote v %d", env.V)
	}
	if _, _, err := Open(bob, env); err != nil {
		t.Errorf("v 1: %v", err)
	}
	// 2, the version of a message with a critical section, is read as far
	// as the section: what stops it is the section, never the version.
	env, _, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{later(true)})
	if err != nil {
		t.Fatal(err)
	}
	if env.V != VersionCritical {
		t.Fatalf("SealSections wrote v %d", env.V)
	}
	if _, _, err := Open(bob, env); !errors.Is(err, wire.ErrNeedsNewer) {
		t.Errorf("v 2: %v; want it read as far as its critical section", err)
	}
}

// TestLimitInnerV: the version under the signature is one of the two this
// build writes, by being equal to the outer one, which is one of them; any
// other value, under an outer 1, is refused as malformed naming both, and
// none at all says the record carries none (ruling 60, D43).
func TestLimitInnerV(t *testing.T) {
	alice, bob := pair(t)
	for _, v := range []int{-1, VersionCritical + 1, math.MinInt, math.MaxInt} {
		_, _, err := Open(bob, sealRecord(t, alice, bob.Public(), Version, record(t, alice, bob, v, nil)))
		want := "malformed: the envelope says version 1 and the sealed record " + strconv.Itoa(v)
		if !errors.Is(err, ErrMalformed) || causeOf(err) != want {
			t.Errorf("inner v %d: %v; want %q", v, causeOf(err), want)
		}
	}
	if _, _, err := Open(bob, sealRecord(t, alice, bob.Public(), Version, record(t, alice, bob, 0, nil))); causeOf(err) != "malformed: the sealed record carries no version; the envelope says 1" {
		t.Errorf("inner v 0: %v", causeOf(err))
	}
	if _, _, err := Open(bob, sealRecord(t, alice, bob.Public(), Version, record(t, alice, bob, Version, nil))); err != nil {
		t.Errorf("inner v 1: %v", err)
	}
	if _, _, err := Open(bob, sealRecord(t, alice, bob.Public(), VersionCritical, record(t, alice, bob, VersionCritical, []wire.Section{later(true)}))); !errors.Is(err, wire.ErrNeedsNewer) {
		t.Errorf("inner v 2: %v; want it read as far as its critical section", err)
	}
}
