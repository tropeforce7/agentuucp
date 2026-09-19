package envelope

import (
	"errors"
	"math"
	"testing"
)

// TestLimitEnvelopeV: an envelope's v is 1, and Open refuses every other
// value as malformed, the type's extremes among them, before it looks at
// the addressee or the seal.
func TestLimitEnvelopeV(t *testing.T) {
	alice, bob := pair(t)
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		env := mustSeal(t, alice, bob, body(t))
		env.V = v
		_, _, err := Open(bob, env)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("v %d: %v; want ErrMalformed", v, err)
		}
	}
	env := mustSeal(t, alice, bob, body(t))
	if env.V != Version {
		t.Fatalf("Seal wrote v %d", env.V)
	}
	if _, _, err := Open(bob, env); err != nil {
		t.Errorf("v 1: %v", err)
	}
}
