package card

import (
	"math"
	"strings"
	"testing"
)

// TestLimitCardV: the one integer a card carries is its version, held to
// exactly 1; every other value, the type's extremes included, is refused
// naming the version this build reads.
func TestLimitCardV(t *testing.T) {
	id := owner(t)
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		d := base(id)
		d.V = v
		err := d.Validate()
		if err == nil || !strings.Contains(err.Error(), "this build reads 1") {
			t.Errorf("v %d: %v; want the refusal naming the version this build reads", v, err)
		}
	}
	if err := base(id).Validate(); err != nil {
		t.Errorf("v 1: %v", err)
	}
}
