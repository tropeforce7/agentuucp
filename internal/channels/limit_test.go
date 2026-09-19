package channels

import (
	"math"
	"strings"
	"testing"
)

// TestLimitDirectoryV: a directory's v is 1, and Validate refuses every
// other value with the version this build reads, the type's extremes
// among them.
func TestLimitDirectoryV(t *testing.T) {
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
