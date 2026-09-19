package identity

import (
	"strings"
	"testing"
)

// TestLimitBundleOneShort: a bundle's length names its suite at
// suiteForWire before ParseBundle cuts it into its keys; one byte short,
// one long and empty are each refused naming the length.
func TestLimitBundleOneShort(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	b := id.Public().Bundle()
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte{}, b...), 0), nil, b[:1]} {
		_, err := ParseBundle(bad)
		if err == nil || !strings.Contains(err.Error(), "no known suite") {
			t.Errorf("a bundle of %d bytes: %v; want the refusal naming the length", len(bad), err)
		}
	}
	if _, err := ParseBundle(b); err != nil {
		t.Errorf("the bundle as written: %v", err)
	}
}
