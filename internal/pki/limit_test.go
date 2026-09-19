package pki

import (
	"crypto/mldsa"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLimitBundleV: a bundle's v is 1, and LoadBundle refuses every other
// value naming the version this build understands, the type's extremes
// among them, before it reads anything else in the file.
func TestLimitBundleV(t *testing.T) {
	store := TestStore(t, mldsa.MLDSA65())
	b, err := store.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		b.V = v
		if err := WriteBundle(path, b); err != nil {
			t.Fatal(err)
		}
		_, err := LoadBundle(path)
		if err == nil || !strings.Contains(err.Error(), "bundle version "+strconv.Itoa(v)+", but this build understands 1") {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}
	b.V = BundleVersion
	if err := WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err != nil {
		t.Errorf("v 1: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
