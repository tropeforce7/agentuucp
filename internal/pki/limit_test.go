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

// TestLimitAServerLeafAndARecordNeedAHost: ServerLeaf names the leaf by
// hosts[0] and FindRecord files a new relay under it, and neither checked
// the list as Intermediate and the bundle's load do; every caller passes
// one, so nothing reached it, but the index was the function's to guard
// (P3, the second trace's E-1 and E-2). Both refuse nil and an empty list,
// and take one host.
func TestLimitAServerLeafAndARecordNeedAHost(t *testing.T) {
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com"})
	for _, hosts := range [][]string{nil, {}} {
		if _, err := ServerLeaf(l.ServerInt, hosts, l.Params, time.Now()); err == nil || !strings.Contains(err.Error(), "at least one host") {
			t.Errorf("ServerLeaf(%#v): %v", hosts, err)
		}
		if _, _, err := s.FindRecord(hosts); err == nil || !strings.Contains(err.Error(), "at least one host") {
			t.Errorf("FindRecord(%#v): %v", hosts, err)
		}
	}
	if leaf, err := ServerLeaf(l.ServerInt, []string{"relay.example.com"}, l.Params, time.Now()); err != nil || leaf.Cert.Subject.CommonName != "relay.example.com" {
		t.Errorf("ServerLeaf with one host: %v", err)
	}
	if name, _, err := s.FindRecord([]string{"other.example.com"}); err != nil || name != "other.example.com" {
		t.Errorf("FindRecord with one host: %q, %v", name, err)
	}
}
