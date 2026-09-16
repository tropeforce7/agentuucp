package pki

import (
	"crypto/mldsa"
	"path/filepath"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// testSecret is the passphrase every test authority is encrypted under. The
// costs come from keyfile.TestPassphrase and are the least each function
// allows, so building a hierarchy in a test stays as quick as it was before
// the keys were encrypted.
const testSecret = "test passphrase"

// TestHierarchy builds a whole PKI in a temporary directory and issues one
// relay's bundle from it, which is what almost every test of the relay needs.
//
// It lives in the package rather than a test file because four other packages
// need it, and because building it by hand in each of them is how the shape
// drifts apart from what auu-ca actually writes.
func TestHierarchy(t *testing.T, hosts []string, params mldsa.Parameters) *Loaded {
	t.Helper()
	store, err := Create(t.TempDir(), "Test", params, keyfile.TestPassphrase(testSecret), time.Now())
	if err != nil {
		t.Fatalf("pki: creating a test hierarchy: %v", err)
	}
	return TestBundleFrom(t, store, hosts)
}

// TestBundleFrom issues another bundle from an existing store, which is how a
// test rotates a relay's signing intermediates.
func TestBundleFrom(t *testing.T, store *Store, hosts []string) *Loaded {
	t.Helper()
	return TestBundleAt(t, store, hosts, time.Now())
}

// TestBundleAt is TestBundleFrom issued at a chosen moment, so that a test
// that needs two bundles with distinct issue times can have them a second
// apart without sleeping for one.
func TestBundleAt(t *testing.T, store *Store, hosts []string, now time.Time) *Loaded {
	t.Helper()
	b, _, err := store.IssueRelay(hosts, DefaultIntermediateYears, now)
	if err != nil {
		t.Fatalf("pki: issuing a test bundle: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteBundle(path, b); err != nil {
		t.Fatalf("pki: writing a test bundle: %v", err)
	}
	// Read it back rather than use the in-memory form, so a test exercises
	// the same path a relay does and a bundle that would not load fails here.
	l, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("pki: loading a test bundle: %v", err)
	}
	return l
}

// TestLoadedAt is TestBundleAt with the bundle also loaded as of the moment
// it was issued, so that a test can hold what a relay that started then
// would hold — a chain that has since run out, for instance — which the
// loader, rightly, would refuse to load today. The relay in the container
// suite's forge does the same with a different "now".
func TestLoadedAt(t *testing.T, store *Store, hosts []string, now time.Time) *Loaded {
	t.Helper()
	b, _, err := store.IssueRelay(hosts, DefaultIntermediateYears, now)
	if err != nil {
		t.Fatalf("pki: issuing a test bundle: %v", err)
	}
	l, err := b.load(now)
	if err != nil {
		t.Fatalf("pki: loading a test bundle as of %s: %v", now.Format(time.DateOnly), err)
	}
	return l
}

// TestStore makes a hierarchy without issuing anything, for a test that wants
// to issue more than once.
func TestStore(t *testing.T, params mldsa.Parameters) *Store {
	t.Helper()
	store, err := Create(t.TempDir(), "Test", params, keyfile.TestPassphrase(testSecret), time.Now())
	if err != nil {
		t.Fatalf("pki: creating a test hierarchy: %v", err)
	}
	return store
}
