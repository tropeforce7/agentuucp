package pki

import (
	"bytes"
	"crypto/mldsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A bundle that stops early was cut in delivery — a copy that did not finish,
// a credential truncated — and Go's "unexpected EOF" says nothing about what
// to do. The container suite's R13 found the bare EOF.
func TestAShortBundleIsNamed(t *testing.T) {
	store := TestStore(t, mldsa.MLDSA65())
	b, err := store.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	whole, err := EncodeBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	// The encoding ends in a newline, which is not the byte that matters.
	whole = bytes.TrimRight(whole, "\n")
	write := func(t *testing.T, raw []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tc := range []struct {
		name string
		keep int
		why  string
	}{
		{"nothing at all", 0, "EOF"},
		{"one byte", 1, "unexpected EOF"},
		{"cut inside a value", len(whole) / 2, "unexpected EOF"},
		{"one byte short", len(whole) - 1, "unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, whole[:tc.keep])
			_, err := LoadBundle(path)
			if err == nil {
				t.Fatal("a cut-short bundle loaded")
			}
			want := path + ": the bundle is cut short (" + tc.why + "): deliver it again"
			if err.Error() != want {
				t.Fatalf("error %q, want %q", err, want)
			}
		})
	}
	// Whole, it loads; damaged some other way, Go's reason stands alone.
	if _, err := LoadBundle(write(t, whole)); err != nil {
		t.Fatalf("the whole bundle was refused: %v", err)
	}
	broken := append([]byte(nil), whole...)
	broken[0] = 'x'
	if _, err := LoadBundle(write(t, broken)); err == nil || strings.Contains(err.Error(), "cut short") {
		t.Fatalf("a bundle broken at the front was called cut short: %v", err)
	}
}
