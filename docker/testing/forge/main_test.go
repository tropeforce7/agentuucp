package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

// --at is the whole point: the moment it names is when the certificates
// are issued, one hour before their validity starts and a lifetime before
// it ends, to the second, on both the authority and the bundle.
func TestAtReachesTheCertificates(t *testing.T) {
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("a passphrase for the forge\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca")
	at := time.Date(2019, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := cmdInit([]string{"--dir", ca, "--name", "Then", "--passphrase-file", pass, "--at", at.Format(time.RFC3339)}); err != nil {
		t.Fatalf("init: %v", err)
	}
	store, err := pki.OpenLocked(ca)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := store.Anchor.Cert.NotAfter, at.AddDate(pki.AnchorYears, 0, 0); !got.Equal(want) {
		t.Errorf("the anchor expires %s, want %s", got, want)
	}
	if got := store.Anchor.Cert.NotBefore; got.After(at) || got.Before(at.Add(-2*time.Hour)) {
		t.Errorf("the anchor is valid from %s, want about an hour before %s", got, at)
	}

	out := filepath.Join(dir, "bundle.json")
	issued := at.AddDate(1, 2, 3)
	if err := cmdRelay([]string{"--dir", ca, "--host", "relay.example.com", "--passphrase-file", pass,
		"--at", issued.Format(time.RFC3339), "--out", out}); err != nil {
		t.Fatalf("relay: %v", err)
	}
	// LoadBundle checks against the real clock and refuses what has
	// expired, so the bundle is read as bytes.
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("an empty bundle")
	}
	_, err = pki.LoadBundle(out)
	if err == nil {
		t.Fatal("a bundle issued in 2020 for a year loaded today")
	}
	if !strings.Contains(err.Error(), "expired on 2021-05-07") {
		t.Errorf("the bundle's refusal does not carry the date --at implies: %v", err)
	}
}

func TestAtIsRequiredAndChecked(t *testing.T) {
	for _, args := range [][]string{
		{"--dir", "x", "--name", "y", "--passphrase-file", "z"},
		{"--dir", "x", "--name", "y", "--passphrase-file", "z", "--at", "yesterday"},
	} {
		if err := cmdInit(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}
