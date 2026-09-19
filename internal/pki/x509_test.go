package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// TestLimitHostsTheRuleTakesAreHostsX509Takes: the relay host rule is held
// to the consumer that matters. For a set of hosts validDNSName takes —
// one label, many, hyphens inside a label, a label of 63 characters, a
// name of 253 — a certificate is issued through the real
// x509.CreateCertificate with the host as a SAN, parsed back, and the SAN
// is asserted present; then a chain is verified against an authority
// whose name constraint permits the host's domain, so the constraint
// matched it too. One direction only: every host the rule takes is a
// host x509 takes, which says nothing about hosts the rule refuses that
// x509 would have taken; the rule is narrower on purpose.
func TestLimitHostsTheRuleTakesAreHostsX509Takes(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// 253 characters: three labels of 63, a dot between each, then one of 61.
	name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	if len(name253) != 253 {
		t.Fatalf("the 253 edge is %d characters", len(name253))
	}
	hosts := []struct {
		host, constraint string
	}{
		{"relay", "relay"},
		{"relay.example.com", "example.com"},
		{"a.b.c.d.e.example.com", "example.com"},
		{"my-relay.example-domain.com", "example-domain.com"},
		{"x1.y2.z3", "z3"},
		{label63 + ".example.com", "example.com"},
		{name253, strings.Repeat("b", 61)},
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tc := range hosts {
		if err := validDNSName(tc.host); err != nil {
			t.Fatalf("%q: the rule refuses a host this test is about: %v", tc.host, err)
		}
		caTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "constraining authority"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{tc.constraint},
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("%q: the authority with a constraint of %q: %v", tc.host, tc.constraint, err)
		}
		ca, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames: []string{tc.host},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Errorf("%q: x509.CreateCertificate refused the host as a SAN: %v", tc.host, err)
			continue
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Errorf("%q: the certificate does not parse back: %v", tc.host, err)
			continue
		}
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != tc.host {
			t.Errorf("%q: the SAN read back is %v", tc.host, leaf.DNSNames)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: tc.host, CurrentTime: now}); err != nil {
			t.Errorf("%q: not verified for its own name under a constraint of %q: %v", tc.host, tc.constraint, err)
		}
	}
}

// TestAnAuthorityBehindASymbolicLinkWorks: the handle check refuses a
// link under a file's name, but a directory reached through a link is a
// directory, and an offline authority kept on removable media behind a
// link in the home is the ordinary case. Create through the link, issue a
// relay, and the syncs of the directory after each rename succeed; the
// second reader on this change found the first version refusing the
// link and leaving the authority half made.
func TestAnAuthorityBehindASymbolicLinkWorks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link to a directory needs a privilege on Windows")
	}
	scratch := t.TempDir()
	real := filepath.Join(scratch, "media")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scratch, "ca")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	store, err := Create(link, "Test", mldsa.MLDSA44(), keyfile.TestPassphrase(testSecret), time.Now())
	if err != nil {
		t.Fatalf("creating an authority behind a link: %v", err)
	}
	if _, err := store.IssueRelay([]string{"relay.example.com"}, 1, time.Now()); err != nil {
		t.Fatalf("issuing through a link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(real, relaysDir)); err != nil {
		t.Errorf("the record directory is not under the real directory: %v", err)
	}
}
