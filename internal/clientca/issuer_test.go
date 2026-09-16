package clientca

import (
	"crypto/mldsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

// TestTheServedChainReachesTheAnchor is the test the end-to-end run should not
// have had to be the one to find.
//
// A client holds the trust anchor and nothing else, so every certificate
// between the relay's leaf and the anchor must be on the wire. Omitting the
// signing intermediate is invisible to the relay — it serves happily — and
// fatal to every client, which fails with "unknown authority" and no clue why.
func TestTheServedChainReachesTheAnchor(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"relay.example.com"}, mldsa.MLDSA65())
	server, err := NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify exactly as a client does: the anchor as the only root, and only
	// what the server sent as intermediates.
	roots := x509.NewCertPool()
	roots.AddCert(bundle.Anchor)
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		inter.AddCert(c)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "relay.example.com",
	}); err != nil {
		t.Fatalf("a client holding only the anchor cannot verify what the relay serves: %v", err)
	}

	// And nothing more than needed: the anchor itself is not sent, because
	// the client already has it and a root on the wire proves nothing.
	for _, der := range cert.Certificate {
		if string(der) == string(bundle.Anchor.Raw) {
			t.Error("the relay sends the trust anchor; the client already has it")
		}
	}
}

func TestARenewedLeafStillReachesTheAnchor(t *testing.T) {
	// The chain must survive a renewal, which replaces the leaf and keeps
	// everything above it.
	bundle := pki.TestHierarchy(t, []string{"relay.example.com"}, mldsa.MLDSA65())
	server, err := NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := server.RenewIfDue(time.Now(), 400*24*time.Hour)
	if err != nil || !renewed {
		t.Fatalf("RenewIfDue: %v, renewed=%v", err, renewed)
	}
	after, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Certificate) != len(before.Certificate) {
		t.Fatalf("the chain changed length across a renewal: %d then %d",
			len(before.Certificate), len(after.Certificate))
	}
	roots := x509.NewCertPool()
	roots.AddCert(bundle.Anchor)
	inter := x509.NewCertPool()
	for _, der := range after.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		inter.AddCert(c)
	}
	leaf, err := x509.ParseCertificate(after.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "relay.example.com",
	}); err != nil {
		t.Fatalf("a renewed leaf does not verify: %v", err)
	}
}
