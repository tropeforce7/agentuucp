package clientca

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

const testLifetime = 365 * 24 * time.Hour

// issueFor signs a certificate for fp and returns the parsed leaf.
func issueFor(t *testing.T, ca *CA, fp string) *x509.Certificate {
	t.Helper()
	issued, err := ca.Issue(testRequest(t, "laptop", ""), fp, time.Now(), testLifetime)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf, err := x509.ParseCertificate(issued.Cert)
	if err != nil {
		t.Fatalf("parsing the issued certificate: %v", err)
	}
	return leaf
}

func TestIssueBuildsTheLeafFromTheRelaysTemplate(t *testing.T) {
	ca := testCA(t)
	now := time.Now()
	issued, err := ca.Issue(testRequest(t, "laptop", "a token"), testFP, now, testLifetime)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf, err := x509.ParseCertificate(issued.Cert)
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Subject.CommonName != testFP {
		t.Errorf("CN = %q, want the fingerprint %q", leaf.Subject.CommonName, testFP)
	}
	if leaf.IsCA {
		t.Error("the leaf is a CA")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature alone", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want ClientAuth alone", leaf.ExtKeyUsage)
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		t.Error("the leaf carries subject alternative names")
	}
	if leaf.SignatureAlgorithm != x509.MLDSA65 {
		t.Errorf("SignatureAlgorithm = %v, want ML-DSA-65", leaf.SignatureAlgorithm)
	}
	if !leaf.NotBefore.Before(now) {
		t.Error("NotBefore is not backdated; a client whose clock is behind could not connect")
	}
	if got := now.Sub(leaf.NotBefore); got < backdate-time.Second || got > backdate+time.Second {
		t.Errorf("backdated by %v, want %v", got, backdate)
	}
	if !ValidSerial(issued.Serial) {
		t.Errorf("serial %q is not 32 lowercase hex characters", issued.Serial)
	}
	if issued.Label != "laptop" {
		t.Errorf("label = %q, want laptop", issued.Label)
	}
}

func TestIssueDoesNotCopyTheTokenIntoTheCertificate(t *testing.T) {
	// The token is spent, not recorded. A certificate is shown to whoever
	// the machine connects to; a live enrolment token in one would be a
	// credential left on the wire.
	const token = "ccxt1.a-very-recognisable-token.signature"
	ca := testCA(t)
	issued, err := ca.Issue(testRequest(t, "laptop", token), testFP, time.Now(), testLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(issued.Cert, []byte(token)) {
		t.Fatal("the enrolment token is inside the issued certificate")
	}
	leaf, err := x509.ParseCertificate(issued.Cert)
	if err != nil {
		t.Fatal(err)
	}
	// And nothing else from the request either: the only extensions are the
	// ones the template asks for.
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidChallengePassword) {
			t.Error("the certificate carries a challengePassword extension")
		}
	}
}

func TestIssueIgnoresTheRequestedSubject(t *testing.T) {
	// A machine asking to be issued for someone else's fingerprint gets its
	// own: the subject is the relay's word, never the requester's.
	other := strings.Repeat("f", 64)
	ca := testCA(t)
	issued, err := ca.Issue(testRequest(t, other, ""), testFP, time.Now(), testLifetime)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(issued.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != testFP {
		t.Errorf("CN = %q; the request's own subject reached the certificate", leaf.Subject.CommonName)
	}
}

func TestIssueClampsToTheAuthoritysExpiry(t *testing.T) {
	ca := testCA(t)
	// A lifetime longer than the CA has left. A leaf outliving its issuer
	// would verify until the day the CA expired and then stop without
	// warning.
	issued, err := ca.Issue(testRequest(t, "laptop", ""), testFP, time.Now(), 100*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if issued.NotAfter.After(ca.NotAfter()) {
		t.Errorf("leaf expires %v, after the CA's %v", issued.NotAfter, ca.NotAfter())
	}
	if !issued.NotAfter.Equal(ca.NotAfter()) {
		t.Errorf("leaf expires %v, want the CA's %v exactly", issued.NotAfter, ca.NotAfter())
	}
}

func TestIssueRefusesAnExpiredAuthority(t *testing.T) {
	ca := testCA(t)
	after := ca.NotAfter().Add(time.Hour)
	_, err := ca.Issue(testRequest(t, "laptop", ""), testFP, after, testLifetime)
	if !errors.Is(err, ErrCALifetime) {
		t.Fatalf("issuing from an expired authority: %v, want ErrCALifetime", err)
	}
	if !strings.Contains(err.Error(), ca.NotAfter().Format("2006")) {
		t.Errorf("error %q does not say when it expired", err)
	}
}

func TestIssueRefusesAnEmptyOrNegativeLifetime(t *testing.T) {
	ca := testCA(t)
	for _, d := range []time.Duration{0, -time.Second} {
		if _, err := ca.Issue(testRequest(t, "laptop", ""), testFP, time.Now(), d); err == nil {
			t.Errorf("a lifetime of %v was accepted", d)
		}
	}
}

func TestSerialsAreWideAndUnique(t *testing.T) {
	ca := testCA(t)
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		issued, err := ca.Issue(testRequest(t, "laptop", ""), testFP, time.Now(), testLifetime)
		if err != nil {
			t.Fatal(err)
		}
		if seen[issued.Serial] {
			t.Fatalf("serial %s issued twice", issued.Serial)
		}
		seen[issued.Serial] = true
	}
}

func TestFormatSerialPadsSoSerialsCompareAsStrings(t *testing.T) {
	// A small serial must still be 32 characters, or a lookup by string
	// would miss it.
	got := FormatSerial(big.NewInt(1))
	if len(got) != 32 {
		t.Errorf("FormatSerial(1) = %q, want 32 characters", got)
	}
	if !ValidSerial(got) {
		t.Errorf("FormatSerial(1) = %q, which ValidSerial rejects", got)
	}
}

func TestValidSerial(t *testing.T) {
	// The serial reaches a database query from a URL path, so what is
	// accepted is exactly 32 lowercase hex characters and nothing else.
	good := strings.Repeat("a1", 16)
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"a serial", good, true},
		{"one short", good[:31], false},
		{"one long", good + "0", false},
		{"uppercase", strings.ToUpper(good), false},
		{"empty", "", false},
		{"not hex", strings.Repeat("g", 32), false},
		{"a wildcard", strings.Repeat("a", 31) + "%", false},
		{"a quote", strings.Repeat("a", 31) + "'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidSerial(tc.in); got != tc.want {
				t.Errorf("ValidSerial(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
