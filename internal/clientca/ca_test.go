package clientca

import (
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA is an authority in a temporary directory.
func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := Create(t.TempDir(), "https://relay.example.com", mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return ca
}

func TestCreateWritesTheKeyUnreadableAndTheCertificateReadable(t *testing.T) {
	dir := t.TempDir()
	ca, err := Create(dir, "https://relay.example.com", mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, tc := range []struct {
		file string
		want fs.FileMode
	}{
		{keyFile, 0o600},
		{certFile, 0o644},
	} {
		info, err := os.Stat(filepath.Join(dir, tc.file))
		if err != nil {
			t.Fatalf("stat %s: %v", tc.file, err)
		}
		if got := info.Mode().Perm(); got != tc.want {
			t.Errorf("%s is mode %04o, want %04o", tc.file, got, tc.want)
		}
	}

	if ca.Certificate().Subject.CommonName != caSubjectCN {
		t.Errorf("CN = %q, want %q", ca.Certificate().Subject.CommonName, caSubjectCN)
	}
	if org := ca.Certificate().Subject.Organization; len(org) != 1 || org[0] != "relay.example.com" {
		t.Errorf("Organization = %v, want [relay.example.com]", org)
	}
	// The unique component: two authorities must not share a subject, or a
	// client would offer one relay's certificate to the other.
	if ou := ca.Certificate().Subject.OrganizationalUnit; len(ou) != 1 || len(ou[0]) != 2*uniqueBytes {
		t.Errorf("OrganizationalUnit = %v, want one %d-character string", ou, 2*uniqueBytes)
	}
}

func TestCreateGivesEveryAuthorityADifferentSubject(t *testing.T) {
	a, b := testCA(t), testCA(t)
	if a.Certificate().Subject.String() == b.Certificate().Subject.String() {
		t.Fatal("two authorities share a subject; a client would offer either one to both")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("two authorities share a fingerprint")
	}
}

func TestCACertificateIsAnAuthorityThatSignsNothingElse(t *testing.T) {
	ca := testCA(t)
	cert := ca.Certificate()

	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("certificate is not a valid CA")
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero is false: the CA may sign an intermediate")
	}
	if cert.KeyUsage != x509.KeyUsageCertSign {
		t.Errorf("KeyUsage = %v, want CertSign alone", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 0 {
		t.Errorf("ExtKeyUsage = %v, want none", cert.ExtKeyUsage)
	}
	if cert.SignatureAlgorithm != x509.MLDSA65 {
		t.Errorf("SignatureAlgorithm = %v, want ML-DSA-65", cert.SignatureAlgorithm)
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Errorf("public key is %T, want *mldsa.PublicKey", cert.PublicKey)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got < caLifetime {
		t.Errorf("lifetime is %v, want at least %v", got, caLifetime)
	}
}

func TestLoadReturnsTheSameAuthority(t *testing.T) {
	dir := t.TempDir()
	made, err := Create(dir, "", mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if made.Fingerprint() != loaded.Fingerprint() {
		t.Errorf("fingerprint changed across a restart: %s then %s",
			made.Fingerprint()[:16], loaded.Fingerprint()[:16])
	}
	// The loaded key must actually sign: a CA that loads but cannot issue
	// would fail at the first enrolment rather than at startup.
	req := testRequest(t, "laptop", "")
	if _, err := loaded.Issue(req, testFP, time.Now(), time.Hour); err != nil {
		t.Fatalf("Issue with the loaded key: %v", err)
	}
}

func TestOpenCreatesThenReuses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clientca")
	first, err := Open(dir, "", mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	second, err := Open(dir, "", mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Error("Open created a second authority instead of reusing the first")
	}
}

func TestLoadRefusesAKeyOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "", mldsa.MLDSA65()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := filepath.Join(dir, keyFile)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("a group-readable CA key was accepted")
	}
	// The operator has to fix this, so the message carries both the path and
	// the mode they must change.
	for _, want := range []string{path, "0640", "must not be readable by group or others"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestLoadRefusesDamagedFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		file    string
		content string
		want    string
	}{
		{"empty key", keyFile, "", "holds no PEM block"},
		{"key is not PEM", keyFile, "not a certificate", "holds no PEM block"},
		{"key is a certificate", keyFile, "", "block"},
		{"truncated key", keyFile, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", ""},
		{"empty certificate", certFile, "", "holds no PEM block"},
		{"two certificates", certFile, "", "more than one PEM block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Create(dir, "", mldsa.MLDSA65()); err != nil {
				t.Fatalf("Create: %v", err)
			}
			path := filepath.Join(dir, tc.file)
			content := tc.content
			switch tc.name {
			case "key is a certificate":
				raw, err := os.ReadFile(filepath.Join(dir, certFile))
				if err != nil {
					t.Fatal(err)
				}
				content = string(raw)
			case "two certificates":
				raw, err := os.ReadFile(filepath.Join(dir, certFile))
				if err != nil {
					t.Fatal(err)
				}
				content = string(raw) + string(raw)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(dir)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), dir) {
				t.Errorf("error %q does not name the file it is about", err)
			}
		})
	}
}

func TestLoadRefusesAKeyThatIsNotTheCertificates(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	if _, err := Create(dir, "", mldsa.MLDSA65()); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(other, "", mldsa.MLDSA65()); err != nil {
		t.Fatal(err)
	}
	// A restore that took the key from one backup and the certificate from
	// another. Every certificate the relay issued would fail to verify.
	raw, err := os.ReadFile(filepath.Join(other, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(dir)
	if err == nil {
		t.Fatal("a mismatched key and certificate were accepted")
	}
	if !strings.Contains(err.Error(), "does not match the key beside it") {
		t.Errorf("error %q does not say what is wrong", err)
	}
}

func TestLoadReportsAMissingAuthorityAsNotExist(t *testing.T) {
	// Open depends on this: anything else must not be mistaken for "there is
	// no CA here yet" and quietly overwritten.
	_, err := Load(t.TempDir())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load of an empty directory: %v, want fs.ErrNotExist", err)
	}
}

func TestCreateRefusesToOverwriteAnAuthority(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "", mldsa.MLDSA65()); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, "", mldsa.MLDSA65()); err == nil {
		t.Fatal("Create overwrote an existing authority")
	}
}

func TestPoolHoldsOnlyThisAuthority(t *testing.T) {
	ca, other := testCA(t), testCA(t)
	if len(ca.Pool().Subjects()) != 1 { //nolint:staticcheck // the count is the point
		t.Errorf("pool holds %d subjects, want 1", len(ca.Pool().Subjects())) //nolint:staticcheck
	}
	leaf := issueFor(t, other, testFP)
	if err := ca.Verify(leaf, time.Now()); err == nil {
		t.Error("one authority's pool accepted another's certificate")
	}
}
