// Package clientca issues and verifies the client certificates a relay uses
// to tell one enrolled machine from another.
//
// The keys are ML-DSA, from crypto/mldsa: pure ML-DSA as specified in FIPS
// 204, which crypto/x509 and crypto/tls understand from Go 1.27 and which TLS
// negotiates only at 1.3. The parameter set — 44, 65 or 87 — is the relay
// operator's choice, made once when the authority is created, and every key
// the authority signs must match it: one security level throughout. The
// default is 65, the level-3 partner of the ML-KEM-768 inside the X-Wing KEM
// the messages themselves use.
//
// A client certificate is a second credential, not a replacement for the
// request signature. It proves the connection comes from a machine the relay
// issued to; the X-CCX-Auth signature still proves which identity is asking.
// Both are required, and the relay checks that they name the same identity.
package clientca

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	keyFile  = "ca.key"
	certFile = "ca.pem"

	keyFileMode  fs.FileMode = 0o600
	certFileMode fs.FileMode = 0o644
	dirMode      fs.FileMode = 0o700

	// caLifetime is how long a certificate authority lives. Rotating one
	// means re-enrolling every machine, so it outlives any leaf by a wide
	// margin and the relay warns from a year out.
	caLifetime = 10 * 365 * 24 * time.Hour

	// caSubjectCN names the authority in every certificate it signs.
	caSubjectCN = "AgentUUCP client CA"

	// uniqueBytes is the random component of the CA's subject. A TLS server
	// advertises its client CAs by subject, and a client offers a
	// certificate only when its issuer is on that list, so two relays whose
	// CAs shared a subject would each invite the other's certificates.
	uniqueBytes = 8
)

// CA is a certificate authority for client certificates: its key, its
// self-signed certificate, and the directory both live in.
type CA struct {
	cert   *x509.Certificate
	key    *mldsa.PrivateKey
	params mldsa.Parameters
	fp     string
	pool   *x509.CertPool
	dir    string
}

// DefaultMLDSA is the parameter set used when an operator does not choose.
const DefaultMLDSA = 65

// ParameterSet returns the ML-DSA parameter set numbered n: 44, 65 or 87.
func ParameterSet(n int) (mldsa.Parameters, error) {
	switch n {
	case 44:
		return mldsa.MLDSA44(), nil
	case 65:
		return mldsa.MLDSA65(), nil
	case 87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, fmt.Errorf("ML-DSA parameter set must be 44, 65 or 87, got %d", n)
	}
}

// ParameterNumber is the inverse of ParameterSet, for configuration and the
// wire. It is zero for a value no set produced.
func ParameterNumber(p mldsa.Parameters) int {
	switch p {
	case mldsa.MLDSA44():
		return 44
	case mldsa.MLDSA65():
		return 65
	case mldsa.MLDSA87():
		return 87
	default:
		return 0
	}
}

// Open loads the authority in dir, creating it under params if it is not
// there yet. An authority that is there is loaded whatever its parameter set;
// the caller decides whether that is the one it wanted.
//
// host, when not empty, is the relay's public host name, recorded in the
// subject so an operator reading a certificate can tell whose it is.
func Open(dir, host string, params mldsa.Parameters) (*CA, error) {
	ca, err := Load(dir)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return Create(dir, host, params)
}

// Create generates an authority under params and writes it to dir, which must
// not already hold one.
func Create(dir, host string, params mldsa.Parameters) (*CA, error) {
	if ParameterNumber(params) == 0 {
		return nil, errors.New("clientca: no ML-DSA parameter set")
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("client CA directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err == nil {
		return nil, fmt.Errorf("client CA already exists in %s", dir)
	}

	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, fmt.Errorf("generating client CA key: %w", err)
	}
	unique := make([]byte, uniqueBytes)
	if _, err := rand.Read(unique); err != nil {
		return nil, err
	}
	now := time.Now()
	subject := pkix.Name{
		CommonName:         caSubjectCN,
		OrganizationalUnit: []string{hex.EncodeToString(unique)},
	}
	if h := hostOf(host); h != "" {
		subject.Organization = []string{h}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		// CertSign only. There are no revocation lists to sign: a
		// certificate is revoked by a row in the relay's database, which
		// every request already consults.
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return nil, fmt.Errorf("signing client CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	// The key first: a certificate without its key is the state Load
	// reports, and a key without its certificate is the state Create is
	// about to leave anyway.
	if err := writeFile(filepath.Join(dir, keyFile),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), keyFileMode); err != nil {
		return nil, fmt.Errorf("writing client CA key: %w", err)
	}
	if err := writeFile(filepath.Join(dir, certFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certFileMode); err != nil {
		return nil, fmt.Errorf("writing client CA certificate: %w", err)
	}
	return newCA(cert, key, dir), nil
}

// Load reads the authority in dir. A missing one wraps fs.ErrNotExist, which
// is what Open tests for.
func Load(dir string) (*CA, error) {
	keyPath := filepath.Join(dir, keyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	// The one file in this project that signs on the relay's behalf.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("client CA key %s is mode %04o: it must not be readable by group or others",
			keyPath, perm)
	}
	key, err := readPEM(keyPath, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("client CA key %s: %w", keyPath, err)
	}
	mk, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("client CA key %s is %T, not ML-DSA", keyPath, parsed)
	}
	if ParameterNumber(mk.PublicKey().Parameters()) == 0 {
		return nil, fmt.Errorf("client CA key %s is %s, which this build does not know",
			keyPath, mk.PublicKey().Parameters())
	}

	certPath := filepath.Join(dir, certFile)
	certDER, err := readPEM(certPath, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("client CA certificate %s: %w", certPath, err)
	}
	pub, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok || !pub.Equal(mk.PublicKey()) {
		return nil, fmt.Errorf("client CA certificate %s does not match the key beside it", certPath)
	}
	return newCA(cert, mk, dir), nil
}

func newCA(cert *x509.Certificate, key *mldsa.PrivateKey, dir string) *CA {
	sum := sha256.Sum256(cert.Raw)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{
		cert: cert, key: key, params: key.PublicKey().Parameters(),
		fp: hex.EncodeToString(sum[:]), pool: pool, dir: dir,
	}
}

// Parameters is the ML-DSA parameter set this authority uses, and requires
// of every client key it signs.
func (c *CA) Parameters() mldsa.Parameters { return c.params }

// Certificate is the authority's own certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// DER is the authority's certificate, for handing to a client.
func (c *CA) DER() []byte { return c.cert.Raw }

// Fingerprint is the SHA-256 of the CA certificate, lowercase hex. It is what
// the relay logs at startup and what auu cert status shows.
func (c *CA) Fingerprint() string { return c.fp }

// NotAfter is when the authority itself expires.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Dir is where the authority is stored.
func (c *CA) Dir() string { return c.dir }

// Pool holds this authority and nothing else.
func (c *CA) Pool() *x509.CertPool { return c.pool }

// TLSConfig makes cfg require TLS 1.3 and verify any client certificate
// offered against this authority.
//
// VerifyClientCertIfGiven rather than RequireAndVerifyClientCert: a machine
// that has not enrolled yet has no certificate and must still be able to
// reach POST /v1/register. Which routes need one is the relay's decision, not
// the handshake's.
func (c *CA) TLSConfig(cfg *tls.Config) *tls.Config {
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	cfg.ClientCAs = c.pool
	// ML-DSA certificates require TLS 1.3, and 1.3 is also the first version
	// to encrypt the client's certificate rather than send it in the clear.
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}

// hostOf reduces a relay's public URL to its host name.
func hostOf(publicURL string) string {
	if publicURL == "" {
		return ""
	}
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// readPEM reads exactly one PEM block of the given type.
func readPEM(path, want string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	if block.Type != want {
		return nil, fmt.Errorf("%s holds a %q block, want %q", path, block.Type, want)
	}
	if len(pem.EncodeToMemory(block)) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	if b, _ := pem.Decode(rest); b != nil {
		return nil, fmt.Errorf("%s holds more than one PEM block", path)
	}
	return block.Bytes, nil
}

// writeFile writes atomically: a temporary file beside the target, synced,
// then renamed, then the directory synced. A relay that is killed mid-write
// finds either the old file or the new one.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
