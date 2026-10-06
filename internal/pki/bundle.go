package pki

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// BundleVersion is the shape a relay understands. A newer one is refused by
// name rather than half-read.
const BundleVersion = 1

// Bundle is everything one relay is given, and nothing more: its own signing
// intermediates with their keys, the public certificates needed to complete a
// chain to the anchor, and the anchor itself.
//
// What is deliberately absent, and asserted absent by a test that searches the
// encoded file for their bytes: the anchor's key, either offline authority's
// key, and the key of any intermediate this relay has retired. A relay's disk
// is enough to be that relay and to issue client certificates, and never
// enough to extend trust.
type Bundle struct {
	V int `json:"v"`

	// TrustAnchor is the root, public. TrustAnchorSPKI is what an enrolment
	// token carries and a client pins.
	TrustAnchor     []byte `json:"trust_anchor"`
	TrustAnchorSPKI string `json:"trust_anchor_spki"`

	// Hosts are the names and addresses this relay answers to, and the names
	// its server intermediate is constrained to.
	Hosts []string `json:"hosts"`

	// ServerChain is the Server CA. A retired server intermediate is carried
	// nowhere: the only thing that ever needed it was this relay, and it has
	// a new one.
	ServerChain   [][]byte `json:"server_chain"`
	ServerIntCert []byte   `json:"server_int_cert"`
	ServerIntKey  []byte   `json:"server_int_key"`

	// ClientChain is the Client CA followed by the certificate of every
	// client intermediate previously issued for this relay, so certificates
	// issued before a rotation still verify. Never a key.
	ClientChain   [][]byte `json:"client_chain"`
	ClientIntCert []byte   `json:"client_int_cert"`
	ClientIntKey  []byte   `json:"client_int_key"`

	Issued time.Time `json:"issued"`
}

// Loaded is a bundle with everything parsed and checked, which is the only
// form the relay uses.
type Loaded struct {
	Anchor     *x509.Certificate
	AnchorSPKI string
	Hosts      []string

	// ServerInt signs this relay's own leaf. ServerChain completes it.
	ServerInt   *Key
	ServerChain []*x509.Certificate

	// ClientInt issues client certificates. ClientChain is the Client CA and
	// any retired intermediates; ClientPool is those plus the current one,
	// which is every certificate a client's leaf may chain through.
	ClientInt   *Key
	ClientChain []*x509.Certificate
	ClientPool  []*x509.Certificate

	// Params is the ML-DSA parameter set of this hierarchy, and so of every
	// client key the relay will accept.
	Params mldsa.Parameters

	Issued time.Time
}

// EncodeBundle is the bytes WriteBundle writes, for a caller that is
// sending them somewhere other than a file.
func EncodeBundle(b *Bundle) ([]byte, error) {
	return marshalIndent(b)
}

// WriteBundle writes a bundle atomically, readable only by its owner. It is
// EncodeBundle and a file, so the two cannot drift.
func WriteBundle(path string, b *Bundle) error {
	data, err := EncodeBundle(b)
	if err != nil {
		return err
	}
	return writeFile(path, data, 0o600)
}

// LoadBundle reads a bundle and checks everything a relay depends on, so that
// a bad one fails at startup with the path in the message rather than at the
// first handshake.
func LoadBundle(path string) (*Loaded, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := unmarshalStrict(raw, &b); err != nil {
		// A bundle that stops early was cut in delivery — a copy that did
		// not finish, a truncated credential — and Go's word for it says
		// nothing about what to do.
		if cutShort(err) {
			return nil, fmt.Errorf("%s: the bundle is cut short (%v): deliver it again", path, err)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.V != BundleVersion {
		return nil, fmt.Errorf("%s: bundle version %d, but this build understands %d; "+
			"it was written by a different release of auu-ca", path, b.V, BundleVersion)
	}
	l, err := b.load(time.Now())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

func (b *Bundle) load(now time.Time) (*Loaded, error) {
	anchor, err := x509.ParseCertificate(b.TrustAnchor)
	if err != nil {
		return nil, fmt.Errorf("trust anchor: %w", err)
	}
	if got := SPKI(anchor); got != b.TrustAnchorSPKI {
		return nil, fmt.Errorf("trust_anchor_spki is %s but the anchor's key hashes to %s",
			b.TrustAnchorSPKI, got)
	}
	if len(b.Hosts) == 0 {
		return nil, errors.New("no hosts")
	}
	serverChain, err := parseAll(b.ServerChain, "server_chain")
	if err != nil {
		return nil, err
	}
	clientChain, err := parseAll(b.ClientChain, "client_chain")
	if err != nil {
		return nil, err
	}
	serverInt, err := loadKey(b.ServerIntCert, b.ServerIntKey, "server signing intermediate")
	if err != nil {
		return nil, err
	}
	clientInt, err := loadKey(b.ClientIntCert, b.ClientIntKey, "client signing intermediate")
	if err != nil {
		return nil, err
	}

	// A retired intermediate that has expired verifies nothing: every leaf
	// it issued was clamped to its own expiry. Carrying it would only make
	// the bundle refuse to load on the day it expired, which is how a
	// relay that had run for a year would fail to restart.
	live := clientChain[:0:0]
	for i, c := range clientChain {
		if i > 0 && now.After(c.NotAfter) {
			continue
		}
		live = append(live, c)
	}
	l := &Loaded{
		Anchor: anchor, AnchorSPKI: b.TrustAnchorSPKI, Hosts: b.Hosts,
		ServerInt: serverInt, ServerChain: serverChain,
		ClientInt:   clientInt,
		ClientChain: live,
		ClientPool:  append([]*x509.Certificate{clientInt.Cert}, live...),
		Params:      serverInt.Key.PublicKey().Parameters(),
		Issued:      b.Issued,
	}
	if err := l.check(now); err != nil {
		return nil, err
	}
	return l, nil
}

// check applies every rule the relay depends on: each intermediate is a
// constrained CA that chains to the anchor for its own purpose, the server
// intermediate may sign for every host this relay answers to, and nothing has
// expired.
func (l *Loaded) check(now time.Time) error {
	for _, tc := range []struct {
		name string
		key  *Key
		eku  x509.ExtKeyUsage
		pool []*x509.Certificate
	}{
		{"server signing intermediate", l.ServerInt, x509.ExtKeyUsageServerAuth, l.ServerChain},
		{"client signing intermediate", l.ClientInt, x509.ExtKeyUsageClientAuth, l.ClientChain},
	} {
		if !tc.key.Cert.IsCA || !tc.key.Cert.BasicConstraintsValid {
			return fmt.Errorf("%s is not a certificate authority", tc.name)
		}
		if !tc.key.Cert.MaxPathLenZero {
			return fmt.Errorf("%s may issue a further authority; it must not", tc.name)
		}
		if !hasEKU(tc.key.Cert, tc.eku) {
			return fmt.Errorf("%s is not restricted to its purpose", tc.name)
		}
		if now.After(tc.key.Cert.NotAfter) {
			return fmt.Errorf("%s expired on %s: run 'auu-ca relay' again",
				tc.name, tc.key.Cert.NotAfter.Format(time.DateOnly))
		}
		if err := chainsTo(tc.key.Cert, l.Anchor, tc.pool, tc.eku, now); err != nil {
			return fmt.Errorf("%s does not chain to the trust anchor: %w", tc.name, err)
		}
	}
	// Every retired client intermediate must chain too, or a certificate it
	// issued would fail in a way that looked like the client's fault.
	for _, c := range l.ClientPool {
		if c.Equal(l.ClientInt.Cert) {
			continue
		}
		if err := chainsTo(c, l.Anchor, l.ClientChain, x509.ExtKeyUsageClientAuth, now); err != nil {
			return fmt.Errorf("a certificate in client_chain does not chain to the trust anchor: %w", err)
		}
	}
	// The server intermediate must be permitted to sign for every host, or
	// the relay would mint itself a leaf that no client could verify.
	if err := l.coversHosts(now); err != nil {
		return err
	}
	if ParameterNumberOf(l.ClientInt.Key.PublicKey().Parameters()) !=
		ParameterNumberOf(l.Params) {
		return errors.New("the two signing intermediates are at different ML-DSA parameter sets")
	}
	return nil
}

// coversHosts checks the server intermediate's name constraints against the
// hosts, by minting a throwaway leaf and verifying it — which asks the same
// verifier the client will, rather than reimplementing its rules.
func (l *Loaded) coversHosts(now time.Time) error {
	leaf, err := ServerLeaf(l.ServerInt, l.Hosts, l.Params, now)
	if err != nil {
		return fmt.Errorf("the server signing intermediate cannot sign for %v: %w", l.Hosts, err)
	}
	for _, h := range l.Hosts {
		opts := x509.VerifyOptions{
			Roots:         poolOf(l.Anchor),
			Intermediates: poolOf(append([]*x509.Certificate{l.ServerInt.Cert}, l.ServerChain...)...),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSName:       h,
			CurrentTime:   now,
		}
		if ip := parseIPHost(h); ip != "" {
			opts.DNSName = ip
		}
		if _, err := leaf.Cert.Verify(opts); err != nil {
			return fmt.Errorf("the server signing intermediate is not permitted to sign for %q: %w", h, err)
		}
	}
	return nil
}

func loadKey(certDER, keyDER []byte, what string) (*Key, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("%s key: %w", what, err)
	}
	key, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s key is %T, not ML-DSA", what, parsed)
	}
	pub, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok || !pub.Equal(key.PublicKey()) {
		return nil, fmt.Errorf("%s key does not match its certificate", what)
	}
	return &Key{Cert: cert, Key: key}, nil
}

func parseAll(ders [][]byte, what string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", what, i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func hasEKU(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, e := range c.ExtKeyUsage {
		if e == want {
			return true
		}
	}
	return false
}

func chainsTo(cert, anchor *x509.Certificate, inter []*x509.Certificate,
	eku x509.ExtKeyUsage, now time.Time) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         poolOf(anchor),
		Intermediates: poolOf(inter...),
		KeyUsages:     []x509.ExtKeyUsage{eku},
		CurrentTime:   now,
	})
	return err
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		if c != nil {
			p.AddCert(c)
		}
	}
	return p
}

// writeFile writes atomically: a temporary file beside the target, synced,
// renamed, and the directory synced.
func writeFile(path string, data []byte, mode os.FileMode) error {
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
	return syncDir(dir)
}

// syncDir flushes a directory entry, so that a rename into it survives a
// power cut as well as the file's own contents do.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		// No directory fsync there; NTFS journals the metadata itself.
		return nil
	}
	// Opened by the handle: what is synced is the directory, and a link
	// planted under its name is refused rather than followed.
	d, err := regular.Dir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// marshalIndent and unmarshalStrict are the one JSON style this package uses:
// indented out, strict in.
func marshalIndent(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// cutShort reports a decode that ran out of input: io.ErrUnexpectedEOF from
// the Decoder, or io.EOF from one given nothing at all.
func cutShort(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

func unmarshalStrict(raw []byte, v any) error {
	err := wire.Decode(raw, v)
	if errors.Is(err, wire.ErrTrailing) {
		return errors.New("trailing data after the object")
	}
	return err
}
