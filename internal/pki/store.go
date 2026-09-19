package pki

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// File names in an auu-ca directory. Three key pairs, and a directory of what
// has been issued to each relay.
const (
	anchorKeyFile   = "ta.key"
	anchorCertFile  = "ta.pem"
	serverKeyFile   = "server-ca.key"
	serverCertFile  = "server-ca.pem"
	clientKeyFile   = "client-ca.key"
	clientCertFile  = "client-ca.pem"
	relaysDir       = "relays"
	dirMode         = 0o700
	keyMode         = 0o600
	relayRecordFile = "issued.json"
)

// Store is an auu-ca directory: the offline half of the hierarchy.
//
// Every key in it is one a relay never sees. It is the reason auu-ca is a
// separate binary — a machine that has this directory is not a machine that
// answers connections. Every key file is encrypted under a passphrase, so a
// backup or a stolen disk yields certificates and nothing else.
//
// A store opened with OpenLocked has its certificates and no private key at
// all: each Key's Key field is nil. That is what show wants, and it is why
// printing what an authority holds never asks for a passphrase.
type Store struct {
	dir       string
	Anchor    *Key
	Server    *Key
	Client    *Key
	Params    mldsa.Parameters
	encrypted bool
	locked    bool
}

// Dir is where this store lives.
func (s *Store) Dir() string { return s.dir }

// Encrypted says whether the key files are under a passphrase. It is false
// only for a directory made before encryption existed.
func (s *Store) Encrypted() bool { return s.encrypted }

// Locked says whether this store was opened without its passphrase, and so
// holds no private key and can issue nothing.
func (s *Store) Locked() bool { return s.locked }

// Create generates a whole hierarchy in dir, which must not already hold one,
// and writes every private key encrypted under pass.
func Create(dir, name string, params mldsa.Parameters, pass keyfile.Passphrase, now time.Time) (*Store, error) {
	if len(pass.Secret) == 0 {
		return nil, keyfile.ErrEmptyPassphrase
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("a name is required: it appears in every certificate this issues")
	}
	if ParameterNumberOf(params) == 0 {
		return nil, errors.New("no ML-DSA parameter set")
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, err
	}
	// Only an empty directory, checked before anything is changed: a
	// mistyped --dir must not have its mode tightened and a PKI written
	// among whatever it holds.
	if entries, err := os.ReadDir(dir); err != nil {
		return nil, err
	} else if len(entries) > 0 {
		if _, err := os.Stat(filepath.Join(dir, anchorKeyFile)); err == nil {
			return nil, fmt.Errorf("%s already holds a trust anchor; "+
				"a second one would be a different PKI, so remove it deliberately if that is what you want", dir)
		}
		return nil, fmt.Errorf("%s is not empty; an authority is created in an empty directory", dir)
	}
	// MkdirAll leaves an existing directory's mode alone, and this one is
	// about to hold the keys the whole PKI rests on.
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("securing %s: %w", dir, err)
	}
	anchor, err := Anchor(name, params, now)
	if err != nil {
		return nil, err
	}
	server, err := Authority(anchor, name, x509.ExtKeyUsageServerAuth, params, now)
	if err != nil {
		return nil, err
	}
	client, err := Authority(anchor, name, x509.ExtKeyUsageClientAuth, params, now)
	if err != nil {
		return nil, err
	}
	for _, w := range []struct {
		keyFile, certFile string
		k                 *Key
	}{
		{anchorKeyFile, anchorCertFile, anchor},
		{serverKeyFile, serverCertFile, server},
		{clientKeyFile, clientCertFile, client},
	} {
		if err := writeKey(filepath.Join(dir, w.keyFile), w.k.Key, pass); err != nil {
			return nil, err
		}
		if err := writeCert(filepath.Join(dir, w.certFile), w.k.Cert); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, relaysDir), dirMode); err != nil {
		return nil, err
	}
	return &Store{dir: dir, Anchor: anchor, Server: server, Client: client,
		Params: params, encrypted: true}, nil
}

// keyPairs is every private key in a store, and the certificate that goes
// with each. The order is the one an error should name them in.
func keyPairs() []struct{ keyFile, certFile string } {
	return []struct{ keyFile, certFile string }{
		{anchorKeyFile, anchorCertFile},
		{serverKeyFile, serverCertFile},
		{clientKeyFile, clientCertFile},
	}
}

// Open loads an existing hierarchy and unlocks its private keys with secret,
// refusing a directory other people can read: it holds the keys everything
// else depends on.
//
// A directory from before key files were encrypted opens with any secret,
// including none, so that auu-ca keeps working on one and can be pointed at
// the command that encrypts it.
func Open(dir string, secret []byte) (*Store, error) {
	return open(dir, secret, false)
}

// OpenLocked loads the certificates and no private key, so that a command
// which only reads what an authority holds never asks for a passphrase.
// Every Key's Key field is nil and the store issues nothing.
func OpenLocked(dir string) (*Store, error) { return open(dir, nil, true) }

func open(dir string, secret []byte, locked bool) (*Store, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o: it holds the keys this whole PKI rests on "+
			"and must not be readable by group or others", dir, perm)
	}
	s := &Store{dir: dir, locked: locked}
	into := []**Key{&s.Anchor, &s.Server, &s.Client}
	var encrypted, plain []string
	for i, l := range keyPairs() {
		k, wasEncrypted, err := readKey(filepath.Join(dir, l.keyFile), filepath.Join(dir, l.certFile),
			secret, locked)
		if err != nil {
			return nil, err
		}
		if wasEncrypted {
			encrypted = append(encrypted, l.keyFile)
		} else {
			plain = append(plain, l.keyFile)
		}
		*into[i] = k
	}
	// A store half-way through a passphrase change: three renames, and the
	// power went off between two of them. Say which files are which way,
	// because the fix is to run the command again and the operator needs to
	// know which passphrase it will want.
	if len(encrypted) > 0 && len(plain) > 0 {
		return nil, fmt.Errorf("%s is part encrypted and part not: %s %s encrypted, %s %s not. "+
			"A passphrase change was interrupted; run 'auu-ca passphrase' again to finish it",
			dir, strings.Join(encrypted, " and "), were(len(encrypted)),
			strings.Join(plain, " and "), were(len(plain)))
	}
	s.encrypted = len(encrypted) > 0
	// From the certificate, not the key: a locked store has no key and the
	// parameter set is a fact about the public half either way.
	pub, ok := s.Anchor.Cert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: the trust anchor's key is %T, not ML-DSA", dir, s.Anchor.Cert.PublicKey)
	}
	s.Params = pub.Parameters()
	if ParameterNumberOf(s.Params) == 0 {
		return nil, fmt.Errorf("%s: the trust anchor is %s, which this build does not know",
			dir, s.Params)
	}
	return s, nil
}

func were(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// SetPassphrase rewrites every key file under pass. It is how a directory
// from before encryption is encrypted, and how a passphrase is changed.
//
// All three files are written beside their targets and only then renamed, so
// the window in which a crash could leave the directory half-converted is
// three renames wide and has no I/O in it. Open reports that state precisely
// if it ever happens, and running this again fixes it.
func SetPassphrase(dir string, oldSecret []byte, pass keyfile.Passphrase) error {
	if len(pass.Secret) == 0 {
		return keyfile.ErrEmptyPassphrase
	}
	s, err := Open(dir, oldSecret)
	if err != nil {
		return err
	}
	keys := []*mldsa.PrivateKey{s.Anchor.Key, s.Server.Key, s.Client.Key}
	staged := make([]string, 0, len(keys))
	defer func() {
		for _, tmp := range staged {
			os.Remove(tmp)
		}
	}()
	for i, l := range keyPairs() {
		tmp := filepath.Join(dir, l.keyFile+".new")
		if err := writeKey(tmp, keys[i], pass); err != nil {
			return err
		}
		staged = append(staged, tmp)
	}
	for i, l := range keyPairs() {
		if err := os.Rename(staged[i], filepath.Join(dir, l.keyFile)); err != nil {
			return err
		}
	}
	staged = nil
	return syncDir(dir)
}

// RelayRecord is what a store remembers about one relay it has issued to: the
// certificates of every client intermediate, so a rotation can keep verifying
// what the retired one signed.
type RelayRecord struct {
	Hosts []string `json:"hosts"`
	// ClientInts are the certificates of every client signing intermediate
	// issued for this relay, oldest first. Keys are never kept here: a
	// retired one has no use and every copy of it is a liability.
	ClientInts [][]byte  `json:"client_intermediates"`
	Updated    time.Time `json:"updated"`
	// BundlePath is the absolute path the last bundle for this relay was
	// written to, and empty when it went to standard output. show uses it to
	// notice a bundle still lying on the machine that made it. A record from
	// before the field existed has none, which means unknown.
	BundlePath string `json:"bundle_path"`
}

// IssueRelay makes a bundle for one relay, and records what it issued.
//
// Called again for the same host it is the rotation: two fresh intermediates,
// the previous client intermediate's certificate carried forward so its
// leaves still verify, and no retired key anywhere in the output.
func (s *Store) IssueRelay(hosts []string, years int, now time.Time) (*Bundle, error) {
	if s.locked {
		return nil, errors.New("this authority was opened without its passphrase, so it can issue nothing")
	}
	if len(hosts) == 0 {
		return nil, errors.New("at least one --host is required")
	}
	if years < 1 {
		return nil, fmt.Errorf("--years must be at least 1, got %d", years)
	}
	// An intermediate cannot outlive its issuer, and one that was quietly
	// cut short would expire on a date nobody planned for, so more years
	// than the authorities have left is refused with the most they allow,
	// not clamped with a warning a script's output loses.
	if err := yearsFit(years, now, s.Server.Cert.NotAfter, s.Client.Cert.NotAfter); err != nil {
		return nil, err
	}
	name := commonName(s.Anchor.Cert)

	serverInt, err := Intermediate(s.Server, name, x509.ExtKeyUsageServerAuth, hosts, years, s.Params, now)
	if err != nil {
		return nil, err
	}
	clientInt, err := Intermediate(s.Client, name, x509.ExtKeyUsageClientAuth, hosts, years, s.Params, now)
	if err != nil {
		return nil, err
	}

	key, rec, err := s.FindRecord(hosts)
	if err != nil {
		return nil, err
	}
	// A retired intermediate that has expired verifies nothing and is
	// dropped, so the bundle does not grow by one certificate a year.
	rec.ClientInts, err = unexpired(rec.ClientInts, now)
	if err != nil {
		return nil, err
	}
	// The Client CA first, then every retired intermediate. The current one
	// is not in the chain: it is carried on its own.
	chain := [][]byte{s.Client.Cert.Raw}
	chain = append(chain, rec.ClientInts...)

	b := &Bundle{
		V:               BundleVersion,
		TrustAnchor:     s.Anchor.Cert.Raw,
		TrustAnchorSPKI: SPKI(s.Anchor.Cert),
		Hosts:           hosts,
		ServerChain:     [][]byte{s.Server.Cert.Raw},
		ServerIntCert:   serverInt.Cert.Raw,
		ServerIntKey:    mustPKCS8(serverInt.Key),
		ClientChain:     chain,
		ClientIntCert:   clientInt.Cert.Raw,
		ClientIntKey:    mustPKCS8(clientInt.Key),
		Issued:          now.UTC().Truncate(time.Second),
	}
	// Checked before it is written, with the same code the relay will use,
	// so a bundle that would not load never reaches a relay host.
	if _, err := b.load(now); err != nil {
		return nil, fmt.Errorf("the bundle this would write does not verify: %w", err)
	}

	rec.Hosts = hosts
	rec.ClientInts = append(rec.ClientInts, clientInt.Cert.Raw)
	rec.Updated = now.UTC().Truncate(time.Second)
	if err := s.saveRelayRecord(key, rec); err != nil {
		return nil, err
	}
	return b, nil
}

// RecordBundlePath remembers where a bundle for hosts was written, or that
// it went to standard output when path is empty. IssueRelay cannot know,
// because it hands the bundle back for the caller to write.
//
// The relay is found by any of its hosts, as a rotation is. A path is kept
// only for a relay something has been issued to: a record with no
// intermediate in it would be an issuance that never happened.
func (s *Store) RecordBundlePath(hosts []string, path string) error {
	if len(hosts) == 0 {
		return errors.New("at least one host is required")
	}
	if path != "" && !filepath.IsAbs(path) {
		return fmt.Errorf("bundle path %q is not absolute", path)
	}
	key, rec, err := s.FindRecord(hosts)
	if err != nil {
		return err
	}
	if len(rec.ClientInts) == 0 {
		return fmt.Errorf("no bundle has been issued for %s", strings.Join(hosts, ", "))
	}
	rec.BundlePath = path
	return s.saveRelayRecord(key, rec)
}

// Relays lists the hosts this store has issued to.
func (s *Store) Relays() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, relaysDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Record returns what was issued to one host.
func (s *Store) Record(host string) (*RelayRecord, error) { return s.relayRecord(host) }

// FindRecord finds the record for a relay by any of its hosts, and the name
// it is filed under. The first host names the record, but a rotation that
// lists the same hosts in another order is the same relay, and treating it as
// a new one would drop the retired intermediate and break every certificate
// it issued.
func (s *Store) FindRecord(hosts []string) (string, *RelayRecord, error) {
	known, err := s.Relays()
	if err != nil {
		return "", nil, err
	}
	for _, k := range known {
		rec, err := s.relayRecord(k)
		if err != nil {
			return "", nil, err
		}
		for _, have := range rec.Hosts {
			for _, want := range hosts {
				if have == want {
					return k, rec, nil
				}
			}
		}
	}
	return hosts[0], &RelayRecord{}, nil
}

// unexpired keeps the certificates still valid at now.
func unexpired(ders [][]byte, now time.Time) ([][]byte, error) {
	out := ders[:0:0]
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("a recorded intermediate does not parse: %w", err)
		}
		if now.After(c.NotAfter) {
			continue
		}
		out = append(out, der)
	}
	return out, nil
}

func (s *Store) relayRecord(host string) (*RelayRecord, error) {
	path := filepath.Join(s.dir, relaysDir, safeHost(host), relayRecordFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &RelayRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var rec RelayRecord
	if err := unmarshalStrict(raw, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rec, nil
}

func (s *Store) saveRelayRecord(host string, rec *RelayRecord) error {
	dir := filepath.Join(s.dir, relaysDir, safeHost(host))
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	data, err := marshalIndent(rec)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, relayRecordFile), data, keyMode)
}

// safeHost makes a host name into one path segment. A host has already been
// validated as a DNS name or an address by the time it gets here; this is
// belt and braces so nothing from a command line becomes a path.
func safeHost(h string) string {
	out := make([]byte, 0, len(h))
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '-':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 || out[0] == '.' {
		return "_" + string(out)
	}
	return string(out)
}

func commonName(c *x509.Certificate) string {
	return strings.TrimSuffix(c.Subject.CommonName, " Trust Anchor")
}

func writeKey(path string, key *mldsa.PrivateKey, pass keyfile.Passphrase) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	encoded, err := keyfile.Encrypt(der, pass)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return writeFile(path, encoded, keyMode)
}

func writeCert(path string, cert *x509.Certificate) error {
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), keyMode)
}

// readKey reads one key file and the certificate that goes with it, and says
// whether the key file was encrypted.
//
// With locked set the key file is opened only far enough to learn that, and
// the Key comes back holding the certificate alone.
func readKey(keyPath, certPath string, secret []byte, locked bool) (*Key, bool, error) {
	key, encrypted, err := readPrivateKey(keyPath, secret, locked)
	if err != nil {
		return nil, false, err
	}
	certDER, err := readPEM(certPath, "CERTIFICATE")
	if err != nil {
		return nil, false, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", certPath, err)
	}
	pub, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, false, fmt.Errorf("%s is %T, not ML-DSA", certPath, cert.PublicKey)
	}
	if key != nil && !pub.Equal(key.PublicKey()) {
		return nil, false, fmt.Errorf("%s does not match the key in %s", certPath, keyPath)
	}
	return &Key{Cert: cert, Key: key}, encrypted, nil
}

// readPrivateKey reads a key file, decrypting it when it is encrypted. It
// returns a nil key when locked is set and the file is encrypted, which is
// the only case in which a store carries a certificate and no key.
func readPrivateKey(path string, secret []byte, locked bool) (*mldsa.PrivateKey, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, false, fmt.Errorf("%s holds no PEM block", path)
	}
	if b, _ := pem.Decode(rest); b != nil {
		return nil, false, fmt.Errorf("%s holds more than one PEM block", path)
	}
	var der []byte
	encrypted := block.Type == keyfile.BlockType
	switch {
	case encrypted && locked:
		return nil, true, nil
	case encrypted:
		if len(secret) == 0 {
			return nil, true, fmt.Errorf("%s is encrypted: a passphrase is required", path)
		}
		if der, err = keyfile.DecryptBlock(block, secret); err != nil {
			return nil, true, fmt.Errorf("%s: %w", path, err)
		}
	case block.Type == "PRIVATE KEY":
		// A directory from before key files were encrypted. It still
		// works; auu-ca says so and names what to run.
		der = block.Bytes
	default:
		return nil, false, fmt.Errorf("%s holds a %q block, want %q or %q",
			path, block.Type, "PRIVATE KEY", keyfile.BlockType)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, encrypted, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, encrypted, fmt.Errorf("%s is %T, not ML-DSA", path, parsed)
	}
	return key, encrypted, nil
}

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
	if b, _ := pem.Decode(rest); b != nil {
		return nil, fmt.Errorf("%s holds more than one PEM block", path)
	}
	return block.Bytes, nil
}

func mustPKCS8(key *mldsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("pki: marshalling an ML-DSA key: " + err.Error())
	}
	return der
}

// yearsFit refuses a lifetime the authorities cannot cover: the sentence
// names what was asked, when the earlier of the two signing authorities
// expires, and the most --years can be, which is the last whole number of
// years from now that ends before that expiry. The most is counted from
// the calendar, not from the count asked for, so a count large enough to
// wrap AddDate is refused like any other over the most and never reaches
// a date.
func yearsFit(years int, now time.Time, ceilings ...time.Time) error {
	ceiling := ceilings[0]
	for _, c := range ceilings[1:] {
		if c.Before(ceiling) {
			ceiling = c
		}
	}
	most := 0
	for now.AddDate(most+1, 0, 0).Before(ceiling) {
		most++
	}
	if most < 1 {
		return fmt.Errorf("--years %d asks for intermediates, but the signing authorities expire %s, "+
			"within a year: rotate the anchor before issuing", years, ceiling.Format(time.DateOnly))
	}
	if years > most {
		return fmt.Errorf("--years %d asks for intermediates beyond %s, when the signing authorities expire; "+
			"the most --years can be is %d", years, ceiling.Format(time.DateOnly), most)
	}
	return nil
}
