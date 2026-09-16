package store

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// certFile holds this machine's client certificate for one relay, and the key
// that goes with it. The key never leaves the machine: that is the whole
// difference between this and the identity, which is meant to be portable.
//
// It lives in the relay's own directory. A certificate is signed by one
// relay's authority and means nothing at another, so a machine on two relays
// holds two of them, each with its own key.
const certFile = "cert.json"

// RenewBefore is how much of a certificate's life must remain before auu
// renews it on the next command. A year's certificate renewed at sixty days
// gives a machine used once a month several chances to notice.
const RenewBefore = 60 * 24 * time.Hour

// ErrNoCert means this machine holds no client certificate for the relay.
var ErrNoCert = errors.New("no client certificate for this relay")

// ErrCertForAnotherRelay means the cert.json in a relay's directory records
// a different relay: a file copied between relay directories, or a relay
// whose URL was changed under it. It is a file that is there and wrong,
// which is not a file that is missing, and it is damaged, since a person
// put it there and a person has to replace it.
var ErrCertForAnotherRelay = errors.New("this machine's certificate is for another relay")

// certForAnotherRelay is the sentence for it, with ErrCertForAnotherRelay
// and ErrDamaged beneath.
type certForAnotherRelay struct{ msg string }

func (e *certForAnotherRelay) Error() string { return e.msg }
func (e *certForAnotherRelay) Unwrap() []error {
	return []error{ErrCertForAnotherRelay, ErrDamaged}
}

// CertRecord is what a machine keeps about its own certificate.
type CertRecord struct {
	// Relay is the relay that issued it. A certificate is only good at the
	// relay whose authority signed it, so switching relays discards it.
	Relay  string `json:"relay"`
	Serial string `json:"serial"`
	Label  string `json:"label"`
	// Key is the machine's private key: PKCS#8 PEM in a plain home, and an
	// AUU WRAPPED PRIVATE KEY block under the home key in an encrypted one.
	Key string `json:"key"`
	// Cert is the certificate, PEM.
	Cert string `json:"cert"`
	// CA is the issuing authority, PEM. Kept so 'auu cert status' can show
	// which authority a machine is enrolled with; nothing verifies against
	// it, because the relay proves that in the handshake.
	CA        string    `json:"ca"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	// signer, set by CertFor when the key is wrapped, is how the key signs:
	// through the agent, under the relay's name, with the public key the
	// certificate carries.
	signer func(pub *mldsa.PublicKey) crypto.Signer
}

// Encrypted says whether the key is under the home key.
func (c *CertRecord) Encrypted() bool { return keyfile.IsWrapped([]byte(c.Key)) }

// TLS turns the record into a certificate the transport can present.
//
// A plain key is parsed and presented. A wrapped key is presented as a
// crypto.Signer that asks the agent, whose public half is the
// certificate's; crypto/tls signs ML-DSA through crypto.SignMessage with
// the raw message, which is what the agent receives.
func (c *CertRecord) TLS() (*tls.Certificate, error) {
	certBlock, _ := pem.Decode([]byte(c.Cert))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("client certificate is not a PEM certificate")
	}
	keyBlock, _ := pem.Decode([]byte(c.Key))
	if keyBlock == nil {
		return nil, errors.New("client certificate key is not a PEM block")
	}
	switch keyBlock.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("client certificate key: %w", err)
		}
		if _, ok := key.(*mldsa.PrivateKey); !ok {
			return nil, fmt.Errorf("client certificate key is %T, not ML-DSA", key)
		}
		return &tls.Certificate{Certificate: [][]byte{certBlock.Bytes}, PrivateKey: key}, nil
	case keyfile.WrappedBlockType:
		if c.signer == nil {
			return nil, errors.New("client certificate key is encrypted but this home is not: " +
				"the file was copied from an encrypted home")
		}
		leaf, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		pub, ok := leaf.PublicKey.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("client certificate key is %T, not ML-DSA", leaf.PublicKey)
		}
		return &tls.Certificate{Certificate: [][]byte{certBlock.Bytes}, PrivateKey: c.signer(pub)}, nil
	default:
		return nil, fmt.Errorf("client certificate key is a %q block, not a private key", keyBlock.Type)
	}
}

// PublicKey is the certificate's key, for display, or nil when the
// certificate cannot be read.
func (c *CertRecord) PublicKey() *mldsa.PublicKey {
	certBlock, _ := pem.Decode([]byte(c.Cert))
	if certBlock == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil
	}
	pub, _ := leaf.PublicKey.(*mldsa.PublicKey)
	return pub
}

// Expiring reports whether the certificate is close enough to its expiry that
// it should be renewed now.
func (c *CertRecord) Expiring(now time.Time) bool {
	return now.Add(RenewBefore).After(c.NotAfter)
}

// CertFor loads this machine's certificate for one relay.
//
// The relay recorded inside the file is checked against the relay whose
// directory it was found in. A certificate is signed by one relay's authority
// and means nothing at another, so a file copied between relay directories is
// refused here exactly as one copied between homes is.
func (s *Store) CertFor(r *Relay) (*CertRecord, error) {
	path := s.relayPath(r, certFile)
	data, err := readPrivate(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoCert
	}
	if err != nil {
		return nil, err
	}
	var c CertRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, certDamaged(path, r.Name, err)
	}
	if !sameRelay(c.Relay, r.URL) {
		// Not "none": treating it as absent made the relay's refusal of a
		// certificate it never saw the only word said, which is what the
		// container suite's K10 found.
		return nil, &certForAnotherRelay{msg: fmt.Sprintf("this machine's %s for %s was issued by %s: "+
			"run 'auu register --relay %s --token TOKEN' to get one for this relay", path, r.Name, c.Relay, r.Name)}
	}
	if c.Encrypted() {
		// Signed by the agent, which reads this same file when asked.
		client, err := agent.NewClient(s.root)
		if err != nil {
			return nil, err
		}
		name := agent.CertPrefix + r.Name
		c.signer = func(pub *mldsa.PublicKey) crypto.Signer { return client.CertSigner(name, pub) }
	}
	return &c, nil
}

// certDamaged is a cert.json nothing can read: the register command that
// replaces it is the whole of the advice, on every path that meets it.
func certDamaged(path, relay string, cause error) error {
	return damaged(path, "is not valid JSON", cause,
		fmt.Sprintf("run 'auu register --relay %s --token TOKEN' to replace it", relay))
}

// SaveCertFor writes a relay's certificate, replacing any there.
func (s *Store) SaveCertFor(r *Relay, c *CertRecord) error {
	if err := os.MkdirAll(s.relayDir(r.Name), dirMode); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.relayPath(r, certFile), append(data, '\n'), fileMode)
}

// RemoveCertFor forgets this machine's certificate for one relay. A missing
// one is not an error: the point is that there is none afterwards.
func (s *Store) RemoveCertFor(r *Relay) error {
	err := os.Remove(s.relayPath(r, certFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// HasCertFor reports whether a certificate file exists for one relay, without
// reading it. It is what separates "this machine has not enrolled" from "the
// certificate it holds was not accepted" in the advice a failure carries.
func (s *Store) HasCertFor(r *Relay) bool {
	_, err := os.Stat(s.relayPath(r, certFile))
	return err == nil
}

// HasAnyCert reports whether this machine holds a certificate for any relay.
// It is for advice at the single exit, where the command that failed is no
// longer in hand.
func (s *Store) HasAnyCert() bool {
	relays, err := s.Relays()
	if err != nil {
		return false
	}
	for _, r := range relays {
		if s.HasCertFor(r) {
			return true
		}
	}
	return false
}

// sameRelay compares two relay URLs the way a person would, ignoring a
// trailing slash. It uses the same normalisation a token's audience gets, so
// one URL cannot be two things in one program.
func sameRelay(a, b string) bool {
	return token.NormaliseRelay(a) == token.NormaliseRelay(b)
}
