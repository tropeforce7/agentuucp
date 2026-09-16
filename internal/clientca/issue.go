package clientca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

const (
	// serialBits is the width of a certificate serial. Random and wide
	// enough that two relays, or one relay across a restore from backup,
	// will not collide.
	serialBits = 128

	// backdate covers a client whose clock is a little behind the relay's.
	// The request signature already tolerates five minutes of skew; a
	// certificate that is not yet valid would refuse the connection before
	// that tolerance could apply.
	backdate = 5 * time.Minute
)

// Issued is a freshly signed client certificate and the metadata the relay
// stores about it.
type Issued struct {
	// Cert is the certificate, DER.
	Cert []byte
	// Serial identifies it, 32 lowercase hex characters.
	Serial string
	// SPKI is the hex SHA-256 of the certified public key.
	SPKI string
	// Label is the machine's name for itself.
	Label     string
	NotBefore time.Time
	NotAfter  time.Time
}

// ErrCALifetime is returned when the authority would expire before any
// certificate it signed could be used.
var ErrCALifetime = errors.New("client CA has expired")

// Issue signs a client certificate for the key in req, naming fp as its
// subject.
//
// Nothing from the request but its key reaches the certificate. The subject
// is the relay's to set, so a machine cannot ask to be issued for an identity
// that is not its own, and the token the request carried is not copied
// anywhere: it is spent, not recorded.
func (c *CA) Issue(req *Request, fp string, now time.Time, lifetime time.Duration) (*Issued, error) {
	if req == nil || req.Key == nil {
		return nil, errors.New("clientca: no certificate request")
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("clientca: certificate lifetime must be positive, got %v", lifetime)
	}
	// Truncated to the second, because that is the precision X.509 encodes:
	// the times reported here must be the times in the certificate, or a
	// client and a relay comparing them would disagree by microseconds.
	notBefore := now.Add(-backdate).Truncate(time.Second)
	if !now.Before(c.cert.NotAfter) {
		return nil, fmt.Errorf("%w: it expired on %s", ErrCALifetime, c.cert.NotAfter.Format(time.RFC3339))
	}
	notAfter := now.Add(lifetime).Truncate(time.Second)
	// A leaf outliving its issuer would verify until the day the CA expired
	// and then stop, without warning. Clamped, it expires when it says it
	// does and the client renews on schedule.
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}

	return issueLeaf(&pki.Key{Cert: c.cert, Key: c.key}, req, fp, notBefore, notAfter)
}

// issueLeaf builds the one client-certificate template this project issues,
// from whichever authority is signing: a self-signed one under PLAN-MTLS, or
// a signing intermediate from an auu-ca bundle.
//
// Nothing from the request but its key reaches the certificate. In particular
// the subject is the caller's fingerprint and never the requester's own
// subject, and the enrolment token the request carried appears nowhere: it is
// spent, not recorded, and a certificate is shown to whoever the machine
// connects to.
func issueLeaf(parent *pki.Key, req *Request, fp string, notBefore, notAfter time.Time) (*Issued, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fp},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, req.Key, parent.Key)
	if err != nil {
		return nil, fmt.Errorf("signing client certificate: %w", err)
	}
	return &Issued{
		Cert:      der,
		Serial:    FormatSerial(serial),
		SPKI:      req.SPKI,
		Label:     req.Label,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, nil
}

// FormatSerial renders a serial the one way this project stores and displays
// one: lowercase hex, zero-padded to the full width, so serials sort and
// compare as strings.
func FormatSerial(n *big.Int) string {
	return fmt.Sprintf("%0*x", serialBits/4, n)
}

// ValidSerial reports whether s is a serial as FormatSerial writes one. The
// relay checks it before a database lookup, so a path segment from the wire
// never reaches a query as anything else.
func ValidSerial(s string) bool {
	if len(s) != serialBits/4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
