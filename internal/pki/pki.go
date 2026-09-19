// Package pki is the private certificate hierarchy an AgentUUCP relay is
// given: a trust anchor and two constrained authorities under it, made
// offline by auu-ca, and the bundle a relay reads.
//
// The shape, and where each key lives:
//
//	KEPT OFFLINE
//	                    TRUST ANCHOR                path length 2
//	            ┌────────────┴────────────┐
//	       SERVER CA                  CLIENT CA     path length 1
//	       EKU serverAuth             EKU clientAuth
//	            │                          │
//	ON THE RELAY▼                          ▼
//	 SERVER SIGNING INTERMEDIATE   CLIENT SIGNING INTERMEDIATE
//	 name-constrained to its hosts  path length 0
//	            │ mints the relay's own      │ issues client certificates
//	            ▼ short-lived leaf           ▼ at enrolment
//
// The relay holds the two intermediates' keys and nothing above them, so a
// relay's disk yields the power to be that one relay and to issue client
// certificates, and never the power to extend trust. Both intermediates are
// disposable: reissuing them from the offline authorities and restarting
// recovers a compromise without anybody re-enrolling.
package pki

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// Lifetimes. A private PKI has no CA policy forcing ninety days on it, and
// every trip to the offline machine is a person's time, so these are the
// rhythm of the design rather than a convention.
const (
	// AnchorYears is how long a trust anchor lives. Replacing one means
	// every machine enrolling again, so it outlives everything under it.
	AnchorYears = 10
	// CAYears is how long each offline authority lives.
	CAYears = 5
	// DefaultIntermediateYears is how long a relay's signing intermediates
	// live, and so how long a stolen one could be replayed for.
	DefaultIntermediateYears = 1
	// LeafDays is how long the relay's own server certificate lives. It is
	// short because the relay mints it itself, in memory, on demand.
	LeafDays = 30
	// serialBits is the width of a certificate serial.
	serialBits = 128
	// uniqueBytes is the random component of an anchor's subject, so that no
	// two anchors share one.
	uniqueBytes = 8
	// DefaultMLDSA is the parameter set used when an operator does not
	// choose: the level-3 partner of the ML-KEM-768 inside the X-Wing KEM
	// the messages themselves use.
	DefaultMLDSA = 65
)

// Key is a private key with the certificate that goes with it.
type Key struct {
	Cert *x509.Certificate
	Key  *mldsa.PrivateKey
}

// SPKI is the hex SHA-256 of a certificate's SubjectPublicKeyInfo. It
// identifies the key rather than the certificate, so an authority can reissue
// its own certificate without invalidating anything that pinned it.
func SPKI(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// serial returns a fresh random certificate serial.
func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
}

// Anchor generates a self-signed trust anchor.
//
// Two levels of CA are permitted beneath it, because each branch is an
// offline authority and then a signing intermediate on the relay. No extended
// key usage: the branches carry that, and a root that named one would
// constrain both.
func Anchor(name string, params mldsa.Parameters, now time.Time) (*Key, error) {
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	unique := make([]byte, uniqueBytes)
	if _, err := rand.Read(unique); err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         name + " Trust Anchor",
			OrganizationalUnit: []string{hex.EncodeToString(unique)},
		},
		NotBefore:             now.Add(-time.Hour).Truncate(time.Second),
		NotAfter:              now.AddDate(AnchorYears, 0, 0).Truncate(time.Second),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	return selfSign(tmpl, key)
}

// Authority generates one of the two offline CAs beneath the anchor.
//
// The extended key usage is the constraint that matters: Go's verifier
// enforces EKU nesting, so nothing under the client authority will ever
// verify as a server, or the reverse.
func Authority(parent *Key, name string, eku x509.ExtKeyUsage, params mldsa.Parameters, now time.Time) (*Key, error) {
	suffix := " Client CA"
	if eku == x509.ExtKeyUsageServerAuth {
		suffix = " Server CA"
	}
	return issueCA(parent, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name + suffix},
		NotBefore:             now.Add(-time.Hour).Truncate(time.Second),
		NotAfter:              clamp(now.AddDate(CAYears, 0, 0), parent.Cert.NotAfter),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
	}, params)
}

// Intermediate generates a signing intermediate for one relay, which is the
// only private key of this hierarchy that a relay is given.
//
// hosts are the relay's names and addresses. On the server side they become
// name constraints, so a stolen server intermediate can sign for that relay
// and for nothing else; on the client side they are only decoration in the
// subject, since a client certificate's subject is a fingerprint and a
// constraint on names would bind nothing.
func Intermediate(parent *Key, name string, eku x509.ExtKeyUsage, hosts []string,
	years int, params mldsa.Parameters, now time.Time) (*Key, error) {
	if len(hosts) == 0 {
		return nil, errors.New("pki: an intermediate needs at least one host")
	}
	suffix := " Client Signing Intermediate "
	if eku == x509.ExtKeyUsageServerAuth {
		suffix = " Server Signing Intermediate "
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name + suffix + hosts[0]},
		NotBefore:             now.Add(-time.Hour).Truncate(time.Second),
		NotAfter:              clamp(now.AddDate(years, 0, 0), parent.Cert.NotAfter),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
	}
	if eku == x509.ExtKeyUsageServerAuth {
		dns, ips, err := splitHosts(hosts)
		if err != nil {
			return nil, err
		}
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = dns
		tmpl.PermittedIPRanges = ips
		// A constraint restricts only its own kind of name. An intermediate
		// permitted some DNS names and given no IP constraint may sign for
		// any address, and one permitted some addresses may sign for any
		// name — which is exactly what a stolen one would do. So the kind
		// this relay has no host of is excluded outright.
		if len(dns) == 0 {
			tmpl.ExcludedDNSDomains = []string{""}
		}
		if len(ips) == 0 {
			tmpl.ExcludedIPRanges = []*net.IPNet{
				{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
				{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			}
		}
	}
	return issueCA(parent, tmpl, params)
}

// ServerLeaf mints the certificate a relay presents, from its own server
// signing intermediate.
//
// The key is returned to the caller and is expected to stay in memory: it is
// the one secret a reader of the relay's disk does not obtain, which is what
// lets a witness tell the real relay from an impostor holding its
// intermediates.
func ServerLeaf(parent *Key, hosts []string, params mldsa.Parameters, now time.Time) (*Key, error) {
	// Past the intermediate's expiry the clamp below would mint a leaf
	// already expired, and a relay would serve it without noticing.
	if !now.Before(parent.Cert.NotAfter) {
		return nil, fmt.Errorf("pki: the server signing intermediate expired on %s; "+
			"run 'auu-ca relay' on the offline machine and replace the bundle",
			parent.Cert.NotAfter.Format(time.DateOnly))
	}
	dns, ips, err := splitHosts(hosts)
	if err != nil {
		return nil, err
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ipAddrs := make([]net.IP, 0, len(ips))
	for _, n := range ips {
		ipAddrs = append(ipAddrs, n.IP)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: hosts[0]},
		DNSNames:              dns,
		IPAddresses:           ipAddrs,
		NotBefore:             now.Add(-5 * time.Minute).Truncate(time.Second),
		NotAfter:              clamp(now.AddDate(0, 0, LeafDays), parent.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, key.PublicKey(), parent.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: signing the server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Key{Cert: cert, Key: key}, nil
}

// issueCA signs a CA certificate under parent with a fresh key.
func issueCA(parent *Key, tmpl *x509.Certificate, params mldsa.Parameters) (*Key, error) {
	if parent == nil {
		return nil, errors.New("pki: no issuing authority")
	}
	if !tmpl.NotAfter.After(tmpl.NotBefore) {
		return nil, fmt.Errorf("pki: %s would expire before it began; its issuer expires %s",
			tmpl.Subject.CommonName, parent.Cert.NotAfter.Format(time.DateOnly))
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = sn
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, key.PublicKey(), parent.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: signing %s: %w", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Key{Cert: cert, Key: key}, nil
}

func selfSign(tmpl *x509.Certificate, key *mldsa.PrivateKey) (*Key, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: signing %s: %w", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Key{Cert: cert, Key: key}, nil
}

// clamp keeps a certificate from outliving its issuer. One that did would
// verify until the issuer expired and then stop, on a date nothing warned
// about.
func clamp(want, ceiling time.Time) time.Time {
	if want.After(ceiling) {
		return ceiling.Truncate(time.Second)
	}
	return want.Truncate(time.Second)
}

// splitHosts sorts names and addresses, refusing anything that is neither.
func splitHosts(hosts []string) (dns []string, ips []*net.IPNet, err error) {
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			} else {
				ip = ip.To4()
			}
			ips = append(ips, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if err := validDNSName(h); err != nil {
			return nil, nil, err
		}
		dns = append(dns, h)
	}
	return dns, ips, nil
}

// validDNSName is the shape a name constraint and a subject alternative name
// will both accept.
func validDNSName(h string) error {
	if h == "" {
		return errors.New("pki: empty host")
	}
	if len(h) > 253 {
		return fmt.Errorf("pki: host %q is %d characters, over 253", h, len(h))
	}
	// The host names the authority's record directory for the relay, and
	// the authority may keep its records on Windows, where a name whose
	// first label is a device opens the device: CON.example.com is the
	// console there, whatever follows the dot.
	if first, _, _ := strings.Cut(h, "."); channels.WindowsDevice(first) {
		return fmt.Errorf("pki: host %q begins with %s, a device name on Windows, where the authority's record of it could not be a directory", h, strings.ToUpper(first))
	}
	for _, label := range splitLabels(h) {
		if label == "" {
			return fmt.Errorf("pki: host %q has an empty label", h)
		}
		if len(label) > 63 {
			return fmt.Errorf("pki: host %q has a label over 63 characters", h)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
			case c == '-' && i > 0 && i < len(label)-1:
			default:
				return fmt.Errorf("pki: host %q is neither an IP address nor a DNS name", h)
			}
		}
	}
	return nil
}

func splitLabels(h string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(h); i++ {
		if i == len(h) || h[i] == '.' {
			out = append(out, h[start:i])
			start = i + 1
		}
	}
	return out
}

// ParameterNumberOf is the ML-DSA parameter set as 44, 65 or 87, and zero for
// anything else.
func ParameterNumberOf(p mldsa.Parameters) int {
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

// ParameterSet is the set numbered n.
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

// parseIPHost returns h if it is an IP address, else "".
func parseIPHost(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	return ""
}
