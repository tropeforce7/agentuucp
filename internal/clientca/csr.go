package clientca

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

const (
	// MaxCSRBytes bounds a certificate request. An ML-DSA-65 request with a
	// full-length token is under six kilobytes; this leaves room and refuses
	// anything that is not one of ours before it is parsed.
	MaxCSRBytes = 16 << 10

	// MaxTokenBytes bounds the challengePassword. An enrolment token is at
	// most a little over eight hundred characters; RFC 2985's own bound of
	// 255 is advisory and too small for one, so this is the bound that is
	// actually enforced.
	MaxTokenBytes = 2048

	// MaxLabelBytes bounds a machine's name for itself. It is displayed, and
	// display names are bounded everywhere else in this project too.
	MaxLabelBytes = 64

	// unnamedLabel stands in for a request that named no machine.
	unnamedLabel = "unnamed"
)

// oidChallengePassword is PKCS#9's challengePassword, RFC 2985 section
// 5.4.1: the standard place an enrolment secret rides in a certificate
// request. SCEP and EST use it for the same purpose. Using the standard
// attribute rather than an invented extension means this project need not own
// an OID arc, and that "openssl req -text" prints the token by name.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// Errors a caller can tell apart. The relay turns each into its own message,
// so the text here is the reason and not the disposition.
var (
	ErrCSRForm      = errors.New("malformed certificate request")
	ErrCSRSignature = errors.New("certificate request signature does not verify")
	ErrCSRKey       = errors.New("unsupported client key")
	ErrCSRToken     = errors.New("bad enrolment token in certificate request")
)

// PKCS#10, RFC 2986. These types exist because crypto/x509 will not write a
// challengePassword: CreateCertificateRequest emits an extensionRequest
// attribute and nothing else. Only the attribute set and the SEQUENCE around
// it are assembled here; the subject, the public key and the signature
// algorithm are lifted from a request crypto/x509 built, so no part of
// ML-DSA's encoding is written out by hand.
type (
	attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}

	certificationRequestInfo struct {
		Version    int
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Attributes asn1.RawValue `asn1:"tag:0"`
	}

	certificationRequest struct {
		Info      asn1.RawValue
		SigAlg    pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
)

// Request is a parsed and checked certificate request: what the relay needs
// from it and nothing else.
type Request struct {
	// Key is the machine's public key, already checked to be ML-DSA of the
	// parameter set the caller required.
	Key *mldsa.PublicKey
	// Token is the enrolment token the request carried, empty if none.
	Token string
	// Label is the machine's name for itself, for display.
	Label string
	// SPKI is the hex SHA-256 of the encoded public key, which the relay
	// records so an operator can tell two certificates apart by key.
	SPKI string

	spki []byte
}

// NewCSR builds the certificate request a machine sends when it enrols or
// renews. token rides in a challengePassword attribute and is omitted
// entirely when empty; a renewal carries none.
//
// The signature covers the token, which is the point: the request is one
// statement, "I hold this key and I hold this authorisation", and neither
// half can be moved to another request.
//
// key is a crypto.Signer whose public key is ML-DSA: an *mldsa.PrivateKey
// held here, or the agent's signer for a key it holds. Either way the
// signature is checked against the public key before the request is
// returned, so a signer that signs with some other key is caught here.
func NewCSR(key crypto.Signer, label, token string) ([]byte, error) {
	if key == nil {
		return nil, errors.New("clientca: no key")
	}
	pub, ok := key.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("clientca: key is %T, not ML-DSA", key.Public())
	}
	if ParameterNumber(pub.Parameters()) == 0 {
		return nil, fmt.Errorf("clientca: key is %s, which this build does not know",
			pub.Parameters())
	}
	if len(token) > MaxTokenBytes {
		return nil, fmt.Errorf("clientca: token is %d bytes, over the %d byte limit",
			len(token), MaxTokenBytes)
	}
	label = cleanLabel(label)

	// A throwaway request, purely to have crypto/x509 encode the subject, the
	// SubjectPublicKeyInfo and the ML-DSA signature AlgorithmIdentifier.
	seed, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: label}}, key)
	if err != nil {
		return nil, err
	}
	var outer certificationRequest
	if _, err := asn1.Unmarshal(seed, &outer); err != nil {
		return nil, err
	}
	var info certificationRequestInfo
	if _, err := asn1.Unmarshal(outer.Info.FullBytes, &info); err != nil {
		return nil, err
	}

	var attrs []byte
	if token != "" {
		value, err := asn1.MarshalWithParams(token, "utf8")
		if err != nil {
			return nil, err
		}
		attrs, err = asn1.Marshal(attribute{
			Type:   oidChallengePassword,
			Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: value},
		})
		if err != nil {
			return nil, err
		}
	}

	infoDER, err := asn1.Marshal(certificationRequestInfo{
		Version: 0,
		Subject: info.Subject,
		SPKI:    info.SPKI,
		Attributes: asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs,
		},
	})
	if err != nil {
		return nil, err
	}
	// Pure ML-DSA: the message is signed directly, with no pre-hash and no
	// context string, which is what the ML-DSA AlgorithmIdentifier above
	// declares.
	sig, err := key.Sign(rand.Reader, infoDER, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if err := mldsa.Verify(pub, infoDER, sig, nil); err != nil {
		return nil, fmt.Errorf("clientca: the signer's signature does not verify under its public key: %w", err)
	}
	return asn1.Marshal(certificationRequest{
		Info:      asn1.RawValue{FullBytes: infoDER},
		SigAlg:    outer.SigAlg,
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
}

// AnyParameters, passed to ParseCSR, accepts a key of any ML-DSA parameter
// set. A relay with client certificates off still reads the request for the
// token inside it, and has no authority whose set the key would have to match.
var AnyParameters mldsa.Parameters

// ParseCSR checks a certificate request and returns what the relay may use.
// want is the parameter set the key must have, or AnyParameters.
//
// The order matters: nothing about the request is believed until its own
// signature has verified, so a caller cannot make the relay act on a key or a
// token it does not hold.
func ParseCSR(der []byte, want mldsa.Parameters) (*Request, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("%w: it is empty", ErrCSRForm)
	}
	if len(der) > MaxCSRBytes {
		return nil, fmt.Errorf("%w: it is %d bytes, over the %d byte limit",
			ErrCSRForm, len(der), MaxCSRBytes)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSRForm, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSRSignature, err)
	}
	key, ok := csr.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: client keys must be %s, got %s",
			ErrCSRKey, wantName(want), keyDescription(csr))
	}
	if ParameterNumber(key.Parameters()) == 0 {
		return nil, fmt.Errorf("%w: client keys must be %s, got %s",
			ErrCSRKey, wantName(want), key.Parameters())
	}
	// The parameter set is the relay's policy, not the client's choice: a
	// relay at one security level does not accept keys at another, so that
	// "one level throughout" is a fact and not a hope.
	if want != AnyParameters && key.Parameters() != want {
		return nil, fmt.Errorf("%w: client keys must be %s, got %s",
			ErrCSRKey, want, key.Parameters())
	}
	token, err := challengePassword(csr.Raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return &Request{
		Key:   key,
		Token: token,
		Label: cleanLabel(csr.Subject.CommonName),
		SPKI:  hex.EncodeToString(sum[:]),
		spki:  csr.RawSubjectPublicKeyInfo,
	}, nil
}

// challengePassword walks the request's attributes for the enrolment token.
//
// Attributes this relay does not read, extensionRequest included, are
// ignored rather than refused: one it never looks at cannot hurt it, and the
// signature covers them all either way.
func challengePassword(der []byte) (string, error) {
	var outer certificationRequest
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return "", fmt.Errorf("%w: %v", ErrCSRForm, err)
	}
	var info certificationRequestInfo
	if _, err := asn1.Unmarshal(outer.Info.FullBytes, &info); err != nil {
		return "", fmt.Errorf("%w: %v", ErrCSRForm, err)
	}

	found, seen := "", 0
	rest := info.Attributes.Bytes
	for len(rest) > 0 {
		var attr attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &attr); err != nil {
			return "", fmt.Errorf("%w: attributes: %v", ErrCSRForm, err)
		}
		if !attr.Type.Equal(oidChallengePassword) {
			continue
		}
		seen++
		if seen > 1 {
			return "", fmt.Errorf("%w: certificate request carries more than one enrolment token",
				ErrCSRToken)
		}
		// Bounded before it is decoded, so an attribute declaring a large
		// string never becomes one.
		if len(attr.Values.Bytes) > MaxTokenBytes {
			return "", fmt.Errorf("%w: it is over the %d byte limit", ErrCSRToken, MaxTokenBytes)
		}
		value, err := singleUTF8String(attr.Values.Bytes)
		if err != nil {
			return "", err
		}
		found = value
	}
	if len(found) > MaxTokenBytes {
		return "", fmt.Errorf("%w: it is over the %d byte limit", ErrCSRToken, MaxTokenBytes)
	}
	return found, nil
}

// singleUTF8String decodes the SET around a challengePassword, which RFC 2985
// declares SINGLE VALUE.
//
// RFC 2985 types the value as a DirectoryString, which is a CHOICE of five
// string types. Only UTF8String is accepted here: it is what NewCSR writes,
// both ends of this wire are this project's own code, and a token is base64url
// text, which a PrintableString cannot hold in any case because it has no
// underscore. The tag is checked rather than left to encoding/asn1, which
// accepts several string types into a Go string.
func singleUTF8String(set []byte) (string, error) {
	if len(set) == 0 {
		return "", fmt.Errorf("%w: it has no value", ErrCSRToken)
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(set, &raw)
	if err != nil {
		return "", fmt.Errorf("%w: its value does not decode", ErrCSRToken)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("%w: it has more than one value", ErrCSRToken)
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagUTF8String || raw.IsCompound {
		return "", fmt.Errorf("%w: its value is not a UTF8String", ErrCSRToken)
	}
	if !utf8.Valid(raw.Bytes) {
		return "", fmt.Errorf("%w: its value is not valid UTF-8", ErrCSRToken)
	}
	return string(raw.Bytes), nil
}

// keyDescription names the key type in a refusal, for a person reading it.
func keyDescription(csr *x509.CertificateRequest) string {
	if csr.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return "an unrecognised key type"
	}
	return csr.PublicKeyAlgorithm.String()
}

// cleanLabel reduces a machine's name for itself to something safe to store
// and print. It never fails: a label is decoration, and refusing an enrolment
// over one would be a poor trade. What it drops is the set a channel name
// may not hold, channels.ForbiddenRune's — control characters, and with
// them the format characters a bidi override is one of, which a listing
// would obey and reverse the rest of the line by.
func cleanLabel(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return unnamedLabel
	}
	s = strings.Map(func(r rune) rune {
		if _, what := channels.ForbiddenRune(string(r)); what != "" {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	for len(s) > MaxLabelBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return unnamedLabel
	}
	return s
}

// wantName is what a refusal calls the required set.
func wantName(want mldsa.Parameters) string {
	if want == AnyParameters {
		return "ML-DSA"
	}
	return want.String()
}
