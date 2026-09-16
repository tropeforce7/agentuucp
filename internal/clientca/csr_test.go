package clientca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testFP is a well-formed fingerprint: 64 lowercase hex characters.
const testFP = "3f9a1c6d5e7b8a2c4d6e8f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c"

func testKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testRequest builds and parses a request, as the relay would see it.
func testRequest(t *testing.T, label, token string) *Request {
	t.Helper()
	der, err := NewCSR(testKey(t), label, token)
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}
	req, err := ParseCSR(der, mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	return req
}

// longestToken is a token of the greatest length one can really be: the
// claims at their maximum, a bound subject, a full note, and an Ed25519
// signature. The challengePassword must carry it, RFC 2985's advisory bound
// of 255 characters notwithstanding.
func longestToken(t *testing.T) string {
	t.Helper()
	claims := map[string]any{
		"id":         strings.Repeat("a", 32),
		"issuer":     strings.Repeat("b", 64),
		"relay":      "https://relay.example.com",
		"use":        "cert",
		"subject":    strings.Repeat("c", 64),
		"note":       strings.Repeat("n", 200),
		"not_before": time.Now().Unix(),
		"not_after":  time.Now().Add(720 * time.Hour).Unix(),
		"uses":       1000,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "ccxt1." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
}

func TestCSRCarriesTheLongestRealToken(t *testing.T) {
	token := longestToken(t)
	if len(token) <= 255 {
		t.Fatalf("token is %d characters; this test exists because a real one exceeds "+
			"RFC 2985's advisory bound of 255", len(token))
	}
	req := testRequest(t, "laptop", token)
	if req.Token != token {
		t.Errorf("token did not survive the round trip:\n got %q\nwant %q", req.Token, token)
	}
	if req.Label != "laptop" {
		t.Errorf("label = %q, want laptop", req.Label)
	}
}

func TestCSRWithoutATokenCarriesNoAttribute(t *testing.T) {
	key := testKey(t)
	der, err := NewCSR(key, "laptop", "")
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}
	req, err := ParseCSR(der, mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	if req.Token != "" {
		t.Errorf("token = %q, want empty", req.Token)
	}
	// Not merely absent from the parse: absent from the encoding, so a
	// renewal cannot be told from an enrolment by its shape.
	if bytes.Contains(der, oidChallengePasswordDER(t)) {
		t.Error("a request with no token still carries a challengePassword attribute")
	}
}

// oidChallengePasswordDER is the encoded OID, for searching raw DER.
func oidChallengePasswordDER(t *testing.T) []byte {
	t.Helper()
	b, err := asn1.Marshal(oidChallengePassword)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCSRSubjectAndKeyMatchWhatCryptoX509Produces(t *testing.T) {
	// NewCSR assembles the request itself. This pins that the only thing it
	// does differently from crypto/x509 is the attribute set: if the subject
	// or the key encoding ever drifts, the CSR is this package's invention
	// rather than a PKCS#10 request.
	key := testKey(t)
	mine, err := NewCSR(key, "laptop", "tok")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "laptop"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := x509.ParseCertificateRequest(mine)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.ParseCertificateRequest(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.RawSubject, b.RawSubject) {
		t.Error("subject encoding differs from crypto/x509's")
	}
	if !bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo) {
		t.Error("public key encoding differs from crypto/x509's")
	}
	if a.SignatureAlgorithm != b.SignatureAlgorithm {
		t.Errorf("signature algorithm %v, crypto/x509 uses %v", a.SignatureAlgorithm, b.SignatureAlgorithm)
	}
}

func TestParseCSRRefusesOversize(t *testing.T) {
	// One byte either side of the limit. The large one is refused before it
	// is parsed, so it need not be a real request.
	if _, err := ParseCSR(make([]byte, MaxCSRBytes+1), mldsa.MLDSA65()); !errors.Is(err, ErrCSRForm) {
		t.Errorf("a request of MaxCSRBytes+1: %v, want ErrCSRForm", err)
	}
	if !strings.Contains(errText(ParseCSR(make([]byte, MaxCSRBytes+1), mldsa.MLDSA65())), strconv.Itoa(MaxCSRBytes)) {
		t.Error("the refusal does not name the limit")
	}
	// At the limit it is parsed, and fails for being nonsense rather than
	// for its size.
	_, err := ParseCSR(make([]byte, MaxCSRBytes), mldsa.MLDSA65())
	if !errors.Is(err, ErrCSRForm) {
		t.Errorf("a request of MaxCSRBytes: %v, want ErrCSRForm", err)
	}
	if strings.Contains(errText(nil, err), "over the") {
		t.Error("a request at exactly the limit was refused for its size")
	}
	if _, err := ParseCSR(nil, mldsa.MLDSA65()); !errors.Is(err, ErrCSRForm) {
		t.Errorf("an empty request: %v, want ErrCSRForm", err)
	}
}

func errText(_ *Request, err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestParseCSRRefusesABadSignature(t *testing.T) {
	der, err := NewCSR(testKey(t), "laptop", "tok")
	if err != nil {
		t.Fatal(err)
	}
	// Vandalise the signature itself: the last byte of the request is inside
	// the BIT STRING.
	bad := append([]byte{}, der...)
	bad[len(bad)-1] ^= 0x01
	if _, err := ParseCSR(bad, mldsa.MLDSA65()); !errors.Is(err, ErrCSRSignature) {
		t.Errorf("a request with a flipped signature bit: %v, want ErrCSRSignature", err)
	}
}

func TestParseCSRRefusesATamperedToken(t *testing.T) {
	// The reason the token belongs in the request rather than in a header:
	// changing it invalidates the signature, so a token cannot be moved from
	// one request to another.
	token := "ccxt1.payload.signature"
	der, err := NewCSR(testKey(t), "laptop", token)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(der, []byte(token))
	if i < 0 {
		t.Fatal("the token is not in the request")
	}
	bad := append([]byte{}, der...)
	bad[i+6] ^= 0x01

	_, err = ParseCSR(bad, mldsa.MLDSA65())
	if !errors.Is(err, ErrCSRSignature) {
		t.Fatalf("a request whose token was altered: %v, want ErrCSRSignature", err)
	}
	// And specifically: it must fail at the signature, before anything reads
	// the altered token.
	if errors.Is(err, ErrCSRToken) {
		t.Error("the altered token was read before the signature was checked")
	}
}

func TestParseCSRRefusesEveryKeyButMLDSA65(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	small, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	large, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		key  any
		want string
	}{
		{"ECDSA P-256", ec, "ECDSA"},
		{"Ed25519", ed, "Ed25519"},
		{"ML-DSA-44", small, "ML-DSA-44"},
		{"ML-DSA-87", large, "ML-DSA-87"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader,
				&x509.CertificateRequest{Subject: pkix.Name{CommonName: "laptop"}}, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseCSR(der, mldsa.MLDSA65())
			if !errors.Is(err, ErrCSRKey) {
				t.Fatalf("%s was accepted or refused wrongly: %v", tc.name, err)
			}
			// The message names what arrived, so an operator can see that a
			// client is building the wrong kind of key.
			if !strings.Contains(err.Error(), "client keys must be ML-DSA-65") {
				t.Errorf("error %q does not say what is required", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the key that arrived (%s)", err, tc.want)
			}
		})
	}

	// NewCSR builds a request for any set: which set a machine's key has is
	// the relay's policy, and the machine asks the relay before generating
	// one. The refusal lives in ParseCSR, against what the relay wanted.
	der, err := NewCSR(small, "laptop", "")
	if err != nil {
		t.Fatalf("NewCSR with an ML-DSA-44 key: %v", err)
	}
	if _, err := ParseCSR(der, mldsa.MLDSA44()); err != nil {
		t.Errorf("a 44 request refused by a relay wanting 44: %v", err)
	}
	if _, err := ParseCSR(der, AnyParameters); err != nil {
		t.Errorf("a 44 request refused by a relay wanting any: %v", err)
	}
}

func TestParameterSetsRoundTrip(t *testing.T) {
	for _, n := range []int{44, 65, 87} {
		p, err := ParameterSet(n)
		if err != nil {
			t.Fatalf("ParameterSet(%d): %v", n, err)
		}
		if got := ParameterNumber(p); got != n {
			t.Errorf("ParameterNumber(ParameterSet(%d)) = %d", n, got)
		}
	}
	// One step either side of each real value, and the zero value, which is
	// what AnyParameters is and must never be mistaken for a real set.
	for _, n := range []int{0, 43, 45, 64, 66, 86, 88, 128} {
		if _, err := ParameterSet(n); err == nil {
			t.Errorf("ParameterSet(%d) was accepted", n)
		}
	}
	if ParameterNumber(AnyParameters) != 0 {
		t.Error("AnyParameters has a number; it must not look like a real set")
	}
}

func TestTheRelaysParameterSetIsPolicyNotPreference(t *testing.T) {
	// A relay at one level does not accept keys at another, whichever way
	// round: a stronger key is refused as well as a weaker one, so that "one
	// level throughout" is a fact about the authority and not a floor.
	keys := map[int]*mldsa.PrivateKey{}
	for _, n := range []int{44, 65, 87} {
		p, _ := ParameterSet(n)
		k, err := mldsa.GenerateKey(p)
		if err != nil {
			t.Fatal(err)
		}
		keys[n] = k
	}
	for _, want := range []int{44, 65, 87} {
		wantP, _ := ParameterSet(want)
		for _, have := range []int{44, 65, 87} {
			der, err := NewCSR(keys[have], "laptop", "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseCSR(der, wantP)
			if have == want {
				if err != nil {
					t.Errorf("relay wanting %d refused a %d key: %v", want, have, err)
				}
				continue
			}
			if !errors.Is(err, ErrCSRKey) {
				t.Errorf("relay wanting %d accepted a %d key: %v", want, have, err)
				continue
			}
			// The message names both, because the person reading it has to
			// go and generate the other one.
			wantMsg := fmt.Sprintf("client keys must be ML-DSA-%d, got ML-DSA-%d", want, have)
			if !strings.Contains(err.Error(), wantMsg) {
				t.Errorf("error %q does not say %q", err, wantMsg)
			}
		}
	}
}

func TestAnAuthorityCanBeAnySet(t *testing.T) {
	for _, n := range []int{44, 65, 87} {
		p, _ := ParameterSet(n)
		dir := t.TempDir()
		ca, err := Create(dir, "", p)
		if err != nil {
			t.Fatalf("Create at %d: %v", n, err)
		}
		if ca.Parameters() != p {
			t.Errorf("authority created at %d reports %s", n, ca.Parameters())
		}
		// And loads back as what it is, so a restart cannot change it.
		back, err := Load(dir)
		if err != nil {
			t.Fatalf("Load at %d: %v", n, err)
		}
		if back.Parameters() != p {
			t.Errorf("authority at %d loaded as %s", n, back.Parameters())
		}
		// And signs a leaf of its own set, which verifies.
		key, err := mldsa.GenerateKey(p)
		if err != nil {
			t.Fatal(err)
		}
		der, err := NewCSR(key, "laptop", "")
		if err != nil {
			t.Fatal(err)
		}
		req, err := ParseCSR(der, p)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := ca.Issue(req, testFP, time.Now(), time.Hour)
		if err != nil {
			t.Fatalf("Issue at %d: %v", n, err)
		}
		leaf, err := x509.ParseCertificate(issued.Cert)
		if err != nil {
			t.Fatal(err)
		}
		if err := ca.Verify(leaf, time.Now()); err != nil {
			t.Errorf("a %d leaf does not verify against its own authority: %v", n, err)
		}
	}
	if _, err := Create(t.TempDir(), "", AnyParameters); err == nil {
		t.Error("Create with no parameter set was accepted")
	}
}

// handmade builds a request with an arbitrary attribute set, for the cases
// NewCSR will not produce.
func handmade(t *testing.T, key *mldsa.PrivateKey, attrs []byte) []byte {
	t.Helper()
	seed, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "laptop"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	var outer certificationRequest
	if _, err := asn1.Unmarshal(seed, &outer); err != nil {
		t.Fatal(err)
	}
	var info certificationRequestInfo
	if _, err := asn1.Unmarshal(outer.Info.FullBytes, &info); err != nil {
		t.Fatal(err)
	}
	infoDER, err := asn1.Marshal(certificationRequestInfo{
		Version: 0, Subject: info.Subject, SPKI: info.SPKI,
		Attributes: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(nil, infoDER, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(certificationRequest{
		Info:      asn1.RawValue{FullBytes: infoDER},
		SigAlg:    outer.SigAlg,
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func challengeAttr(t *testing.T, values ...[]byte) []byte {
	t.Helper()
	var set []byte
	for _, v := range values {
		set = append(set, v...)
	}
	b, err := asn1.Marshal(attribute{
		Type:   oidChallengePassword,
		Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: set},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func utf8Value(t *testing.T, s string) []byte {
	t.Helper()
	b, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseCSRRefusesMalformedTokenAttributes(t *testing.T) {
	key := testKey(t)
	printable, err := asn1.MarshalWithParams("token", "printable")
	if err != nil {
		t.Fatal(err)
	}
	oversize := utf8Value(t, strings.Repeat("x", MaxTokenBytes+1))

	for _, tc := range []struct {
		name  string
		attrs []byte
		want  string
	}{
		{"two attributes", append(challengeAttr(t, utf8Value(t, "a")), challengeAttr(t, utf8Value(t, "b"))...),
			"more than one enrolment token"},
		{"two values in the set", challengeAttr(t, utf8Value(t, "a"), utf8Value(t, "b")),
			"more than one value"},
		{"no value in the set", challengeAttr(t), "no value"},
		{"a PrintableString", challengeAttr(t, printable), "not a UTF8String"},
		{"over the limit", challengeAttr(t, oversize), "over the"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCSR(handmade(t, key, tc.attrs), mldsa.MLDSA65())
			if !errors.Is(err, ErrCSRToken) {
				t.Fatalf("%s: %v, want ErrCSRToken", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseCSRAcceptsATokenAtTheLimit(t *testing.T) {
	// One step under the boundary the previous test steps over.
	token := strings.Repeat("x", MaxTokenBytes-16)
	req, err := ParseCSR(handmade(t, testKey(t), challengeAttr(t, utf8Value(t, token))), mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("a token of %d bytes was refused: %v", len(token), err)
	}
	if req.Token != token {
		t.Error("the token did not survive")
	}
}

func TestParseCSRIgnoresOtherAttributes(t *testing.T) {
	// extensionRequest is what crypto/x509 itself emits. A request carrying
	// one alongside the token must still work: an attribute the relay never
	// reads cannot hurt it, and refusing one would break any client that
	// used the standard library to build its request.
	oidExtensionRequest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	// An extension crypto/x509 does not itself interpret. One it does, such
	// as a subject alternative name, is parsed and validated by
	// ParseCertificateRequest before this package ever sees the request.
	exts, err := asn1.Marshal([]pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: []byte("x")},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := asn1.Marshal(attribute{
		Type:   oidExtensionRequest,
		Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: exts},
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs := append(other, challengeAttr(t, utf8Value(t, "ccxt1.a.b"))...)

	req, err := ParseCSR(handmade(t, testKey(t), attrs), mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("a request with an extensionRequest beside the token: %v", err)
	}
	if req.Token != "ccxt1.a.b" {
		t.Errorf("token = %q, want ccxt1.a.b", req.Token)
	}
}

func TestLabelsAreCleanedNotRefused(t *testing.T) {
	// A label is decoration. Refusing an enrolment over one would be a poor
	// trade, so every one of these is cleaned and the request still stands.
	sixtyFour := strings.Repeat("m", MaxLabelBytes)
	for _, tc := range []struct {
		name  string
		label string
		want  string
	}{
		{"empty", "", unnamedLabel},
		{"whitespace", "   ", unnamedLabel},
		{"at the limit", sixtyFour, sixtyFour},
		{"one over the limit", sixtyFour + "m", sixtyFour},
		{"control characters", "lap\x00top\n", "laptop"},
		{"trimmed", "  laptop  ", "laptop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := testRequest(t, tc.label, "")
			if req.Label != tc.want {
				t.Errorf("label %q became %q, want %q", tc.label, req.Label, tc.want)
			}
			if len(req.Label) > MaxLabelBytes {
				t.Errorf("label is %d bytes, over the %d limit", len(req.Label), MaxLabelBytes)
			}
		})
	}
}

func TestLabelTruncationKeepsValidUTF8(t *testing.T) {
	// Cutting at a byte count can split a rune. The label reaches a log line
	// and a terminal, so it must still be text afterwards.
	req := testRequest(t, strings.Repeat("é", MaxLabelBytes), "")
	if !utf8Valid(req.Label) {
		t.Errorf("truncated label is not valid UTF-8: %q", req.Label)
	}
	if len(req.Label) > MaxLabelBytes {
		t.Errorf("label is %d bytes, over the limit", len(req.Label))
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// TestOpenSSLReadsTheRequest is the only check in this project that the
// hand-assembled PKCS#10 is what it claims to be rather than merely what this
// package happens to parse.
func TestOpenSSLReadsTheRequest(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on this machine")
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Skipf("openssl version: %v", err)
	}
	version := strings.TrimSpace(string(out))
	if !opensslAtLeast35(version) {
		t.Skipf("%s cannot read ML-DSA; 3.5 or later is needed", version)
	}

	token := longestToken(t)
	der, err := NewCSR(testKey(t), "laptop", token)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "req.pem")
	if err := os.WriteFile(path, pemBlock("CERTIFICATE REQUEST", der), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command(bin, "req", "-in", path, "-verify", "-noout").CombinedOutput(); err != nil {
		t.Fatalf("openssl could not verify the request: %v\n%s", err, out)
	}
	text, err := exec.Command(bin, "req", "-in", path, "-text", "-noout").Output()
	if err != nil {
		t.Fatalf("openssl req -text: %v", err)
	}
	got := string(text)
	if !strings.Contains(got, "challengePassword") {
		t.Error("openssl does not see a challengePassword attribute")
	}
	if !strings.Contains(got, token) {
		t.Error("openssl does not show the token")
	}
	if !strings.Contains(got, "ML-DSA-65") {
		t.Error("openssl does not report an ML-DSA-65 key")
	}
}

func pemBlock(kind string, der []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "-----BEGIN %s-----\n", kind)
	enc := base64.StdEncoding.EncodeToString(der)
	for len(enc) > 64 {
		b.WriteString(enc[:64])
		b.WriteByte('\n')
		enc = enc[64:]
	}
	b.WriteString(enc)
	fmt.Fprintf(&b, "\n-----END %s-----\n", kind)
	return b.Bytes()
}

// opensslAtLeast35 reports whether "OpenSSL 3.5.0 ..." names 3.5 or later.
func opensslAtLeast35(version string) bool {
	fields := strings.Fields(version)
	if len(fields) < 2 || fields[0] != "OpenSSL" {
		return false
	}
	parts := strings.SplitN(fields[1], ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return major > 3 || (major == 3 && minor >= 5)
}

// lyingSigner reports one public key and signs with another: what a
// misconfigured agent, or a key named for the wrong relay, would look like.
type lyingSigner struct {
	pub  *mldsa.PublicKey
	priv *mldsa.PrivateKey
}

func (l lyingSigner) Public() crypto.PublicKey { return l.pub }
func (l lyingSigner) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return l.priv.Sign(r, msg, opts)
}

// TestNewCSRRefusesASignerThatSignsWithAnotherKey: a crypto.Signer is a
// claim, and the request's own signature is checked against the public key
// it names before the request is returned, because a request the relay
// would refuse is worth refusing here, with the reason. crypto/x509 makes
// the same check on the throwaway request it signs first, which is what
// refuses a consistently lying signer; NewCSR's own check covers the second
// signature, the one the relay sees, and is the one that would fire for a
// signer that changed its mind between the two.
func TestNewCSRRefusesASignerThatSignsWithAnotherKey(t *testing.T) {
	honest, other := testKey(t), testKey(t)
	if _, err := NewCSR(lyingSigner{honest.PublicKey(), honest}, "laptop", ""); err != nil {
		t.Fatalf("an honest signer was refused: %v", err)
	}
	_, err := NewCSR(lyingSigner{honest.PublicKey(), other}, "laptop", "")
	if err == nil {
		t.Fatal("a signer that signs with another key produced a request")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("the refusal is %q, which does not name the signature", err)
	}
	// And a signer whose public key is not ML-DSA at all.
	ed := ed25519Signer(t)
	if _, err := NewCSR(ed, "laptop", ""); err == nil || !strings.Contains(err.Error(), "not ML-DSA") {
		t.Errorf("an Ed25519 signer gave %v", err)
	}
}

func ed25519Signer(t *testing.T) crypto.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
