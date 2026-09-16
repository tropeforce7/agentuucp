package pki

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

func hierarchy(t *testing.T) *Store {
	t.Helper()
	return TestStore(t, mldsa.MLDSA65())
}

func TestTheAnchorAndAuthoritiesAreShapedAsIntended(t *testing.T) {
	s := hierarchy(t)

	if !s.Anchor.Cert.IsCA || s.Anchor.Cert.MaxPathLen != 2 {
		t.Errorf("anchor: IsCA=%v MaxPathLen=%d, want true and 2 — two levels below it",
			s.Anchor.Cert.IsCA, s.Anchor.Cert.MaxPathLen)
	}
	if len(s.Anchor.Cert.ExtKeyUsage) != 0 {
		t.Error("the anchor carries an extended key usage; it would constrain both branches")
	}
	if ou := s.Anchor.Cert.Subject.OrganizationalUnit; len(ou) != 1 || len(ou[0]) != 2*uniqueBytes {
		t.Errorf("the anchor's subject is not unique: OU=%v", ou)
	}
	for _, tc := range []struct {
		name string
		key  *Key
		eku  x509.ExtKeyUsage
	}{
		{"server CA", s.Server, x509.ExtKeyUsageServerAuth},
		{"client CA", s.Client, x509.ExtKeyUsageClientAuth},
	} {
		if !tc.key.Cert.IsCA || tc.key.Cert.MaxPathLen != 1 {
			t.Errorf("%s: IsCA=%v MaxPathLen=%d, want true and 1",
				tc.name, tc.key.Cert.IsCA, tc.key.Cert.MaxPathLen)
		}
		if len(tc.key.Cert.ExtKeyUsage) != 1 || tc.key.Cert.ExtKeyUsage[0] != tc.eku {
			t.Errorf("%s: ExtKeyUsage=%v, want exactly its own purpose", tc.name, tc.key.Cert.ExtKeyUsage)
		}
	}
	// Two anchors must never share a subject: a client offers a certificate
	// based on the authority subjects a server advertises.
	if hierarchy(t).Anchor.Cert.Subject.String() == s.Anchor.Cert.Subject.String() {
		t.Error("two anchors share a subject")
	}
}

// TestTheBranchesCannotSignForEachOther is the reason there are two, and it
// is enforced by Go's verifier rather than by anybody remembering.
func TestTheBranchesCannotSignForEachOther(t *testing.T) {
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com"})

	roots := poolOf(l.Anchor)
	for _, tc := range []struct {
		name     string
		signer   *Key
		chain    []*x509.Certificate
		leafEKU  x509.ExtKeyUsage
		checkFor x509.ExtKeyUsage
		want     bool
	}{
		{"client leaf under the client branch", l.ClientInt, l.ClientChain,
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth, true},
		{"server leaf under the client branch", l.ClientInt, l.ClientChain,
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageServerAuth, false},
		{"client leaf under the server branch", l.ServerInt, l.ServerChain,
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := leafUnder(t, tc.signer, tc.leafEKU, "relay.example.com")
			inter := poolOf(append([]*x509.Certificate{tc.signer.Cert}, tc.chain...)...)
			_, err := leaf.Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{tc.checkFor},
			})
			if tc.want && err != nil {
				t.Errorf("%s was refused: %v", tc.name, err)
			}
			if !tc.want && err == nil {
				t.Errorf("%s verified; the branches are not separated", tc.name)
			}
		})
	}
}

// TestASigningIntermediateCannotMakeAnother: path length zero, so a stolen
// key cannot grow into an authority.
func TestASigningIntermediateCannotMakeAnother(t *testing.T) {
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com"})
	for _, k := range []*Key{l.ServerInt, l.ClientInt} {
		if !k.Cert.MaxPathLenZero {
			t.Errorf("%s may issue a further authority", k.Cert.Subject.CommonName)
		}
	}
	sub, err := issueCA(l.ClientInt, &x509.Certificate{
		Subject:               pkixName("sub"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, l.Params)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafUnder(t, sub, x509.ExtKeyUsageClientAuth, "")
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         poolOf(l.Anchor),
		Intermediates: poolOf(append([]*x509.Certificate{sub.Cert, l.ClientInt.Cert}, l.ClientChain...)...),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Fatal("a certificate under a sub-authority verified; path length is not enforced")
	}
}

// TestTheServerIntermediateSignsForItsOwnRelayAndNoOther: the name constraint
// is what makes a stolen server intermediate worth no more than a stolen leaf.
func TestTheServerIntermediateSignsForItsOwnRelayAndNoOther(t *testing.T) {
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com", "10.0.0.5", "::1"})
	roots := poolOf(l.Anchor)
	inter := poolOf(append([]*x509.Certificate{l.ServerInt.Cert}, l.ServerChain...)...)

	for _, tc := range []struct {
		host string
		want bool
	}{
		{"relay.example.com", true},
		{"sub.relay.example.com", true}, // a DNS constraint permits below it
		{"10.0.0.5", true},
		{"::1", true},
		{"evil.example.org", false},
		{"10.0.0.6", false},
		{"relay.example.com.evil.org", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			leaf, err := ServerLeaf(l.ServerInt, []string{tc.host}, l.Params, time.Now())
			if err != nil {
				if tc.want {
					t.Fatalf("could not issue for %s: %v", tc.host, err)
				}
				return
			}
			name := tc.host
			_, err = leaf.Cert.Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSName:   name,
			})
			if tc.want && err != nil {
				t.Errorf("%s was refused: %v", tc.host, err)
			}
			if !tc.want && err == nil {
				t.Errorf("%s verified; the name constraint is not enforced", tc.host)
			}
		})
	}
}

// TestTheExportWithholdsEveryOfflineKey is the property the whole design
// rests on: a relay's disk yields the power to be that relay, and never the
// power to extend trust.
//
// Every field is decoded before it is searched. An earlier version of this
// test compared raw DER against the JSON, where certificates are base64, so it
// could never have failed — a test that cannot fail is worse than no test,
// because it is counted.
func TestTheExportWithholdsEveryOfflineKey(t *testing.T) {
	s := hierarchy(t)
	first, _, err := s.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Rotate, so a retired intermediate exists to be leaked too.
	second, _, err := s.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	// Every byte string the bundle carries, decoded: the file's own bytes
	// prove nothing, because everything in it is base64.
	haystack := decodedFields(t, encoded)

	// First, prove the search works, or everything below is vacuous.
	if !containsAny(haystack, second.ClientIntKey) {
		t.Fatal("the search cannot find a key the bundle certainly contains; " +
			"every assertion below would be meaningless")
	}

	for _, tc := range []struct {
		name string
		key  *mldsa.PrivateKey
	}{
		{"the trust anchor's key", s.Anchor.Key},
		{"the Server CA's key", s.Server.Key},
		{"the Client CA's key", s.Client.Key},
	} {
		der, err := x509.MarshalPKCS8PrivateKey(tc.key)
		if err != nil {
			t.Fatal(err)
		}
		if containsAny(haystack, der) {
			t.Errorf("the bundle contains %s", tc.name)
		}
		if containsAny(haystack, tc.key.Bytes()) {
			t.Errorf("the bundle contains the seed of %s", tc.name)
		}
	}

	// The retired client intermediate's certificate is carried, so what it
	// issued still verifies; its key is not, and neither is the retired
	// server intermediate, which nothing needs.
	if !containsAny(haystack, first.ClientIntCert) {
		t.Error("the bundle does not carry the retired client intermediate's certificate; " +
			"certificates it issued would stop verifying")
	}
	if containsAny(haystack, first.ClientIntKey) {
		t.Error("the bundle carries a retired intermediate's key")
	}
	if containsAny(haystack, first.ServerIntCert) {
		t.Error("the bundle carries a retired server intermediate; nothing needs it")
	}
	if containsAny(haystack, first.ServerIntKey) {
		t.Error("the bundle carries a retired server intermediate's key")
	}
}

// decodedFields is every byte string in an encoded bundle, decoded, plus the
// raw file, so a search covers both forms.
func decodedFields(t *testing.T, encoded []byte) [][]byte {
	t.Helper()
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &probe); err != nil {
		t.Fatal(err)
	}
	out := [][]byte{encoded}
	for _, raw := range probe {
		var one []byte
		if err := json.Unmarshal(raw, &one); err == nil {
			out = append(out, one)
			continue
		}
		var many [][]byte
		if err := json.Unmarshal(raw, &many); err == nil {
			out = append(out, many...)
		}
	}
	return out
}

func containsAny(haystack [][]byte, needle []byte) bool {
	for _, h := range haystack {
		if bytes.Contains(h, needle) {
			return true
		}
	}
	return false
}

func TestARotationKeepsEarlierClientCertificatesVerifiable(t *testing.T) {
	s := hierarchy(t)
	before := TestBundleFrom(t, s, []string{"relay.example.com"})
	leaf := leafUnder(t, before.ClientInt, x509.ExtKeyUsageClientAuth, "")

	after := TestBundleFrom(t, s, []string{"relay.example.com"})
	if after.ClientInt.Cert.Equal(before.ClientInt.Cert) {
		t.Fatal("a rotation reused the intermediate")
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         poolOf(after.Anchor),
		Intermediates: poolOf(after.ClientPool...),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("a certificate issued before the rotation no longer verifies: %v", err)
	}
}

func TestLifetimesAreClampedToTheChain(t *testing.T) {
	// A certificate outliving its issuer would verify until the issuer
	// expired and then stop, on a date nothing warned about.
	s := hierarchy(t)
	_, warnings, err := s.IssueRelay([]string{"relay.example.com"}, 50, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 {
		t.Errorf("clamping produced %d warnings, want one per intermediate: %v", len(warnings), warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "clamped") {
			t.Errorf("warning %q does not say it clamped", w)
		}
	}
	l := TestBundleFrom(t, s, []string{"relay.example.com"})
	if l.ServerInt.Cert.NotAfter.After(s.Server.Cert.NotAfter) {
		t.Error("the server intermediate outlives its authority")
	}
	leaf, err := ServerLeaf(l.ServerInt, l.Hosts, l.Params, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Cert.NotAfter.After(l.ServerInt.Cert.NotAfter) {
		t.Error("the relay's own certificate outlives the intermediate that signed it")
	}
}

func TestABundleRoundTripsAndIsCheckedOnTheWayIn(t *testing.T) {
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com"})
	if l.AnchorSPKI != SPKI(s.Anchor.Cert) {
		t.Error("the loaded bundle does not name its own anchor")
	}
	if ParameterNumberOf(l.Params) != 65 {
		t.Errorf("params = %v", l.Params)
	}
}

// leafUnder issues a leaf directly, for the shapes IssueRelay would not make.
func leafUnder(t *testing.T, parent *Key, eku x509.ExtKeyUsage, host string) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(parent.Key.PublicKey().Parameters())
	if err != nil {
		t.Fatal(err)
	}
	sn, err := serial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkixName("leaf"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{host}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, key.PublicKey(), parent.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// pkixName is a subject with just a common name.
func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

// TestAConstraintOnOneKindOfNameClosesTheOther: a name constraint restricts
// only its own kind. Without the blanket exclusion, an intermediate for a
// DNS name could sign for any IP address and one for an address could sign
// for any DNS name — the first version of this package did exactly that, and
// the mixed-host test above never noticed because both kinds were present.
func TestAConstraintOnOneKindOfNameClosesTheOther(t *testing.T) {
	s := hierarchy(t)
	for _, tc := range []struct {
		host, other string
	}{
		{"relay.example.com", "203.0.113.9"},
		{"10.0.0.5", "evil.example.com"},
		{"::1", "evil.example.com"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			l := TestBundleFrom(t, s, []string{tc.host})
			inter := poolOf(append([]*x509.Certificate{l.ServerInt.Cert}, l.ServerChain...)...)
			for _, name := range []string{tc.host, tc.other} {
				leaf := leafUnder(t, l.ServerInt, x509.ExtKeyUsageServerAuth, name)
				_, err := leaf.Verify(x509.VerifyOptions{
					Roots: poolOf(l.Anchor), Intermediates: inter,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					DNSName:   name,
				})
				if name == tc.host && err != nil {
					t.Errorf("the relay's own name %s was refused: %v", name, err)
				}
				if name != tc.host && err == nil {
					t.Errorf("an intermediate for %s signed for %s; the other kind of name is open",
						tc.host, name)
				}
			}
		})
	}
}

func TestAnExpiredIntermediateMintsNoLeaf(t *testing.T) {
	// Past its expiry the clamp would produce a leaf already expired, and a
	// relay would serve it without noticing anything was wrong.
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com"})
	after := l.ServerInt.Cert.NotAfter.Add(time.Second)
	_, err := ServerLeaf(l.ServerInt, l.Hosts, l.Params, after)
	if err == nil {
		t.Fatal("a leaf was minted from an expired intermediate")
	}
	if !strings.Contains(err.Error(), "auu-ca relay") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

// TestAnExpiredRetiredIntermediateDoesNotStopTheBundleLoading is the relay
// restarting a year after a rotation. The retired intermediate has expired,
// and so has everything it issued, so it verifies nothing — but the first
// version of the loader verified it anyway, and refused the whole bundle.
func TestAnExpiredRetiredIntermediateDoesNotStopTheBundleLoading(t *testing.T) {
	twoYearsAgo := time.Now().AddDate(-2, 0, 0)
	s, err := Create(t.TempDir(), "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{"relay.example.com"}
	old, _, err := s.IssueRelay(hosts, 1, twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}

	// The rotation, now: the expired one is not carried.
	current, _, err := s.IssueRelay(hosts, 1, time.Now())
	if err != nil {
		t.Fatalf("a rotation after the retired intermediate expired: %v", err)
	}
	if n := len(current.ClientChain); n != 1 {
		t.Errorf("the rotated bundle carries %d certificates in client_chain, want only the Client CA", n)
	}

	// And a bundle already on a relay's disk that carries it still loads,
	// with the expired one dropped rather than the relay refusing to start.
	current.ClientChain = append(current.ClientChain, old.ClientIntCert)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteBundle(path, current); err != nil {
		t.Fatal(err)
	}
	l, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("a bundle carrying an expired retired intermediate does not load: %v", err)
	}
	if n := len(l.ClientPool); n != 2 {
		t.Errorf("the loaded pool holds %d certificates, want the current intermediate and the Client CA", n)
	}
}

func TestARotationFindsTheRelayByAnyOfItsHosts(t *testing.T) {
	// The same relay, its hosts listed in another order. Treating that as a
	// new relay would drop the retired intermediate and break every
	// certificate it issued.
	s := hierarchy(t)
	first := TestBundleFrom(t, s, []string{"relay.example.com", "10.0.0.5"})
	second := TestBundleFrom(t, s, []string{"10.0.0.5", "relay.example.com"})
	found := false
	for _, c := range second.ClientChain {
		if c.Equal(first.ClientInt.Cert) {
			found = true
		}
	}
	if !found {
		t.Fatal("reordering the hosts lost the retired client intermediate")
	}
	relays, err := s.Relays()
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 {
		t.Errorf("the store now has %d relays, want 1: %v", len(relays), relays)
	}
}
