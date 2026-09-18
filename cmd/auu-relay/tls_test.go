package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned writes a certificate and key for localhost to dir and returns the
// two paths plus a pool that trusts it.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		// httptest listens on a loopback address, so the certificate needs the
		// matching IP SANs for verification to succeed.
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not build a trust pool for the test certificate")
	}
	return certPath, keyPath, pool
}

// A relay in files mode must actually serve TLS that a client trusting the
// certificate can complete a request over.
func TestFilesModeServesTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := selfSigned(t, dir)

	cfg := Defaults()
	cfg.TLS.Mode = ModeFiles
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath

	tlsCfg, err := buildTLS(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion %x, want TLS 1.3", tlsCfg.MinVersion)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected the loaded pair, got %d certificates", len(tlsCfg.Certificates))
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"ok":true}`)
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}}}
	resp, err := client.Get(srv.URL + "/v1/health")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("body %q", body)
	}
}

func TestFilesModeMissingFilesFails(t *testing.T) {
	cfg := Defaults()
	cfg.TLS.Mode = ModeFiles
	cfg.TLS.CertFile = filepath.Join(t.TempDir(), "missing.pem")
	cfg.TLS.KeyFile = filepath.Join(t.TempDir(), "missing.key")
	if _, err := buildTLS(cfg, nil); err == nil {
		t.Fatal("buildTLS accepted missing certificate files")
	}
}

func TestOffModeHasNoTLS(t *testing.T) {
	cfg := Defaults()
	cfg.TLS.Mode = ModeOff
	tlsCfg, err := buildTLS(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		t.Fatal("off mode must produce no TLS config")
	}
}

// pinnedListener starts a TLS listener with the relay's config for one
// branch and answers a health line, for handshakes to be tried against.
func pinnedListener(t *testing.T, tlsCfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The relay refuses a client that offers only X25519, and one capped at
// TLS 1.2, on both branches — the certificate files and the self-minted
// leaf — and a client offering the hybrid over 1.3 succeeds on the same
// listener, so the refusals are the pin and not a broken listener. The
// handshake is made with tls.Dial, which is where a refusal is seen.
func TestTheRelayRefusesAnythingButTheHybridOverTLS13(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := selfSigned(t, dir)
	files := Defaults()
	files.TLS.Mode = ModeFiles
	files.TLS.CertFile = certPath
	files.TLS.KeyFile = keyPath
	fromFiles, err := buildTLS(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	minted := certConfig(t)
	if err := minted.Validate(); err != nil {
		t.Fatal(err)
	}
	parts, err := openBundle(minted)
	if err != nil {
		t.Fatal(err)
	}
	fromBundle, err := buildTLS(minted, parts)
	if err != nil {
		t.Fatal(err)
	}
	for _, branch := range []struct {
		name string
		cfg  *tls.Config
	}{{"certificate files", fromFiles}, {"self-minted leaf", fromBundle}} {
		t.Run(branch.name, func(t *testing.T) {
			if branch.cfg.MinVersion != tls.VersionTLS13 || len(branch.cfg.CurvePreferences) != 1 || branch.cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
				t.Fatalf("the branch is not pinned: MinVersion %x, curves %v", branch.cfg.MinVersion, branch.cfg.CurvePreferences)
			}
			srv := pinnedListener(t, branch.cfg)
			addr := strings.TrimPrefix(srv.URL, "https://")
			// The certificate is not the point here: the handshake fails
			// or succeeds on the key exchange and the version before any
			// verification, and the files branch has a self-signed cert
			// the pool knows while the minted one has the bundle's chain.
			base := &tls.Config{InsecureSkipVerify: true, RootCAs: pool}
			for _, c := range []struct {
				label string
				cfg   *tls.Config
				want  string
			}{
				{"only X25519", &tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}}, "tls: handshake failure"},
				{"capped at 1.2", &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, "tls: protocol version not supported"},
			} {
				conn, err := tls.Dial("tcp", addr, c.cfg)
				if err == nil {
					conn.Close()
					t.Fatalf("a client offering %s completed the handshake", c.label)
				}
				if !strings.Contains(err.Error(), c.want) {
					t.Fatalf("a client offering %s: %v, want %q", c.label, err, c.want)
				}
			}
			hybrid := base.Clone()
			hybrid.MinVersion = tls.VersionTLS13
			hybrid.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
			conn, err := tls.Dial("tcp", addr, hybrid)
			if err != nil {
				t.Fatalf("the hybrid over 1.3 was refused: %v", err)
			}
			defer conn.Close()
			st := conn.ConnectionState()
			if st.Version != tls.VersionTLS13 || st.CurveID != tls.X25519MLKEM768 {
				t.Fatalf("the handshake that succeeded used version %x and curve %v", st.Version, st.CurveID)
			}
		})
	}
}

// The relay's half of the regression: on a connection that succeeds, the
// relay's own view of the handshake is TLS 1.3 with X25519MLKEM768, on
// both branches, and a client built with Go's defaults — the pin removed
// on that side — is still held to the hybrid, since Go's default offers
// it; a client that does not offer it is refused, above. A future Go
// default that dropped or reordered the hybrid, or an edit that lost the
// relay's pin, fails here rather than negotiating less.
func TestNeitherEndAcceptsLessThanTheHybridOverTLS13(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := selfSigned(t, dir)
	files := Defaults()
	files.TLS.Mode = ModeFiles
	files.TLS.CertFile = certPath
	files.TLS.KeyFile = keyPath
	fromFiles, err := buildTLS(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	minted := certConfig(t)
	if err := minted.Validate(); err != nil {
		t.Fatal(err)
	}
	parts, err := openBundle(minted)
	if err != nil {
		t.Fatal(err)
	}
	fromBundle, err := buildTLS(minted, parts)
	if err != nil {
		t.Fatal(err)
	}
	for _, branch := range []struct {
		name string
		cfg  *tls.Config
	}{{"certificate files", fromFiles}, {"self-minted leaf", fromBundle}} {
		t.Run(branch.name, func(t *testing.T) {
			var seen tls.ConnectionState
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = *r.TLS
				io.WriteString(w, `{"ok":true}`)
			}))
			srv.TLS = branch.cfg
			srv.StartTLS()
			defer srv.Close()
			// A client with Go's defaults and no pin of its own.
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			resp, err := client.Get(srv.URL + "/v1/health")
			if err != nil {
				t.Fatalf("a Go-default client against the pinned relay: %v", err)
			}
			resp.Body.Close()
			for _, end := range []struct {
				name string
				st   tls.ConnectionState
			}{{"the client's", *resp.TLS}, {"the relay's", seen}} {
				if end.st.Version != tls.VersionTLS13 || end.st.CurveID != tls.X25519MLKEM768 {
					t.Errorf("%s view of the handshake is version %x curve %v; want TLS 1.3 and X25519MLKEM768", end.name, end.st.Version, end.st.CurveID)
				}
			}
		})
	}
}
