package clientca

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyAcceptsThisAuthoritysCertificate(t *testing.T) {
	ca := testCA(t)
	if err := ca.Verify(issueFor(t, ca, testFP), time.Now()); err != nil {
		t.Fatalf("Verify of our own certificate: %v", err)
	}
}

func TestVerifyRefusesWhatItMust(t *testing.T) {
	ca := testCA(t)
	other := testCA(t)

	t.Run("another authority", func(t *testing.T) {
		err := ca.Verify(issueFor(t, other, testFP), time.Now())
		if !errors.Is(err, ErrCertUntrusted) {
			t.Fatalf("%v, want ErrCertUntrusted", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		leaf := issueFor(t, ca, testFP)
		// One second past its own expiry, which is the boundary that
		// matters: at NotAfter it is still good.
		if err := ca.Verify(leaf, leaf.NotAfter.Add(time.Second)); !errors.Is(err, ErrCertUntrusted) {
			t.Errorf("one second after expiry: %v, want ErrCertUntrusted", err)
		}
		if err := ca.Verify(leaf, leaf.NotAfter); err != nil {
			t.Errorf("at the moment of expiry: %v, want it still valid", err)
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		leaf := issueFor(t, ca, testFP)
		if err := ca.Verify(leaf, leaf.NotBefore.Add(-time.Second)); !errors.Is(err, ErrCertUntrusted) {
			t.Errorf("one second before validity: %v, want ErrCertUntrusted", err)
		}
	})

	t.Run("a server certificate", func(t *testing.T) {
		// A relay's own certificate, or anything else meant for server
		// authentication, must not be usable as a client's.
		leaf := signedBy(t, ca, testFP, x509.ExtKeyUsageServerAuth, time.Now(), time.Hour)
		if err := ca.Verify(leaf, time.Now()); !errors.Is(err, ErrCertUntrusted) {
			t.Errorf("a serverAuth certificate: %v, want ErrCertUntrusted", err)
		}
	})

	t.Run("a subject that is not a fingerprint", func(t *testing.T) {
		for _, cn := range []string{"laptop", "", strings.ToUpper(testFP), testFP[:63], testFP + "0"} {
			leaf := signedBy(t, ca, cn, x509.ExtKeyUsageClientAuth, time.Now(), time.Hour)
			if err := ca.Verify(leaf, time.Now()); !errors.Is(err, ErrCertSubject) {
				t.Errorf("a certificate for subject %q: %v, want ErrCertSubject", cn, err)
			}
		}
	})

	t.Run("nothing at all", func(t *testing.T) {
		if err := ca.Verify(nil, time.Now()); !errors.Is(err, ErrCertUntrusted) {
			t.Errorf("a nil certificate: %v, want ErrCertUntrusted", err)
		}
	})
}

// signedBy issues a certificate outside Issue's template, for the shapes a
// well-behaved relay would never produce but an attacker might send.
func signedBy(t *testing.T, ca *CA, cn string, eku x509.ExtKeyUsage, now time.Time, life time.Duration) *x509.Certificate {
	t.Helper()
	key := testKey(t)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}, ca.Certificate(), key.PublicKey(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// serverFor starts a TLS server that requires this authority's client
// certificates and reports the subject of whatever it was shown.
func serverFor(t *testing.T, ca *CA) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			io.WriteString(w, "none")
			return
		}
		io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	// The server's own certificate is a throwaway; only the client half of
	// the handshake is under test.
	srv.TLS = ca.TLSConfig(&tls.Config{})
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// clientWith dials the server presenting cert, or nothing when it is nil.
func clientWith(t *testing.T, srv *httptest.Server, cert *tls.Certificate, max uint16) (string, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		MinVersion: tls.VersionTLS12}
	if max != 0 {
		cfg.MaxVersion = max
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// keyPair pairs a leaf with a key the test holds.
func keyPair(t *testing.T, ca *CA, fp string) *tls.Certificate {
	t.Helper()
	key := testKey(t)
	der, err := NewCSR(key, "laptop", "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseCSR(der, mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.Issue(req, fp, time.Now(), testLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{issued.Cert}, PrivateKey: key}
}

func TestHandshakePresentsOurCertificate(t *testing.T) {
	ca := testCA(t)
	srv := serverFor(t, ca)
	got, err := clientWith(t, srv, keyPair(t, ca, testFP), 0)
	if err != nil {
		t.Fatalf("connecting with our own certificate: %v", err)
	}
	if got != testFP {
		t.Errorf("the server saw %q, want the fingerprint", got)
	}
}

func TestHandshakeWithoutACertificateSucceedsWithNone(t *testing.T) {
	// A machine that has not enrolled must still reach POST /v1/register,
	// so the handshake asks for a certificate rather than requiring one.
	ca := testCA(t)
	srv := serverFor(t, ca)
	got, err := clientWith(t, srv, nil, 0)
	if err != nil {
		t.Fatalf("connecting with no certificate: %v", err)
	}
	if got != "none" {
		t.Errorf("the server saw %q, want none", got)
	}
}

func TestACertificateFromAnotherAuthorityIsNeverOffered(t *testing.T) {
	// The client picks what to send from the CA subjects the server
	// advertises, so a certificate from another authority is simply not
	// sent: the handshake succeeds with none and the refusal happens at the
	// HTTP layer. The client's advice message depends on this, which is why
	// it is pinned here.
	ca, other := testCA(t), testCA(t)
	srv := serverFor(t, ca)
	got, err := clientWith(t, srv, keyPair(t, other, testFP), 0)
	if err != nil {
		t.Fatalf("connecting with another authority's certificate: %v, "+
			"want a completed handshake carrying nothing", err)
	}
	if got != "none" {
		t.Errorf("the server saw %q, want none", got)
	}
}

func TestARejectedCertificateFailsAsARemoteError(t *testing.T) {
	// The other half: a certificate the client does send and the server
	// refuses. In TLS 1.3 the client learns of it after the dial, on the
	// first read, and it arrives as a *net.OpError whose Op is "remote
	// error" — never as a tls.AlertError, which is QUIC's. internal/client
	// turns exactly this into its advice.
	ca := testCA(t)
	key := testKey(t)
	expired := signedByKey(t, ca, key, testFP, time.Now().Add(-2*testLifetime))

	err := refusedInHandshake(t, ca, &tls.Certificate{Certificate: [][]byte{expired}, PrivateKey: key})
	if err == nil {
		t.Fatal("an expired certificate was accepted")
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" {
		t.Fatalf("error is %v (%T); want a *net.OpError with Op \"remote error\"", err, err)
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		t.Error("the error is a tls.AlertError; the client's advice does not look for one")
	}
}

// refusedInHandshake dials a server that will reject cert, and returns the
// error the client is left holding.
//
// It serves the connection itself instead of using serverFor, because of what
// happens after the refusal. crypto/tls gives up on the client's Certificate
// message, so the CertificateVerify and Finished behind it are still in the
// server's receive queue, unread, and a socket closed with data unread is
// reset rather than shut down. The reset discards whatever the client has not
// read yet, which is the alert saying why: the client is told "connection
// reset by peer", or "broken pipe" on macOS, and never learns the reason.
// Draining first makes the close a FIN, so the alert always arrives.
//
// The client reads rather than sending a request for the same reason. An
// http.Client writes before it reads and returns the write error, so losing
// that race hides the alert even when it did arrive. That is what CI caught,
// and twelve copies of `go test -race -count=20` reproduce it: four failures
// in 240.
func refusedInHandshake(t *testing.T, ca *CA, cert *tls.Certificate) error {
	t.Helper()
	// StartTLS supplies a server certificate and a client that trusts it.
	// Borrow both; the serving below is what has to be done by hand.
	srv := serverFor(t, ca)
	cfg := srv.TLS.Clone()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := tls.Server(conn, cfg)
		if err := sc.Handshake(); err == nil {
			// Accepted, which is the failure this test exists to
			// catch. Answer, so that the client's read returns no
			// error rather than the EOF of a silent close.
			sc.Write([]byte("ok"))
			return
		}
		// The alert has been sent. Read the rest of what the client
		// said and let it close first, so that this close is a FIN.
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		io.Copy(io.Discard, conn)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{
		RootCAs:      srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName:   "127.0.0.1",
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	if err = tc.Handshake(); err == nil {
		_, err = tc.Read(make([]byte, 1))
	}
	c.Close()
	<-served
	return err
}

// signedByKey issues for a specific key at a specific time, so a test can
// hold the key of an expired certificate.
func signedByKey(t *testing.T, ca *CA, key *mldsa.PrivateKey, fp string, issuedAt time.Time) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: fp},
		NotBefore: issuedAt, NotAfter: issuedAt.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, ca.Certificate(), key.PublicKey(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestHandshakeRefusesTLS12(t *testing.T) {
	// ML-DSA is TLS 1.3 only, and 1.3 is also the first version to encrypt
	// the client's certificate rather than send the fingerprint in it in
	// the clear.
	ca := testCA(t)
	srv := serverFor(t, ca)
	if _, err := clientWith(t, srv, keyPair(t, ca, testFP), tls.VersionTLS12); err == nil {
		t.Fatal("a TLS 1.2 connection was accepted")
	}
}

func TestTLSConfigSetsWhatTheRelayNeeds(t *testing.T) {
	ca := testCA(t)
	cfg := ca.TLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.ClientCAs != ca.Pool() {
		t.Error("ClientCAs is not this authority's pool")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3; it must raise a lower one", cfg.MinVersion)
	}
}
