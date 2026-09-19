package client

import (
	"bufio"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/pki"
)

// refusing serves one 401 with the given message, as the relay would.
func refusing(t *testing.T, message string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":` + quote(message) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

func TestCertProblemAdviceNamesWhatIsWrongAndWhatToDo(t *testing.T) {
	// The whole value of these messages is that somebody reading one knows
	// the next command to type, so the exact words are pinned.
	for _, tc := range []struct {
		name     string
		message  string
		haveCert bool
		state    string
	}{
		{"no certificate at all", "this relay requires a client certificate", false, "missing"},
		{"one we hold was not offered", "this relay requires a client certificate", true, "not accepted"},
		{"unknown", "client certificate is not known to this relay", true, "not known"},
		{"revoked", "client certificate has been revoked", true, "revoked"},
		{"expired", "client certificate has expired", true, "expired"},
		{"another identity", "client certificate does not belong to the signing identity", true,
			"for another identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := refusing(t, tc.message)
			id := testIdentity(t, "alice")
			c, err := New(srv.URL, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = ClassifyCertError(c.Health(t.Context()), tc.haveCert)
			var problem *CertProblem
			if !errors.As(err, &problem) {
				t.Fatalf("%q was not classified as a certificate problem: %v", tc.message, err)
			}
			if problem.State != tc.state {
				t.Errorf("state = %q, want %q", problem.State, tc.state)
			}
			want := "this relay requires a client certificate and this machine's is " + tc.state +
				": run 'auu register --token TOKEN' with a token from an administrator"
			if got := problem.Advice("auu"); got != want {
				t.Errorf("advice is\n %q\nwant\n %q", got, want)
			}
			// The program's own name, whichever it was installed under.
			if got := problem.Advice("agentuucp"); !strings.Contains(got, "'agentuucp register") {
				t.Errorf("advice does not name the program: %q", got)
			}
		})
	}
}

func TestOtherFailuresAreNotCertificateProblems(t *testing.T) {
	// A 401 that is about the signature, or any other status, must pass
	// through untouched: telling somebody to get a certificate token when
	// their clock is wrong would send them a long way in the wrong direction.
	for _, tc := range []struct {
		name    string
		message string
		status  int
	}{
		{"unauthorized", "unauthorized", http.StatusUnauthorized},
		{"blocked", "this identity is blocked on this relay", http.StatusForbidden},
		{"not found", "no such mailbox", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":` + quote(tc.message) + `}`))
			}))
			defer srv.Close()
			c, err := New(srv.URL, testIdentity(t, "alice"), nil)
			if err != nil {
				t.Fatal(err)
			}
			err = ClassifyCertError(c.Health(t.Context()), true)
			var problem *CertProblem
			var refused *CertRefused
			if errors.As(err, &problem) || errors.As(err, &refused) {
				t.Errorf("%q was misread as a certificate problem: %v", tc.message, err)
			}
		})
	}
	if err := ClassifyCertError(nil, true); err != nil {
		t.Errorf("ClassifyCertError(nil) = %v, want nil", err)
	}
}

func TestARejectedHandshakeBecomesCertRefused(t *testing.T) {
	// The other shape a certificate failure takes: one the client did send
	// and the relay rejected. In TLS 1.3 that surfaces on the request, as a
	// *net.OpError with Op "remote error".
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216}`))
	}))
	srv.TLS = clientca.NewVerifier(bundle).TLSConfig(&tls.Config{})
	srv.StartTLS()
	defer srv.Close()

	// A certificate from this authority that expired long ago: the client
	// offers it, and the server refuses the handshake.
	expired := expiredCert(t, bundle)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	// The test's own root, since httptest's certificate is not a public one.
	// Set on the default transport, which New clones and adds to.
	restoreRoots(t, roots)
	c, err := New(srv.URL, testIdentity(t, "alice"), expired)
	if err != nil {
		t.Fatal(err)
	}

	err = ClassifyCertError(c.Health(t.Context()), true)
	var refused *CertRefused
	if !errors.As(err, &refused) {
		t.Fatalf("a rejected handshake was not classified: %v (%T)", err, err)
	}
	advice := refused.Advice("auu")
	if !strings.HasPrefix(advice, "the relay refused this machine's certificate (") {
		t.Errorf("advice does not say what happened: %q", advice)
	}
	if !strings.Contains(advice, "run 'auu register --token TOKEN' with a new token from an administrator") {
		t.Errorf("advice does not say what to do: %q", advice)
	}
}

// expiredCert issues a certificate that expired an hour ago, with its key.
func expiredCert(t *testing.T, bundle *pki.Loaded) *tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "old", "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := clientca.ParseCSR(csr, clientca.AnyParameters)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := clientca.NewIssuer(bundle).Issue(req, strings.Repeat("a", 64), time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{issued.Cert}, PrivateKey: key}
}

func TestAClientWithACertificatePresentsIt(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	seen := make(chan string, 4)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := "none"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		seen <- cn
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216}`))
	}))
	srv.TLS = clientca.NewVerifier(bundle).TLSConfig(&tls.Config{})
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	restoreRoots(t, roots)
	fp := strings.Repeat("b", 64)
	cert := issuedFor(t, bundle, fp)
	c, err := New(srv.URL, testIdentity(t, "alice"), cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Health(t.Context()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if got := <-seen; got != fp {
		t.Errorf("the server saw %q, want the certificate's subject", got)
	}

	// Without one, nothing is presented, which is what a relay that does not
	// use client certificates sees.
	plain, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// No transport of its own: it uses the default, which restoreRoots has
	// pointed at this test's authority and which carries no certificate.
	if err := plain.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "none" {
		t.Errorf("a client with no certificate presented %q", got)
	}
}

func issuedFor(t *testing.T, bundle *pki.Loaded, fp string) *tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "laptop", "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := clientca.ParseCSR(csr, clientca.AnyParameters)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := clientca.NewIssuer(bundle).Issue(req, fp, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{issued.Cert}, PrivateKey: key}
}

func testIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// restoreRoots points the default transport at a test's own certificate
// authority for the duration of one test, and puts it back afterwards.
//
// It is a process-wide setting, which is why it is restored rather than left:
// a later test that expected the real roots would otherwise fail in a way that
// had nothing to do with what it was testing.
func restoreRoots(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport)
	previous := tr.TLSClientConfig
	tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(func() { tr.TLSClientConfig = previous })
}

func TestMLDSAAsksTheRelayAndDefaultsWhenItDoesNotSay(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"the relay says 87", `{"ok":true,"mldsa":87,"max_bytes":16777216}`, 87},
		{"the relay says 44", `{"ok":true,"mldsa":44,"max_bytes":16777216}`, 44},
		{"the relay says nothing", `{"ok":true,"max_bytes":16777216}`, clientca.DefaultMLDSA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/health" {
					t.Errorf("asked %s, want /v1/health", r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c, err := New(srv.URL, testIdentity(t, "alice"), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.MLDSA(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("MLDSA = %d, want %d", got, tc.want)
			}
		})
	}
}

// deaf drops what is written to it once it is muted.
//
// It is how tlsRelay destroys a handshake alert reliably. In production the
// alert is written to the socket and then thrown away by the reset that
// follows; racing that in a test would make the test flaky, so here it is
// never written at all. What the client sees is the same either way: a
// connection reset, and no reason.
type deaf struct {
	net.Conn
	mute atomic.Bool
}

func (d *deaf) Write(p []byte) (int, error) {
	if d.mute.Load() {
		return len(p), nil
	}
	return d.Conn.Write(p)
}

// What tlsRelay does with a connection.
type verdict int

const (
	// serveHealth answers a health request.
	serveHealth verdict = iota
	// resetSilently throws the connection away with SetLinger(0), so the
	// close is a TCP reset, and swallows the alert on the way out. That is
	// the refusal a client cannot see, and the reason diagnoseRefusal
	// exists.
	resetSilently
	// refuseAloud rejects the handshake and lets the alert through,
	// draining first so the close is a FIN and the alert is not discarded.
	refuseAloud
)

// tlsRelay serves TLS on 127.0.0.1 and asks policy what to do with each
// connection, given its number from 1 and whether the client offered a
// certificate.
//
// It is by hand because httptest cannot refuse a connection these ways, and
// because the point of these tests is what happens to a connection that dies
// rather than what happens to a request that is answered.
func tlsRelay(t *testing.T, leaf tls.Certificate, policy func(n int, offeredCert bool) verdict) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for n := 1; ; n++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOrRefuse(conn, leaf, n, policy)
		}
	}()
	return "https://" + ln.Addr().String()
}

func serveOrRefuse(conn net.Conn, leaf tls.Certificate, n int, policy func(int, bool) verdict) {
	d := &deaf{Conn: conn}
	said := serveHealth
	tc := tls.Server(d, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS13,
		// RequestClientCert rather than a verifier: which connections are
		// refused is policy's decision, so that a test can refuse one
		// carrying a perfectly good certificate.
		ClientAuth: tls.RequestClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			said = policy(n, len(raw) > 0)
			if said == resetSilently {
				d.mute.Store(true)
			}
			if said != serveHealth {
				return errors.New("client certificate refused")
			}
			return nil
		},
	})
	if err := tc.Handshake(); err != nil {
		if said == resetSilently {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
		} else {
			// Read what the client sent and never got to, so that this
			// close is a FIN: a close with data unread is a reset, and a
			// reset would destroy the alert this connection is meant to
			// deliver.
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			_, _ = io.Copy(io.Discard, conn)
		}
		_ = conn.Close()
		return
	}
	defer tc.Close()
	// Read the request before answering: a close with data still unread is
	// itself a reset, which is the very thing under test.
	br := bufio.NewReader(tc)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	body := `{"ok":true,"max_bytes":16777216}`
	fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// relayLeaf is the certificate a relay built from this bundle would present.
func relayLeaf(t *testing.T, bundle *pki.Loaded) tls.Certificate {
	t.Helper()
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return *leaf
}

func TestARefusalWhoseAlertIsLostIsStillDiagnosed(t *testing.T) {
	// The failure this exists for. The relay refuses the certificate in the
	// handshake and the alert never arrives, so all the client holds is a
	// reset. Asking again with the certificate fails the same way and asking
	// without it succeeds, which is what identifies the refusal.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	url := tlsRelay(t, relayLeaf(t, bundle), func(_ int, offeredCert bool) verdict {
		if offeredCert {
			return resetSilently
		}
		return serveHealth
	})

	c, err := NewWithAnchor(url, testIdentity(t, "alice"), expiredCert(t, bundle), &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	err = ClassifyCertError(c.Health(t.Context()), true)
	var refused *CertRefused
	if !errors.As(err, &refused) {
		t.Fatalf("a refusal with no alert was not classified: %v (%T)", err, err)
	}
	if !refused.Inferred {
		t.Error("the refusal is reported as one the relay stated, and it was deduced")
	}
	advice := refused.Advice("auu")
	// The same opening as a refusal whose alert did arrive: one message
	// covers both, because the person has the same thing to do either way.
	if !strings.HasPrefix(advice, "the relay refused this machine's certificate (") {
		t.Errorf("advice does not say what happened: %q", advice)
	}
	if !strings.Contains(advice, "answered when the certificate was not offered") {
		t.Errorf("advice does not say how it was worked out: %q", advice)
	}
	if !strings.Contains(advice, "run 'auu register --token TOKEN' with a new token from an administrator") {
		t.Errorf("advice does not say what to do: %q", advice)
	}
}

func TestAConnectionThatDiesWithTheRelayStillUpIsNotBlamedOnTheCertificate(t *testing.T) {
	// A relay restarting, or a connection dropped for its own reasons. Only
	// the first connection is thrown away, and the certificate is offered
	// again on the second and accepted, so the certificate is not what the
	// two attempts differed by. Getting this wrong sends somebody to an
	// administrator for a token they do not need.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	url := tlsRelay(t, relayLeaf(t, bundle), func(n int, _ bool) verdict {
		if n == 1 {
			return resetSilently
		}
		return serveHealth
	})

	c, err := NewWithAnchor(url, testIdentity(t, "alice"), expiredCert(t, bundle), &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	err = ClassifyCertError(c.Health(t.Context()), true)
	var refused *CertRefused
	if errors.As(err, &refused) {
		t.Fatalf("a relay that answered the very next request was blamed on the certificate: %v", err)
	}
	if err == nil {
		t.Fatal("a reset connection was reported as a success")
	}
}

func TestARelayThatIsNotThereIsNotBlamedOnTheCertificate(t *testing.T) {
	// Nothing is listening, so the dial never connects: there was no
	// handshake to refuse and no alert to have been lost. What is asserted
	// is the outcome — an unreachable relay is reported as unreachable. The
	// guard on a dial error is what stops two pointless round trips being
	// spent to reach it, and it cannot be seen from out here, because a
	// probe of a dead port fails on its own.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	c, err := New("https://"+addr, testIdentity(t, "alice"), expiredCert(t, bundle))
	if err != nil {
		t.Fatal(err)
	}
	err = ClassifyCertError(c.Health(t.Context()), true)
	var refused *CertRefused
	if errors.As(err, &refused) {
		t.Fatalf("a relay that is not running was blamed on the certificate: %v", err)
	}
}

func TestAMachineWithNoCertificateIsNeverDiagnosed(t *testing.T) {
	// There is nothing to diagnose without a certificate to have offered,
	// and a machine that has not enrolled must not be told its certificate
	// was refused.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	url := tlsRelay(t, relayLeaf(t, bundle), func(int, bool) verdict { return resetSilently })

	c, err := NewWithAnchor(url, testIdentity(t, "alice"), nil, &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	err = ClassifyCertError(c.Health(t.Context()), false)
	var refused *CertRefused
	if errors.As(err, &refused) {
		t.Fatalf("a machine holding no certificate was told one was refused: %v", err)
	}
}

func TestACancelledRequestIsNotDiagnosed(t *testing.T) {
	// The caller stopped, which explains the failure on its own. Probing
	// afterwards would spend two more round trips on a question nobody
	// asked, so no connection should be made at all.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	var conns atomic.Int32
	url := tlsRelay(t, relayLeaf(t, bundle), func(int, bool) verdict {
		conns.Add(1)
		return resetSilently
	})

	c, err := NewWithAnchor(url, testIdentity(t, "alice"), expiredCert(t, bundle), &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = ClassifyCertError(c.Health(ctx), true)
	var refused *CertRefused
	if errors.As(err, &refused) {
		t.Fatalf("a cancelled request was blamed on the certificate: %v", err)
	}
	if got := conns.Load(); got != 0 {
		t.Errorf("%d connections were made to a relay after the caller cancelled, want 0", got)
	}
}

func TestARefusalTheRelayStatedIsNotProbedFor(t *testing.T) {
	// The alert arrived, so there is nothing to work out. It is reported as
	// what it is rather than as a deduction, and no second connection is
	// made: the diagnostic costs two round trips and buys nothing here.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	var conns atomic.Int32
	url := tlsRelay(t, relayLeaf(t, bundle), func(int, bool) verdict {
		conns.Add(1)
		return refuseAloud
	})

	c, err := NewWithAnchor(url, testIdentity(t, "alice"), expiredCert(t, bundle), &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	err = ClassifyCertError(c.Health(t.Context()), true)
	var refused *CertRefused
	if !errors.As(err, &refused) {
		t.Fatalf("a stated refusal was not classified: %v (%T)", err, err)
	}
	if refused.Inferred {
		t.Error("a refusal the relay stated is reported as one that was deduced")
	}
	if strings.Contains(refused.Advice("auu"), "answered when the certificate was not offered") {
		t.Errorf("advice describes a diagnostic that was not run: %q", refused.Advice("auu"))
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("%d connections were made, want 1: the relay had already said why", got)
	}
}

// dialFails is a transport that fails the test if anything is sent through
// it: the proof that a probe was not made, rather than an inference that it
// need not have been.
type dialFails struct{ t *testing.T }

func (d dialFails) RoundTrip(r *http.Request) (*http.Response, error) {
	d.t.Errorf("the probe transport was dialled for %s %s; a verification this machine refused "+
		"is nothing to probe", r.Method, r.URL)
	return nil, errors.New("the probe transport was dialled")
}

// A relay presenting a signing authority older than the one this machine
// accepted is refused by the ratchet on this side, so nothing about the
// relay's opinion of the client certificate can be learned by asking again
// without it — and the probe's transport does not run the ratchet, so it
// would accept exactly what was refused. The container suite's X09 found the
// replay probed, accepted, and reported as the relay refusing alice's
// certificate. The advice names both issue times to the second and says what
// only the operator can settle.
func TestAReplayIsNotProbedAsACertificateRefusal(t *testing.T) {
	store := pki.TestStore(t, mldsa.MLDSA65())
	older := pki.TestBundleAt(t, store, []string{"127.0.0.1"}, time.Now().Add(-time.Second))
	newer := pki.TestBundleAt(t, store, []string{"127.0.0.1"}, time.Now())
	srv := relayServing(t, older)

	// This machine has accepted the newer authority and holds a certificate.
	anchor := &Anchor{
		Cert:          older.Anchor,
		SeenSPKI:      pki.SPKI(newer.ServerInt.Cert),
		SeenNotBefore: newer.ServerInt.Cert.NotBefore,
	}
	c, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), issuedFor(t, newer, "fp"), anchor)
	if err != nil {
		t.Fatal(err)
	}
	if c.certless == nil {
		t.Fatal("a client with a certificate has no probe; the test proves nothing")
	}
	c.certless.Transport = dialFails{t}

	err = c.Health(t.Context())
	if err == nil {
		t.Fatal("the older authority was accepted")
	}
	var replayed *ReplayedAuthority
	if !errors.As(err, &replayed) || !errors.Is(err, ErrReplayedAuthority) {
		t.Fatalf("the failure is not the replay: %v", err)
	}
	var refused *CertRefused
	if errors.As(err, &refused) {
		t.Fatalf("the replay was diagnosed as a refused certificate: %v", err)
	}
	if !replayed.Presented.Equal(older.ServerInt.Cert.NotBefore) || !replayed.Accepted.Equal(newer.ServerInt.Cert.NotBefore) {
		t.Fatalf("the times are %v and %v, want the presented and accepted issue times", replayed.Presented, replayed.Accepted)
	}

	var problem *AnchorProblem
	if !errors.As(ClassifyAnchorError(err, true), &problem) || problem.Replayed == nil {
		t.Fatalf("the replay was not classified as an anchor problem carrying the replay: %v", err)
	}
	want := fmt.Sprintf("the relay presented an older signing authority than the one this machine accepted: "+
		"issued %s, replacing one issued %s. Either the relay's operator restored an earlier bundle, or "+
		"somebody is replaying a retired one. Ask the operator before doing anything; if it was theirs, "+
		"enrol again with a new token, which accepts what the relay serves now",
		older.ServerInt.Cert.NotBefore.Local().Format(StampFormat),
		newer.ServerInt.Cert.NotBefore.Local().Format(StampFormat))
	if got := problem.Advice("auu"); got != want {
		t.Fatalf("advice:\n  %q\nwant\n  %q", got, want)
	}
	// Seconds, and the two are one second apart, which minutes would hide.
	if len(StampFormat) != len("2006-01-02 15:04:05") {
		t.Fatalf("StampFormat %q does not carry seconds", StampFormat)
	}
}

// Every verification failure of this machine's own is left alone by the
// diagnostic, not only the ratchet's: an unknown authority, an invalid
// certificate and the wrong host each mean the relay never got to answer.
func TestAVerificationFailureIsNeverProbed(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	srv := relayServing(t, bundle)
	other := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())

	c, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), issuedFor(t, bundle, "fp"), &Anchor{Cert: other.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	c.certless.Transport = dialFails{t}
	err = c.Health(t.Context())
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("a relay under another anchor gave %v, want an unknown authority", err)
	}
	var refused *CertRefused
	if errors.As(err, &refused) {
		t.Fatalf("an unknown authority was diagnosed as a refused certificate: %v", err)
	}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the ratchet", &ReplayedAuthority{}, true},
		{"an unknown authority", x509.UnknownAuthorityError{}, true},
		{"an invalid certificate", x509.CertificateInvalidError{Reason: x509.Expired}, true},
		{"the wrong host", x509.HostnameError{Host: "relay"}, true},
		{"a reset", errors.New("read: connection reset by peer"), false},
		{"a bare EOF", io.EOF, false},
	} {
		if got := VerificationFailure(fmt.Errorf("contacting relay: %w", tc.err)); got != tc.want {
			t.Errorf("VerificationFailure(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The ratchet's refusal and an expired certificate are classified apart, and
// in a fixed order: the replay comes first. The two never share a chain in
// practice, since the ratchet runs only after the standard verification has
// succeeded, so this pins the order for whoever classifies expiry next.
func TestAReplayAndAnExpiryAreNotMistakenForOneAnother(t *testing.T) {
	replay := &ReplayedAuthority{Presented: time.Unix(1, 0), Accepted: time.Unix(2, 0)}
	expired := x509.CertificateInvalidError{Reason: x509.Expired}

	var problem *AnchorProblem
	if !errors.As(ClassifyAnchorError(fmt.Errorf("tls: %w", replay), true), &problem) || problem.Replayed == nil {
		t.Fatal("a replay alone was not classified as a replay")
	}
	if !errors.As(ClassifyAnchorError(fmt.Errorf("tls: %w", expired), true), &problem) || problem.Replayed != nil {
		t.Fatal("an expiry alone was classified as a replay")
	}
	// Both in one chain, which nothing produces: the replay wins.
	both := fmt.Errorf("%w: %w", replay, expired)
	if !errors.As(ClassifyAnchorError(both, true), &problem) || problem.Replayed == nil {
		t.Fatal("a chain carrying both was not reported as the replay")
	}
}

// A relay whose certificate has run out is the operator's to fix, and
// nothing on this machine is wrong: the advice says so and does not send
// the user to enrol again, which would accept the same expired chain. The
// fixture is built in the past — an authority two years old, a bundle
// issued and loaded as of then, whose year has passed — rather than by
// waiting. The container suite's X05 found "certificate has expired" inside
// the brackets of the rebuilt-relay advice.
func TestAnExpiredRelayCertificateIsSaidToBe(t *testing.T) {
	twoYearsAgo := time.Now().AddDate(-2, 0, 0)
	store, err := pki.Create(t.TempDir(), "Test", mldsa.MLDSA65(), keyfile.TestPassphrase("test"), twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}
	expired := pki.TestLoadedAt(t, store, []string{"127.0.0.1"}, twoYearsAgo)
	if !expired.ServerInt.Cert.NotAfter.Before(time.Now()) {
		t.Fatal("the fixture's intermediate has not expired; the test proves nothing")
	}
	server, err := clientca.NewServer(expired, twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	for _, pinned := range []bool{true, false} {
		anchor := &Anchor{Cert: expired.Anchor}
		c, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, anchor)
		if err != nil {
			t.Fatal(err)
		}
		err = c.Health(t.Context())
		if err == nil {
			t.Fatal("an expired chain was accepted")
		}
		if !RelayExpired(err) {
			t.Fatalf("the failure is not the relay's expiry: %v", err)
		}
		var problem *AnchorProblem
		if !errors.As(ClassifyAnchorError(err, pinned), &problem) || !problem.Expired {
			t.Fatalf("pinned %v: not classified as the relay's expiry: %v", pinned, err)
		}
		want := "the relay's certificate has expired; its operator needs to run 'auu-ca relay' on the offline " +
			"machine and replace the bundle. Nothing on this machine is wrong"
		if got := problem.Advice("auu"); got != want {
			t.Fatalf("pinned %v: advice\n  %q\nwant\n  %q", pinned, got, want)
		}
	}
	// And what is not an expiry is not called one.
	for _, other := range []error{
		x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign},
		x509.UnknownAuthorityError{},
		errors.New("read: connection reset by peer"),
	} {
		if RelayExpired(fmt.Errorf("contacting relay: %w", other)) {
			t.Errorf("%v was called the relay's expiry", other)
		}
	}
}
