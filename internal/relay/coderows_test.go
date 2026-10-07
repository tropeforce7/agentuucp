package relay

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// Each refusal a client acts on is proved here end to end, at a real relay
// and read by the real client where the client has a decision to make, so
// that a relay writing the sentence without its code fails a test rather
// than leaving a client to fall back on words it no longer reads.

// TestANeedsNewerRefusalReachesTheClientAsItsSentinel: a hand-over carrying a
// critical section the relay does not know, sent by client.Client to a real
// relay that admits the courier signing it. What the courier's worker acts on
// is errors.Is(err, client.ErrRelayNeedsNewer), which reads the status and the
// code and never the sentence; so the test holds the sentinel, the status,
// the code and the sentence, each from the relay's own answer.
//
// The same request with the section not critical is then taken, so the
// refusal is the section's doing and not the envelope's or the courier's.
func TestANeedsNewerRefusalReachesTheClientAsItsSentinel(t *testing.T) {
	ch := newChain(t)
	bob := ch.c.user(t, "bob")

	c, err := client.New(ch.c.srv.URL, ch.bCourier, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := request(sealedFor(bob.Fingerprint(), "for bob"), nil, []string{"alpha"})
	req.Sections = relayapi.Sections{Sections: []wire.Section{
		{Name: "must-know", Critical: true, Data: json.RawMessage("1")},
	}}

	_, err = c.Forward(context.Background(), req)
	if !errors.Is(err, client.ErrRelayNeedsNewer) {
		t.Fatalf("a hand-over with a critical section the relay does not know: %v, want ErrRelayNeedsNewer", err)
	}
	var he *client.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("the refusal is not an HTTPError: %T %v", err, err)
	}
	want := fmt.Sprintf(relayapi.MsgNeedsNewer, relayapi.WireLevel, "must-know")
	if he.Status != http.StatusBadRequest || he.Code != relayapi.CodeNeedsNewer || he.Message != want {
		t.Errorf("the client read %d %q %q, want %d %q %q",
			he.Status, he.Code, he.Message, http.StatusBadRequest, relayapi.CodeNeedsNewer, want)
	}

	// The control: the one bit flipped, and the relay takes it.
	req.Sections.Sections[0].Critical = false
	id, err := c.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("the same hand-over with the section not critical: %v", err)
	}
	if msgs := ch.c.stored(t, bob.Fingerprint()); len(msgs) != 1 || msgs[0].ID != id {
		t.Errorf("bob's mailbox after the hand-over is taken: %+v, want the one message %d", msgs, id)
	}
}

// TestACertificateThatCannotBeReadIsRefusedUnderItsOwnCode: a certificate the
// relay cannot read as one of its own is refused 401 under cert-refused, with
// the reason after the sentence, and never under one of the five codes a
// client turns into advice.
//
// The relay's own listener cannot be made to deliver such a certificate: its
// handshake runs clientca's Verify, which checks the subject as well as the
// chain, so the one path to certRefused that exists — a leaf whose subject
// fails clientca.Subject — is refused before HTTP. The test holds that first,
// over the harness's listener. It then serves the same relay, the same
// handler over the same store, behind a listener that asks for any
// certificate and verifies none, which is the relay's check standing alone:
// what it answers when a TLS layer in front of it let one through.
//
// The leaf is chained to the relay's client intermediate and names no
// identity, so the subject is the only thing wrong with it. A genuine
// machine's certificate over the same listener is taken, so the listener is
// not what refuses.
func TestACertificateThatCannotBeReadIsRefusedUnderItsOwnCode(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	if status != http.StatusOK {
		t.Fatalf("enrolment: %d %s", status, body)
	}
	path := "/v1/mailbox/" + alice.Fingerprint()
	odd := rowC6NamelessLeaf(t, h)

	// The shipped handshake refuses it before the relay sees a request.
	if err := rowC6Handshake(t, h.tlsSrv, odd); err == nil {
		t.Fatal("the relay's own listener took a certificate naming no identity")
	}

	open := httptest.NewUnstartedServer(h.tlsSrv.Config.Handler)
	open.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	open.StartTLS()
	t.Cleanup(open.Close)

	if status, body := rowC6OverTLS(t, open, alice, m.tlsCert(), path); status != http.StatusOK {
		t.Fatalf("a genuine certificate over the listener that verifies nothing: %d %s", status, body)
	}

	status, body = rowC6OverTLS(t, open, alice, odd, path)
	if status != http.StatusUnauthorized {
		t.Fatalf("a certificate naming no identity: %d %s, want 401", status, body)
	}
	var refusal relayapi.ErrorResponse
	if err := json.Unmarshal(body, &refusal); err != nil {
		t.Fatalf("the refusal is not an error body: %v: %s", err, body)
	}
	if refusal.Code != relayapi.CodeCertRefused {
		t.Errorf("the refusal's code is %q, want %q", refusal.Code, relayapi.CodeCertRefused)
	}
	if want := relayapi.MsgCertRefused + ": " + clientca.ErrCertSubject.Error(); refusal.Error != want {
		t.Errorf("the refusal says %q, want %q", refusal.Error, want)
	}
	if !refusal.At.IsZero() {
		t.Errorf("the refusal carries at %v; a certificate refusal is about no time", refusal.At)
	}
}

// rowC6NamelessLeaf is a client certificate from the relay's own client
// intermediate, valid now and for client authentication, whose common name
// is not a fingerprint.
func rowC6NamelessLeaf(t *testing.T, h *certHarness) *tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(h.bundle.Params)
	if err != nil {
		t.Fatal(err)
	}
	signer := h.stolenSigningKey()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0x6c6),
		Subject:      pkix.Name{CommonName: "not-a-fingerprint"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, signer.Cert, key.PublicKey(), signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// rowC6Config is a TLS 1.3 client trusting srv and presenting cert.
func rowC6Config(srv *httptest.Server, cert *tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}}
}

// rowC6Handshake completes a handshake with srv presenting cert, and reads
// once so that a TLS 1.3 server's refusal of the client's certificate, which
// arrives after the client thinks the handshake is done, is seen.
func rowC6Handshake(t *testing.T, srv *httptest.Server, cert *tls.Certificate) error {
	t.Helper()
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), rowC6Config(srv, cert))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 1))
	return err
}

// rowC6OverTLS sends a signed GET to srv presenting cert.
func rowC6OverTLS(t *testing.T, srv *httptest.Server, id *identity.Identity, cert *tls.Certificate, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(id, req, nil); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: rowC6Config(srv, cert)}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}
