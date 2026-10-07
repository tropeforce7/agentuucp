package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// Anchor is the trust anchor a machine pins for one relay, and what it
// remembers about the certificates that relay has presented under it.
type Anchor struct {
	// Cert is the root. Nothing else is trusted for this relay: not the
	// system roots either, which is the point of pinning.
	Cert *x509.Certificate
	// SeenSPKI and SeenNotBefore are the server signing intermediate last
	// accepted, empty on the first connection.
	SeenSPKI      string
	SeenNotBefore time.Time
	// OnRotation is called once when a newer intermediate is accepted, so
	// the program can say so. Nil is silent.
	OnRotation func(newNotBefore, oldNotBefore time.Time)
	// OnSeen records a newly accepted intermediate. Nil does not record.
	OnSeen func(spki string, notBefore time.Time) error
}

// ErrReplayedAuthority means the relay presented a server signing
// intermediate older than the one this machine has already accepted.
//
// Only the operator's offline authority can issue a newer one, so a newer one
// is a rotation by construction. An older one is a retired authority being
// replayed by somebody who read the relay's disk before it was rotated — or
// restored by the operator from an earlier bundle, which looks the same from
// here and is theirs to say.
var ErrReplayedAuthority = errors.New("a retired certificate authority is being replayed")

// ReplayedAuthority is ErrReplayedAuthority with the two issue times, so the
// advice can name them. It unwraps to ErrReplayedAuthority.
type ReplayedAuthority struct {
	// Presented is when the authority the relay served was issued; Accepted
	// is when the one this machine holds was, which is later.
	Presented, Accepted time.Time
}

func (e *ReplayedAuthority) Error() string {
	return fmt.Sprintf("%v: the relay presented a server certificate authority issued %s, "+
		"older than the one this machine accepted, issued %s",
		ErrReplayedAuthority, e.Presented.Format(StampFormat), e.Accepted.Format(StampFormat))
}

func (e *ReplayedAuthority) Unwrap() error { return ErrReplayedAuthority }

// StampFormat is how an authority's issue time is shown. It carries the time
// to the second and not only the date, because two rotations in one day are
// ordinary while a relay is being set up, and the container suite's X09 saw
// two in one minute, so that "issued X, older than the one accepted, issued
// X" read as nonsense.
const StampFormat = "2006-01-02 15:04:05"

// anchorAnswerHold is the most of the trust anchor answer the client holds.
const anchorAnswerHold = 1 << 20

// FetchTrustAnchor asks a relay for its trust anchor over a connection nothing
// has verified.
//
// This is the only request in the program that skips verification, and it is
// safe for one reason: the caller compares what comes back against the hash in
// an enrolment token before believing a byte of it. A man in the middle who
// forwards the real anchor has pinned the machine to the real anchor; one who
// substitutes another fails the comparison. It sends no signature and no
// identity, because there is nothing yet to prove and nobody yet to prove it
// to.
func FetchTrustAnchor(ctx context.Context, base string) (*x509.Certificate, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/trust-anchor", nil)
	if err != nil {
		return nil, "", err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := transport.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	tlsCfg.InsecureSkipVerify = true // checked against the token, below
	pinTransport(tlsCfg)
	transport.TLSClientConfig = tlsCfg
	boundTransport(transport)

	c := relayHTTP(transport, 30*time.Second)
	resp, err := c.Do(req)
	if err != nil {
		if pinnedHandshakeRefused(err) {
			// The first thing a new user runs, so the sentence names the
			// relay by the address they typed.
			return nil, "", fmt.Errorf("%s: %w", base, &NoPQTransportError{Err: err})
		}
		return nil, "", fmt.Errorf("fetching the relay's trust anchor: %w", err)
	}
	defer resp.Body.Close()
	// The answer is held to a mebibyte, room for any anchor certificate
	// many times over; one over it is refused by name rather than read
	// short and failed as JSON.
	body, err := io.ReadAll(io.LimitReader(resp.Body, anchorAnswerHold+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > anchorAnswerHold {
		return nil, "", fmt.Errorf("the relay's trust anchor answer is over %d bytes, the most this client holds; nothing of it was used", anchorAnswerHold)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("this relay does not use a private trust anchor, " +
			"so there is nothing to pin; its certificate must verify on its own")
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return nil, "", fmt.Errorf("the relay answered its trust anchor with a redirect (%d), which this build does not follow; nothing of the answer was used", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// The reason phrase is the relay's own words, escaped like any.
		return nil, "", fmt.Errorf("fetching the relay's trust anchor: %s", identity.PrintableText(resp.Status))
	}
	var out relayapi.TrustAnchorResponse
	if err := wire.Decode(body, &out); err != nil {
		return nil, "", fmt.Errorf("the relay's trust anchor is not readable: %w", err)
	}
	if err := sectionsProblem(out.Sections.Sections); err != nil {
		return nil, "", fmt.Errorf("the relay answered its trust anchor %v", err)
	}
	cert, err := x509.ParseCertificate(out.TrustAnchor)
	if err != nil {
		return nil, "", fmt.Errorf("the relay's trust anchor is not a certificate: %w", err)
	}
	// Its own claim about its hash is not believed either: recomputed here,
	// so the only thing that decides is the bytes.
	return cert, pki.SPKI(cert), nil
}

// tlsConfig builds the client half: this anchor as the only root, and the
// ratchet on the relay's own certificate chain.
func (a *Anchor) tlsConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(a.Cert)
	cfg.RootCAs = roots
	pinTransport(cfg)
	cfg.VerifyConnection = a.verifyConnection
	return cfg
}

// verifyConnection runs after the standard verification has succeeded, and
// decides whether a change in the relay's authority is a rotation or a replay.
func (a *Anchor) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) < 2 {
		// A leaf signed directly by the anchor: not what auu-ca produces,
		// and nothing to ratchet on.
		return nil
	}
	// The leaf's issuer: the server signing intermediate.
	issuer := cs.VerifiedChains[0][1]
	spki := pki.SPKI(issuer)
	if spki == a.SeenSPKI {
		return nil
	}
	if a.SeenSPKI != "" && !issuer.NotBefore.After(a.SeenNotBefore) {
		return &ReplayedAuthority{Presented: issuer.NotBefore, Accepted: a.SeenNotBefore}
	}
	if a.SeenSPKI != "" && a.OnRotation != nil {
		a.OnRotation(issuer.NotBefore, a.SeenNotBefore)
	}
	if a.OnSeen != nil {
		if err := a.OnSeen(spki, issuer.NotBefore); err != nil {
			return err
		}
	}
	a.SeenSPKI, a.SeenNotBefore = spki, issuer.NotBefore
	return nil
}
