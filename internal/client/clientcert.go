package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// The relay's refusals, as a client must recognise them. They are constants
// here and in internal/relay, and a test in each package pins them, because
// what the user is told to do next depends on telling them apart.
const (
	certRequired = "requires a client certificate"
	certUnknown  = "not known to this relay"
	certRevoked  = "has been revoked"
	certExpired  = "has expired"
	certMismatch = "does not belong to the signing identity"
)

// CertProblem is a relay refusing this machine's client certificate, or the
// absence of one. It carries advice because there is exactly one thing to do
// about it and the user should not have to work it out.
type CertProblem struct {
	// State is missing, not accepted, not known, revoked, expired, or wrong.
	State string
	// Err is what actually happened.
	Err error
}

func (e *CertProblem) Error() string { return e.Err.Error() }
func (e *CertProblem) Unwrap() error { return e.Err }

// Advice is what to tell the user, given the name the program was invoked as.
func (e *CertProblem) Advice(prog string) string {
	return fmt.Sprintf("this relay requires a client certificate and this machine's is %s: "+
		"run '%s register --token TOKEN' with a token from an administrator", e.State, prog)
}

// CertRefused is the relay rejecting this machine's certificate in the
// handshake itself, before any HTTP happened.
type CertRefused struct {
	// Inferred says the alert never arrived and this was concluded from the
	// relay's behaviour instead: see diagnoseRefusal. The claim is the same
	// either way; the advice says which it is, because a person deserves to
	// know whether they are being told what was heard or what was deduced.
	Inferred bool
	Err      error
}

func (e *CertRefused) Error() string { return e.Err.Error() }
func (e *CertRefused) Unwrap() error { return e.Err }

// Advice is what to tell the user.
func (e *CertRefused) Advice(prog string) string {
	how := fmt.Sprint(e.Err)
	if e.Inferred {
		how += "; it did not say why, and answered when the certificate was not offered"
	}
	return fmt.Sprintf("the relay refused this machine's certificate (%s): "+
		"run '%s register --token TOKEN' with a new token from an administrator", how, prog)
}

// probeTimeout bounds each half of the diagnostic below. It is short because
// the question is only whether the relay is there, and because it is being
// asked on top of a request that has already failed.
const probeTimeout = 10 * time.Second

// diagnoseRefusal turns a connection that died into the refusal it was.
//
// A relay rejects a client certificate in the handshake, and the alert saying
// so is often lost. crypto/tls gives up while the rest of the client's
// certificate flight is still arriving, so the socket is reset rather than
// shut down, and a reset discards whatever the peer has not read yet — which
// is the alert. An http.Client makes it likelier still by writing its request
// before it reads anything and returning the write error. What is left is
// "connection reset by peer", or "broken pipe", or a bare EOF: nothing anybody
// can act on.
//
// So run the experiment the failure did not. Ask the relay again with the
// certificate, and then without it. A relay that is down answers neither. A
// relay that was restarting, or a connection that died of its own accord,
// answers both. Only a refused certificate answers one, and then the
// certificate is the only difference between the two attempts. That is not
// proof, and the advice says so; it is the difference between a person knowing
// what to do and a person reading an errno.
//
// It runs only when this machine holds a certificate, only when the request
// failed at the transport rather than being answered, and never after a dial
// that did not connect, a context the caller cancelled, or a verification
// this machine itself refused: no alert can be hiding in any of those, and
// a probe without the certificate proves nothing about the certificate when
// it was this side that hung up. The container suite's X09 found a replayed
// authority probed and reported as a refused certificate.
func (c *Client) diagnoseRefusal(ctx context.Context, err error) error {
	if c.certless == nil || ctx.Err() != nil || !lostConnection(err) || VerificationFailure(err) {
		return err
	}
	if c.answers(ctx, c.http) {
		return err
	}
	if !c.answers(ctx, c.certless) {
		return err
	}
	return &CertRefused{Inferred: true, Err: err}
}

// lostConnection reports whether err could be hiding an alert: a request that
// reached the relay and then failed without being answered.
//
// A dial that never connected is not one, because there was no handshake to
// refuse. Neither is a cancellation, which is the caller's doing. Everything
// else that comes back from an http.Client.Do is, including the bare EOF a
// reset arriving between the request and the response leaves behind.
func lostConnection(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var op *net.OpError
	if errors.As(err, &op) {
		// A dial that never connected, and an alert that did arrive.
		// ClassifyCertError already knows the second shape, and probing
		// would spend two round trips reaching the same answer with less
		// to stand on.
		return op.Op != "dial" && op.Op != "remote error"
	}
	return true
}

// VerificationFailure reports whether err is this machine refusing the
// relay's certificate — the ratchet, an unknown authority, an invalid
// certificate, the wrong host — rather than the relay refusing this
// machine's. The relay never got to answer, so nothing is to be learned by
// asking it again without the certificate; and the probe's transport does
// not run the ratchet, so it would accept exactly what was refused. It is
// exported because a wait, too, must know a failure that will not pass.
func VerificationFailure(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return errors.Is(err, ErrReplayedAuthority) ||
		errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname)
}

// answers reports whether the relay replies to h at all.
//
// Any reply counts, a refusal included: the question is whether the handshake
// completes, not what the relay thinks of this identity. /v1/health is the one
// route exempt from every limit and from authentication, so asking costs the
// caller nothing and cannot itself be refused for a certificate.
func (c *Client) answers(ctx context.Context, h *http.Client) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/v1/health", nil)
	if err != nil {
		return false
	}
	resp, err := h.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// ClassifyCertError turns a failed request into a certificate problem when it
// is one, and returns err unchanged when it is not.
//
// haveCert says whether this machine holds one at all, which is what separates
// "you have not enrolled this machine" from "the one you have was not
// accepted". A certificate from an authority the relay does not know is never
// offered in the handshake at all — the server advertises which authorities it
// accepts and the client stays silent — so it arrives here looking exactly
// like having none.
func ClassifyCertError(err error, haveCert bool) error {
	if err == nil {
		return nil
	}
	// A certificate this machine sent and the relay rejected fails the
	// handshake. In TLS 1.3 that surfaces on the first request rather than
	// the dial, as a *net.OpError whose Op is "remote error". It is never a
	// tls.AlertError, which is QUIC's.
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" {
		return &CertRefused{Err: err}
	}

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != 401 {
		return err
	}
	msg := httpErr.Message
	switch {
	case strings.Contains(msg, certUnknown):
		return &CertProblem{State: "not known", Err: err}
	case strings.Contains(msg, certRevoked):
		return &CertProblem{State: "revoked", Err: err}
	case strings.Contains(msg, certExpired):
		return &CertProblem{State: "expired", Err: err}
	case strings.Contains(msg, certMismatch):
		return &CertProblem{State: "for another identity", Err: err}
	case strings.Contains(msg, certRequired):
		if haveCert {
			// We hold one and the relay saw none. That is what a certificate
			// from another authority looks like: the handshake completed and
			// the client never offered it.
			return &CertProblem{State: "not accepted", Err: err}
		}
		return &CertProblem{State: "missing", Err: err}
	}
	return err
}

// AnchorProblem is a relay whose certificate this machine cannot verify.
//
// It exists because the message underneath is never useful. A relay serving an
// ML-DSA certificate to a machine that has pinned nothing gets whatever the
// platform verifier says, and on macOS that is "certificate is using a broken
// key size", which is true only in the sense that the verifier has never heard
// of ML-DSA.
type AnchorProblem struct {
	// Pinned says this machine had pinned an anchor and the relay still did
	// not verify, which is a different situation from having pinned none.
	Pinned bool
	// Replayed is set when the chain verified and the ratchet refused it:
	// the relay's authority is older than the one this machine accepted.
	Replayed *ReplayedAuthority
	// Expired says the relay's certificate, or an authority above it, has
	// run out: the operator's to fix, and nothing on this machine is wrong.
	Expired bool
	Err     error
}

func (e *AnchorProblem) Error() string { return e.Err.Error() }
func (e *AnchorProblem) Unwrap() error { return e.Err }

// Advice is what to tell the user.
func (e *AnchorProblem) Advice(prog string) string {
	if e.Replayed != nil {
		// Two explanations, one innocent, and only the operator can tell
		// them apart. Enrolling again is what resets the ratchet, since
		// SaveAnchorFor clears the recorded intermediate.
		return fmt.Sprintf("the relay presented an older signing authority than the one this "+
			"machine accepted: issued %s, replacing one issued %s. Either the relay's operator "+
			"restored an earlier bundle, or somebody is replaying a retired one. Ask the operator "+
			"before doing anything; if it was theirs, enrol again with a new token, which accepts "+
			"what the relay serves now",
			e.Replayed.Presented.Local().Format(StampFormat), e.Replayed.Accepted.Local().Format(StampFormat))
	}
	if e.Expired {
		// Not a rebuilt relay, so not "enrol again", which would not help:
		// a new token accepts the same expired chain.
		return "the relay's certificate has expired; its operator needs to run 'auu-ca relay' on the " +
			"offline machine and replace the bundle. Nothing on this machine is wrong"
	}
	if e.Pinned {
		return fmt.Sprintf("the relay's certificate is not signed by the trust anchor this "+
			"machine pinned (%v); if the relay was rebuilt, enrol again with a new token", e.Err)
	}
	return fmt.Sprintf("this relay's certificate is not from a public authority and this "+
		"machine has pinned no trust anchor: enrol with a token, or run "+
		"'%s init --anchor HASH' with the hash from 'auu-ca show'", prog)
}

// ClassifyAnchorError turns a failed verification into that advice.
//
// pinned says whether this machine had an anchor to check against, which is
// what separates "you have not enrolled here" from "this is not the relay you
// enrolled with".
func ClassifyAnchorError(err error, pinned bool) error {
	if err == nil {
		return nil
	}
	// The ratchet first. It runs only after the standard verification has
	// succeeded, so a replay never shares a chain with an expired or
	// unknown certificate in practice; the order here is for the record,
	// and a later classification of expiry must stay below it.
	var replayed *ReplayedAuthority
	if errors.As(err, &replayed) {
		return &AnchorProblem{Pinned: pinned, Replayed: replayed, Err: err}
	}
	// Expiry next, below the replay as the ratchet's tests pin it: a
	// certificate that has run out is the operator's, whether this machine
	// pinned or not, and the advice for a rebuilt relay would send the
	// user to enrol again for nothing. The container suite's X05 found
	// "certificate has expired" inside the brackets of that advice.
	if RelayExpired(err) {
		return &AnchorProblem{Pinned: pinned, Expired: true, Err: err}
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &unknown), errors.As(err, &invalid):
		return &AnchorProblem{Pinned: pinned, Err: err}
	case errors.As(err, &hostname):
		// Its own message names both the certificate and the host, which is
		// the operator's mistake and already legible.
		return err
	}
	// The platform verifier's errors are opaque strings rather than typed,
	// so the ones a private ML-DSA chain actually produces are matched here.
	msg := err.Error()
	for _, s := range []string{
		"certificate signed by unknown authority",
		"broken key size",
		"certificate is not standards compliant",
		"failed to verify certificate",
	} {
		if strings.Contains(msg, s) {
			return &AnchorProblem{Pinned: pinned, Err: err}
		}
	}
	return err
}

// RelayExpired reports whether err is the relay's certificate, or an
// authority above it, having run out: an x509.CertificateInvalidError with
// Reason Expired anywhere in the chain. It is exported because the renewal
// that runs before a command has to know not to warn about it, since the
// command's own failure is about to say it properly.
func RelayExpired(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.Expired
}
