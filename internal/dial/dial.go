// Package dial builds a client for one relay out of a home, and keeps this
// machine's certificate at that relay alive.
//
// It exists because two programs will do this. The command line dials the
// relays a person joined, and is the only caller in the tree today; a relay
// will dial its neighbours as a courier, out of a home of its own, needing
// the same certificate renewed on the same window by the same code, and
// arrives with relay-to-relay routing. A second implementation would be a
// second thing to get wrong, and the one running unattended would be the
// copy nobody watched. Everything here was internal/auu's and is unchanged
// but for what the next paragraph says.
//
// A Dialer carries the two things this code cannot know for itself: the name
// of the program, for the sentences that tell a person what to run, and where
// a remark goes. The command line writes remarks to standard error with its
// own name in front; a relay logs them. Neither is a decision this package is
// in a position to make, and a package-level standard error would make it for
// both of them.
package dial

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A Dialer is a caller of this package: who it is, and where its remarks go.
type Dialer struct {
	// Prog is the name the calling program was installed under, as it
	// appears inside the advice this package returns in an error. It is
	// required: the one sentence carrying it says to run "<Prog> register
	// --relay NAME --token TOKEN", so a caller that sets it is a program
	// with a register subcommand to be sent to, and an empty Prog quotes a
	// command that is a leading space. A program without one — a relay
	// dialling a neighbour, whose operator repairs a courier's certificate
	// by other means — wants a sentence of its own before it ever reaches
	// that advice, which the routing work's first commit is to write.
	Prog string

	// Note takes a remark this code has no other way to deliver: the
	// authority rotation notice and the renewal warning, each a whole
	// sentence with no name in front and no newline at the end. A nil Note
	// drops both, which is what a caller with nowhere to put them wants;
	// neither remark is a failure, and neither is worth a caller's error
	// path.
	Note func(string)

	// KeepConnections gives the client it builds a kept connection for the
	// requests net/http cannot send again (client.KeepConnections). A
	// relay's courier sets it, and nothing else does.
	KeepConnections bool
}

// note delivers a remark, if this caller takes them.
func (d Dialer) note(format string, args ...any) {
	if d.Note == nil {
		return
	}
	d.Note(fmt.Sprintf(format, args...))
}

// MachineKey is a client key this machine has just made: what signs the
// certificate request, and what cert.json will carry.
//
// In a plain home the key is made here and the PEM is its PKCS#8. In an
// encrypted home the agent makes it, holds it under a pending name, and
// hands back the wrapped PEM; the signer asks the agent, and the key is
// never in this process at all.
type MachineKey struct {
	signer crypto.Signer
	pem    string
}

// NewMachineKey generates this machine's client key, of the parameter set the
// relay requires. It is fresh every time, including at renewal: a key that
// never leaves one machine is the whole difference between a client
// certificate and the identity, which is meant to be portable.
func NewMachineKey(s *store.Store, id *identity.Identity, r *store.Relay, params mldsa.Parameters) (*MachineKey, error) {
	if id.Remote() {
		c, err := agent.NewClient(s.Root())
		if err != nil {
			return nil, err
		}
		g, err := c.Generate(agent.CertPrefix+r.Name, clientca.ParameterNumber(params))
		if err != nil {
			return nil, err
		}
		return &MachineKey{signer: c.CertSigner(g.Handle, g.Public), pem: string(g.Wrapped)}, nil
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &MachineKey{
		signer: key,
		pem:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}, nil
}

// RelayParams asks the relay which parameter set it wants a client key to
// have. The relay refuses a key of any other set, so asking first is what
// saves the person a failed enrolment with a message about key sizes.
func RelayParams(ctx context.Context, c *client.Client) (mldsa.Parameters, error) {
	n, err := c.MLDSA(ctx)
	if err != nil {
		return mldsa.Parameters{}, err
	}
	params, err := clientca.ParameterSet(n)
	if err != nil {
		return mldsa.Parameters{}, fmt.Errorf("the relay asks for a key this build cannot make: %v", err)
	}
	return params, nil
}

// MachineLabel is what a machine calls itself when it enrols. The hostname is
// what an administrator listing certificates will recognise.
func MachineLabel(explicit string) string {
	if explicit != "" {
		return explicit
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "unnamed"
	}
	// The short form: "laptop" reads better in a list than
	// "laptop.corp.example.com".
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	return host
}

// NewCSR generates a key of the given set and the request that asks for a
// certificate for it.
func NewCSR(s *store.Store, id *identity.Identity, r *store.Relay, label, tok string, params mldsa.Parameters) (*MachineKey, []byte, error) {
	key, err := NewMachineKey(s, id, r, params)
	if err != nil {
		return nil, nil, fmt.Errorf("generating this machine's key: %w", err)
	}
	csr, err := clientca.NewCSR(key.signer, MachineLabel(label), tok)
	if err != nil {
		return nil, nil, fmt.Errorf("building the certificate request: %w", err)
	}
	return key, csr, nil
}

// SaveIssued writes a freshly issued certificate and the key it belongs to,
// into the directory of the relay that issued it.
func SaveIssued(s *store.Store, r *store.Relay, label string, key *MachineKey, cert, ca []byte) (*store.CertRecord, error) {
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("the relay returned a certificate we cannot read: %w", err)
	}
	rec := &store.CertRecord{
		Relay:     r.URL,
		Serial:    clientca.FormatSerial(leaf.SerialNumber),
		Label:     MachineLabel(label),
		Key:       key.pem,
		Cert:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	if len(ca) > 0 {
		rec.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}))
	}
	if err := s.SaveCertFor(r, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// RenewCert asks for a fresh certificate and stores it, replacing the one this
// machine holds. The connection is dropped afterwards so the next request uses
// the new one.
func RenewCert(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay) (*store.CertRecord, error) {
	old, err := s.CertFor(r)
	if err != nil {
		return nil, err
	}
	params, err := RelayParams(ctx, c)
	if err != nil {
		return nil, err
	}
	key, csr, err := NewCSR(s, id, r, old.Label, "", params)
	if err != nil {
		return nil, err
	}
	resp, err := c.RenewCert(ctx, csr)
	if err != nil {
		return nil, err
	}
	rec, err := SaveIssued(s, r, old.Label, key, resp.Cert, resp.CA)
	if err != nil {
		return nil, err
	}
	c.CloseIdle()
	return rec, nil
}

// RenewIfExpiring renews a certificate that is close to its expiry, before the
// command that needs it runs. It reports whether a new one was issued.
//
// A failure here is a warning, never a failure of the command: the current
// certificate is still good for weeks, and a relay that is briefly unreachable
// must not stop somebody reading their mail.
func (d Dialer) RenewIfExpiring(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, now time.Time) bool {
	rec, err := s.CertFor(r)
	if err != nil || !rec.Expiring(now) {
		return false
	}
	if _, err := RenewCert(ctx, s, id, c, r); err != nil {
		// A renewal refused because the relay's own certificate has run
		// out is not this machine's problem, and the command that follows
		// is about to say whose it is; a warning here would put the same
		// words in front of it, in brackets, as a renewal failure.
		if !client.RelayExpired(err) {
			d.note("certificate renewal for %s failed (%v); it expires on %s",
				r.Name, err, rec.NotAfter.Local().Format("2006-01-02"))
		}
		return false
	}
	return true
}

// Dial builds a client for one relay, presenting this machine's client
// certificate when it has one there.
//
// A certificate close to its expiry is renewed first, so a machine in regular
// use never reaches the day it stops working. The renewal is best-effort: see
// RenewIfExpiring.
//
// The context is the caller's whole patience for the renewal, which is the
// only part of this that talks to the relay. It matters for a caller that is
// not a person waiting at a terminal: a relay stopping cancels it, and
// without that a shutdown waits on a neighbour that has stopped answering
// for as long as the transport's own timeout allows.
func (d Dialer) Dial(ctx context.Context, s *store.Store, id *identity.Identity, r *store.Relay) (*client.Client, error) {
	c, err := d.NoRenew(s, id, r)
	if err != nil {
		return nil, err
	}
	// A renewal retires the certificate it was authenticated with, so the
	// client that performed it is holding a revoked one. Rebuilt here, with
	// the certificate that came back, or the very next request would be
	// refused for the renewal having succeeded.
	if d.RenewIfExpiring(ctx, s, id, c, r, time.Now()) {
		return d.NoRenew(s, id, r)
	}
	return c, nil
}

// NoRenew is Dial without the renewal check, for the paths that are the
// renewal, or that run before this machine has a certificate at all.
func (d Dialer) NoRenew(s *store.Store, id *identity.Identity, r *store.Relay) (*client.Client, error) {
	var cert *tls.Certificate
	rec, err := s.CertFor(r)
	switch {
	case err == nil:
		if cert, err = rec.TLS(); err != nil {
			// A certificate file we cannot read is worth saying out loud:
			// the alternative is a puzzling 401 from the relay.
			return nil, fmt.Errorf("%w; run '%s register --relay %s --token TOKEN' to replace it",
				err, d.Prog, r.Name)
		}
	case errors.Is(err, store.ErrNoCert):
		// None is a state, not a failure: a relay may not use them at all,
		// and a machine not yet enrolled has none to offer.
	default:
		// A file that is there and wrong is not a file that is missing.
		// Dialling without it, as before, left the relay's refusal of a
		// certificate it never saw as the only word said; the store's
		// sentence names the file and what to run.
		return nil, err
	}
	anchor, err := d.anchor(s, r)
	if err != nil {
		return nil, err
	}
	c, err := client.NewWithAnchor(r.URL, id, cert, anchor)
	if err != nil {
		return nil, err
	}
	if d.KeepConnections {
		c.KeepConnections()
	}
	return c, nil
}

// NoCert is NoRenew without this machine's certificate.
//
// Registering is how a machine whose certificate the relay refuses replaces
// it, and a refusal happens in the handshake, before any route is chosen: a
// client that offered the old one would fail the very command sent to fix it,
// and the advice it printed would name that command. Neither /v1/register nor
// /v1/health reads a client certificate, so there is nothing to leave behind.
func (d Dialer) NoCert(s *store.Store, id *identity.Identity, r *store.Relay) (*client.Client, error) {
	anchor, err := d.anchor(s, r)
	if err != nil {
		return nil, err
	}
	return client.NewWithAnchor(r.URL, id, nil, anchor)
}

// anchor builds the trust anchor half of a client, if this machine pinned one
// for that relay, wired to say once when the relay's authority is rotated and
// to remember it afterwards.
//
// The ratchet is the relay's own: a rotation on one relay says nothing about
// another, and comparing one relay's intermediate against another's record
// would refuse an honest relay as a replay.
func (d Dialer) anchor(s *store.Store, r *store.Relay) (*client.Anchor, error) {
	rec, err := s.AnchorFor(r)
	if errors.Is(err, store.ErrNoAnchor) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &client.Anchor{
		Cert:          rec.Cert,
		SeenSPKI:      r.ServerIntSPKI,
		SeenNotBefore: r.ServerIntNotBefore,
		OnRotation: func(now, before time.Time) {
			d.note("the server certificate authority of %s was rotated: issued %s, "+
				"replacing one issued %s. Only the relay operator's offline authority "+
				"can issue one, so this is a rotation, not an attack; recorded.",
				r.Name,
				now.Local().Format(client.StampFormat), before.Local().Format(client.StampFormat))
		},
		OnSeen: func(spki string, notBefore time.Time) error {
			return s.SeenIntermediateFor(r, spki, notBefore)
		},
	}, nil
}
