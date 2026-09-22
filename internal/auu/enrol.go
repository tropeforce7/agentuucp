package auu

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// cmdEnrol joins a relay with an enrolment token: create an identity if there
// is none, add the relay the token names, and register there.
//
// It shows the token before doing anything, because a token names the relay it
// will register you with, and a person should see which one that is before a
// key of theirs is announced to it. The token authorises a mailbox; it says
// nothing about who is safe to talk to, and enrolment changes nothing about
// trust between peers.
//
// There is deliberately no --relay: the token says which relay, and a flag
// that disagreed with it could only ever be a mistake. Joining a second relay
// is this same command with that relay's token, and the home ends up on both.
func cmdEnrol(args []string) error {
	fs := newFlagSet("enrol")
	name := fs.String("name", "", "your name, as peers will address you: letters, digits, '.', '_' and '-'")
	label := fs.String("label", "", "a name for this machine, shown to administrators (default: hostname)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return usageErrf("usage: %s enrol --name NAME TOKEN", prog)
	}
	if len(positional) > 1 {
		return usageErrf("unexpected argument %q", positional[1])
	}
	raw := positional[0]

	u, err := token.Parse(raw)
	if err != nil {
		return usageErrf("%v", err)
	}
	// The shape before anything reads a field: Parse decodes the claims
	// and checks nothing, and what is described below is sliced for a
	// person to read.
	if err := u.Claims.Validate(); err != nil {
		return malformedToken(err)
	}
	claims := u.Claims

	s, err := openStore()
	if err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	hadIdentity := s.HasIdentity()
	relayURL := token.NormaliseRelay(claims.Relay)

	// The relay may already be here, under whatever this home calls it, in
	// which case this is re-enrolling rather than joining somewhere new.
	existing, relayErr := s.Relay(relayURL)
	if relayErr != nil && !errors.Is(relayErr, store.ErrNoSuchRelay) {
		return relayErr
	}
	if !hadIdentity && *name == "" {
		return usageErrf("--name is required when creating an identity")
	}
	if strings.ContainsAny(*name, "\n\r") {
		return usageErrf("--name must be a single line")
	}

	fmt.Print(describeToken(s, u))
	switch {
	case !hadIdentity:
		fmt.Printf("\nAn identity for %q will be created in %s and registered on this relay.\n",
			*name, s.Root())
	case existing != nil:
		fmt.Printf("\nYou already have an identity; it will be registered on %s, "+
			"which this home already knows.\n", existing.Name)
	default:
		fmt.Printf("\nYou already have an identity; it will be registered on this relay, "+
			"which will be added to the %d this home already has.\n", relayCount(s))
	}
	if !*yes && !confirm("Continue?") {
		fmt.Fprintln(os.Stderr, "enrolment cancelled; nothing was changed")
		return &exitError{code: exitUsage, err: fmt.Errorf("cancelled")}
	}

	// The anchor before anything is written: it is what makes every request
	// after this one verifiable, and a mismatch must stop the enrolment
	// while the home is still as it was.
	anchorCert, err := fetchAnchor(relayURL, claims.Anchor)
	if err != nil {
		return err
	}

	id, err := s.Identity()
	if err == nil && id.Remote() {
		// Registering signs requests and makes a machine key, which is
		// send scope: the agent has to be unlocked to send, and a person
		// at the terminal is asked for the passphrase into it.
		if err := ensureUnlocked(s, agent.ScopeSend); err != nil {
			return err
		}
	}
	if err != nil && !errors.Is(err, store.ErrNoIdentity) {
		return err
	}
	if err != nil {
		// No identity yet: make one. Nothing has been written before this
		// point, so a declined prompt above leaves the home untouched.
		id, err = identity.Generate(*name)
		if err != nil {
			return err
		}
		if err := s.SaveIdentity(id); err != nil {
			return err
		}
		cfg.Name = *name
		if err := s.SaveConfig(cfg); err != nil {
			return err
		}
	}
	r := existing
	if r == nil {
		// Named after its host, and the default only if it is the first: a
		// token must not silently move where somebody's mail goes.
		if r, err = s.AddRelay("", relayURL); err != nil {
			return usageErrf("%v", err)
		}
	}
	if anchorCert != nil {
		if err := s.SaveAnchorFor(r, anchorCert); err != nil {
			return err
		}
	}
	// Without this machine's certificate: enrolling is the other way to
	// replace one the relay refuses, and offering it would fail the
	// handshake before the request was ever made. See dialNoCert.
	c, err := dialNoCert(s, id, r)
	if err != nil {
		return err
	}
	// A key for this machine and the request that asks for a certificate for
	// it, with the token inside. The relay may not issue certificates at all,
	// in which case the key is discarded below.
	params, err := relayParams(c)
	if err != nil {
		return transportErr(err)
	}
	key, csr, err := newCSR(s, id, r, *label, raw, params)
	if err != nil {
		return err
	}
	resp, err := c.Register(ctx(), csr)
	if err != nil {
		if !hadIdentity {
			fmt.Fprintf(os.Stderr,
				"your identity was created in %s but the relay refused the token;\n"+
					"ask for a new one and run: %s register --token TOKEN\n", s.Root(), prog)
		}
		return transportErr(err)
	}
	cert, err := storeIssued(s, r, *label, key, resp)
	if err != nil {
		return err
	}
	if err := s.MarkRegistered(r); err != nil {
		return err
	}

	if !hadIdentity {
		fmt.Printf("\nidentity created in %s\n", s.Root())
		fmt.Printf("fingerprint: %s\n", id.Fingerprint())
		fmt.Printf("\nGive this line to the people you want to hear from:\n\n%s\n\n",
			id.Public().ExportLine())
	}
	fmt.Printf("registered %s as %q on %s (%s)\n", id.Public().Short(), id.Name, r.Name, r.URL)
	reportIssued(cert)
	reportDefault(s, r)
	if !hadIdentity {
		fmt.Printf("%s\n", encryptHint())
	}
	return nil
}

// relayCount is how many relays this home already knows, for a sentence that
// tells somebody they are about to be on one more.
func relayCount(s *store.Store) int {
	relays, err := s.Relays()
	if err != nil {
		return 0
	}
	return len(relays)
}

// reportDefault says which relay commands will use from here, once a home has
// more than one and the answer stops being obvious.
func reportDefault(s *store.Store, r *store.Relay) {
	relays, err := s.Relays()
	if err != nil || len(relays) < 2 {
		return
	}
	def, err := s.DefaultRelay()
	if err != nil {
		fmt.Printf("\nThis home has no default relay; pass --relay %s, or set one with: "+
			"%s relay default %s\n", r.Name, prog, r.Name)
		return
	}
	if def.Name == r.Name {
		return
	}
	fmt.Printf("\nCommands with no --relay still use %s. Use this one with --relay %s, "+
		"or make it the default: %s relay default %s\n", def.Name, r.Name, prog, r.Name)
}

// storeIssued saves a certificate the relay issued, if it issued one. A relay
// with client certificates off returns none, and this machine keeps no key:
// an unused private key on disk is a liability, not a spare.
func storeIssued(s *store.Store, r *store.Relay, label string, key *machineKey, resp *relayapi.RegisterResponse) (*store.CertRecord, error) {
	if len(resp.Cert) == 0 {
		return nil, nil
	}
	return saveIssued(s, r, label, key, resp.Cert, resp.CA)
}

// reportIssued says what happened to this machine's certificate, either way.
func reportIssued(cert *store.CertRecord) {
	if cert == nil {
		fmt.Printf("this relay does not use client certificates\n")
		return
	}
	fmt.Printf("client certificate for this machine (%s): expires %s\n",
		cert.Label, cert.NotAfter.Local().Format("2006-01-02"))
}

// cmdToken is the holder's half of token inspection: read what you were sent
// before you act on it.
func cmdToken(args []string) error {
	if len(args) == 0 || args[0] != "show" {
		return usageErrf("usage: %s token show TOKEN", prog)
	}
	fs := newFlagSet("token show")
	positional, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s token show TOKEN", prog)
	}
	u, err := token.Parse(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	if err := u.Claims.Validate(); err != nil {
		return malformedToken(err)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	fmt.Print(describeToken(s, u))
	return nil
}

// malformedToken is the usage error for a pasted token whose claims are
// not the shape of a token's, naming the field, with nothing described.
func malformedToken(err error) error {
	return usageErrf("malformed token: %s; nothing was described",
		strings.TrimPrefix(err.Error(), token.ErrForm.Error()+": "))
}

// describeToken renders a token, checking the signature when the issuer turns
// out to be somebody the local peer list already knows.
func describeToken(s *store.Store, u *token.Unverified) string {
	var issuerName string
	verified := false
	if pub, err := s.Resolve(u.IssuerFingerprint()); err == nil {
		issuerName = pub.Name
		if _, err := u.Verify(pub, time.Now(), 0); err == nil {
			verified = true
		}
	}
	return token.Describe(u.Claims, issuerName, verified, time.Now())
}

// fetchAnchor fetches the relay's trust anchor and checks it against the hash
// the person was given, by a token or by hand. It writes nothing: a command
// fetches first and saves once everything else it does has succeeded, so a
// wrong hash or an unreachable relay leaves the home exactly as it was.
//
// An empty hash means none: the machine keeps using the system roots, which
// is what a relay with a publicly trusted certificate needs. A hash that the
// relay's anchor does not match is refused outright: the hash is the only
// thing that vouches for the relay, and if it does not agree with what the
// relay says then one of them is not what the person was told.
func fetchAnchor(relay, want string) (*x509.Certificate, error) {
	if want == "" {
		return nil, nil
	}
	cert, got, err := client.FetchTrustAnchor(ctx(), relay)
	if err != nil {
		return nil, transportErr(err)
	}
	if got != want {
		return nil, &exitError{code: exitTransport, err: fmt.Errorf(
			"the relay's trust anchor is not the one you were given "+
				"(%s, not %s); do not continue", got[:16], want[:16])}
	}
	return cert, nil
}

// pinAnchor is fetchAnchor and then the save, for a command with nothing
// else to write.
func pinAnchor(s *store.Store, r *store.Relay, want string) error {
	cert, err := fetchAnchor(r.URL, want)
	if err != nil || cert == nil {
		return err
	}
	return s.SaveAnchorFor(r, cert)
}
