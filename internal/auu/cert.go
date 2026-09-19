package auu

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

// machineKey is a client key this machine has just made: what signs the
// certificate request, and what cert.json will carry.
//
// In a plain home the key is made here and the PEM is its PKCS#8. In an
// encrypted home the agent makes it, holds it under a pending name, and
// hands back the wrapped PEM; the signer asks the agent, and the key is
// never in this process at all.
type machineKey struct {
	signer crypto.Signer
	pem    string
}

// newMachineKey generates this machine's client key, of the parameter set the
// relay requires. It is fresh every time, including at renewal: a key that
// never leaves one machine is the whole difference between a client
// certificate and the identity, which is meant to be portable.
func newMachineKey(s *store.Store, id *identity.Identity, r *store.Relay, params mldsa.Parameters) (*machineKey, error) {
	if id.Remote() {
		c, err := agent.NewClient(s.Root())
		if err != nil {
			return nil, err
		}
		g, err := c.Generate(agent.CertPrefix+r.Name, clientca.ParameterNumber(params))
		if err != nil {
			return nil, err
		}
		return &machineKey{signer: c.CertSigner(g.Handle, g.Public), pem: string(g.Wrapped)}, nil
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &machineKey{
		signer: key,
		pem:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}, nil
}

// relayParams asks the relay which parameter set it wants a client key to
// have. The relay refuses a key of any other set, so asking first is what
// saves the person a failed enrolment with a message about key sizes.
func relayParams(c *client.Client) (mldsa.Parameters, error) {
	n, err := c.MLDSA(ctx())
	if err != nil {
		return mldsa.Parameters{}, err
	}
	params, err := clientca.ParameterSet(n)
	if err != nil {
		return mldsa.Parameters{}, fmt.Errorf("the relay asks for a key this build cannot make: %v", err)
	}
	return params, nil
}

// machineLabel is what a machine calls itself when it enrols. The hostname is
// what an administrator listing certificates will recognise.
func machineLabel(explicit string) string {
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

// newCSR generates a key of the given set and the request that asks for a
// certificate for it.
func newCSR(s *store.Store, id *identity.Identity, r *store.Relay, label, tok string, params mldsa.Parameters) (*machineKey, []byte, error) {
	key, err := newMachineKey(s, id, r, params)
	if err != nil {
		return nil, nil, fmt.Errorf("generating this machine's key: %w", err)
	}
	csr, err := clientca.NewCSR(key.signer, machineLabel(label), tok)
	if err != nil {
		return nil, nil, fmt.Errorf("building the certificate request: %w", err)
	}
	return key, csr, nil
}

// saveIssued writes a freshly issued certificate and the key it belongs to,
// into the directory of the relay that issued it.
func saveIssued(s *store.Store, r *store.Relay, label string, key *machineKey, cert, ca []byte) (*store.CertRecord, error) {
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("the relay returned a certificate we cannot read: %w", err)
	}
	rec := &store.CertRecord{
		Relay:     r.URL,
		Serial:    clientca.FormatSerial(leaf.SerialNumber),
		Label:     machineLabel(label),
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

// cmdCert is the machine's view of its own certificate.
func cmdCert(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s cert status|ls|renew", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return certStatus(rest)
	case "ls":
		return certList(rest)
	case "renew":
		return certRenew(rest)
	default:
		return usageErrf("unknown command %q; run '%s cert status|ls|renew'", sub, prog)
	}
}

// certStatusOutput is what --json prints.
type certStatusOutput struct {
	// RelayName is what this home calls the relay; Relay is its URL.
	RelayName   string     `json:"relay_name"`
	Relay       string     `json:"relay"`
	Serial      string     `json:"serial,omitempty"`
	Label       string     `json:"label,omitempty"`
	MLDSA       int        `json:"mldsa,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	RenewsAfter *time.Time `json:"renews_after,omitempty"`
	CA          string     `json:"ca_fingerprint,omitempty"`
	Present     bool       `json:"present"`
}

func certStatus(args []string) error {
	fs := newFlagSet("cert status")
	asJSON := fs.Bool("json", false, "print as JSON")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}

	rec, err := s.CertFor(r)
	if err != nil && !errors.Is(err, store.ErrNoCert) {
		// A file that is there and wrong says what it is.
		return err
	}
	if err != nil {
		// No certificate is a normal state, not a failure: a relay may not
		// use them at all.
		out := certStatusOutput{RelayName: r.Name, Relay: r.URL}
		if *asJSON {
			return printJSON(out)
		}
		fmt.Printf("relay:  %s (%s)\n", r.Name, r.URL)
		fmt.Printf("client certificate: none on this machine\n")
		return nil
	}

	renews := rec.NotAfter.Add(-store.RenewBefore)
	out := certStatusOutput{
		RelayName: r.Name,
		Relay:     rec.Relay, Serial: rec.Serial, Label: rec.Label, MLDSA: keyParams(rec),
		NotBefore: &rec.NotBefore, NotAfter: &rec.NotAfter, RenewsAfter: &renews,
		CA: caFingerprint(rec), Present: true,
	}
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("relay:   %s (%s)\n", r.Name, rec.Relay)
	fmt.Printf("machine: %s\n", identity.PrintableText(rec.Label))
	fmt.Printf("serial:  %s\n", rec.Serial)
	if n := keyParams(rec); n != 0 {
		fmt.Printf("key:     ML-DSA-%d\n", n)
	}
	fmt.Printf("issued:  %s\n", rec.NotBefore.Local().Format("2006-01-02 15:04 MST"))
	fmt.Printf("expires: %s (%s)\n",
		rec.NotAfter.Local().Format("2006-01-02 15:04 MST"), until(rec.NotAfter))
	fmt.Printf("renews:  from %s\n", renews.Local().Format("2006-01-02"))
	if fp := caFingerprint(rec); fp != "" {
		fmt.Printf("issued by: %s\n", fp[:16])
	}
	return nil
}

// caFingerprint is the SHA-256 of the stored authority, for display.
func caFingerprint(rec *store.CertRecord) string {
	if rec.CA == "" {
		return ""
	}
	block, _ := pem.Decode([]byte(rec.CA))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return fingerprintOf(cert.Raw)
}

func certList(args []string) error {
	fs := newFlagSet("cert ls")
	asJSON := fs.Bool("json", false, "print as JSON")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return err
	}
	certs, err := c.Certs(ctx())
	if err != nil {
		return transportErr(err)
	}
	if *asJSON {
		return printJSON(certs)
	}
	if len(certs) == 0 {
		fmt.Printf("no client certificates on %s\n", r.Name)
		return nil
	}
	for _, cert := range certs {
		mark := " "
		if cert.Current {
			mark = "*"
		}
		state := "expires " + cert.NotAfter.Local().Format("2006-01-02")
		if cert.Revoked {
			state = "revoked"
			if cert.Reason != "" {
				state += " (" + cert.Reason + ")"
			}
		} else if time.Now().After(cert.NotAfter) {
			state = "expired " + cert.NotAfter.Local().Format("2006-01-02")
		}
		fmt.Printf("%s %s  %-20s  %s\n", mark, cert.Serial[:16], truncate(identity.PrintableText(cert.Label), 20), state)
	}
	fmt.Printf("\n* is this machine\n")
	return nil
}

func certRenew(args []string) error {
	fs := newFlagSet("cert renew")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	if _, err := s.CertFor(r); errors.Is(err, store.ErrNoCert) {
		return fmt.Errorf("this machine has no client certificate for %s: "+
			"run '%s register --relay %s --token TOKEN' with a token from an administrator",
			r.Name, prog, r.Name)
	} else if err != nil {
		return err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return err
	}
	rec, err := renewCert(s, id, c, r)
	if err != nil {
		return transportErr(err)
	}
	fmt.Printf("renewed: %s, expires %s\n", rec.Serial[:16],
		rec.NotAfter.Local().Format("2006-01-02"))
	return nil
}

// renewCert asks for a fresh certificate and stores it, replacing the one this
// machine holds. The connection is dropped afterwards so the next request uses
// the new one.
func renewCert(s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay) (*store.CertRecord, error) {
	old, err := s.CertFor(r)
	if err != nil {
		return nil, err
	}
	params, err := relayParams(c)
	if err != nil {
		return nil, err
	}
	key, csr, err := newCSR(s, id, r, old.Label, "", params)
	if err != nil {
		return nil, err
	}
	resp, err := c.RenewCert(ctx(), csr)
	if err != nil {
		return nil, err
	}
	rec, err := saveIssued(s, r, old.Label, key, resp.Cert, resp.CA)
	if err != nil {
		return nil, err
	}
	c.CloseIdle()
	return rec, nil
}

// renewIfExpiring renews a certificate that is close to its expiry, before the
// command that needs it runs. It reports whether a new one was issued.
//
// A failure here is a warning, never a failure of the command: the current
// certificate is still good for weeks, and a relay that is briefly unreachable
// must not stop somebody reading their mail.
func renewIfExpiring(s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, now time.Time) bool {
	rec, err := s.CertFor(r)
	if err != nil || !rec.Expiring(now) {
		return false
	}
	if _, err := renewCert(s, id, c, r); err != nil {
		// A renewal refused because the relay's own certificate has run
		// out is not this machine's problem, and the command that follows
		// is about to say whose it is; a warning here would put the same
		// words in front of it, in brackets, as a renewal failure.
		if !client.RelayExpired(err) {
			fmt.Fprintf(os.Stderr, "%s: certificate renewal for %s failed (%v); it expires on %s\n",
				prog, r.Name, err, rec.NotAfter.Local().Format("2006-01-02"))
		}
		return false
	}
	return true
}

// until renders how long is left, for a person.
func until(t time.Time) string {
	d := time.Until(t)
	switch {
	case d <= 0:
		return "expired"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// keyParams is the parameter set of the machine key, for display, or zero
// if the certificate cannot be read. From the certificate's public half: the
// private half may be in the agent.
func keyParams(rec *store.CertRecord) int {
	pub := rec.PublicKey()
	if pub == nil {
		return 0
	}
	return clientca.ParameterNumber(pub.Parameters())
}

// fingerprintOf is the SHA-256 of a DER certificate, lowercase hex: the same
// form the relay's own startup line and 'auu-admin status' use.
func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
