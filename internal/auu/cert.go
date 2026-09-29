package auu

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	relaydial "github.com/tropeforce7/agentuucp/internal/dial"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// machineKey is internal/dial's, under the name every command here calls it
// by, and the wrappers below are that package's functions under theirs. All
// of it moved when the relay came to need the same dialling and the same
// renewal; the names are kept so that no call site here changed. Two of the
// moved functions are not here: newMachineKey and machineLabel were only ever
// called by newCSR and saveIssued, whose bodies moved with them, so a wrapper
// for either would be a name nothing calls in the file a reader greps to find
// out who makes this machine's key.
type machineKey = relaydial.MachineKey

func relayParams(c *client.Client) (mldsa.Parameters, error) { return relaydial.RelayParams(ctx(), c) }

func newCSR(s *store.Store, id *identity.Identity, r *store.Relay, label, tok string, params mldsa.Parameters) (*machineKey, []byte, error) {
	return relaydial.NewCSR(s, id, r, label, tok, params)
}

func saveIssued(s *store.Store, r *store.Relay, label string, key *machineKey, cert, ca []byte) (*store.CertRecord, error) {
	return relaydial.SaveIssued(s, r, label, key, cert, ca)
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

func renewCert(s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay) (*store.CertRecord, error) {
	return relaydial.RenewCert(ctx(), s, id, c, r)
}

func renewIfExpiring(s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, now time.Time) bool {
	return dialer().RenewIfExpiring(ctx(), s, id, c, r, now)
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
