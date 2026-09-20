// Command auu-ca makes and holds the certificate authority an AgentUUCP relay
// is issued from.
//
// It talks to nothing: no relay, no network, no AUU_HOME. That is the point of
// it being its own program. The keys it holds are the ones a relay must never
// have, so "do not put this on the relay" is enforced by not installing it
// there, and this program gives an operator no way to weaken that by accident.
package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/internal/pki"
)

const usage = `auu-ca - the offline certificate authority for an auu relay

Usage:
  auu-ca init       --name NAME [--dir DIR] [--mldsa 44|65|87] [--json]
  auu-ca relay      --host NAME|IP [--host ...] --out FILE|- [--dir DIR] [--years 1]
  auu-ca kit        --host NAME|IP [--host ...] --relay-binary FILE --out FILE
                    [--admin LINE|@FILE ...] [--listen :9443] [--registration token]
                    [--client-certs off] [--without-bundle] [--years 1] [--dir DIR]
  auu-ca show       [--dir DIR] [--json]
  auu-ca passphrase [--dir DIR]
  auu-ca version

  init        create a trust anchor and the two authorities beneath it
  relay       issue one relay its signing intermediates, as a bundle
  kit         issue the bundle and pack it with the relay binary, its settings,
              its administrators, its unit and an installer into one archive
  show        print what this directory holds and when each part expires
  passphrase  change the passphrase the private keys are encrypted under
  version     the version this binary was built from

--dir defaults to $AUU_CA_HOME, then ~/.auu-ca. It holds private keys and is
mode 0700; keep it off any machine that answers connections, which is the
whole reason this is a separate program.

Every private key in it is encrypted under a passphrase, so what a backup or
a stolen disk yields is certificates. init, relay and kit ask for it; show never
does, because it reads no key. --passphrase-file PATH reads the first line of
a file instead of asking, for a script or a secret manager; with neither, and
with standard input not a terminal, the first line of standard input is used.

The bundle holds the relay's two signing keys in the clear. --out FILE
writes it, mode 0600; copy it to the relay, seal it there, and delete both
copies:

  auu-ca relay --host HOST --out relay-bundle.json
  scp relay-bundle.json HOST:
  ssh -t HOST 'sudo systemd-creds encrypt --name=relay-bundle relay-bundle.json \
    /etc/auu/relay-bundle.cred && rm relay-bundle.json'
  rm relay-bundle.json

show warns while the file is still here. --out - writes the bundle to
standard output and everything else to standard error, for keeping it off
this disk altogether; the deployment guide has that form. Do not pipe it
straight into ssh: auu-ca and ssh would both ask on the terminal at once.

A kit is the other thing that holds the bundle: 'auu-ca kit' issues it and
packs it with the relay binary you cross-compiled, the settings and the
administrators for the host, the systemd unit and a script that installs
the lot, or brings an installed relay up to date. The archive is handled
exactly as the bundle file is — copied, run, deleted at both ends — and
show warns about it the same way. --without-bundle leaves the bundle out
and issues nothing, for an operator who moves it another way.

Run 'auu-ca relay' or 'auu-ca kit' again for a host to rotate it: the relay
gets fresh intermediates and keeps verifying the certificates the old one
issued.
`

const (
	exitOK    = 0
	exitUsage = 1
	exitFail  = 2
)

func main() {
	if len(os.Args) < 2 {
		io.WriteString(os.Stdout, usage)
		os.Exit(exitUsage)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "-h", "--help", "help":
		io.WriteString(os.Stdout, usage)
		return
	case "init":
		err = cmdInit(args)
	case "relay":
		err = cmdRelay(args)
	case "kit":
		err = cmdKit(args)
	case "show":
		err = cmdShow(args)
	case "passphrase":
		err = cmdPassphrase(args)
	case "version":
		fmt.Printf("auu-ca %s\n", buildinfo.Version())
	default:
		err = usageErrf("unknown command %q; run 'auu-ca help'", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "auu-ca: "+err.Error())
		var u *usageError
		if errors.As(err, &u) {
			os.Exit(exitUsage)
		}
		os.Exit(exitFail)
	}
}

type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageErrf(format string, a ...any) error {
	return &usageError{err: fmt.Errorf(format, a...)}
}

// defaultDir is $AUU_CA_HOME, then ~/.auu-ca.
func defaultDir() string {
	if d := os.Getenv("AUU_CA_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".auu-ca"
	}
	return filepath.Join(home, ".auu-ca")
}

// hostList collects a repeatable --host.
type hostList []string

func (h *hostList) String() string     { return strings.Join(*h, ",") }
func (h *hostList) Set(v string) error { *h = append(*h, v); return nil }

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() { io.WriteString(os.Stdout, usage) }
	dir := fs.String("dir", defaultDir(), "where to create the authority")
	name := fs.String("name", "", "who this authority belongs to; it appears in every certificate")
	mldsa := fs.Int("mldsa", pki.DefaultMLDSA,
		"ML-DSA parameter set for the whole hierarchy: 44, 65 or 87")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	passFile := fs.String("passphrase-file", "",
		"read the passphrase for the new keys from the first line of this file")
	if err := fs.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if fs.NArg() > 0 {
		return usageErrf("unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*name) == "" {
		return usageErrf("--name is required: it appears in every certificate this authority issues")
	}
	params, err := pki.ParameterSet(*mldsa)
	if err != nil {
		return usageErrf("--mldsa: %v", err)
	}

	// Asked for before anything is generated, so that a mistyped
	// confirmation costs nothing and leaves no directory behind.
	secret, err := readNewPassphrase("Passphrase for the new keys: ", *passFile)
	if err != nil {
		return err
	}
	store, err := pki.Create(*dir, strings.TrimSpace(*name), params, withSecret(secret), time.Now())
	if err != nil {
		return err
	}
	anchor := pki.SPKI(store.Anchor.Cert)
	if *asJSON {
		return printJSON(map[string]any{
			"dir": store.Dir(), "anchor": anchor, "mldsa": *mldsa,
			"expires": store.Anchor.Cert.NotAfter,
		})
	}
	fmt.Printf("created %s\n", store.Dir())
	fmt.Printf("  trust anchor  %s\n", anchor)
	fmt.Printf("  keys          ML-DSA-%d, encrypted under your passphrase\n", *mldsa)
	fmt.Printf("  expires       %s\n", store.Anchor.Cert.NotAfter.Format(time.DateOnly))
	fmt.Printf("\nThe trust anchor above is what an enrolment token carries and what a\n")
	fmt.Printf("machine pins. Give it to whoever issues tokens for this relay.\n")
	fmt.Printf("\nThe passphrase is not recoverable and is not stored anywhere: without it\n")
	fmt.Printf("these keys are lost, and losing them means every machine enrolling again.\n")
	fmt.Printf("\nEvery key here must stay on this machine. Next, the relay's bundle:\n")
	printCopy(os.Stdout, "YOUR.RELAY.NAME", "relay-bundle.json", true)
	return nil
}

func cmdRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.Usage = func() { io.WriteString(os.Stdout, usage) }
	dir := fs.String("dir", defaultDir(), "the authority to issue from")
	out := fs.String("out", "", "write the bundle here, or to standard output with -")
	years := fs.Int("years", pki.DefaultIntermediateYears, "how long the intermediates live")
	passFile := fs.String("passphrase-file", "",
		"read the authority's passphrase from the first line of this file")
	var hosts hostList
	fs.Var(&hosts, "host", "a name or address this relay answers to (repeatable)")
	if err := fs.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if fs.NArg() > 0 {
		return usageErrf("unexpected argument %q", fs.Arg(0))
	}
	if len(hosts) == 0 {
		return usageErrf("--host is required: it is what the relay's certificate will be valid for")
	}
	if *out == "" {
		return usageErrf("--out is required: the file you copy to the relay, or - for standard output")
	}
	// With the bundle on standard output, everything meant for a person goes
	// to standard error, so that the pipe carries the bundle and nothing else.
	toStdout := *out == "-"
	w := os.Stdout
	if toStdout {
		w = os.Stderr
	}

	secret, err := unlock(*dir, *passFile)
	if err != nil {
		return err
	}
	store, err := pki.Open(*dir, secret)
	if err != nil {
		return err
	}
	bundle, err := store.IssueRelay(hosts, *years, time.Now())
	if err != nil {
		return err
	}
	// The record remembers where the bundle went, so that show can say when
	// a file is still lying on this machine. Standard output is recorded as
	// no path at all.
	var wrote, recorded string
	if toStdout {
		data, err := pki.EncodeBundle(bundle)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("writing the bundle to standard output: %w", err)
		}
		wrote = "the bundle to standard output"
	} else {
		if err := pki.WriteBundle(*out, bundle); err != nil {
			return err
		}
		if recorded, err = filepath.Abs(*out); err != nil {
			return err
		}
		wrote = *out
	}
	if err := store.RecordBundlePath(hosts, recorded); err != nil {
		return err
	}

	_, rec, err := store.FindRecord(hosts)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %s\n", wrote)
	fmt.Fprintf(w, "  for           %s\n", strings.Join(hosts, ", "))
	fmt.Fprintf(w, "  trust anchor  %s\n", bundle.TrustAnchorSPKI)
	if n := len(rec.ClientInts); n > 1 {
		fmt.Fprintf(w, "  rotation      %d, keeping %d earlier client intermediate(s) so existing\n",
			n, n-1)
		fmt.Fprintf(w, "                machines keep working without re-enrolling\n")
	}
	if toStdout {
		// There is no file to copy or delete: the operator is running the
		// pipe already.
		return nil
	}
	host := hosts[0]
	fmt.Fprintf(w, "\nCopy it to the relay and seal it to that host, then restart the relay:\n")
	printCopy(w, host, *out, false)
	fmt.Fprintf(w, "  with \"tls\": {\"bundle_credential\": \"relay-bundle\"} in the relay's settings, or\n")
	fmt.Fprintf(w, "  install it as /etc/auu/relay-bundle.json, mode 0600, owned by the relay's user,\n")
	fmt.Fprintf(w, "  with \"tls\": {\"bundle\": \"/etc/auu/relay-bundle.json\"}.\n")
	fmt.Fprintf(w, "\nThen delete %s from this machine: it holds the relay's two signing keys in\n", *out)
	fmt.Fprintf(w, "the clear, and this machine's backups must not; show warns while it is here.\n")
	return nil
}

// printCopy is the recipe for getting a bundle file onto the relay and
// sealed there: scp, then sudo over a terminal of its own, then the copy on
// the relay removed. One command per prompt, because auu-ca's passphrase,
// ssh's password and sudo's are three prompts and two of them on one
// terminal at once get each other's keystrokes, which is what piping
// auu-ca straight into ssh does. withIssue includes the issuing command,
// for a hint printed before the bundle exists.
func printCopy(w io.Writer, host, file string, withIssue bool) {
	if withIssue {
		fmt.Fprintf(w, "  auu-ca relay --host %s --out %s\n", host, file)
	}
	remote := filepath.Base(file)
	fmt.Fprintf(w, "  scp %s %s:\n", file, host)
	fmt.Fprintf(w, "  ssh -t %s 'sudo systemd-creds encrypt --name=relay-bundle %s \\\n", host, remote)
	fmt.Fprintf(w, "    /etc/auu/relay-bundle.cred && rm %s'\n", remote)
	if withIssue {
		fmt.Fprintf(w, "  rm %s\n", file)
	}
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.Usage = func() { io.WriteString(os.Stdout, usage) }
	dir := fs.String("dir", defaultDir(), "the authority to describe")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := fs.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if fs.NArg() > 0 {
		return usageErrf("unexpected argument %q", fs.Arg(0))
	}
	store, err := pki.OpenLocked(*dir)
	if err != nil {
		return err
	}
	hosts, err := store.Relays()
	if err != nil {
		return err
	}

	type relayOut struct {
		Host string `json:"host"`
		// Expires is when the current signing intermediates expire: the
		// date an operator has to plan a trip to this machine around.
		Expires time.Time `json:"intermediates_expire"`
		Retired int       `json:"retired_client_intermediates"`
		// BundleOnDisk is the path of the last bundle written for this
		// relay when that file is still on this machine, and empty when
		// there is nothing to say: it was deleted, or it went to standard
		// output.
		BundleOnDisk string `json:"bundle_on_disk"`
		updated      time.Time
	}
	out := struct {
		Dir     string     `json:"dir"`
		Anchor  string     `json:"anchor"`
		MLDSA   int        `json:"mldsa"`
		Expires time.Time  `json:"anchor_expires"`
		Relays  []relayOut `json:"relays"`
	}{
		Dir: store.Dir(), Anchor: pki.SPKI(store.Anchor.Cert),
		MLDSA:   pki.ParameterNumberOf(store.Params),
		Expires: store.Anchor.Cert.NotAfter,
	}
	for _, h := range hosts {
		rec, err := store.Record(h)
		if err != nil {
			return err
		}
		r := relayOut{Host: h}
		if n := len(rec.ClientInts); n > 0 {
			r.Retired = n - 1
			current, err := x509.ParseCertificate(rec.ClientInts[n-1])
			if err != nil {
				return fmt.Errorf("%s: the recorded intermediate does not parse: %w", h, err)
			}
			r.Expires = current.NotAfter
		}
		// A recorded path the operator has since moved or deleted is gone
		// from where it was written, which is all that is asked.
		if rec.BundlePath != "" {
			if _, err := os.Stat(rec.BundlePath); err == nil {
				r.BundleOnDisk = rec.BundlePath
				r.updated = rec.Updated
			}
		}
		out.Relays = append(out.Relays, r)
	}
	if *asJSON {
		return printJSON(out)
	}

	fmt.Printf("directory:    %s\n", out.Dir)
	fmt.Printf("trust anchor: %s\n", out.Anchor)
	fmt.Printf("keys:         ML-DSA-%d\n", out.MLDSA)
	for _, tc := range []struct {
		label string
		when  time.Time
	}{
		{"anchor", store.Anchor.Cert.NotAfter},
		{"server CA", store.Server.Cert.NotAfter},
		{"client CA", store.Client.Cert.NotAfter},
	} {
		fmt.Printf("%-14s%s (%s)\n", tc.label+":", tc.when.Format(time.DateOnly), until(tc.when))
	}
	if len(out.Relays) == 0 {
		fmt.Printf("\nno relays issued yet; run 'auu-ca relay --host NAME --out FILE'\n")
		return nil
	}
	fmt.Printf("\nrelays issued:\n")
	for _, r := range out.Relays {
		line := fmt.Sprintf("  %-28s intermediates expire %s (%s)",
			r.Host, r.Expires.Format(time.DateOnly), until(r.Expires))
		if r.Retired > 0 {
			line += fmt.Sprintf("; %d retired client intermediate(s) still trusted", r.Retired)
		}
		fmt.Println(line)
	}
	// A warning and never an error: show prints public facts and keeps
	// doing so. It is the command run at least yearly, which is why the
	// reminder lives here rather than only in a document.
	for _, r := range out.Relays {
		if r.BundleOnDisk != "" {
			fmt.Fprintf(os.Stderr, "auu-ca: the bundle written for %s on %s is still at %s; "+
				"delete it once it is on the relay, or write the next one with --out -\n",
				r.Host, r.updated.Format(time.DateOnly), r.BundleOnDisk)
		}
	}
	return nil
}

// cmdPassphrase changes the passphrase every key file is encrypted under.
func cmdPassphrase(args []string) error {
	fs := flag.NewFlagSet("passphrase", flag.ContinueOnError)
	fs.Usage = func() { io.WriteString(os.Stdout, usage) }
	dir := fs.String("dir", defaultDir(), "the authority to change")
	oldFile := fs.String("passphrase-file", "",
		"read the current passphrase from the first line of this file")
	newFile := fs.String("new-passphrase-file", "",
		"read the new passphrase from the first line of this file")
	if err := fs.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if fs.NArg() > 0 {
		return usageErrf("unexpected argument %q", fs.Arg(0))
	}

	store, err := pki.OpenLocked(*dir)
	if err != nil {
		return err
	}
	old, err := readPassphrase("Current passphrase: ", *oldFile)
	if err != nil {
		return err
	}
	fresh, err := readNewPassphrase("New passphrase: ", *newFile)
	if err != nil {
		return err
	}
	if err := pki.SetPassphrase(store.Dir(), old, withSecret(fresh)); err != nil {
		return err
	}
	fmt.Printf("changed the passphrase on %s\n", store.Dir())
	fmt.Printf("\nThe passphrase is not recoverable and is not stored anywhere: without it\n")
	fmt.Printf("these keys are lost.\n")
	return nil
}

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

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
