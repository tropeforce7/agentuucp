// Command forge issues, from a real auu-ca directory, what auu-ca would
// issue at another time.
//
// No shipped binary can be told the time, and a static Go binary cannot be
// lied to by a preloaded library, so the container suite gets its expired
// certificates this way: the same library calls auu-ca makes, handed a
// different "now". An authority created eleven years ago, or a bundle whose
// signing intermediates run out ninety seconds from now, then meets the
// real clock in the relay and the clients exactly as one that had aged
// would. Nothing here is a construction of its own, and nothing here is
// built by make build: the image for the suite is the only place it goes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/term"
)

const usage = `forge - auu-ca's issuance at a time of your choosing (for tests)

Usage:
  forge init  --dir DIR --name NAME --passphrase-file PATH --at RFC3339 [--mldsa 44|65|87]
  forge relay --dir DIR --host NAME [--host ...] --passphrase-file PATH --at RFC3339
              --out FILE [--years 1]

--at is the moment the certificates are issued: their validity starts an
hour before it and runs the usual lifetime from it. Everything else is what
auu-ca does.
`

// hosts collects a repeatable --host.
type hosts []string

func (h *hosts) String() string     { return strings.Join(*h, ",") }
func (h *hosts) Set(v string) error { *h = append(*h, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "relay":
		err = cmdRelay(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "forge: "+err.Error())
		os.Exit(1)
	}
}

func at(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("--at is required")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--at: %w", err)
	}
	return t, nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", "", "the authority's directory, which must be empty")
	name := fs.String("name", "", "the name that appears in every certificate")
	passFile := fs.String("passphrase-file", "", "the passphrase, from the first line of this file")
	when := fs.String("at", "", "when the authority is created, RFC 3339")
	mldsaN := fs.Int("mldsa", pki.DefaultMLDSA, "ML-DSA parameter set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *name == "" || *passFile == "" {
		return fmt.Errorf("--dir, --name and --passphrase-file are required")
	}
	now, err := at(*when)
	if err != nil {
		return err
	}
	params, err := pki.ParameterSet(*mldsaN)
	if err != nil {
		return err
	}
	secret, err := term.FromFile(*passFile)
	if err != nil {
		return err
	}
	store, err := pki.Create(*dir, *name, params, keyfile.Passphrase{Secret: secret}, now)
	if err != nil {
		return err
	}
	fmt.Printf("created %s\n", store.Dir())
	fmt.Printf("  trust anchor  %s\n", pki.SPKI(store.Anchor.Cert))
	fmt.Printf("  at            %s\n", now.UTC().Format(time.RFC3339))
	fmt.Printf("  expires       %s\n", store.Anchor.Cert.NotAfter.Format(time.DateOnly))
	return nil
}

func cmdRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	dir := fs.String("dir", "", "the authority's directory")
	var hs hosts
	fs.Var(&hs, "host", "a name or address the relay is reached at (repeatable)")
	passFile := fs.String("passphrase-file", "", "the passphrase, from the first line of this file")
	when := fs.String("at", "", "when the bundle is issued, RFC 3339")
	out := fs.String("out", "", "where to write the bundle")
	years := fs.Int("years", pki.DefaultIntermediateYears, "how long the signing intermediates live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || len(hs) == 0 || *passFile == "" || *out == "" {
		return fmt.Errorf("--dir, --host, --passphrase-file and --out are required")
	}
	now, err := at(*when)
	if err != nil {
		return err
	}
	secret, err := term.FromFile(*passFile)
	if err != nil {
		return err
	}
	store, err := pki.Open(*dir, secret)
	if err != nil {
		return err
	}
	bundle, err := store.IssueRelay(hs, *years, now)
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, bundle); err != nil {
		return err
	}
	abs, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := store.RecordBundlePath(hs, abs); err != nil {
		return err
	}
	loaded, err := pki.LoadBundle(*out)
	if err != nil {
		// Expected when --at is far enough in the past: the bundle was
		// written all the same, and the relay will say the same thing.
		fmt.Printf("wrote %s\n", *out)
		fmt.Printf("  for           %s\n", strings.Join(hs, ", "))
		fmt.Printf("  at            %s\n", now.UTC().Format(time.RFC3339))
		fmt.Printf("  note          it does not load today: %v\n", err)
		return nil
	}
	fmt.Printf("wrote %s\n", *out)
	fmt.Printf("  for           %s\n", strings.Join(hs, ", "))
	fmt.Printf("  at            %s\n", now.UTC().Format(time.RFC3339))
	fmt.Printf("  intermediates expire %s\n", loaded.ServerInt.Cert.NotAfter.UTC().Format(time.RFC3339))
	return nil
}
