package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/kit"
	"github.com/tropeforce7/agentuucp/internal/pki"
)

// adminList collects a repeatable --admin: an export line, or @FILE for a
// file of them.
type adminList []string

func (a *adminList) String() string     { return strings.Join(*a, ",") }
func (a *adminList) Set(v string) error { *a = append(*a, v); return nil }

// cmdKit issues a relay its bundle, as relay does, and packs it with the
// relay binary, the settings and administrators for the host, the unit and
// the installer into one archive. The archive holds the bundle, so it is a
// secret and is handled as the bundle file is: written 0600, recorded so
// show warns while it is here, copied, run, deleted at both ends.
func cmdKit(args []string) error {
	fs := flag.NewFlagSet("kit", flag.ContinueOnError)
	fs.Usage = func() { io.WriteString(os.Stdout, usage) }
	dir := fs.String("dir", defaultDir(), "the authority to issue from")
	out := fs.String("out", "", "write the archive here")
	relayBinary := fs.String("relay-binary", "", "the relay built for the host: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/auu-relay")
	listen := fs.String("listen", ":9443", "the address the relay listens on; public_url takes its port")
	registration := fs.String("registration", "token", "open, token or closed")
	clientCerts := fs.String("client-certs", "off", "off or required")
	withoutBundle := fs.Bool("without-bundle", false, "leave the bundle out, for an operator who moves it another way")
	years := fs.Int("years", pki.DefaultIntermediateYears, "how long the intermediates live")
	passFile := fs.String("passphrase-file", "",
		"read the authority's passphrase from the first line of this file")
	var hosts hostList
	fs.Var(&hosts, "host", "a name or address this relay answers to (repeatable); the first is public_url's")
	var admins adminList
	fs.Var(&admins, "admin", "an administrator's export line, or @FILE for a file of them (repeatable)")
	if err := fs.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if fs.NArg() > 0 {
		return usageErrf("unexpected argument %q", fs.Arg(0))
	}
	if len(hosts) == 0 {
		return usageErrf("--host is required: it is what the relay's certificate will be valid for")
	}
	if *relayBinary == "" {
		return usageErrf("--relay-binary is required: the relay built for the host, " +
			"CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/auu-relay")
	}
	switch *out {
	case "":
		return usageErrf("--out is required: the archive you copy to the relay")
	case "-":
		return usageErrf("--out - is not accepted: an archive with a binary in it is not a thing to pipe; name a file")
	}
	if *withoutBundle {
		// The bundle is issued by relay when the operator moves it their
		// own way, and that is where its lifetime is chosen.
		var yearsSet bool
		fs.Visit(func(f *flag.Flag) { yearsSet = yearsSet || f.Name == "years" })
		if yearsSet {
			return usageErrf("--years means nothing with --without-bundle: the bundle is issued by 'auu-ca relay' then")
		}
	}
	lines, err := adminLines(admins)
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(*relayBinary)
	if err != nil {
		return fmt.Errorf("reading --relay-binary: %w", err)
	}
	now := time.Now()
	spec := kit.Spec{
		Hosts: hosts, Listen: *listen, Registration: *registration, ClientCerts: *clientCerts,
		Admins: lines, RelayBinary: bin, Now: now,
	}

	// Every rule the kit has is checked before the bundle is issued, so a
	// refused kit — the binary a Mach-O, say — records no rotation for an
	// archive that was never written.
	if err := kit.Check(spec); err != nil {
		return err
	}

	var store *pki.Store
	if *withoutBundle {
		// Nothing is issued and no passphrase is asked for: the anchor is
		// read as show reads it.
		if store, err = pki.OpenLocked(*dir); err != nil {
			return err
		}
		spec.Anchor = pki.SPKI(store.Anchor.Cert)
	} else {
		secret, err := unlock(*dir, *passFile)
		if err != nil {
			return err
		}
		if store, err = pki.Open(*dir, secret); err != nil {
			return err
		}
		if !store.Encrypted() {
			fmt.Fprintln(os.Stderr, "auu-ca: "+legacyWarning(store.Dir()))
		}
		bundle, err := store.IssueRelay(hosts, *years, now)
		if err != nil {
			return err
		}
		if spec.Bundle, err = pki.EncodeBundle(bundle); err != nil {
			return err
		}
		spec.Anchor = bundle.TrustAnchorSPKI
	}
	// A kit for a host the store already holds a record for goes to a relay
	// that is installed, and the recipe says update.
	_, rec, err := store.FindRecord(hosts)
	if err != nil {
		return err
	}
	rotation := len(rec.ClientInts)
	if !*withoutBundle {
		rotation-- // the one just issued
	}

	var archive bytes.Buffer
	sum, err := kit.Build(&archive, spec)
	if err != nil {
		return err
	}
	if err := writeSecret(*out, archive.Bytes()); err != nil {
		return err
	}
	if !*withoutBundle {
		recorded, err := filepath.Abs(*out)
		if err != nil {
			return err
		}
		if err := store.RecordBundlePath(hosts, recorded); err != nil {
			return err
		}
	}

	wrote := fmt.Sprintf("%s, %s", sizeText(sum.Size), sum.Arch)
	if sum.RelayVersion != "" {
		wrote += ", relay " + sum.RelayVersion
	}
	fmt.Printf("wrote %s (%s)\n", *out, wrote)
	fmt.Printf("  for           %s\n", strings.Join(hosts, ", "))
	fmt.Printf("  trust anchor  %s\n", spec.Anchor)
	if !*withoutBundle {
		if n := len(rec.ClientInts); n > 1 {
			fmt.Printf("  rotation      %d, keeping %d earlier client intermediate(s) so existing\n", n, n-1)
			fmt.Printf("                machines keep working without re-enrolling\n")
		}
	} else {
		fmt.Printf("  bundle        none; install.sh will stop before starting the relay and print the\n")
		fmt.Printf("                systemd-creds encrypt and systemctl enable lines to run once it is there\n")
	}
	fmt.Printf("  files\n")
	for _, f := range sum.Files {
		fmt.Printf("    %s  %s (%s)\n", f.SHA256, f.Name, sizeText(f.Size))
	}
	fmt.Printf("\nCopy it to the relay, run the script there, and delete it at both ends:\n")
	printKitCopy(os.Stdout, hosts[0], *out, rotation > 0)
	fmt.Printf("The host needs unzip, which a minimal install does not have: apt install unzip,\n")
	fmt.Printf("or dnf install unzip; python3 -m zipfile -e %s . unpacks it too.\n", filepath.Base(*out))
	if !*withoutBundle {
		fmt.Printf("\nThe archive holds the relay's two signing keys in the clear, and this machine's\n")
		fmt.Printf("backups must not; show warns while it is here.\n")
	}
	return nil
}

// adminLines is the --admin values as lines: each an export line, or @FILE
// read as a file of them with blank and # lines skipped. A file is parsed
// first so a bad line is named by the file and its line number; the lines
// themselves go into the kit as they were.
func adminLines(admins adminList) ([]string, error) {
	var lines []string
	for _, a := range admins {
		if !strings.HasPrefix(a, "@") {
			lines = append(lines, a)
			continue
		}
		path := a[1:]
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("--admin: %w", err)
		}
		if _, err := identity.ParseExportLines(path, data); err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
				lines = append(lines, t)
			}
		}
	}
	return lines, nil
}

// writeSecret writes the archive readable by its owner alone, whole or not
// at all: to a file beside its name, then renamed over it.
func writeSecret(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// printKitCopy is the recipe for getting a kit onto the relay and run
// there: scp, then unzip and the script under sudo over a terminal of its
// own, then the copies removed at both ends. The archive is unpacked as
// the login user in their home, where scp put it, and the script runs
// from there; nothing changes directory. A kit for a relay that is already
// installed runs the script's update form. unzip runs with -o, replacing a
// kit still unpacked there from last time without asking: its "replace?"
// prompt on the terminal sudo is about to ask on looked like a password
// prompt gone wrong, on an update from a Mac.
func printKitCopy(w io.Writer, host, file string, update bool) {
	remote := filepath.Base(file)
	form := ""
	if update {
		form = " update"
	}
	fmt.Fprintf(w, "  scp %s %s:\n", file, host)
	fmt.Fprintf(w, "  ssh -t %s 'unzip -oq %s && sudo sh %s/install.sh%s'\n", host, remote, kit.Dir, form)
	fmt.Fprintf(w, "  ssh %s 'rm -r %s %s'\n", host, remote, kit.Dir)
	fmt.Fprintf(w, "  rm %s\n", file)
}

// sizeText is a size a person reads: bytes under a kibibyte, then KiB or
// MiB to one decimal.
func sizeText(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	}
}
