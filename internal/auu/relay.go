package auu

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdRelay is the home's list of relays: adding one, seeing what each holds,
// and choosing which one commands mean when they are not told.
//
// A home with one relay never needs any of this. It exists because a person
// can be on two — a company's and their own — with one identity, one peer
// list and one inbox, and the only thing that differs between them is where
// the mail is picked up.
func cmdRelay(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s relay add|ls|show|default|rename|rm", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return relayAdd(rest)
	case "ls", "list":
		return relayList(rest)
	case "show":
		return relayShow(rest)
	case "default":
		return relayDefault(rest)
	case "rename":
		return relayRename(rest)
	case "rm", "remove":
		return relayRemove(rest)
	default:
		return usageErrf("unknown command %q; run '%s relay add|ls|show|default|rename|rm'", sub, prog)
	}
}

// relayJSON is what --json prints, for one relay.
type relayJSON struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Added      time.Time `json:"added"`
	Default    bool      `json:"default"`
	Registered bool      `json:"registered"`

	Anchor        string     `json:"anchor,omitempty"`
	AnchorExpires *time.Time `json:"anchor_expires,omitempty"`
	// The server signing intermediate this machine last accepted from this
	// relay, which is what its rotation ratchet compares against.
	ServerIntermediate       string     `json:"server_intermediate,omitempty"`
	ServerIntermediateIssued *time.Time `json:"server_intermediate_issued,omitempty"`

	CertSerial  string     `json:"cert_serial,omitempty"`
	CertLabel   string     `json:"cert_label,omitempty"`
	CertExpires *time.Time `json:"cert_expires,omitempty"`
}

// describeRelay gathers everything the home knows about one relay. It reads
// only local files: no command in this family contacts anything.
func describeRelay(s *store.Store, r *store.Relay, defaultName string) relayJSON {
	out := relayJSON{
		Name:       r.Name,
		URL:        r.URL,
		Added:      r.Added,
		Default:    r.Name == defaultName,
		Registered: s.Registered(r),
	}
	if rec, err := s.AnchorFor(r); err == nil {
		expires := rec.Cert.NotAfter
		out.Anchor, out.AnchorExpires = rec.SPKI, &expires
	} else {
		// A recorded hash with an unreadable file is still worth showing:
		// the hash is what a token vouched for, and the mismatch is the
		// thing somebody has to see.
		out.Anchor = r.TrustAnchorSPKI
	}
	if r.ServerIntSPKI != "" {
		issued := r.ServerIntNotBefore
		out.ServerIntermediate, out.ServerIntermediateIssued = r.ServerIntSPKI, &issued
	}
	if rec, err := s.CertFor(r); err == nil {
		expires := rec.NotAfter
		out.CertSerial, out.CertLabel, out.CertExpires = rec.Serial, rec.Label, &expires
	}
	return out
}

func relayAdd(args []string) error {
	fs := newFlagSet("relay add")
	name := fs.String("name", "", "what to call it here (default: the URL's host)")
	anchor := fs.String("anchor", "",
		"the relay's trust anchor hash, from 'auu-ca show', when it has no publicly trusted certificate")
	makeDefault := fs.Bool("default", false, "make this the relay commands use when none is named")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s relay add URL [--name NAME] [--anchor HASH] [--default]", prog)
	}
	url := positional[0]
	if *anchor != "" && !identity.ValidFingerprint(*anchor) {
		return usageErrf("--anchor must be 64 lowercase hex characters, as 'auu-ca show' prints")
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	// The anchor is fetched and checked before the relay is recorded, so a
	// wrong hash or an unreachable relay leaves the home as it was.
	anchorCert, err := fetchAnchor(url, *anchor)
	if err != nil {
		return err
	}
	r, err := s.AddRelay(*name, url)
	if err != nil {
		return usageErrf("%v", err)
	}
	if anchorCert != nil {
		if err := s.SaveAnchorFor(r, anchorCert); err != nil {
			return err
		}
	}
	if *makeDefault {
		if err := s.SetDefaultRelay(r.Name); err != nil {
			return err
		}
	}
	fmt.Printf("added %s as %q\n", r.URL, r.Name)
	if anchorCert != nil {
		fmt.Printf("pinned its trust anchor %s\n", (*anchor)[:16])
	}
	def, err := s.DefaultRelay()
	if err == nil && def.Name == r.Name {
		fmt.Printf("it is this home's default relay\n")
	}
	fmt.Printf("\nNext: %s register --relay %s --token TOKEN\n", prog, r.Name)
	return nil
}

func relayList(args []string) error {
	fs := newFlagSet("relay ls")
	asJSON := fs.Bool("json", false, "machine readable output")
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
	relays, err := s.Relays()
	if err != nil {
		return err
	}
	defaultName := ""
	if def, err := s.DefaultRelay(); err == nil {
		defaultName = def.Name
	}
	out := make([]relayJSON, 0, len(relays))
	for _, r := range relays {
		out = append(out, describeRelay(s, r, defaultName))
	}
	if *asJSON {
		return printJSON(out)
	}
	if len(relays) == 0 {
		fmt.Printf("no relays yet; join one with '%s enrol --name NAME TOKEN', "+
			"or add one with '%s relay add URL'\n", prog, prog)
		return nil
	}
	for _, r := range out {
		mark := " "
		if r.Default {
			mark = "*"
		}
		fmt.Printf("%s %-20s %-40s %s\n", mark, truncate(r.Name, 20), truncate(r.URL, 40), relayFlags(r))
	}
	if defaultName == "" {
		fmt.Printf("\nNo default relay. Choose one with: %s relay default NAME\n", prog)
	} else {
		fmt.Printf("\n* is the default; override it with --relay NAME or AUU_RELAY\n")
	}
	return nil
}

// relayFlags is the short summary at the end of an 'auu relay ls' line: what
// this home holds for that relay, in the order somebody troubleshooting asks
// about it.
func relayFlags(r relayJSON) string {
	out := ""
	add := func(s string) {
		if out != "" {
			out += ", "
		}
		out += s
	}
	if r.Registered {
		add("registered")
	} else {
		add("not registered")
	}
	if r.Anchor != "" {
		add("anchor " + r.Anchor[:8])
	}
	if r.CertExpires != nil {
		add("cert to " + r.CertExpires.Local().Format(time.DateOnly))
	}
	return out
}

func relayShow(args []string) error {
	fs := newFlagSet("relay show")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		return usageErrf("unexpected argument %q", positional[1])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	query := ""
	if len(positional) == 1 {
		query = positional[0]
	}
	r, err := selectRelay(s, query)
	if err != nil {
		return err
	}
	defaultName := ""
	if def, err := s.DefaultRelay(); err == nil {
		defaultName = def.Name
	}
	out := describeRelay(s, r, defaultName)
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("name:       %s\n", out.Name)
	fmt.Printf("url:        %s\n", out.URL)
	fmt.Printf("added:      %s\n", out.Added.Local().Format(time.DateOnly))
	fmt.Printf("default:    %v\n", out.Default)
	fmt.Printf("registered: %v\n", out.Registered)
	if out.Anchor == "" {
		fmt.Printf("anchor:     none pinned; this relay's certificate must verify on its own\n")
	} else {
		fmt.Printf("anchor:     %s\n", out.Anchor)
		if out.AnchorExpires != nil {
			fmt.Printf("            expires %s\n", out.AnchorExpires.Local().Format(time.DateOnly))
		}
		if out.ServerIntermediate != "" {
			fmt.Printf("            signing intermediate last seen %s, issued %s\n",
				out.ServerIntermediate[:16], out.ServerIntermediateIssued.Local().Format(time.DateOnly))
		}
	}
	if out.CertSerial == "" {
		fmt.Printf("certificate: none on this machine\n")
	} else {
		fmt.Printf("certificate: %s (%s), expires %s\n",
			out.CertSerial[:16], out.CertLabel, out.CertExpires.Local().Format(time.DateOnly))
	}
	fmt.Printf("directory:  %s\n", s.RelayDir(r))
	return nil
}

func relayDefault(args []string) error {
	fs := newFlagSet("relay default")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		def, err := s.DefaultRelay()
		if errors.Is(err, store.ErrNoDefaultRelay) {
			return usageErrf("no default relay; this home has %s", s.RelayNames())
		}
		if err != nil {
			return err
		}
		fmt.Printf("%s  %s\n", def.Name, def.URL)
		return nil
	}
	if len(positional) > 1 {
		return usageErrf("unexpected argument %q", positional[1])
	}
	r, err := s.Relay(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	if err := s.SetDefaultRelay(r.Name); err != nil {
		return err
	}
	fmt.Printf("commands with no --relay now use %s (%s)\n", r.Name, r.URL)
	return nil
}

func relayRename(args []string) error {
	fs := newFlagSet("relay rename")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		return usageErrf("usage: %s relay rename OLD NEW", prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	old, err := s.Relay(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	was := old.Name
	if err := s.RenameRelay(was, positional[1]); err != nil {
		return usageErrf("%v", err)
	}
	fmt.Printf("%s is now %s\n", was, positional[1])
	return nil
}

func relayRemove(args []string) error {
	fs := newFlagSet("relay rm")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s relay rm NAME [--yes]", prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	r, err := s.Relay(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	// What goes is named before the question is asked: the certificate and
	// the pinned anchor in that directory cannot be recovered except by
	// enrolling again.
	fmt.Printf("%s (%s) will be forgotten:\n", r.Name, r.URL)
	if s.HasCertFor(r) {
		fmt.Printf("  this machine's client certificate there, and its private key\n")
	}
	if r.TrustAnchorSPKI != "" {
		fmt.Printf("  the pinned trust anchor %s\n", r.TrustAnchorSPKI[:16])
	}
	if s.Registered(r) {
		fmt.Printf("  how far its mailbox has been drained\n")
	}
	fmt.Printf("Mail already fetched stays in your spool. Your mailbox on the relay is\n")
	fmt.Printf("not deleted; this only forgets it here.\n")
	if !*yes && !confirm("Remove it?") {
		fmt.Fprintln(os.Stderr, "nothing was removed")
		return &exitError{code: exitUsage, err: errors.New("cancelled")}
	}
	wasDefault := false
	if def, err := s.DefaultRelay(); err == nil && def.Name == r.Name {
		wasDefault = true
	}
	if err := s.RemoveRelay(r.Name); err != nil {
		return err
	}
	fmt.Printf("removed %s\n", r.Name)
	if wasDefault {
		fmt.Printf("it was the default; choose another with: %s relay default NAME\n", prog)
	}
	return nil
}
