package auu

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
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
		return usageErrf("usage: %s relay add|ls|show|couriers|default|rename|rm", prog)
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
	case "couriers":
		return relayCouriers(rest)
	case "rm", "remove":
		return relayRemove(rest)
	default:
		return usageErrf("unknown command %q; run '%s relay add|ls|show|couriers|default|rename|rm'", sub, prog)
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

	// Registration is the relay's registration mode as its health answer
	// gave it just now — open, token or closed — which is what a name
	// listed there rests on; RegistrationError is why it could not be
	// asked. Only 'relay show' fills them: 'relay ls' reads local files
	// alone.
	Registration      string `json:"registration,omitempty"`
	RegistrationError string `json:"registration_error,omitempty"`
}

// describeRelay gathers everything the home knows about one relay. It reads
// only local files: 'relay ls' contacts nothing, and 'relay show' asks the
// relay one thing more, its registration mode, after this.
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
	// The relay's registration mode, from its health answer, which needs
	// neither a certificate nor a signature: a relay that cannot be
	// reached is said on its line, and the rest of what the home holds is
	// printed all the same, since that is what this command is for.
	if c, err := dialNoCert(s, nil, r); err != nil {
		out.RegistrationError = err.Error()
	} else if health, err := c.HealthInfo(ctx()); err != nil {
		out.RegistrationError = err.Error()
	} else {
		out.Registration = health.Registration
	}
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
	if out.Registration != "" {
		fmt.Printf("registration: %s (%s)\n", out.Registration, registrationMeans(out.Registration, "an identity here"))
	} else {
		fmt.Printf("registration: not asked (%s)\n", identity.PrintableText(out.RegistrationError))
	}
	return nil
}

// registrationMeans is what a relay's registration mode says about an
// identity found on it, subject being "this identity" or "an identity
// here": the sentence every command that asks a person to trust a listed
// name prints, since that trust rests on the relay's admission and no
// further. It is the identity the admission covers, never the name: a
// token pins at most a fingerprint, and the name on a card or a
// registration is the owner's own claim, which the sentence says. A
// relay that lies about its mode is admitting anybody, which is the case
// the open sentence warns of.
func registrationMeans(mode, subject string) string {
	switch mode {
	case relayapi.RegistrationToken:
		return "invites by token: " + subject + " was let in by an administrator, and its name is its own claim"
	case relayapi.RegistrationClosed:
		return "registers nobody now: " + subject + " was let in before it closed, under whichever rule held then, and its name is its own claim"
	default:
		return "registers anyone: " + subject + " proves nothing about who holds it, and its name is its own claim"
	}
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

// courierJSON is what 'relay couriers --json' prints, for one relay.
type courierJSON struct {
	Relay    string           `json:"relay"`
	Couriers []courierRowJSON `json:"couriers"`
}

// courierRowJSON is one neighbour, with whether this machine admits it.
type courierRowJSON struct {
	Name string `json:"name"`
	FP   string `json:"fp"`
	// Admitted says whether this machine's own couriers file for that relay
	// lists the fingerprint, which is what decides whether mail forwarded
	// through it reaches this identity once an allow list is pushed.
	Admitted bool `json:"admitted"`
	// Gone says this machine admits it and the relay no longer accepts from
	// it: nothing can arrive through it any more, and the admission is still
	// being signed into every list pushed from here until it is withdrawn.
	Gone bool `json:"gone,omitempty"`
}

// relayCouriers is the relays a relay accepts forwarded mail from: the names a
// sender writes in front of an address to reach somebody here, and the
// fingerprints a recipient must admit to be reachable from off it.
//
// The names are the relay's own and mean nothing anywhere else. Two relays may
// call the same neighbour different things, and what a neighbour calls itself
// is published nowhere, so a name from here is good for addressing mail
// through this relay and for nothing else. That is said in the output rather
// than left to be discovered, because a name that looks like a hostname invites
// the opposite assumption.
//
// It also says which of them this machine admits, since the list is most often
// read in order to decide what to admit, and a listing that made the reader
// cross-reference their own file by hand would be answering half the question.
func relayCouriers(args []string) error {
	fs := newFlagSet("relay couriers")
	relay := relayFlag(fs)
	asJSON := fs.Bool("json", false, "machine readable output")
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
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	var out []courierJSON
	for _, r := range relays {
		admitted, err := s.Couriers(r.Name)
		if err != nil {
			return err
		}
		byFP := make(map[string]bool, len(admitted))
		for _, a := range admitted {
			byFP[a.FP] = true
		}
		c, err := dial(s, id, r)
		var list []relayapi.Courier
		if err == nil {
			list, err = c.Couriers(ctx())
		}
		if err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		one := courierJSON{Relay: r.Name, Couriers: []courierRowJSON{}}
		listed := make(map[string]bool, len(list))
		for _, n := range list {
			listed[n.FP] = true
			one.Couriers = append(one.Couriers, courierRowJSON{
				Name: n.Name, FP: n.FP, Admitted: byFP[n.FP],
			})
		}
		// And the ones this machine admits that the relay no longer lists,
		// which printing only the intersection would hide. A neighbour that
		// was de-peered leaves a line in this home's file: it is still signed
		// into every allow list pushed from here, and de-peering does not
		// unregister the courier's mailbox, so the fingerprint keeps whatever
		// its admission granted. Somebody who cannot see it cannot withdraw
		// it, and 'allow show' names it only as sixty-four characters, a
		// courier not being a peer. So it is printed, marked, with the command
		// that removes it.
		for _, a := range admitted {
			if !listed[a.FP] {
				one.Couriers = append(one.Couriers, courierRowJSON{
					Name: a.Name, FP: a.FP, Admitted: true, Gone: true,
				})
			}
		}
		out = append(out, one)
	}
	if *asJSON {
		return printJSON(out)
	}
	for i, one := range out {
		if i > 0 {
			fmt.Println()
		}
		printCouriers(one)
	}
	return nil
}

// printCouriers is one relay's listing, and says three things a reader needs
// beyond the names: that a relay with none forwards nothing, that the names are
// that relay's own, and which of them this machine admits.
func printCouriers(one courierJSON) {
	if len(one.Couriers) == 0 {
		fmt.Printf("%s: accepts no forwarded mail; nobody can address mail to you through it\n", one.Relay)
		return
	}
	fmt.Printf("%s: accepts forwarded mail from %s\n", one.Relay, plural(len(one.Couriers), "relay"))
	stale := false
	for _, n := range one.Couriers {
		mark := "not admitted"
		switch {
		case n.Gone:
			mark = "admitted, but this relay no longer accepts from it"
			stale = true
		case n.Admitted:
			mark = "admitted"
		}
		fmt.Printf("  %-20s %s  %s\n", identity.PrintableText(n.Name), n.FP[:16], mark)
	}
	if stale {
		fmt.Printf("  a courier this relay no longer accepts from can carry nothing to you, and is still\n")
		fmt.Printf("  named in every list pushed from here: withdraw it with '%s allow rm --courier NAME --relay %s'\n",
			prog, one.Relay)
	}
	fmt.Printf("  these names are %s's own: a sender writes '%s!you' to reach you through one,\n",
		one.Relay, identity.PrintableText(one.Couriers[0].Name))
	fmt.Println("  and the same relay may be called something else elsewhere")
	fmt.Printf("  admit one with '%s allow add --courier NAME --relay %s', then '%s allow push'\n",
		prog, one.Relay, prog)
}
