package auu

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

func cmdInit(args []string) error {
	fs := newFlagSet("init")
	name := fs.String("name", "", "your name, as peers will address you: letters, digits, '.', '_' and '-'")
	relay := fs.String("relay", "", "relay base URL, for example https://relay.example")
	anchor := fs.String("anchor", "",
		"the relay's trust anchor hash, from 'auu-ca show', when it has no publicly trusted certificate")
	force := fs.Bool("force", false, "overwrite an existing identity (you lose access to mail sent to the old one)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	if *name == "" {
		return usageErrf("--name is required")
	}
	if strings.ContainsAny(*name, "\n\r") {
		return usageErrf("--name must be a single line")
	}
	if *anchor != "" {
		if !identity.ValidFingerprint(*anchor) {
			return usageErrf("--anchor must be 64 lowercase hex characters, as 'auu-ca show' prints")
		}
		if *relay == "" {
			return usageErrf("--anchor needs --relay: an anchor is pinned for one relay")
		}
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	replacing := s.HasIdentity()
	if replacing && !*force {
		return usageErrf("an identity already exists in %s; pass --force to replace it, "+
			"or '%s anchor pin' to pin a relay's anchor and keep it", s.Root(), prog)
	}
	if replacing {
		// An encrypted home is decrypted first, deliberately by hand: a
		// plain identity written beside home.key is the state a crash
		// leaves, and this command must not leave it on purpose.
		enc, err := s.Encrypted()
		if err != nil {
			return err
		}
		if enc {
			return usageErrf("the keys in %s are encrypted; run '%s passphrase remove' first, "+
				"then init --force, then '%s passphrase set' again", s.Root(), prog, prog)
		}
	}

	// The anchor is fetched and checked before anything is written, so a
	// wrong hash or an unreachable relay leaves the home as it was. An
	// identity, above all one being replaced, is not something to discard
	// on the way to an error.
	var anchorCert *x509.Certificate
	if *anchor != "" {
		if anchorCert, err = fetchAnchor(*relay, *anchor); err != nil {
			return err
		}
	}

	id, err := identity.Generate(*name)
	if err != nil {
		return err
	}
	if err := s.SaveIdentity(id); err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.Name = *name
	if err := s.SaveConfig(cfg); err != nil {
		return err
	}

	// Every relay this home knows is kept: they are relays, and the new
	// identity can register on any of them. What went with the old identity
	// goes: its certificates, which those relays' authorities issued to a
	// key that is now gone, and its cursors, because the new identity has
	// drained nothing anywhere. The pinned anchors stay, because they are
	// the relays' own and are what makes registering again verifiable.
	if replacing {
		relays, err := s.Relays()
		if err != nil {
			return err
		}
		for _, r := range relays {
			had := s.HasCertFor(r)
			if err := s.ForgetIdentityAt(r); err != nil {
				return err
			}
			if had {
				fmt.Fprintf(os.Stderr,
					"%s: this machine's client certificate for %s belonged to the old "+
						"identity and has been discarded\n", prog, r.Name)
			}
		}
	}

	var added *store.Relay
	if *relay != "" {
		if added, err = s.Relay(*relay); err != nil {
			if !errors.Is(err, store.ErrNoSuchRelay) {
				return err
			}
			if added, err = s.AddRelay("", *relay); err != nil {
				return usageErrf("%v", err)
			}
		}
		if err := s.SetDefaultRelay(added.Name); err != nil {
			return err
		}
		if anchorCert != nil {
			if err := s.SaveAnchorFor(added, anchorCert); err != nil {
				return err
			}
			fmt.Printf("pinned the trust anchor of %s: %s\n", added.Name, (*anchor)[:16])
		}
	}

	fmt.Printf("identity created in %s\n", s.Root())
	fmt.Printf("fingerprint: %s\n", id.Fingerprint())
	fmt.Printf("\nGive this line to the people you want to hear from:\n\n%s\n\n", id.Public().ExportLine())
	if added == nil {
		fmt.Printf("No relay yet. Add one with: %s relay add URL\n", prog)
	} else {
		fmt.Printf("Next: %s register --relay %s\n", prog, added.Name)
	}
	fmt.Printf("%s\n", encryptHint())
	return nil
}

// encryptHint is the one line init and enrol print about the passphrase
// they did not ask for.
func encryptHint() string {
	return fmt.Sprintf("To encrypt these keys under a passphrase: %s passphrase set", prog)
}

type idJSON struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Short       string `json:"short"`
	Suite       string `json:"suite"`
	SuiteID     int    `json:"suite_id"`
	PQCategory  int    `json:"pq_category"`
	// Encrypted says the keys are under a passphrase; Locked says no agent
	// is holding them unlocked right now. A plain home is never locked.
	// The skill reads Locked before it starts a long task.
	Encrypted bool `json:"encrypted"`
	Locked    bool `json:"locked"`
	// Until is when the agent will lock, RFC 3339, when it is unlocked
	// for a fixed time.
	Until string `json:"until,omitempty"`
	// Relay is the default relay's URL and RelayName what this home calls
	// it; Relays is every relay the home knows, by name. One identity is on
	// all of them, which is what one home means.
	Relays     []string `json:"relays"`
	RelayName  string   `json:"relay_name,omitempty"`
	Relay      string   `json:"relay"`
	ExportLine string   `json:"export_line"`
	Home       string   `json:"home"`
}

// cmdID prints what the identity is. It reads the public half and asks
// the agent nothing but whether it is unlocked, so it works — and says
// "locked" — with the identity locked.
func cmdID(args []string) error {
	if len(args) > 0 && args[0] == "export" {
		_, self, err := requireIdentity()
		if err != nil {
			return err
		}
		fmt.Println(self.ExportLine())
		return nil
	}
	fs := newFlagSet("id")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, self, err := requireIdentity()
	if err != nil {
		return err
	}
	relays, err := s.Relays()
	if err != nil {
		return err
	}
	suite := self.Suite()
	out := idJSON{
		Name:        self.Name,
		Fingerprint: self.Fingerprint(),
		Short:       self.Short(),
		Suite:       suite.Name,
		SuiteID:     int(suite.ID),
		PQCategory:  suite.PQCategory,
		Relays:      make([]string, 0, len(relays)),
		ExportLine:  self.ExportLine(),
		Home:        s.Root(),
	}
	for _, r := range relays {
		out.Relays = append(out.Relays, r.Name)
	}
	if def, err := s.DefaultRelay(); err == nil {
		out.RelayName, out.Relay = def.Name, def.URL
	}
	if out.Encrypted, err = s.Encrypted(); err != nil {
		return err
	}
	secrets := "not encrypted"
	if out.Encrypted {
		out.Locked = true
		secrets = "encrypted, locked"
		if c, err := agent.NewClient(s.Root()); err == nil {
			if st, err := c.Status(); err == nil && !st.Locked {
				out.Locked = false
				secrets = "encrypted, " + untilLine(st)
				if !st.Until.IsZero() {
					out.Until = st.Until.Format(time.RFC3339)
				}
			}
		}
	}
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("name:        %s\n", out.Name)
	fmt.Printf("fingerprint: %s\n", out.Fingerprint)
	fmt.Printf("keys:        %s\n", suite.Describe())
	fmt.Printf("secrets:     %s\n", secrets)
	switch {
	case out.Relay == "":
		fmt.Printf("relay:       %s\n", orNone(""))
	default:
		fmt.Printf("relay:       %s (%s)\n", out.RelayName, out.Relay)
	}
	if len(out.Relays) > 1 {
		fmt.Printf("relays:      %s\n", strings.Join(out.Relays, ", "))
	}
	fmt.Printf("home:        %s\n", out.Home)
	return nil
}

func cmdRegister(args []string) error {
	fs := newFlagSet("register")
	tok := fs.String("token", "", "enrolment token, if the relay requires one")
	label := fs.String("label", "", "a name for this machine, shown to administrators (default: hostname)")
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
	// Deliberately without this machine's certificate, and without the
	// renewal check: this command is how a machine whose certificate is
	// missing or refused gets a working one, and it must not fail on the way
	// in by renewing what it has or by offering it.
	c, err := dialNoCert(s, id, r)
	if err != nil {
		return err
	}
	params, err := relayParams(c)
	if err != nil {
		return transportErr(err)
	}
	key, csr, err := newCSR(s, id, r, *label, *tok, params)
	if err != nil {
		return err
	}
	resp, err := c.Register(ctx(), csr)
	if err != nil {
		return transportErr(err)
	}
	cert, err := storeIssued(s, r, *label, key, resp)
	if err != nil {
		return err
	}
	if err := s.MarkRegistered(r); err != nil {
		return err
	}
	fmt.Printf("registered %s as %q on %s (%s)\n", id.Public().Short(), id.Name, r.Name, r.URL)
	reportIssued(cert)
	return nil
}

func cmdPeers(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s peers add|ls|rm|fetch", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return peersAdd(rest)
	case "ls", "list":
		return peersList(rest)
	case "rm", "remove":
		return peersRemove(rest)
	case "fetch":
		return peersFetch(rest)
	default:
		return usageErrf("unknown peers subcommand %q", sub)
	}
}

func peersAdd(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s peers add <export-line | @file | ->", prog)
	}
	source := strings.Join(args, " ")
	var lines []string
	switch {
	case source == "-":
		text, err := readText([]string{"-"}, "")
		if err != nil {
			return err
		}
		lines = strings.Split(text, "\n")
	case strings.HasPrefix(source, "@"):
		data, err := os.ReadFile(strings.TrimPrefix(source, "@"))
		if err != nil {
			return usageErrf("reading peer file: %v", err)
		}
		lines = strings.Split(string(data), "\n")
	default:
		// One line, pasted. A break in it is the paste's, not a key's: a
		// mail client or a terminal wrapped what was one line.
		if strings.Contains(strings.TrimSpace(source), "\n") {
			return usageErrf("the line has a break in it; paste it as one line")
		}
		lines = []string{source}
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	added := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		pub, err := identity.ParseExportLine(trimmed)
		if err != nil {
			return usageErrf("%v", err)
		}
		ok, err := s.AddPeer(pub)
		if err != nil {
			return usageErrf("%v", err)
		}
		if ok {
			added++
			fmt.Printf("added %s  %s\n", pub.Short(), orNone(pub.Name))
			fmt.Printf("  confirm this fingerprint with them over a channel you trust:\n  %s\n", pub.Fingerprint())
		} else {
			fmt.Printf("already known: %s  %s\n", pub.Short(), orNone(pub.Name))
		}
	}
	if added > 0 {
		fmt.Printf("\nIf your relay mailbox is restricted, run '%s allow push' so they can reach you.\n", prog)
	}
	return nil
}

type peerJSON struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Short       string `json:"short"`
	// Suite says what this peer's keys are made of. A peer's suite is fixed
	// by their fingerprint and cannot be changed by anything on the network,
	// so this is a fact about who they are, not about one message.
	Suite      string `json:"suite"`
	SuiteID    int    `json:"suite_id"`
	PQCategory int    `json:"pq_category"`
}

func peersList(args []string) error {
	fs := newFlagSet("peers ls")
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
	peers, err := s.Peers()
	if err != nil {
		return err
	}
	if *asJSON {
		out := make([]peerJSON, 0, len(peers))
		for _, p := range peers {
			out = append(out, peerJSON{
				Name: p.Name, Fingerprint: p.Fingerprint(), Short: p.Short(),
				Suite: p.Suite().Name, SuiteID: int(p.Suite().ID),
				PQCategory: p.Suite().PQCategory,
			})
		}
		return printJSON(out)
	}
	if len(peers) == 0 {
		fmt.Printf("no peers yet; add one with '%s peers add <their export line>'\n", prog)
		return nil
	}
	// The suite is shown only when a peer is not on the default one. With a
	// single suite in existence, a column repeating the same value on every
	// line would be noise; the moment there are two, the odd one out is what
	// somebody needs to see.
	for _, p := range peers {
		fmt.Printf("%-16s  %-24s  %s", p.Short(), truncate(p.Name, 24), p.Fingerprint())
		if p.Suite().ID != identity.DefaultSuite().ID {
			fmt.Printf("  [%s]", p.Suite().Name)
		}
		fmt.Println()
	}
	return nil
}

func peersRemove(args []string) error {
	if len(args) != 1 {
		return usageErrf("usage: %s peers rm <name|fingerprint>", prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	pub, err := s.Resolve(args[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	removed, err := s.RemovePeer(pub.Fingerprint())
	if err != nil {
		return err
	}
	if !removed {
		return usageErrf("no peer %q", args[0])
	}
	fmt.Printf("removed %s  %s\n", pub.Short(), orNone(pub.Name))
	return nil
}

// peersFetch is a convenience only. It deliberately does not add the peer: the
// relay is not a trust anchor, so a human has to confirm the fingerprint first.
// peersFetch is 'auu lookup' under its older name.
func peersFetch(args []string) error {
	fs := newFlagSet("peers fetch")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s peers fetch <fingerprint>", prog)
	}
	return runLookup(positional[0], false, *relay)
}

// cmdAllow sets who may queue mail for you, on every relay you are on.
//
// Your peer list is one list wherever your mail arrives, so the policy that
// follows from it is one policy. --relay narrows it to a single relay for the
// case where somebody wants two different answers, which is unusual enough to
// have to be asked for.
func cmdAllow(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s allow push|clear", prog)
	}
	sub, rest := args[0], args[1:]
	if sub != "push" && sub != "clear" {
		return usageErrf("unknown allow subcommand %q", sub)
	}
	fs := newFlagSet("allow " + sub)
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, rest)
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

	var fps []string
	if sub == "push" {
		peers, err := s.Peers()
		if err != nil {
			return err
		}
		fps = make([]string, 0, len(peers))
		for _, p := range peers {
			fps = append(fps, p.Fingerprint())
		}
	}
	for _, r := range relays {
		c, err := dial(s, id, r)
		if err != nil {
			return err
		}
		if err := c.SetAllowlist(ctx(), fps); err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		if sub == "push" {
			fmt.Printf("%s will now accept mail for you from %d peer(s) only\n", r.Name, len(fps))
		} else {
			fmt.Printf("%s: allow list cleared; any registered user there can queue mail for you\n", r.Name)
		}
	}
	if sub == "push" && len(fps) == 0 {
		fmt.Println("warning: your peer list is empty, so nobody can reach you")
	}
	if sub == "clear" {
		fmt.Println("(messages from senders outside your peer list still land in quarantine)")
	}
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
