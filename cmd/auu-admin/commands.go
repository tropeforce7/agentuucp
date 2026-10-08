package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
	"github.com/tropeforce7/agentuucp/internal/token"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdStatus(args []string) error {
	fs, c := newFlagSet("status")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	st, err := cl.AdminStatus(ctx())
	if err != nil {
		return adminErr(c, err)
	}
	if *c.asJSON {
		return printJSON(st)
	}
	fmt.Printf("relay:          %s\n", relayURL(c))
	// The relay's free text through the escaper; its words for the
	// registration mode and the certificate mode were checked against
	// the protocol's set when the answer was read.
	fmt.Printf("public url:     %s\n", orNone(identity.PrintableText(st.PublicURL)))
	fmt.Printf("registration:   %s\n", st.Registration)
	fmt.Printf("uptime:         %s\n", identity.PrintableText(st.Uptime))
	fmt.Printf("administrators: %d\n", st.Administrators)
	fmt.Printf("mailboxes:      %d\n", st.Mailboxes)
	fmt.Printf("queued:         %d messages, %s\n", st.QueuedMessages, term.HumanBytes(st.QueuedBytes))
	fmt.Printf("live tokens:    %d\n", st.LiveTokens)
	fmt.Printf("blocks:         %d\n", st.Blocks)
	fmt.Printf("access log:     %s\n", identity.PrintableText(st.AccessLog))
	fmt.Printf("token max age:  %s\n", (time.Duration(st.TokenMaxAgeSecs) * time.Second).String())
	fmt.Print(maxRecipientsLine(st.Sections.Sections))
	fmt.Printf("client certs:   %s\n", st.ClientCerts)
	if st.CAFingerprint != "" {
		fmt.Printf("  live:         %d\n", st.LiveCerts)
		fmt.Printf("  lifetime:     %s\n", (time.Duration(st.CertLifetimeSecs) * time.Second).String())
		fmt.Printf("  authority:    %s\n", st.CAFingerprint[:16])
		if st.CANotAfter != nil {
			// Rotating the authority means re-enrolling every machine, so
			// the date belongs in front of an operator rather than in a
			// directory listing.
			fmt.Printf("  expires:      %s\n", st.CANotAfter.Local().Format("2006-01-02"))
		}
	}
	return nil
}

// maxRecipientsLine is the status report's line for the relay's
// max_recipients, which travels in a section so that an auu-admin from
// before it reads the answer still: the number in force when the answer
// carries the section, and nothing at all from a relay from before the
// setting. The section was held to its rule when the answer was read.
func maxRecipientsLine(sections []wire.Section) string {
	data, ok := recipients.Find(sections, recipients.MaxName)
	if !ok {
		return ""
	}
	n, err := recipients.CheckMax(data)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("max recipients: %d\n", n)
}

func cmdMailboxes(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: auu-admin mailboxes ls|show|rm|purge")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls":
		return mailboxesList(rest)
	case "show":
		return mailboxShow(rest)
	case "rm":
		return mailboxRemove(rest, false)
	case "purge":
		return mailboxRemove(rest, true)
	default:
		return usageErrf("unknown mailboxes subcommand %q", sub)
	}
}

func mailboxesList(args []string) error {
	fs, c := newFlagSet("mailboxes ls")
	after := fs.String("after", "", "start after this fingerprint")
	limit := fs.Int("limit", 50, "how many to return")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *limit < 1 {
		return usageErrf("--limit must be at least 1, got %d", *limit)
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	resp, err := cl.AdminMailboxes(ctx(), *after, *limit)
	if err != nil {
		return adminErr(c, err)
	}
	if *c.asJSON {
		return printJSON(resp)
	}
	if len(resp.Mailboxes) == 0 {
		fmt.Println("no mailboxes")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tNAME\tQUEUED\tBYTES\tALLOW\tCARD\tDIRECTORY\tSTATE")
	for _, m := range resp.Mailboxes {
		state := "-"
		if m.Blocked {
			state = "blocked"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			m.FP[:16], truncate(orNone(identity.Printable(m.Name)), 20), m.QueuedMessages,
			term.HumanBytes(m.QueuedBytes), allowColumn(m), cardColumn(m), directoryColumn(m), state)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if resp.Next != "" {
		fmt.Printf("\nmore: auu-admin mailboxes ls --after %s\n", resp.Next)
	}
	return nil
}

func mailboxShow(args []string) error {
	fs, c := newFlagSet("mailboxes show")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	fp, err := oneFingerprint(positional, "auu-admin mailboxes show FP")
	if err != nil {
		return err
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	m, err := cl.AdminMailbox(ctx(), fp)
	if err != nil {
		return adminErr(c, err)
	}
	if *c.asJSON {
		return printJSON(m)
	}
	fmt.Printf("fingerprint: %s\n", m.FP)
	fmt.Printf("name:        %s\n", orNone(identity.Printable(m.Name)))
	fmt.Printf("created:     %s\n", m.Created.Local().Format(time.RFC3339))
	fmt.Printf("queued:      %d messages, %s\n", m.QueuedMessages, term.HumanBytes(m.QueuedBytes))
	fmt.Printf("allowlist:   %s\n", allowField(*m))
	fmt.Printf("card:        %s\n", cardField(*m))
	fmt.Printf("directory:   %s\n", directoryField(*m))
	fmt.Printf("channels:    %d\n", m.Channels)
	fmt.Printf("blocked:     %t\n", m.Blocked)
	return nil
}

// allowColumn is a mailbox's allow list in the listing: the count and the
// state word, or "-" for a mailbox that has never pushed one. "broken" is
// the word to look for after an incident: a list that does not verify is
// refused on until its owner pushes again.
func allowColumn(m relayapi.MailboxRecord) string {
	if m.Allow == "" {
		return "-"
	}
	return fmt.Sprintf("%d %s", m.AllowlistSize, m.Allow)
}

// allowField is the same for 'show', in words.
func allowField(m relayapi.MailboxRecord) string {
	if m.Allow == "" {
		return "none"
	}
	return fmt.Sprintf("%d senders, %s", m.AllowlistSize, m.Allow)
}

// cardColumn is a mailbox's card in the listing: "-" for a mailbox that
// has never pushed one, "broken" for a row that no longer verifies, and
// otherwise the two words the relay parsed from it, "listed,knocks",
// "listed", "knocks" or "neither".
func cardColumn(m relayapi.MailboxRecord) string {
	if m.Card == "" {
		return "-"
	}
	return cardField(m)
}

// cardField is the same for 'show', in words: "none", "broken", or what
// the card says.
func cardField(m relayapi.MailboxRecord) string {
	switch m.Card {
	case "":
		return "none"
	case relayapi.CardSigned:
	default:
		return m.Card
	}
	switch {
	case m.CardListed && m.CardKnocks:
		return "listed, knocks"
	case m.CardListed:
		return "listed"
	case m.CardKnocks:
		return "knocks"
	}
	return "neither"
}

// directoryColumn is a mailbox's channel directory in the listing: "-" for
// a mailbox that has never pushed one, which has the one channel, default,
// and otherwise the word the relay reached by verifying the stored
// document against the owner's key. "broken" here is the heaviest of the
// three: that mailbox takes no post at all until its owner pushes again.
// The channel count is not in this line; 'show' has it, beside the word
// that says whether any of them routes.
func directoryColumn(m relayapi.MailboxRecord) string {
	if m.Directory == "" {
		return "-"
	}
	return m.Directory
}

// directoryField is the same for 'show', in words: "none" for a mailbox
// that has never pushed one, and otherwise the word.
func directoryField(m relayapi.MailboxRecord) string {
	if m.Directory == "" {
		return "none"
	}
	return m.Directory
}

// mailboxRemove backs both rm and purge, which differ only in whether the
// mailbox itself survives.
func mailboxRemove(args []string, purgeOnly bool) error {
	name := "mailboxes rm"
	if purgeOnly {
		name = "mailboxes purge"
	}
	fs, c := newFlagSet(name)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	fp, err := oneFingerprint(positional, "auu-admin "+name+" FP")
	if err != nil {
		return err
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}

	// Say what will actually be destroyed before destroying it.
	m, err := cl.AdminMailbox(ctx(), fp)
	if err != nil {
		return adminErr(c, err)
	}
	what := fmt.Sprintf("%d queued message(s), %s", m.QueuedMessages, term.HumanBytes(m.QueuedBytes))
	if purgeOnly {
		fmt.Printf("Purging %s (%s) will discard %s. The mailbox itself stays.\n",
			m.FP[:16], orNone(identity.Printable(m.Name)), what)
	} else {
		fmt.Printf("Removing %s (%s) will discard %s and its allowlist, "+
			"and the owner will have to register again.\n", m.FP[:16], orNone(identity.Printable(m.Name)), what)
	}
	if !*yes && !confirm("Continue?") {
		return usageErrf("cancelled")
	}

	if purgeOnly {
		err = cl.AdminPurge(ctx(), fp)
	} else {
		err = cl.AdminDeregister(ctx(), fp)
	}
	if err != nil {
		return adminErr(c, err)
	}
	if purgeOnly {
		fmt.Printf("purged %s\n", fp[:16])
	} else {
		fmt.Printf("removed %s\n", fp[:16])
	}
	return nil
}

func cmdBlocks(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: auu-admin blocks ls|add|rm")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls":
		return blocksList(rest)
	case "add":
		return blockAdd(rest)
	case "rm":
		return blockRemove(rest)
	default:
		return usageErrf("unknown blocks subcommand %q", sub)
	}
}

func blocksList(args []string) error {
	fs, c := newFlagSet("blocks ls")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	blocks, err := cl.AdminBlocks(ctx())
	if err != nil {
		return adminErr(c, err)
	}
	if *c.asJSON {
		return printJSON(blocks)
	}
	if len(blocks) == 0 {
		fmt.Println("no blocks")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tSINCE\tBY\tREASON")
	for _, b := range blocks {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			b.FP[:16], b.Created.Local().Format("2006-01-02"), b.ByFP[:16], identity.PrintableText(b.Reason))
	}
	return w.Flush()
}

func blockAdd(args []string) error {
	fs, c := newFlagSet("blocks add")
	reason := fs.String("reason", "", "why this identity is blocked (required)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	fp, err := oneFingerprint(positional, "auu-admin blocks add FP --reason TEXT")
	if err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return usageErrf("--reason is required: a block nobody can explain is a block nobody can lift")
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	fmt.Printf("Blocking %s stops them registering, authenticating, and receiving mail.\n"+
		"Queued messages are left alone; purge them separately if you mean to.\n", fp[:16])
	if !*yes && !confirm("Continue?") {
		return usageErrf("cancelled")
	}
	if err := cl.AdminBlock(ctx(), fp, strings.TrimSpace(*reason)); err != nil {
		return adminErr(c, err)
	}
	fmt.Printf("blocked %s\n", fp[:16])
	return nil
}

func blockRemove(args []string) error {
	fs, c := newFlagSet("blocks rm")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	fp, err := oneFingerprint(positional, "auu-admin blocks rm FP")
	if err != nil {
		return err
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	if err := cl.AdminUnblock(ctx(), fp); err != nil {
		return adminErr(c, err)
	}
	fmt.Printf("unblocked %s\n", fp[:16])
	return nil
}

func cmdToken(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: auu-admin token issue|ls|revoke|show")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "issue":
		return tokenIssue(rest)
	case "ls":
		return tokenList(rest)
	case "revoke":
		return tokenRevoke(rest)
	case "show":
		return tokenShow(rest)
	default:
		return usageErrf("unknown token subcommand %q", sub)
	}
}

type issuedJSON struct {
	Token  string               `json:"token"`
	Record relayapi.TokenRecord `json:"record"`
}

// tokenIssue signs a token with this administrator's identity and registers it
// with the relay in one step.
//
// MinTokenLife is the shortest --expires there is. A token records two whole
// seconds, so anything under one cannot be represented.
const MinTokenLife = time.Second

// tokenWindow is the interval a token issued at now would carry: two whole
// seconds since the epoch, because that is what a token records.
//
// A duration under a second is refused outright rather than truncated. Left
// to the truncation it is neither accepted nor refused but both, depending on
// where in the current second now happens to fall: --expires 1ns yields a
// full second of life when now is at .999 and none when now is at .001. An
// input whose meaning depends on the phase of the wall clock is worse than
// one that is simply refused, and nothing legitimate asks for a token that
// lives less than a second.
//
// --not-after is an absolute time and keeps the weaker rule, that it must
// name a later second than this one: an administrator giving a timestamp has
// said exactly what they mean, and the only thing to check is that it has not
// already passed.
func tokenWindow(now time.Time, expires time.Duration, notAfter string) (int64, int64, error) {
	if notAfter == "" {
		if expires < MinTokenLife {
			return 0, 0, usageErrf("--expires must be at least %v, got %v: "+
				"a token's window is whole seconds", MinTokenLife, expires)
		}
		return now.Unix(), now.Add(expires).Unix(), nil
	}
	end, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return 0, 0, usageErrf("--not-after must be RFC3339, for example 2026-10-01T12:00:00Z: %v", err)
	}
	if end.Unix() <= now.Unix() {
		return 0, 0, usageErrf("the token would already have expired: " +
			"--not-after leaves it no whole second to live")
	}
	return now.Unix(), end.Unix(), nil
}

// Both halves matter. The signature is what proves an administrator issued it;
// registering is what lets the relay revoke it, count its uses, and refuse one
// it has never heard of.
func tokenIssue(args []string) error {
	fs, c := newFlagSet("token issue")
	note := fs.String("note", "", "who this token is for and why (required)")
	expires := fs.Duration("expires", 168*time.Hour, "how long the token is valid for")
	notAfter := fs.String("not-after", "", "absolute expiry, RFC3339 (overrides --expires)")
	uses := fs.Int("uses", 1, "how many mailboxes, or machines, this token may create")
	forFP := fs.String("for", "", "bind the token to one fingerprint, so only they can spend it")
	use := fs.String("use", token.UseRegister,
		"register to create a mailbox, cert to add a machine to an identity that has one")
	anchor := fs.String("anchor", "",
		"the relay's trust anchor hash, or 'none'; default: whatever this machine pinned")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if !token.ValidUse(*use) {
		return usageErrf("--use must be %q or %q, got %q", token.UseRegister, token.UseCert, *use)
	}
	// A certificate token adds a machine to one identity, so there is no
	// sense in an unbound one, and token.Issue would refuse it anyway. Said
	// here, where the flags are, rather than as a validation error.
	if *use == token.UseCert && *forFP == "" {
		return usageErrf("--use cert needs --for FINGERPRINT: a certificate token is bound to one identity")
	}
	if strings.TrimSpace(*note) == "" {
		return usageErrf("--note is required: a token that does not say what it is for " +
			"is a shared secret with extra steps")
	}
	if *forFP != "" && !identity.ValidFingerprint(*forFP) {
		return usageErrf("--for must be a full 64 character fingerprint")
	}
	// An explicit --uses is a choice, not an absent value, so zero is refused
	// rather than quietly becoming the default of one.
	if *uses < 1 || *uses > token.MaxUses {
		return usageErrf("--uses must be between 1 and %d, got %d", token.MaxUses, *uses)
	}

	s, id, cl, err := dial(c)
	if err != nil {
		return err
	}

	now := time.Now()
	notBeforeSec, notAfterSec, err := tokenWindow(now, *expires, *notAfter)
	if err != nil {
		return err
	}

	// The audience is the relay this command is talking to, so a token can
	// never be spent on a relay its issuer did not mean.
	target, err := adminRelay(s, c)
	if err != nil {
		return err
	}
	relay := token.NormaliseRelay(target.URL)
	if err := token.ValidateRelay(relay); err != nil {
		return usageErrf("relay URL %v", err)
	}

	// The anchor the holder will pin. Taken from what this machine itself
	// pinned rather than fetched from the relay: a client that has not
	// pinned it cannot complete a handshake with the relay at all, so there
	// would be nothing to fetch it from, and an administrator who has not
	// pinned a relay has no business vouching for it.
	anchorHash, err := tokenAnchor(target, *anchor)
	if err != nil {
		return err
	}

	raw, err := token.Issue(id, token.Claims{
		Relay:     relay,
		Anchor:    anchorHash,
		Use:       *use,
		Subject:   *forFP,
		Note:      strings.TrimSpace(*note),
		NotBefore: notBeforeSec,
		NotAfter:  notAfterSec,
		Uses:      *uses,
	})
	if err != nil {
		return usageErrf("%v", err)
	}
	record, err := cl.AdminAddToken(ctx(), raw)
	if err != nil {
		return adminErr(c, err)
	}

	if *c.asJSON {
		return printJSON(issuedJSON{Token: raw, Record: *record})
	}
	// Read back what was actually signed, rather than what was asked for: the
	// id and any defaults were filled in during issue.
	issued, err := token.Parse(raw)
	if err != nil {
		return err
	}
	fmt.Print(token.Describe(issued.Claims, id.Name, true, now))
	what := "create a mailbox"
	if *use == token.UseCert {
		what = "enrol a machine on that identity"
	}
	fmt.Printf("\nSend this to them. It is a bearer credential: anyone holding it can\n"+
		"%s, so use a channel you would trust for that.\n\n", what)
	// Last line, and nothing after it, so the token can be piped.
	fmt.Println(raw)
	return nil
}

func tokenList(args []string) error {
	fs, c := newFlagSet("token ls")
	all := fs.Bool("all", false, "include spent, revoked and expired tokens")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	tokens, err := cl.AdminTokens(ctx(), *all)
	if err != nil {
		return adminErr(c, err)
	}
	if *c.asJSON {
		return printJSON(tokens)
	}
	if len(tokens) == 0 {
		fmt.Println("no tokens")
		return nil
	}
	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tUSE\tSTATE\tUSES\tEXPIRES\tFOR")
	for _, t := range tokens {
		bound := ""
		if t.Subject != "" {
			bound = " [" + t.Subject[:8] + "]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t%s\t%s%s\n",
			t.ID[:12], t.Use, t.State, t.UsesLeft, t.Uses,
			token.Until(t.NotAfter, now), truncate(identity.PrintableText(t.Note), 40), bound)
	}
	return w.Flush()
}

func tokenRevoke(args []string) error {
	fs, c := newFlagSet("token revoke")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: auu-admin token revoke ID")
	}
	// The shape before the id is joined onto a URL, as a fingerprint's is
	// checked before a mailbox command's.
	if !token.ValidID(positional[0]) {
		return usageErrf("%q is not a token id (32 lowercase hex characters); list them with: auu-admin token ls --all", positional[0])
	}
	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	if err := cl.AdminRevokeToken(ctx(), positional[0]); err != nil {
		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
			return usageErrf("no token with id %s; list them with: auu-admin token ls --all", positional[0])
		}
		return adminErr(c, err)
	}
	fmt.Printf("revoked %s\n", positional[0])
	return nil
}

// tokenShow is offline. It reads a token without asking any relay about it, so
// an administrator can check what they, or somebody else, actually sent.
func tokenShow(args []string) error {
	fs, c := newFlagSet("token show")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: auu-admin token show TOKEN")
	}
	u, err := token.Parse(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	// The shape before anything reads a field: Parse checks no claim, and
	// the description slices ids for a person to read.
	if err := u.Claims.Validate(); err != nil {
		return usageErrf("malformed token: %s; nothing was described",
			strings.TrimPrefix(err.Error(), token.ErrForm.Error()+": "))
	}
	if *c.asJSON {
		return printJSON(u.Claims)
	}

	// Check the signature when the issuer is somebody this home already knows,
	// which for an administrator's own tokens is themselves.
	var issuerName string
	verified := false
	if s, id, _, err := dial(c); err == nil {
		if id.Fingerprint() == u.IssuerFingerprint() {
			issuerName = id.Name
			_, verified = verifiedBy(u, id.Public())
		} else if pub, err := s.Resolve(u.IssuerFingerprint()); err == nil {
			issuerName = pub.Name
			_, verified = verifiedBy(u, pub)
		}
	}
	fmt.Print(token.Describe(u.Claims, issuerName, verified, time.Now()))
	return nil
}

func verifiedBy(u *token.Unverified, pub *identity.Public) (*token.Claims, bool) {
	c, err := u.Verify(pub, time.Now(), 0)
	// An expired token still has a good signature, and saying so is the point.
	if errors.Is(err, token.ErrExpired) || errors.Is(err, token.ErrNotYetValid) {
		return nil, true
	}
	return c, err == nil
}

func oneFingerprint(positional []string, usage string) (string, error) {
	if len(positional) != 1 {
		return "", usageErrf("usage: %s", usage)
	}
	if !identity.ValidFingerprint(positional[0]) {
		return "", usageErrf("%q is not a fingerprint; give all 64 characters", positional[0])
	}
	return positional[0], nil
}

func confirm(question string) bool {
	fmt.Printf("%s [y/N]: ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Println()
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// truncate cuts s to at most n characters, on a rune boundary, with an
// ellipsis where it cut; bytes were cut before, which left a broken final
// rune on the terminal for a label of wide characters.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	kept := 0
	for i := range s {
		if kept == n-1 {
			return s[:i] + "…"
		}
		kept++
	}
	return s
}

// cmdCerts is the administrator's view of the client certificates this relay
// has issued: which machines exist, and the power to take one away.
func cmdCerts(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: auu-admin certs ls|revoke")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls":
		return certsList(rest)
	case "revoke":
		return certsRevoke(rest)
	default:
		return usageErrf("unknown command %q; run 'auu-admin certs ls|revoke'", sub)
	}
}

func certsList(args []string) error {
	fs, c := newFlagSet("certs ls")
	all := fs.Bool("all", false, "include revoked and expired certificates")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	fp := ""
	if len(positional) == 1 {
		fp = positional[0]
		if !identity.ValidFingerprint(fp) {
			return usageErrf("give a full 64 character fingerprint, or none for every certificate")
		}
	} else if len(positional) > 1 {
		return usageErrf("unexpected argument %q", positional[1])
	}

	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	certs, err := cl.AdminCerts(ctx(), fp, *all)
	if err != nil {
		return adminErr(c, err)
	}
	if *c.asJSON {
		return printJSON(certs)
	}
	if len(certs) == 0 {
		fmt.Println("no client certificates")
		return nil
	}
	now := time.Now()
	for _, cert := range certs {
		state := "expires " + cert.NotAfter.Format("2006-01-02")
		switch {
		case cert.Revoked:
			state = "revoked"
			if cert.Reason != "" {
				state += " (" + truncate(identity.PrintableText(cert.Reason), 30) + ")"
			}
		case now.After(cert.NotAfter):
			state = "expired " + cert.NotAfter.Format("2006-01-02")
		}
		fmt.Printf("%s  %s  %-20s  %s\n",
			cert.Serial[:16], cert.FP[:16], truncate(identity.PrintableText(cert.Label), 20), state)
	}
	return nil
}

func certsRevoke(args []string) error {
	fs, c := newFlagSet("certs revoke")
	reason := fs.String("reason", "", "why, for the audit log and the certificate list")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: auu-admin certs revoke SERIAL [--reason TEXT]")
	}
	serial := positional[0]
	if !clientca.ValidSerial(serial) {
		return usageErrf("a serial is 32 lowercase hex characters; " +
			"'auu-admin certs ls' shows them")
	}

	_, _, cl, err := dial(c)
	if err != nil {
		return err
	}
	if !*yes {
		fmt.Printf("Revoking %s stops that machine reaching this relay on its very next\n"+
			"request. Its owner will need a new certificate token to enrol it again.\n", serial[:16])
		if !confirm("Revoke it?") {
			fmt.Fprintln(os.Stderr, "cancelled; nothing was changed")
			return &exitError{code: exitUsage, err: fmt.Errorf("cancelled")}
		}
	}
	if err := cl.AdminRevokeCert(ctx(), serial, strings.TrimSpace(*reason)); err != nil {
		return adminErr(c, err)
	}
	fmt.Printf("revoked %s\n", serial[:16])
	return nil
}

// tokenAnchor decides what trust anchor a token should name.
//
// "none" is for a relay with a publicly trusted certificate, where there is
// nothing to pin. An explicit hash is for the person setting a relay up, who
// has it from 'auu-ca show' and may not have enrolled against it yet.
// Otherwise it is what this machine pinned, which is the case that needs no
// thought and is therefore the default.
func tokenAnchor(r *store.Relay, flagValue string) (string, error) {
	switch {
	case flagValue == "none":
		return "", nil
	case flagValue != "":
		if !identity.ValidFingerprint(flagValue) {
			return "", usageErrf("--anchor must be 64 lowercase hex characters, " +
				"as 'auu-ca show' prints, or 'none'")
		}
		return flagValue, nil
	}
	// A relay reached over plain HTTP has no certificate to pin, so there is
	// nothing to name and nothing to ask for.
	if strings.HasPrefix(r.URL, "http://") {
		return "", nil
	}
	if r.TrustAnchorSPKI == "" {
		return "", usageErrf("this machine has pinned no trust anchor for %s: "+
			"pass --anchor HASH from 'auu-ca show', or --anchor none for a relay with a "+
			"publicly trusted certificate", r.URL)
	}
	return r.TrustAnchorSPKI, nil
}
