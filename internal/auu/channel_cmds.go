package auu

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// auu channel: the owner's directory of named sub-mailboxes, and a sender's
// view of a peer's.

func cmdChannel(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s channel ls|create|update|close|delete|keep|push|pull", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls", "list":
		return channelLs(rest)
	case "create":
		return channelCreate(rest)
	case "update":
		return channelUpdate(rest)
	case "close":
		return channelClose(rest)
	case "delete", "rm":
		return channelDelete(rest)
	case "keep":
		return channelKeep(rest)
	case "push":
		return channelPush(rest)
	case "pull":
		return channelPull(rest)
	default:
		return usageErrf("unknown channel subcommand %q", sub)
	}
}

// oneName is the one positional argument the editing commands take.
func oneName(positional []string, usage string) (string, error) {
	if len(positional) != 1 {
		return "", usageErrf("usage: %s", usage)
	}
	if err := channels.ValidName(positional[0]); err != nil {
		return "", usageErrf("channel %q: %v", positional[0], err)
	}
	return positional[0], nil
}

// localDirectory is the home's directory and the issue time to preflight
// against: a home with none starts from default alone, at issue zero, which
// every relay that holds anything is ahead of.
func localDirectory(s *store.Store) (*channels.Directory, time.Time, bool, error) {
	d, found, err := s.Directory()
	if err != nil {
		return nil, time.Time{}, false, err
	}
	if !found {
		return &channels.Directory{Channels: []channels.Channel{{Name: channels.Default}}}, time.Time{}, false, nil
	}
	return d, d.Issued, true, nil
}

// existing is the channel named, or the usage error that says it is not
// there.
func existing(d *channels.Directory, name string) (*channels.Channel, error) {
	ch := d.Find(name)
	if ch == nil {
		return nil, usageErrf("channel %q is not in your directory; run '%s channel ls'", name, prog)
	}
	return ch, nil
}

// checked validates an edited directory as the relays will, and turns a
// broken rule into the usage error it is here.
func checked(d *channels.Directory, self *identity.Identity) error {
	d.V = channels.Version
	d.Owner = self.Fingerprint()
	if d.Issued.IsZero() {
		// Validate wants one; the push sets the real one.
		d.Issued = time.Now()
	}
	if err := d.Validate(); err != nil {
		return usageErrf("%v", err)
	}
	return nil
}

// description folds and checks a description given on the command line.
func description(text string) (string, error) {
	folded := foldLines(text)
	if err := channels.ValidDescription(folded); err != nil {
		return "", usageErrf("%v", err)
	}
	return folded, nil
}

func channelCreate(args []string) error {
	fs := newFlagSet("channel create")
	desc := fs.String("description", "", "what the channel is for, one line; line breaks are folded")
	notBefore := fs.String("not-before", "", "when the channel opens: RFC 3339, or a day as local midnight")
	notAfter := fs.String("not-after", "", "when the channel closes: RFC 3339, or a day as local midnight")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := oneName(positional, prog+" channel create NAME [--description TEXT] [--not-before T] [--not-after T]")
	if err != nil {
		return err
	}
	ch := channels.Channel{Name: name}
	if ch.Description, err = description(*desc); err != nil {
		return err
	}
	if *notBefore != "" {
		if ch.NotBefore, _, err = parseWhen("--not-before", *notBefore); err != nil {
			return err
		}
	}
	if *notAfter != "" {
		if ch.NotAfter, _, err = parseWhen("--not-after", *notAfter); err != nil {
			return err
		}
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	d, issued, _, err := localDirectory(s)
	if err != nil {
		return err
	}
	if d.Find(name) != nil {
		return usageErrf("channel %q already exists; run '%s channel update %s' to change it", name, prog, name)
	}
	d.Channels = append(d.Channels, ch)
	if err := checked(d, id); err != nil {
		return err
	}
	return editAndPush(s, id, relays, d, issued)
}

func channelUpdate(args []string) error {
	fs := newFlagSet("channel update")
	desc := fs.String("description", "", "what the channel is for, one line; line breaks are folded")
	notBefore := fs.String("not-before", "", "when the channel opens, or none")
	notAfter := fs.String("not-after", "", "when the channel closes, or none")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := oneName(positional, prog+" channel update NAME [--description TEXT] [--not-before T|none] [--not-after T|none]")
	if err != nil {
		return err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if !given["description"] && !given["not-before"] && !given["not-after"] {
		return usageErrf("nothing to change: give --description, --not-before or --not-after")
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	d, issued, _, err := localDirectory(s)
	if err != nil {
		return err
	}
	ch, err := existing(d, name)
	if err != nil {
		return err
	}
	if given["description"] {
		if ch.Description, err = description(*desc); err != nil {
			return err
		}
	}
	if given["not-before"] {
		at, cleared, err := parseWhen("--not-before", *notBefore)
		if err != nil {
			return err
		}
		if cleared {
			ch.NotBefore = nil
		} else {
			ch.NotBefore = at
		}
	}
	if given["not-after"] {
		at, cleared, err := parseWhen("--not-after", *notAfter)
		if err != nil {
			return err
		}
		if cleared {
			ch.NotAfter = nil
		} else {
			ch.NotAfter = at
		}
	}
	if err := checked(d, id); err != nil {
		return err
	}
	return editAndPush(s, id, relays, d, issued)
}

func channelClose(args []string) error {
	fs := newFlagSet("channel close")
	at := fs.String("at", "", "when the channel closes; now if not given")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := oneName(positional, prog+" channel close NAME [--at T]")
	if err != nil {
		return err
	}
	when := time.Now().UTC().Truncate(time.Second)
	if *at != "" {
		t, cleared, err := parseWhen("--at", *at)
		if err != nil {
			return err
		}
		if cleared {
			return usageErrf("--at wants a time; to reopen a channel run '%s channel update %s --not-after none'", prog, name)
		}
		when = *t
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	d, issued, _, err := localDirectory(s)
	if err != nil {
		return err
	}
	ch, err := existing(d, name)
	if err != nil {
		return err
	}
	if ch.NotBefore != nil && when.Before(*ch.NotBefore) {
		return usageErrf("channel %q opens %s; it cannot close before that", name, stampLocal(*ch.NotBefore))
	}
	ch.NotAfter = &when
	if err := checked(d, id); err != nil {
		return err
	}
	return editAndPush(s, id, relays, d, issued)
}

func channelDelete(args []string) error {
	fs := newFlagSet("channel delete")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := oneName(positional, prog+" channel delete NAME")
	if err != nil {
		return err
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	d, issued, _, err := localDirectory(s)
	if err != nil {
		return err
	}
	if _, err := existing(d, name); err != nil {
		return err
	}
	kept := d.Channels[:0:0]
	for _, ch := range d.Channels {
		if ch.Name != name {
			kept = append(kept, ch)
		}
	}
	d.Channels = kept
	if err := checked(d, id); err != nil {
		return err
	}
	if err := editAndPush(s, id, relays, d, issued); err != nil {
		return err
	}
	if len(d.Channels) == 0 {
		fmt.Println("warning: your directory is empty, so nobody can post to you")
	}
	return nil
}

func channelPush(args []string) error {
	fs := newFlagSet("channel push")
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
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	d, found, err := s.Directory()
	if err != nil {
		return err
	}
	if !found {
		return usageErrf("no directory: your mailbox has the one channel, default; nothing to push")
	}
	// Under the stored issue, deliberately: a relay holding a newer one
	// from another machine must refuse this, not be written over.
	out, err := pushDirectory(s, id, relays, d)
	if err != nil {
		return err
	}
	if out.Conflict || out.Failed {
		return &exitError{code: exitTransport, err: errors.New("not every relay took the directory")}
	}
	return nil
}

func channelPull(args []string) error {
	fs := newFlagSet("channel pull")
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
	held, err := relayDirectory(c, id.Public())
	if errors.Is(err, channels.ErrSignature) || errors.Is(err, channels.ErrOwner) {
		return &exitError{code: exitTransport, err: fmt.Errorf(
			"the directory %s serves for you does not verify against your key; do not trust it", r.Name)}
	}
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	if held == nil {
		return usageErrf("no directory on %s; nothing to pull", r.Name)
	}
	if err := s.SetDirectory(held); err != nil {
		return err
	}
	fmt.Printf("%s: directory pulled (%s, issued %s)\n", r.Name, plural(len(held.Channels), "channel"), stampLocal(held.Issued))
	return nil
}

// stampLocal renders a time for a person, in their zone.
func stampLocal(t time.Time) string { return t.Local().Format(time.RFC3339) }

// The listing.

type channelJSON struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Open        bool       `json:"open"`
	Why         string     `json:"why,omitempty"`
	// Keep says mail fetched from this channel is left on the relay
	// afterwards. It is this machine's own setting, so it is there in the
	// owner's listing and absent from a peer's, which is why it is a
	// pointer: false is a setting and nil is not the owner.
	Keep *bool `json:"keep,omitempty"`
}

type relayChannelsJSON struct {
	Name string `json:"name"`
	// State is one of: same, older, newer, none, unreachable (a dial or
	// transport failure, Error says which), untrusted (the relay was
	// reached and serves a directory for this identity that does not
	// verify under its key).
	State  string           `json:"state"`
	Issued *time.Time       `json:"issued,omitempty"`
	Queued map[string]int64 `json:"queued,omitempty"`
	Error  string           `json:"error,omitempty"`
}

type channelLsJSON struct {
	Peer        string              `json:"peer,omitempty"`
	Fingerprint string              `json:"fingerprint,omitempty"`
	Directory   bool                `json:"directory"`
	Issued      *time.Time          `json:"issued,omitempty"`
	Channels    []channelJSON       `json:"channels"`
	Relays      []relayChannelsJSON `json:"relays,omitempty"`
}

func channelRows(d *channels.Directory, now time.Time) []channelJSON {
	var out []channelJSON
	for _, ch := range d.Channels {
		open, why := ch.OpenAt(now)
		out = append(out, channelJSON{Name: ch.Name, Description: ch.Description,
			NotBefore: ch.NotBefore, NotAfter: ch.NotAfter, Open: open, Why: why})
	}
	return out
}

// printChannels is the table: name, description, period and state, with a
// queued count per channel when the caller is the owner and has one, and
// what this machine does with mail it fetches from each when the caller is
// the owner at all.
func printChannels(rows []channelJSON, queued map[string]int64) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	keep := len(rows) > 0 && rows[0].Keep != nil
	header := "NAME\tDESCRIPTION\tPERIOD\tSTATE"
	if queued != nil {
		header += "\tQUEUED"
	}
	if keep {
		header += "\tKEEP"
	}
	fmt.Fprintln(w, header)
	for _, r := range rows {
		state := "open"
		if !r.Open {
			state = localState(r)
		}
		line := fmt.Sprintf("%s\t%s\t%s\t%s", r.Name, r.Description, period(r.NotBefore, r.NotAfter), state)
		if queued != nil {
			line += fmt.Sprintf("\t%d", queued[r.Name])
		}
		if keep {
			line += "\t" + onOff(r.Keep != nil && *r.Keep)
		}
		fmt.Fprintln(w, line)
	}
	w.Flush()
}

// onOff is a setting as the table and the completion say it.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// localState is OpenAt's sentence with the time in the reader's zone: the
// sentence itself is UTC, since the relay and a sender must say the same
// words, and a table on one terminal need not.
func localState(r channelJSON) string {
	switch {
	case r.NotBefore != nil && r.Why == "opens "+r.NotBefore.UTC().Format(time.RFC3339):
		return "opens " + stampLocal(*r.NotBefore)
	case r.NotAfter != nil && r.Why == "closed "+r.NotAfter.UTC().Format(time.RFC3339):
		return "closed " + stampLocal(*r.NotAfter)
	}
	return r.Why
}

func period(from, until *time.Time) string {
	switch {
	case from == nil && until == nil:
		return "-"
	case until == nil:
		return "from " + stampLocal(*from)
	case from == nil:
		return "until " + stampLocal(*until)
	default:
		return stampLocal(*from) + " to " + stampLocal(*until)
	}
}

func channelLs(args []string) error {
	fs := newFlagSet("channel ls")
	relay := relayFlag(fs)
	asJSON := fs.Bool("json", false, "print as JSON")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		return usageErrf("usage: %s channel ls [PEER] [--relay NAME] [--json]", prog)
	}
	if len(positional) == 1 {
		return channelLsPeer(positional[0], *relay, *asJSON)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	d, found, err := s.Directory()
	if err != nil {
		return err
	}
	now := time.Now()
	out := channelLsJSON{Directory: found, Channels: []channelJSON{}}
	if found {
		issued := d.Issued
		out.Issued = &issued
		out.Channels = channelRows(d, now)
	}
	// This machine's own setting per channel, which is the owner's
	// business and nobody else's: read once, and never in a peer's
	// listing. A damaged file is said here rather than at the next fetch,
	// where it would be a puzzle.
	settings, err := s.ChannelSettings()
	if err != nil {
		return err
	}
	for i, row := range out.Channels {
		keep := true
		if one, ok := settings.Channels[row.Name]; ok {
			keep = one.Keep
		}
		out.Channels[i].Keep = &keep
	}
	// What each relay holds, against the local issue. The counts come with
	// the owner's own fetch, and are printed for the local directory when
	// the relay holds this very issue, since only then do its names and
	// ours agree.
	var queued map[string]int64
	for _, r := range relays {
		rc := relayChannelsJSON{Name: r.Name}
		c, err := dial(s, id, r)
		var held *channels.Directory
		var res map[string]int64
		if err == nil {
			held, res, err = ownDirectory(c, id.Public())
		}
		switch {
		case errors.Is(err, channels.ErrSignature) || errors.Is(err, channels.ErrOwner):
			rc.State = "untrusted"
		case err != nil:
			rc.State, rc.Error = "unreachable", err.Error()
		case held == nil:
			rc.State = "none"
		default:
			issued := held.Issued
			rc.Issued, rc.Queued = &issued, res
			switch {
			case !found || held.Issued.After(d.Issued):
				rc.State = "newer"
			case held.Issued.Before(d.Issued):
				rc.State = "older"
			default:
				rc.State = "same"
				if queued == nil {
					queued = res
				}
			}
		}
		out.Relays = append(out.Relays, rc)
	}
	if *asJSON {
		return printJSON(out)
	}
	switch {
	case !found:
		fmt.Println("no directory: your mailbox has the one channel, default")
	case len(out.Channels) == 0:
		fmt.Printf("your directory is empty, so nobody can post to you; issued %s by this machine\n", stampLocal(d.Issued))
	default:
		printChannels(out.Channels, queued)
		fmt.Printf("issued %s by this machine\n", stampLocal(d.Issued))
	}
	for _, rc := range out.Relays {
		switch rc.State {
		case "same":
			fmt.Printf("%s: holds this directory\n", rc.Name)
		case "older":
			fmt.Printf("%s: holds an older directory, issued %s; run '%s channel push'\n", rc.Name, stampLocal(*rc.Issued), prog)
		case "newer":
			fmt.Printf("%s: holds a newer directory, issued %s, from another machine of yours; run '%s channel pull --relay %s' to take it\n",
				rc.Name, stampLocal(*rc.Issued), prog, rc.Name)
		case "none":
			if found {
				fmt.Printf("%s: holds no directory; run '%s channel push'\n", rc.Name, prog)
			} else {
				fmt.Printf("%s: holds no directory\n", rc.Name)
			}
		case "untrusted":
			fmt.Printf("%s: the directory it serves for you does not verify against your key; do not trust it\n", rc.Name)
		default:
			fmt.Printf("%s: could not be reached (%s)\n", rc.Name, rc.Error)
		}
	}
	return nil
}

// channelKeep sets what this machine does with mail it fetches from one
// channel: leaves it on the relay, or acknowledges it away as a fetch
// always did. It is this machine's own policy — nothing is signed, nothing
// is pushed, no relay is told and none is contacted — so it works with the
// keys locked, and it takes a name the directory need not hold, since mail
// queued under a channel since deleted still arrives.
func channelKeep(args []string) error {
	fs := newFlagSet("channel keep")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		return usageErrf("usage: %s channel keep NAME on|off", prog)
	}
	name := positional[0]
	if err := channels.ValidName(name); err != nil {
		return usageErrf("channel %q: %v", name, err)
	}
	var keep bool
	switch positional[1] {
	case "on", "true":
		keep = true
	case "off", "false":
		keep = false
	default:
		return usageErrf("usage: %s channel keep NAME on|off", prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	if err := s.SetKeep(name, keep); err != nil {
		return err
	}
	if keep {
		fmt.Printf("%s: mail is kept on the relay after it is fetched\n", name)
	} else {
		fmt.Printf("%s: mail is removed from the relay once it is fetched\n", name)
	}
	return nil
}

// ownDirectory is relayDirectory with the owner's counts kept: what a relay
// holds for this identity, verified under its key, and how much waits under
// each name. A directory that does not verify comes back as Verify's own
// error, so the caller can tell a relay that was reached and lies from one
// that could not be reached at all.
func ownDirectory(c *client.Client, self *identity.Public) (*channels.Directory, map[string]int64, error) {
	res, err := c.Directory(ctx(), self.Fingerprint())
	if err != nil {
		return nil, nil, err
	}
	if res.None {
		return nil, nil, nil
	}
	d, err := channels.Verify(self, res.Document, res.Signature)
	if err != nil {
		return nil, nil, err
	}
	return d, res.Queued, nil
}

// channelLsPeer is the sender's view: the peer's directory fetched from the
// selected relay and verified against the key held for them, printed
// without counts. The names and descriptions printed have passed the
// directory's own rules under the peer's signature — no control, format or
// separator character — which is what makes somebody else's text safe on
// this terminal.
func channelLsPeer(peer, relayName string, asJSON bool) error {
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	who, err := s.Resolve(peer)
	if err != nil {
		// A peer's directory is verified against the key held for them,
		// never taken on the relay's word, so there is nothing to show
		// for somebody who is not on the list yet.
		return usageErrf("%v; a peer's channels are verified against the key you hold for them, "+
			"so add them with '%s peers add' first", err, prog)
	}
	r, err := selectRelay(s, relayName)
	if err != nil {
		return err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return err
	}
	res, err := c.Directory(ctx(), who.Fingerprint())
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	label := who.Name
	if label == "" {
		label = who.Short()
	}
	out := channelLsJSON{Peer: label, Fingerprint: who.Fingerprint(), Channels: []channelJSON{}}
	if res.None {
		if asJSON {
			return printJSON(out)
		}
		fmt.Printf("%s's mailbox has the one channel, default\n", label)
		return nil
	}
	d, err := channels.Verify(who, res.Document, res.Signature)
	if err != nil {
		return &exitError{code: exitTransport, err: fmt.Errorf(
			"the directory %s served for %s does not verify against the key you hold; do not trust it", r.Name, label)}
	}
	out.Directory = true
	issued := d.Issued
	out.Issued = &issued
	out.Channels = channelRows(d, time.Now())
	if asJSON {
		return printJSON(out)
	}
	if len(out.Channels) == 0 {
		fmt.Printf("%s's directory is empty: nobody can post to them\n", label)
		return nil
	}
	printChannels(out.Channels, nil)
	fmt.Printf("issued %s by %s\n", stampLocal(d.Issued), label)
	return nil
}
