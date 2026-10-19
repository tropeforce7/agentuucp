package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// auu damaged ls lists what the fetch kept under damaged/, and auu damaged
// reopen opens again what was kept because it needed a newer auu (D61).
// That is the one cause a kept message is ever opened again for: the rest
// either open for nobody or were refused by a check that would refuse them
// again. Reopening runs the fetch's open path over the kept bytes, with
// the record's relay and received time, and files what opens where the
// fetch would have filed it. It fetches and acknowledges nothing, since the
// fetch acknowledged the message when it kept it. The one request it can
// make is the vouch answer a fetch makes, once mail is filed.

func cmdDamaged(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "ls":
			return damagedLs(args[1:])
		case "reopen":
			return damagedReopen(args[1:])
		}
	}
	return usageErrf("usage: %s damaged ls [--json] | %s damaged reopen RELAY ID | --all [--json]", prog, prog)
}

// damagedJSON is one kept message in damaged ls --json.
type damagedJSON struct {
	Relay    string    `json:"relay"`
	ID       int64     `json:"id"`
	Received time.Time `json:"received"`
	Size     int64     `json:"size"`
	Cause    string    `json:"cause"`
	Section  string    `json:"section,omitempty"`
}

// newerSection is the section a cause names when the message was kept as
// newer, and whether it was.
func newerSection(cause string) (string, bool) {
	if cause != store.CauseNewer && !strings.HasPrefix(cause, store.CauseNewer+":") {
		return "", false
	}
	quoted, ok := strings.CutPrefix(cause, store.CauseNewer+": section ")
	if !ok {
		return "", true
	}
	name, err := strconv.Unquote(quoted)
	if err != nil {
		return "", true
	}
	return name, true
}

// causeWord is a cause up to its colon, newer, malformed, did not decrypt
// and the rest, as a sentence names the kind of thing that was kept.
func causeWord(e store.DamagedEntry) string {
	switch {
	case e.NoRecord:
		return "a keep cut off before its record was written"
	case e.BadRecord:
		return "a record that does not read"
	}
	word, _, _ := strings.Cut(e.Cause, ":")
	return word
}

func damagedLs(args []string) error {
	fs := newFlagSet("damaged ls")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("usage: %s damaged ls [--json]", prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	entries, strays, err := s.DamagedEntries()
	if err != nil {
		return err
	}
	for _, p := range strays {
		fmt.Fprintf(os.Stderr, "warning: %s is not a kept message and is not listed\n", identity.PrintableText(p))
	}
	if *asJSON {
		out := make([]damagedJSON, 0, len(entries))
		for _, e := range entries {
			// A keep with no record, or one whose record does not read,
			// has no cause: its record says none that can be believed.
			cause, section := e.Cause, ""
			if e.NoRecord || e.BadRecord {
				cause = ""
			} else {
				section, _ = newerSection(e.Cause)
			}
			out = append(out, damagedJSON{Relay: e.Relay, ID: e.RelayID, Received: e.Received.UTC(),
				Size: e.Bytes, Cause: cause, Section: section})
		}
		return printJSON(out)
	}
	if len(entries) == 0 {
		fmt.Printf("nothing is kept under %s\n", s.DamagedDir())
		return nil
	}
	for _, e := range entries {
		cause := identity.PrintableText(e.Cause)
		switch {
		case e.NoRecord:
			cause = "no record: " + causeWord(e)
		case e.BadRecord:
			cause = "unreadable record: " + cause
		}
		fmt.Printf("%-20s %8d  %s  %8s  %s\n", e.Relay, e.RelayID, e.Received.UTC().Format(time.RFC3339),
			store.MiB(e.Bytes), cause)
	}
	if n := countNewer(entries); n > 0 {
		fmt.Printf("\n%d kept as needing a newer auu; %s damaged reopen --all opens them with this one\n", n, prog)
	}
	return nil
}

func countNewer(entries []store.DamagedEntry) int {
	n := 0
	for _, e := range entries {
		if _, ok := newerSection(e.Cause); ok && !e.NoRecord && !e.BadRecord {
			n++
		}
	}
	return n
}

// reopenJSON is what damaged reopen --json says of one kept message.
type reopenJSON struct {
	Relay   string `json:"relay"`
	ID      int64  `json:"id"`
	Outcome string `json:"outcome"`
	// Box is where an opened message was filed: inbox or quarantine.
	Box string `json:"box,omitempty"`
	// Unchecked names the fetch's checks that could not run, because the
	// record an earlier release wrote does not say what the listing said.
	Unchecked []string `json:"unchecked,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// The outcomes of reopening one kept message.
const (
	reopenFiled     = "filed"
	reopenHeld      = "already held"
	reopenNewer     = "still newer"
	reopenCollided  = "collided"
	reopenRemaining = "left"
)

func damagedReopen(args []string) error {
	fs := newFlagSet("damaged reopen")
	all := fs.Bool("all", false, "every message kept as needing a newer auu")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	usage := usageErrf("usage: %s damaged reopen RELAY ID | --all [--json]", prog)
	if *all != (len(positional) == 0) || (!*all && len(positional) != 2) {
		return usage
	}
	var relayName string
	var relayID int64
	if !*all {
		relayName = positional[0]
		if err := store.ValidRelayName(relayName); err != nil {
			return usageErrf("%v", err)
		}
		// An id as the relay numbers them, 0 or more, as damaged ls
		// prints it.
		n, err := strconv.ParseInt(positional[1], 10, 64)
		if err != nil || n < 0 {
			return usageErrf("%s is not a relay message id; %s damaged ls lists them", identity.PrintableText(positional[1]), prog)
		}
		relayID = n
	}
	// Opening needs the key, in receive scope as a fetch does; a locked
	// agent is exit 4 here, before anything is read.
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	var targets []store.DamagedEntry
	if *all {
		entries, _, err := s.DamagedEntries()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if _, ok := newerSection(e.Cause); ok && !e.NoRecord && !e.BadRecord {
				targets = append(targets, e)
			}
		}
	} else {
		e, _, err := s.ReadDamaged(relayName, relayID)
		if errors.Is(err, store.ErrNotDamaged) {
			return usageErrf("nothing is kept for %s %d; %s damaged ls lists what is", relayName, relayID, prog)
		}
		if errors.Is(err, store.ErrNoRecord) {
			return usageErrf("%s %d is bytes kept with no record, a keep cut off before its record was written, which is never reopened; "+
				"only a message kept as needing a newer auu is", relayName, relayID)
		}
		if err != nil {
			return usageErrf("%s %d is kept beside a record that does not read (%s), which is never reopened; "+
				"only a message kept as needing a newer auu is", relayName, relayID, identity.PrintableText(err.Error()))
		}
		if _, ok := newerSection(e.Cause); !ok {
			return usageErrf("%s %d was kept with the cause %q, which is never reopened; only a message kept as needing a newer auu is",
				relayName, relayID, identity.PrintableText(causeWord(e)))
		}
		targets = append(targets, e)
	}
	settings, err := s.ChannelSettings()
	if err != nil {
		return err
	}
	relays, err := s.Relays()
	if err != nil {
		return err
	}
	var results []reopenJSON
	filed := 0
	for _, e := range targets {
		res, err := reopenOne(s, id, relays, settings, e)
		if err != nil {
			if filed > 0 {
				stopped := "this stopped"
				if isLocked(err) {
					stopped = "the key locked"
				}
				fmt.Fprintf(os.Stderr, "%s: %d reopened and filed before %s; the rest are where they were\n", prog, filed, stopped)
			}
			return err
		}
		if res.Outcome == reopenFiled {
			filed++
		}
		results = append(results, res)
	}
	// What a fetch does once mail is filed, done for what was filed here:
	// a vouch kept and a peer's question answered, where the person has
	// turned that on.
	if filed > 0 {
		out := io.Writer(os.Stdout)
		if *asJSON {
			out = os.Stderr
		}
		keepVouches(s, out)
		answerAsks(s, id, out)
	}
	if *asJSON {
		if results == nil {
			results = []reopenJSON{}
		}
		return printJSON(results)
	}
	if len(results) == 0 {
		fmt.Println("nothing is kept as needing a newer auu")
		return nil
	}
	for _, r := range results {
		fmt.Println(reopenLine(r))
	}
	return nil
}

// reopenLine is one result as a person reads it.
func reopenLine(r reopenJSON) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d: ", r.Relay, r.ID)
	switch r.Outcome {
	case reopenFiled:
		fmt.Fprintf(&b, "opened and filed in the %s", r.Box)
	case reopenHeld:
		b.WriteString("already held, so its kept copy is removed")
	case reopenNewer:
		fmt.Fprintf(&b, "still needs a newer auu (%s) and is left where it is", r.Detail)
	case reopenCollided:
		b.WriteString("its id is held from another sender, so it is left where it is")
	default:
		fmt.Fprintf(&b, "%s, and is left where it is", r.Detail)
	}
	if len(r.Unchecked) > 0 {
		fmt.Fprintf(&b, "; its record does not say %s, so that check could not run", strings.Join(r.Unchecked, " or "))
	}
	return b.String()
}

// reopenOne reopens one kept message. It returns an error only for what
// stops the whole command: a locked key, a relay's fetch lock it cannot
// take, or a file this home cannot write.
func reopenOne(s *store.Store, id *identity.Identity, relays []*store.Relay, settings store.ChannelSettings, e store.DamagedEntry) (reopenJSON, error) {
	res := reopenJSON{Relay: e.Relay, ID: e.RelayID}
	// The relay the record names, by the rule the home's names are taken
	// under, so a name in another case or with a trailing dot is that relay
	// on every filesystem, with its fetch lock, and not, on one that folds
	// case, its directory reached under a name the home does not have
	// (S62). A relay since removed from this home is no reason not to open
	// what it delivered; there is then no fetch of it to wait for, and no
	// lock to take.
	r := &store.Relay{Name: e.Relay}
	for _, have := range relays {
		if store.SameRelayName(have.Name, e.Relay) {
			r = have
			// One fetch or reopen at a time per relay, as the fetch takes
			// it: a fetch running now could meet and save the same id.
			lock, _, err := lockfile.Take(ctx(), filepath.Join(s.RelayDir(r), fetchLockName), fetchLockWait, fetchLockSleep)
			if errors.Is(err, lockfile.ErrHeld) {
				return res, transportErr(fmt.Errorf("another %s is fetching from %s; try again in a moment: %w", prog, r.Name, err))
			}
			if err != nil {
				return res, fmt.Errorf("taking the fetch lock for %s: %w", r.Name, err)
			}
			defer lock.Release()
			break
		}
	}
	rec, data, err := s.ReadDamaged(e.Relay, e.RelayID)
	if err != nil {
		res.Outcome, res.Detail = reopenRemaining, fmt.Sprintf("it cannot be read: %s", identity.PrintableText(err.Error()))
		return res, nil
	}
	// Read again under the lock, so held to the cause again: a fetch that
	// ran since may have kept another message under the same id.
	if _, ok := newerSection(rec.Cause); !ok {
		res.Outcome, res.Detail = reopenRemaining, fmt.Sprintf("its record now says %q", identity.PrintableText(rec.Cause))
		return res, nil
	}
	// The bytes as the client reads a listed envelope: one that does not
	// parse is given to Open as nothing, which says why.
	var env *envelope.Envelope
	var parsed envelope.Envelope
	if json.Unmarshal(data, &parsed) == nil {
		env = &parsed
	}
	inner, sender, openErr := envelope.Open(id, env)
	if isLocked(openErr) {
		return res, openErr
	}
	var newer *wire.NeedsNewerError
	if errors.As(openErr, &newer) && sender != nil {
		res.Outcome, res.Detail = reopenNewer, fmt.Sprintf("section %q", newer.Name)
		return res, nil
	}
	if openErr == nil {
		// An id already held: the fetch met it on the relay, and reopen
		// meets it here alone. From the same signer it is the message
		// held already, a copy posted twice and kept twice, and the kept
		// copy goes, with no relay asked and no record moved. From
		// another it is a collision, and is left.
		for _, box := range []store.Box{store.Inbox, store.Quarantine} {
			held, err := s.Holding(box, inner.ID)
			if err != nil || held == nil {
				continue
			}
			if held.Inner.From != sender.Fingerprint() {
				res.Outcome = reopenCollided
				return res, nil
			}
			if err := s.RemoveDamaged(e.Relay, e.RelayID); err != nil {
				return res, err
			}
			res.Outcome = reopenHeld
			return res, nil
		}
	}
	// What the listing said, where the record says it; an earlier
	// release's record does not, and the check against it cannot run.
	run := checks{kind: rec.Kind != "", listedChannel: rec.Channel != ""}
	if !run.kind {
		res.Unchecked = append(res.Unchecked, "the kind it was listed under")
	}
	if !run.listedChannel {
		res.Unchecked = append(res.Unchecked, "the channel it was listed under")
	}
	m := client.Message{ID: rec.RelayID, Received: rec.Received, Kind: rec.Kind, Size: rec.Size,
		Envelope: env, Raw: data, Channel: rec.Channel, Via: rec.Via}
	o := openOne(s, r, m, inner, sender, openErr, settings, run)
	switch o.verdict {
	case unreadable:
		res.Outcome, res.Detail = reopenRemaining, fmt.Sprintf("it does not open: %s", o.cause)
		return res, nil
	case miskinded:
		res.Outcome, res.Detail = reopenRemaining, fmt.Sprintf("it was listed as %q and sealed as %q",
			identity.PrintableText(rec.Kind), identity.PrintableText(o.typ))
		return res, nil
	case misfiled:
		res.Outcome, res.Detail = reopenRemaining, fmt.Sprintf("it was filed under %q and sealed for %q",
			identity.PrintableText(o.filedAs), identity.PrintableText(channelName(o.sealed)))
		return res, nil
	}
	// The fetch acknowledged it when it kept it, so nothing of it is left
	// on the relay to keep.
	o.stored.OnRelay = false
	if err := s.Save(o.box, o.stored); err != nil {
		return res, fmt.Errorf("saving message locally: %w", err)
	}
	if err := s.RemoveDamaged(e.Relay, e.RelayID); err != nil {
		return res, err
	}
	res.Outcome, res.Box = reopenFiled, string(o.box)
	return res, nil
}
