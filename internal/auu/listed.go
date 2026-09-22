package auu

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdListed prints every identity on a relay whose card says the relay may
// list them: the short id, the name on the card, the suite, and whether
// the peer list has them already. Every entry was verified by the client
// with the bundle beside it — the fingerprint is the bundle's, the
// signature is the owner's, the card says listed — and what did not
// verify was left out and is counted on stderr. It adds nobody: that is
// 'auu peers fetch', at a terminal.
//
// What a name here rests on is the relay's admission, and no further:
// on a relay that invites by token, a listed identity was let in by an
// administrator; on one that registers anyone, a name proves nothing
// about who holds it. The relay says which it is, and so does this
// command.
func cmdListed(args []string) error {
	fs := newFlagSet("listed")
	asJSON := fs.Bool("json", false, "machine readable output")
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
	health, err := c.HealthInfo(ctx())
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	listed, err := c.Listed(ctx())
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	out := listedJSON{Relay: r.Name, Registration: health.Registration, Entries: []listedEntryJSON{}, Dropped: listed.Dropped}
	for _, e := range listed.Entries {
		out.Entries = append(out.Entries, listedEntryJSON{
			Fingerprint: e.Public.Fingerprint(),
			Short:       e.Public.Short(),
			Name:        e.Card.Name,
			Suite:       e.Public.Suite().Name,
			KnownAs:     knownAs(s, id, e.Public.Fingerprint()),
		})
	}
	if *asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		printListed(out, len(listed.Entries), listed.Total)
	}
	if out.Dropped > 0 {
		fmt.Fprintf(os.Stderr, "%s: %s did not verify and %s left out\n", prog, entries(out.Dropped), wasWere(out.Dropped))
	}
	return nil
}

// entries is a count of entries in words.
func entries(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}

// listedJSON is 'auu listed --json'.
type listedJSON struct {
	Relay        string            `json:"relay"`
	Registration string            `json:"registration"`
	Entries      []listedEntryJSON `json:"entries"`
	// Dropped is how many entries the relay served that did not verify
	// and were left out.
	Dropped int `json:"dropped"`
}

type listedEntryJSON struct {
	Fingerprint string `json:"fingerprint"`
	Short       string `json:"short"`
	// Name is the name on the card, the owner's own claim, signed by them
	// and never a local label.
	Name  string `json:"name"`
	Suite string `json:"suite"`
	// KnownAs is what the local peer list calls this identity, "self"
	// for the caller's own, absent for one on neither.
	KnownAs string `json:"known_as,omitempty"`
}

// printListed prints one line per entry: the short id, the name through
// the escaper as the last line under the rule (it passed ValidName at
// Verify, so it is unchanged), the suite, and "peer" or "you" where the
// local peer list has the identity. Two entries with one name are both
// printed: names on a relay are not unique.
func printListed(out listedJSON, shown int, total int64) {
	identities := fmt.Sprintf("%d identities", total)
	if total == 1 {
		identities = "1 identity"
	}
	fmt.Printf("%s: %s listed, %s\n", out.Relay, identities, pluralShown(shown, total))
	if len(out.Entries) == 0 {
		return
	}
	fmt.Println()
	for _, e := range out.Entries {
		mark := ""
		switch e.KnownAs {
		case "":
		case "self":
			mark = "  you"
		default:
			mark = "  peer"
		}
		fmt.Printf("%s  %-24s  %s%s\n", e.Short, identity.Printable(e.Name), e.Suite, mark)
	}
	fmt.Printf("\nThe relay %s.\n", registrationMeans(out.Registration, "an identity here"))
	fmt.Printf("To add one, at a terminal: %s peers fetch NAME|SHORT-ID\n", prog)
}

// pluralShown says how many of the relay's count are shown, or that
// they all are.
func pluralShown(shown int, total int64) string {
	if int64(shown) == total {
		return "all shown"
	}
	return fmt.Sprintf("%d shown", shown)
}

func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// listedPeer is an identity found on a relay for peers fetch or knock:
// the bundle, verified against the fingerprint asked for or the card's
// owner; the name that came with it, a suggestion for the local label;
// where the name came from; and when the mailbox registered, when the
// relay said.
type listedPeer struct {
	Public     *identity.Public
	Suggested  string
	Registered time.Time
}

// findOnRelay resolves what peers fetch or knock was given: a fingerprint
// or a short id through the key lookup, as lookup does, with the
// registered name as the suggestion; a name through the card listing,
// refused when nobody claims it or when two do (use the short id), with
// the card's name as the suggestion. The bundle's fingerprint is held to
// what was asked for by the client in either path.
func findOnRelay(c *client.Client, r *store.Relay, query string) (*listedPeer, error) {
	if identity.ValidFingerprint(query) || identity.ValidShortID(query) {
		found, err := c.Lookup(ctx(), query)
		if err != nil {
			var httpErr *client.HTTPError
			if errors.As(err, &httpErr) && httpErr.Status == 404 {
				return nil, usageErrf("%s is not registered on %s", query, r.Name)
			}
			return nil, transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		return &listedPeer{Public: found.Public, Suggested: found.Public.Name, Registered: found.Registered}, nil
	}
	if err := identity.ValidName(query); err != nil {
		return nil, usageErrf("%q is not a fingerprint, a short id, or a name a card could carry (%s)",
			query, strings.TrimPrefix(err.Error(), "identity: "))
	}
	listed, err := c.Listed(ctx())
	if err != nil {
		return nil, transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	entry, err := listed.FindListed(query)
	if errors.Is(err, client.ErrAmbiguousName) {
		return nil, usageErrf("two listed identities call themselves %q on %s; use the short id (%s listed shows them)", query, r.Name, prog)
	}
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, usageErrf("no listed identity calls itself %q on %s; %s listed shows who is, and a fingerprint or short id finds anyone registered", query, r.Name, prog)
	}
	pub := entry.Public
	pub.Name = entry.Card.Name
	return &listedPeer{Public: pub, Suggested: entry.Card.Name}, nil
}

// suggestedName is the default offered at the local-name prompt: the name
// that came with the identity — the card's, or the relay's registered
// name — when it is one the export line's rule takes and the peer list
// does not already use for somebody else, and peer-<fp8> otherwise. A
// suggestion and never the label: the person accepts it or types another.
//
// Taken means what AddPeer refuses on, a peer whose name folds equal, so
// the offer and the refusal agree: "bo" is offered beside "bob", and "Bob"
// is not. Resolve is not the test, since it matches a name by unique
// prefix, and would have called a free name another peer's.
func suggestedName(s *store.Store, found *listedPeer) (name string, takenBy string) {
	fp := found.Public.Fingerprint()
	if found.Suggested == "" || identity.ValidName(found.Suggested) != nil {
		return fallbackName(fp), ""
	}
	// A peer list that cannot be read is AddPeer's error to report, a
	// moment later, so the offer stands.
	peers, _ := s.Peers()
	for _, other := range peers {
		if other.Fingerprint() != fp && strings.EqualFold(other.Name, found.Suggested) {
			return fallbackName(fp), other.Fingerprint()
		}
	}
	return found.Suggested, ""
}
