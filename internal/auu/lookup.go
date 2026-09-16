package auu

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdLookup asks the relay what it knows about an identity: the name it
// registered under, when, and its keys. The argument is a fingerprint, the
// 16-character short id that listings print, or a peer already on the list
// by name or prefix, which is resolved locally first.
//
// The relay is not a trust anchor. What comes back is for confirming with the
// person before adding them, and this command adds nobody.
func cmdLookup(args []string) error {
	fs := newFlagSet("lookup")
	asJSON := fs.Bool("json", false, "machine readable output")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s lookup FINGERPRINT|SHORT-ID|PEER [--json]", prog)
	}
	return runLookup(positional[0], *asJSON, *relay)
}

// lookupJSON is what --json prints.
type lookupJSON struct {
	Fingerprint string     `json:"fingerprint"`
	Short       string     `json:"short"`
	Name        string     `json:"name"`
	Suite       string     `json:"suite"`
	SuiteID     int        `json:"suite_id"`
	PQCategory  int        `json:"pq_category"`
	Registered  *time.Time `json:"registered,omitempty"`
	// KnownAs is the name this identity has on the local peer list, and
	// "self" when it is the caller's own. Absent when it is on neither.
	KnownAs    string `json:"known_as,omitempty"`
	ExportLine string `json:"export_line"`
}

func runLookup(query string, asJSON bool, relay string) error {
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	if !identity.ValidFingerprint(query) && !identity.ValidShortID(query) {
		// A name, or a prefix of one, of somebody already on the list.
		pub, err := s.Resolve(query)
		if err != nil {
			return usageErrf("%q is not a fingerprint, a short id, or a peer you know (%v)", query, err)
		}
		query = pub.Fingerprint()
	}
	r, err := selectRelay(s, relay)
	if err != nil {
		return err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return err
	}
	found, err := c.Lookup(ctx(), query)
	if err != nil {
		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
			label := query
			if name := knownAs(s, id, query); name != "" && name != "self" {
				label = name
			}
			return fmt.Errorf("%s is not registered on %s%s",
				query, r.Name, elsewhere(s, query, label, r))
		}
		return transportErr(err)
	}

	pub := found.Public
	suite := pub.Suite()
	out := lookupJSON{
		Fingerprint: pub.Fingerprint(),
		Short:       pub.Short(),
		Name:        pub.Name,
		Suite:       suite.Name,
		SuiteID:     int(suite.ID),
		PQCategory:  suite.PQCategory,
		ExportLine:  pub.ExportLine(),
		KnownAs:     knownAs(s, id, pub.Fingerprint()),
	}
	if !found.Registered.IsZero() {
		registered := found.Registered
		out.Registered = &registered
	}
	if asJSON {
		return printJSON(out)
	}

	fmt.Printf("relay:         %s (%s)\n", r.Name, r.URL)
	fmt.Printf("name on relay: %s\n", orNone(out.Name))
	fmt.Printf("fingerprint:   %s\n", out.Fingerprint)
	fmt.Printf("short id:      %s\n", out.Short)
	fmt.Printf("keys:          %s\n", suite.Describe())
	if out.Registered != nil {
		fmt.Printf("registered:    %s\n", out.Registered.Local().Format(time.DateOnly))
	} else {
		fmt.Printf("registered:    the relay did not say\n")
	}
	switch out.KnownAs {
	case "self":
		fmt.Printf("peer list:     this is you\n")
	case "":
		fmt.Printf("peer list:     not on yours\n")
	default:
		fmt.Printf("peer list:     on yours, as %q\n", out.KnownAs)
	}
	fmt.Printf("\n%s\n", out.ExportLine)
	if out.KnownAs == "" {
		fmt.Println("\nThe relay is not a trust anchor. Confirm that fingerprint with the")
		fmt.Printf("person directly, then add them with: %s peers add '<the line above>'\n", prog)
	}
	return nil
}

// elsewhere names the relays somebody's mail has arrived through, when the
// relay being asked has never heard of them. It reads the spool: the relay a
// message came through is recorded on it, so the home already knows where
// this person is without asking anybody.
//
// There is no automatic choice made from this. Which relay to use is the
// person's, and this is the sentence that lets them make it.
func elsewhere(s *store.Store, fp, label string, not *store.Relay) string {
	seen := map[string]bool{}
	var names []string
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		msgs, err := s.List(box)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if m.Inner.From != fp || m.Relay == "" || m.Relay == not.Name || seen[m.Relay] {
				continue
			}
			seen[m.Relay] = true
			names = append(names, m.Relay)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return fmt.Sprintf("; mail from %s has arrived through %s", label, strings.Join(names, ", "))
}

// knownAs says what the local peer list calls a fingerprint: "self" for the
// caller's own, the peer's name, or nothing.
func knownAs(s *store.Store, id *identity.Identity, fp string) string {
	if fp == id.Fingerprint() {
		return "self"
	}
	pub, err := s.Resolve(fp)
	if err != nil || pub.Fingerprint() != fp {
		return ""
	}
	if pub.Name == "" {
		return fp[:identity.ShortIDLen]
	}
	return pub.Name
}
