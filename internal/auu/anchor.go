package auu

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdAnchor is this machine's view of the relay's trust anchor: what it has
// pinned, pinning one for an identity that already exists, and forgetting it.
// 'auu init --anchor' and an enrolment token pin at creation; this is for
// afterwards, and it never touches the identity. The first deployment needed
// it: the administrator had run 'auu init' before there was an anchor to
// give it, and the only way to pin was to make a new identity.
func cmdAnchor(args []string) error {
	// Bare, or bare with flags, is status.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return anchorStatus(args)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return anchorStatus(rest)
	case "pin":
		return anchorPin(rest)
	case "forget":
		return anchorForget(rest)
	default:
		return usageErrf("unknown command %q; run '%s anchor status|pin|forget'", sub, prog)
	}
}

// anchorStatusOutput is what --json prints.
type anchorStatusOutput struct {
	// RelayName is what this home calls the relay; Relay is its URL.
	RelayName string     `json:"relay_name"`
	Relay     string     `json:"relay"`
	Anchor    string     `json:"anchor,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	// The server signing intermediate this machine last accepted, which
	// is what the rotation ratchet compares against.
	ServerIntermediate       string     `json:"server_intermediate,omitempty"`
	ServerIntermediateIssued *time.Time `json:"server_intermediate_issued,omitempty"`
}

func anchorStatus(args []string) error {
	fs := newFlagSet("anchor status")
	asJSON := fs.Bool("json", false, "machine readable output")
	relay := relayFlag(fs)
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
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	out := anchorStatusOutput{RelayName: r.Name, Relay: r.URL}
	rec, err := s.AnchorFor(r)
	switch {
	case errors.Is(err, store.ErrNoAnchor):
	case err != nil:
		return err
	default:
		expires := rec.Cert.NotAfter
		out.Anchor, out.Expires = rec.SPKI, &expires
		if r.ServerIntSPKI != "" {
			issued := r.ServerIntNotBefore
			out.ServerIntermediate, out.ServerIntermediateIssued = r.ServerIntSPKI, &issued
		}
	}
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("relay:   %s (%s)\n", r.Name, r.URL)
	if out.Anchor == "" {
		fmt.Printf("anchor:  none pinned; this relay's certificate must verify on its own\n")
		fmt.Printf("\nFor a relay issued by auu-ca, pin it with: %s anchor pin HASH\n", prog)
		return nil
	}
	fmt.Printf("anchor:  %s\n", out.Anchor)
	fmt.Printf("expires: %s\n", out.Expires.Local().Format(time.DateOnly))
	if out.ServerIntermediate != "" {
		fmt.Printf("relay's signing intermediate last seen: %s, issued %s\n",
			out.ServerIntermediate[:16], out.ServerIntermediateIssued.Local().Format(time.DateOnly))
	}
	return nil
}

func anchorPin(args []string) error {
	fs := newFlagSet("anchor pin")
	asJSON := fs.Bool("json", false, "machine readable output")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s anchor pin HASH, with HASH as 'auu-ca show' prints it", prog)
	}
	hash := positional[0]
	if !identity.ValidFingerprint(hash) {
		return usageErrf("the anchor hash must be 64 lowercase hex characters, as 'auu-ca show' prints")
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	if err := pinAnchor(s, r, hash); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(anchorStatusOutput{RelayName: r.Name, Relay: r.URL, Anchor: hash})
	}
	fmt.Printf("pinned %s as the trust anchor for %s (%s)\n", hash[:16], r.Name, r.URL)
	fmt.Printf("From now on this machine trusts that anchor, and nothing else, for this relay.\n")
	return nil
}

func anchorForget(args []string) error {
	fs := newFlagSet("anchor forget")
	relay := relayFlag(fs)
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
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	if err := s.RemoveAnchorFor(r); err != nil {
		return err
	}
	fmt.Printf("forgotten; the certificate of %s (%s) must now verify on its own\n", r.Name, r.URL)
	return nil
}
