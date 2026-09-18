// Command auu-admin administers an auu relay.
//
// It is a separate binary from auu on purpose. The privilege boundary is then
// visible in what is installed where, the connect skill never documents it,
// and an administrator can keep a dedicated identity in its own AUU_HOME
// without it ever touching their messaging.
//
// Authority comes from the relay's host: an identity may administer a relay if
// and only if its export line is in the file the relay was started with. This
// binary does not know whether it will be allowed, and asks like anybody else.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// Exit codes, the ones auu uses: usage, transport, a locked identity, and a
// damaged file in the home.
const (
	exitUsage     = 1
	exitTransport = 2
	exitLocked    = 4
	exitDamaged   = 5
)

const usage = `auu-admin - administer an auu relay

Usage:
  auu-admin status

  auu-admin mailboxes ls [--after FP] [--limit N]
  auu-admin mailboxes show FP
  auu-admin mailboxes rm FP [--yes]
  auu-admin mailboxes purge FP [--yes]

  auu-admin blocks ls
  auu-admin blocks add FP --reason TEXT [--yes]
  auu-admin blocks rm FP

  auu-admin token issue --note TEXT [--expires 168h | --not-after RFC3339] [--uses N]
                        [--for FP] [--use register|cert] [--anchor HASH|none]
  auu-admin token ls [--all]
  auu-admin token revoke ID
  auu-admin token show TOKEN

  auu-admin certs ls [FP] [--all]
  auu-admin certs revoke SERIAL [--reason TEXT] [--yes]

  auu-admin version

Every command takes --json, and --relay NAME|URL to choose the relay. Without
it the relay is AUU_RELAY, and then your auu home's default.

You may administer a relay when your export line is in the file that relay was
started with (--admin-file). Print yours with: auu id export
`

// exitError carries a specific exit code out of a command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageErrf(format string, a ...any) error {
	return &exitError{code: exitUsage, err: fmt.Errorf(format, a...)}
}

func transportErr(err error) error {
	return &exitError{code: exitTransport, err: err}
}

func main() {
	if err := adviseLocked(run(os.Args[1:])); err != nil {
		fmt.Fprintln(os.Stderr, "auu-admin: "+err.Error())
		var e *exitError
		if errors.As(err, &e) {
			os.Exit(e.code)
		}
		os.Exit(exitUsage)
	}
}

// adviseLocked turns a locked agent into the sentence auu prints for it,
// with the same exit code. An administrator's identity is an auu identity
// in an auu home, encrypted the same way and unlocked the same way; this
// program only needs to say so.
func adviseLocked(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, identity.ErrLocked) || strings.Contains(err.Error(), agent.LockedMessage) {
		return &exitError{code: exitLocked,
			err: errors.New("your identity is locked: run 'auu unlock' in your own terminal")}
	}
	// Unlocked to receive, and every administrative route originates: the
	// agent's sentence, verbatim, with the same code.
	if strings.Contains(err.Error(), agent.ReceiveOnlyMessage) {
		return &exitError{code: exitLocked, err: errors.New(agent.ReceiveOnlyMessage)}
	}
	// An administrator's home is an auu home: a damaged file in it is the
	// same person's problem, with the same code.
	if errors.Is(err, store.ErrDamaged) {
		return &exitError{code: exitDamaged, err: err}
	}
	return err
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "status":
		return cmdStatus(rest)
	case "mailboxes":
		return cmdMailboxes(rest)
	case "blocks":
		return cmdBlocks(rest)
	case "certs":
		return cmdCerts(rest)
	case "token":
		return cmdToken(rest)
	case "version":
		fmt.Printf("auu-admin %s\n", buildinfo.Version())
		return nil
	default:
		return usageErrf("unknown command %q; run 'auu-admin help'", cmd)
	}
}

// relayFlag is on every command, so it is registered in one place.
type common struct {
	relay  *string
	asJSON *bool
}

func newFlagSet(name string) (*flag.FlagSet, *common) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := &common{
		relay:  fs.String("relay", "", "which relay: a name from 'auu relay ls', or a base URL"),
		asJSON: fs.Bool("json", false, "machine readable output"),
	}
	return fs, c
}

// parseArgs collects positional arguments wherever they appear, so that
// "auu-admin mailboxes show FP --json" works.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, &exitError{code: exitUsage, err: err}
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// adminRelay is the relay this command acts on: --relay, then AUU_RELAY, then
// the home's default, resolved through the same store auu uses, so a name
// from 'auu relay ls' works here too.
//
// A URL the home does not know is taken as it stands, with no pinned anchor
// and no certificate. That is how the first administrator's machine starts:
// there is a relay to administer before anybody has joined it.
func adminRelay(s *store.Store, c *common) (*store.Relay, error) {
	query := strings.TrimSpace(*c.relay)
	if query == "" {
		query = strings.TrimSpace(os.Getenv("AUU_RELAY"))
	}
	if query != "" {
		r, err := s.Relay(query)
		if err == nil {
			return r, nil
		}
		if strings.Contains(query, "://") {
			url := token.NormaliseRelay(query)
			return &store.Relay{Name: url, URL: url}, nil
		}
		return nil, usageErrf("%v", err)
	}
	r, err := s.DefaultRelay()
	if errors.Is(err, store.ErrNoDefaultRelay) {
		return nil, usageErrf("no relay selected: pass --relay NAME or --relay URL, " +
			"set AUU_RELAY, or run 'auu relay default NAME'")
	}
	return r, err
}

// dial builds a client for the relay this administrator is talking to.
func dial(c *common) (*store.Store, *identity.Identity, *client.Client, error) {
	s, err := store.OpenDefault()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening auu home: %w", err)
	}
	id, err := s.Identity()
	if err != nil {
		return nil, nil, nil, err
	}
	r, err := adminRelay(s, c)
	if err != nil {
		return nil, nil, nil, err
	}
	// An administrator needs no client certificate: their authority is the
	// line in the relay host's file, and /v1/admin is exempt so that
	// administering a relay never depends on having a mailbox on it. One is
	// presented when this machine happens to hold it, which costs nothing and
	// means an administrator who is also a user has one client, not two.
	var cert *tls.Certificate
	if rec, err := s.CertFor(r); err == nil {
		if cert, err = rec.TLS(); err != nil {
			cert = nil
		}
	}
	// The same pinned anchor a user's client uses: an administrator's
	// connection is verified exactly as anybody else's, and against that
	// relay's anchor rather than some other relay's.
	var anchor *client.Anchor
	if rec, err := s.AnchorFor(r); err == nil {
		anchor = &client.Anchor{
			Cert:          rec.Cert,
			SeenSPKI:      r.ServerIntSPKI,
			SeenNotBefore: r.ServerIntNotBefore,
			OnSeen: func(spki string, notBefore time.Time) error {
				return s.SeenIntermediateFor(r, spki, notBefore)
			},
		}
	}
	cl, err := client.NewWithAnchor(r.URL, id, cert, anchor)
	if err != nil {
		return nil, nil, nil, err
	}
	return s, id, cl, nil
}

// relayURL is the address a command is acting on, for error messages.
func relayURL(c *common) string {
	s, err := store.OpenDefault()
	if err != nil {
		return "the relay"
	}
	r, err := adminRelay(s, c)
	if err != nil {
		return "the relay"
	}
	return r.URL
}

// adminErr turns the relay's refusals into advice for a person who may simply
// not be an administrator, which is by far the likeliest reason to see one.
func adminErr(c *common, err error) error {
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			if strings.Contains(httpErr.Message, "no administrators") ||
				httpErr.Status == http.StatusUnauthorized {
				return transportErr(fmt.Errorf(
					"you are not an administrator of %s; an administrator's export line "+
						"must be in that relay's authorized file. Print yours with: auu id export",
					relayURL(c)))
			}
		}
	}
	return transportErr(err)
}

func ctx() context.Context { return context.Background() }
