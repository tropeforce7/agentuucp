package auu

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// 'auu cursor': how far this machine has fetched from each relay, beside
// what the relay holds, and the one command that sets it by hand. A fetch
// puts a cursor past everything right by itself (reset.go); a cursor that
// skipped mail inside the relay's span is a person's to put right, and
// this is how, in place of deleting the file.

func cmdCursor(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s cursor show|reset", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "show":
		return cursorShow(rest)
	case "reset":
		return cursorReset(rest)
	default:
		return usageErrf("unknown command %q; run '%s cursor show|reset'", sub, prog)
	}
}

// cursorJSON is one relay's line of 'cursor show --json'. Cursor is absent
// when the file will not read, and CursorError says why; First, Last and
// Queued are absent when the relay could not be asked, and Error says why.
type cursorJSON struct {
	Relay       string `json:"relay"`
	Cursor      *int64 `json:"cursor,omitempty"`
	CursorError string `json:"cursor_error,omitempty"`
	First       *int64 `json:"first,omitempty"`
	Last        *int64 `json:"last,omitempty"`
	Queued      *int64 `json:"queued,omitempty"`
	Error       string `json:"error,omitempty"`
}

// cursorShow is 'auu cursor show [--relay NAME] [--json]': each relay the
// home is on, or the one named, with the cursor file's number and, from
// one listing each, the lowest and highest ids the relay holds and how
// many. A relay that cannot be asked shows its cursor and a dash.
func cursorShow(args []string) error {
	fs := newFlagSet("cursor show")
	relayName := relayFlag(fs)
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return usageErrf("usage: %s cursor show [--relay NAME] [--json]", prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	var relays []*store.Relay
	if *relayName != "" {
		r, err := s.Relay(*relayName)
		if err != nil {
			return usageErrf("--relay: %v", err)
		}
		relays = []*store.Relay{r}
	} else if relays, err = s.Relays(); err != nil {
		return err
	}
	_, id, idErr := loadIdentity()
	var out []cursorJSON
	for _, r := range relays {
		line := cursorJSON{Relay: r.Name}
		if n, err := s.CursorFor(r); err != nil {
			line.CursorError = err.Error()
		} else {
			line.Cursor = &n
		}
		if idErr != nil {
			line.Error = idErr.Error()
		} else if l, err := spanOf(s, id, r); err != nil {
			line.Error = err.Error()
		} else {
			line.First, line.Last, line.Queued = &l.First, &l.Last, &l.Queued
		}
		out = append(out, line)
	}
	if *asJSON {
		if out == nil {
			out = []cursorJSON{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	for _, l := range out {
		cursor := "-"
		if l.Cursor != nil {
			cursor = strconv.FormatInt(*l.Cursor, 10)
		}
		if l.First == nil {
			fmt.Printf("%s  cursor %s  relay -  (%s)\n", l.Relay, cursor, identity.PrintableText(l.Error))
		} else {
			fmt.Printf("%s  cursor %s  relay holds %d, numbered %d to %d\n", l.Relay, cursor, *l.Queued, *l.First, *l.Last)
		}
		if l.CursorError != "" {
			fmt.Printf("  %s\n", identity.PrintableText(l.CursorError))
		}
	}
	return nil
}

// spanOf is one listing of a relay's mailbox, as stubs and one row, for
// what it holds: the span of its ids and how many.
func spanOf(s *store.Store, id *identity.Identity, r *store.Relay) (client.Listing, error) {
	c, err := dial(s, id, r)
	if err != nil {
		return client.Listing{}, err
	}
	return c.ListWait(ctx(), client.ListRequest{After: math.MaxInt64, Limit: 1, Stubs: true})
}

// cursorReset is 'auu cursor reset --relay NAME [--to N] [--yes]': it says
// what the next fetch from that relay will then fetch, asks at a terminal,
// and writes the cursor. It never fetches; 'auu inbox --relay NAME' does
// that. What this machine already has is met by that fetch and not
// delivered again, so a cursor set too low costs a listing and no mail.
func cursorReset(args []string) error {
	fs := newFlagSet("cursor reset")
	relayName := relayFlag(fs)
	toText := fs.String("to", "0", "the relay id to fetch after (default 0: from the beginning)")
	yes := fs.Bool("yes", false, "set it without asking")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 || *relayName == "" {
		return usageErrf("usage: %s cursor reset --relay NAME [--to N] [--yes]", prog)
	}
	// A relay message id is a number written in decimal, as every one
	// from outside is read: flag's own Int64 would take 010 as eight and
	// 0x10 as sixteen.
	n, err := strconv.ParseInt(*toText, 10, 64)
	if err != nil || n < 0 {
		return usageErrf("--to is a relay message id, 0 or more, in decimal; %q is not", *toText)
	}
	to := &n
	s, err := openStore()
	if err != nil {
		return err
	}
	r, err := s.Relay(*relayName)
	if err != nil {
		return usageErrf("--relay: %v", err)
	}
	// The cursor file is also this home's record that it joined the
	// relay: writing one for a relay it never joined would make every
	// plain fetch try it.
	if !s.Registered(r) {
		return usageErrf("this home has not joined %s, so it has no cursor there; join it with '%s register --relay %s'",
			r.Name, prog, r.Name)
	}
	// What the next fetch will then do, from what the relay holds now.
	_, id, idErr := loadIdentity()
	var l client.Listing
	if idErr == nil {
		l, idErr = spanOf(s, id, r)
	}
	switch {
	case idErr != nil:
		fmt.Printf("%s could not be asked what it holds (%s); the next fetch will fetch what it holds after message %d\n",
			r.Name, identity.PrintableText(idErr.Error()), *to)
	case *to < l.First || l.Last == 0:
		fmt.Printf("the next fetch from %s will fetch everything the relay holds, %d messages; "+
			"mail this machine already has is recognised and not delivered again\n", r.Name, l.Queued)
	case *to > l.Last:
		fmt.Printf("%s holds messages numbered %d to %d, all of them before %d, so the next fetch will "+
			"find the cursor past everything and set it right itself\n", r.Name, l.First, l.Last, *to)
	default:
		fmt.Printf("the next fetch from %s will fetch what it holds after message %d, of the messages numbered %d to %d; "+
			"mail this machine already has is recognised and not delivered again\n", r.Name, *to, l.First, l.Last)
	}
	if !*yes {
		if !stdinIsTerminal() {
			return usageErrf("setting a cursor is a person's decision: run this at a terminal, or pass --yes from your own script")
		}
		if !confirm(fmt.Sprintf("Set %s's cursor to %d?", r.Name, *to)) {
			fmt.Println("nothing changed")
			return nil
		}
	}
	if err := s.SetCursorFor(r, *to); err != nil {
		return err
	}
	fmt.Printf("%s's cursor is %d; run '%s inbox --relay %s' to fetch\n", r.Name, *to, prog, r.Name)
	return nil
}
