package auu

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The queue a relay holds for you: mail you addressed to somebody on another
// relay, which your relay has taken and has still to hand to the first hop.
//
// It exists because that mail is not in your sent record's usual sense — it
// has left your machine and not arrived anywhere — and because when it goes
// wrong the only party who can tell you is the relay holding it. A message on
// its way to a mailbox on your own relay never appears here: it was delivered
// when the post returned.

// queuedJSON is one row as --json gives it, which is the wire's own shape
// with the times as this machine renders every time.
type queuedJSON struct {
	ID        int64  `json:"id"`
	Neighbour string `json:"neighbour"`
	Path      string `json:"path,omitempty"`
	State     string `json:"state"`
	Tries     int64  `json:"tries"`
	// omitzero and not omitempty: omitempty does nothing to a struct, so
	// these rendered as a date in year 1 on a row that had none — which is
	// the same fault as the relay's own zero reading as 1970, one layer out,
	// and worse for an agent reading the JSON than an absent key.
	LastTry time.Time `json:"last_try,omitzero"`
	NextTry time.Time `json:"next_try,omitzero"`
	GivesUp time.Time `json:"gives_up,omitzero"`
	Code    string    `json:"code,omitempty"`
	Said    string    `json:"said,omitempty"`
	// Relay is the relay holding it, which --json needs because one home
	// may be on several and the rows of each are the relay's own.
	Relay string `json:"relay"`
}

func cmdQueue(args []string) error {
	fs := newFlagSet("queue")
	relay := relayFlag(fs)
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("usage: %s queue [--relay NAME] [--json]", prog)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	// Every relay this home is on, unless one is named: "what of mine is
	// still on its way" is not a question about one relay, which is the
	// same reason inbox and wait cover them all.
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	var rows []queuedJSON
	var unreachable []string
	for _, r := range relays {
		queued, err := queueOf(s, id, r)
		if err != nil {
			// A relay that cannot be reached, or one that forwards
			// nothing, is named and skipped: the queues on the others are
			// still worth showing, exactly as inbox does it.
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		for _, q := range queued {
			rows = append(rows, queuedJSON{
				ID: q.ID, Neighbour: q.Neighbour, Path: q.Path, State: q.State,
				Tries: q.Tries, LastTry: q.LastTry, NextTry: q.NextTry, GivesUp: q.GivesUp,
				Code: q.Code, Said: q.Said, Relay: r.Name,
			})
		}
	}
	for _, line := range unreachable {
		fmt.Fprintf(os.Stderr, "warning: %s\n", line)
	}
	// Oldest first across every relay, which is the order each relay
	// answers in and the order a person reads a queue in.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	printQueue(rows)
	return nil
}

// queueOf is one relay's rows, or why they could not be read.
func queueOf(s *store.Store, id *identity.Identity, r *store.Relay) ([]relayapi.QueuedMessage, error) {
	c, err := dial(s, id, r)
	if err != nil {
		return nil, err
	}
	defer c.CloseIdle()
	return c.Queue(ctx())
}

// printQueue says what is waiting, as a person reads it.
func printQueue(rows []queuedJSON) {
	if len(rows) == 0 {
		fmt.Println("nothing of yours is waiting to leave a relay")
		return
	}
	for _, q := range rows {
		where := identity.PrintableText(q.Neighbour)
		if q.Path != "" {
			where += "!" + identity.PrintableText(q.Path)
		}
		fmt.Printf("%s %-7s to %s at %s\n", shortQueueID(q.ID), q.State, where,
			identity.PrintableText(q.Relay))
		switch q.State {
		case "waiting":
			// What it is waiting for and how long it has: the numbers a
			// person wants are when it will be tried and when it stops.
			if q.Tries == 0 {
				fmt.Printf("    not yet tried; gives up %s\n", stamp(q.GivesUp))
			} else {
				fmt.Printf("    %s since %s, next try %s, gives up %s\n",
					tries(q.Tries), stamp(q.LastTry), stamp(q.NextTry), stamp(q.GivesUp))
			}
		case "handed":
			fmt.Printf("    handed over %s; anything further comes back as a report\n", stamp(q.LastTry))
		case "final":
			// Both the code and the sentence are another relay's words and
			// reach a terminal here, so both are escaped. The client held
			// each to its shape before this, and this is the last line
			// under that rule rather than the rule: a byte from the
			// network is escaped before a terminal sees it, whatever else
			// has already looked at it.
			fmt.Printf("    %s: %s\n", identity.PrintableText(q.Code), identity.PrintableText(q.Said))
		}
	}
}

// shortQueueID is a row's id, padded so the lines line up. A queue id is the
// relay's own row number and is small; a person quotes it when they ask their
// operator about a message.
func shortQueueID(id int64) string { return fmt.Sprintf("%6d", id) }

func tries(n int64) string {
	if n == 1 {
		return "1 try"
	}
	return fmt.Sprintf("%d tries", n)
}

// stamp renders a time for a person, or says it is not set: the zero time is
// a value here — a row never tried has no last try — and "never" is what that
// means rather than a date in 1970.
func stamp(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("Mon 15:04")
}

// queueLine is what `auu inbox` says about one relay's forwarding queue, or
// the empty string when it has nothing of this identity's.
//
// It is one line because the inbox is a summary: the counts, where the oldest
// is stuck, and the command that shows the rest. "Unreachable since" is the
// oldest last_try among the waiting rows for that neighbour that have been
// tried, and the clause is left out when none has — a row queued and not yet
// offered says nothing about whether the neighbour is answering, and a claim
// that it does would be this program inventing one.
func queueLine(rep relayFetch) string {
	if len(rep.Outbound) == 0 {
		return ""
	}
	var waiting, failed int
	// Per neighbour, since "unreachable since" is a claim about a
	// neighbour: the oldest attempt among that neighbour's waiting rows.
	type neighbourState struct {
		waiting int
		since   time.Time
		next    time.Time
		givesUp time.Time
	}
	byNeighbour := map[string]*neighbourState{}
	var order []string
	for _, q := range rep.Outbound {
		switch q.State {
		case "final":
			failed++
		case "waiting":
			waiting++
			n := byNeighbour[q.Neighbour]
			if n == nil {
				n = &neighbourState{}
				byNeighbour[q.Neighbour] = n
				order = append(order, q.Neighbour)
			}
			n.waiting++
			if !q.LastTry.IsZero() && (n.since.IsZero() || q.LastTry.Before(n.since)) {
				n.since = q.LastTry
			}
			if n.next.IsZero() || q.NextTry.Before(n.next) {
				n.next = q.NextTry
			}
			if n.givesUp.IsZero() || q.GivesUp.Before(n.givesUp) {
				n.givesUp = q.GivesUp
			}
		}
	}
	var line string
	if waiting > 0 {
		// The neighbour with the most waiting, since the times in the
		// clause are one neighbour's and cannot be said of several. The
		// count beside its name is that neighbour's own, and anything
		// waiting for another is said separately: attributing the whole
		// count to one neighbour would send somebody to their operator
		// about the wrong relay, and the times would be about a relay that
		// was holding fewer messages than the number in front of them.
		worst := order[0]
		for _, name := range order {
			if byNeighbour[name].waiting > byNeighbour[worst].waiting {
				worst = name
			}
		}
		n := byNeighbour[worst]
		line = fmt.Sprintf("%d waiting at %s for %s", n.waiting,
			identity.PrintableText(rep.Relay), identity.PrintableText(worst))
		var clauses []string
		if !n.since.IsZero() {
			clauses = append(clauses, "unreachable since "+stamp(n.since))
		}
		clauses = append(clauses, "next try "+stamp(n.next), "gives up "+stamp(n.givesUp))
		line += " (" + strings.Join(clauses, ", ") + ")"
		if rest := waiting - n.waiting; rest > 0 {
			line += fmt.Sprintf("; %d more for other relays", rest)
		}
	}
	if failed > 0 {
		if line != "" {
			line += "; "
		}
		line += fmt.Sprintf("%d failed", failed)
	}
	if line == "" {
		return ""
	}
	return line + ": run " + prog + " queue"
}
