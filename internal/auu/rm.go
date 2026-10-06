package auu

import (
	"errors"
	"fmt"
	"os"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// auu rm: a message removed from the relay and from here.
//
// With a channel set to keep, which is the default, mail stays queued on
// the relay after it has been fetched, so that a second machine of the same
// identity reads the same mail. This is what takes it away. Removing it
// from the relay is the acknowledgement the fetch used to send; removing it
// here is the record and its attachments.

// rmResult is one id's outcome, for --json.
type rmResult struct {
	ID    string `json:"id"`
	Relay string `json:"relay,omitempty"`
	// RemovedRelay says the relay was told; RemovedLocal that the local
	// copy is gone.
	RemovedRelay bool `json:"removed_relay"`
	RemovedLocal bool `json:"removed_local"`
}

func cmdRm(args []string) error {
	fs := newFlagSet("rm")
	localOnly := fs.Bool("local-only", false, "remove the local copy and leave the relay's")
	remoteOnly := fs.Bool("remote-only", false, "remove the relay's copy and keep the local one")
	asJSON := fs.Bool("json", false, "machine readable output")
	relayFlagValue := relayFlag(fs)
	ids, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return usageErrf("usage: %s rm MESSAGE-ID... [--local-only | --remote-only]", prog)
	}
	if *localOnly && *remoteOnly {
		return usageErrf("--local-only and --remote-only ask for opposite things; give one or neither")
	}

	// Removing the local copy alone touches no relay and needs no key, so
	// it works with the agent locked. Anything else is about to speak for
	// this identity.
	var (
		s  *store.Store
		id *identity.Identity
	)
	if *localOnly {
		if s, err = openStore(); err != nil {
			return err
		}
	} else if s, id, err = loadIdentity(); err != nil {
		return err
	}

	// One client per relay: several ids usually came through one.
	clients := map[string]*client.Client{}
	results := make([]rmResult, 0, len(ids))
	for _, want := range ids {
		box, m, err := s.Find(want)
		if err != nil {
			// A record Load refuses is not listed and cannot be found by
			// a prefix, but a whole id can still name it: it is removed
			// without being read, so that a record this program cannot
			// read is never one it cannot let go of either. Only when
			// nothing matched: any other failure of Find — a box that
			// could not be listed — is its own error, not a reason to
			// remove a record blind.
			if message.ValidID(want) == nil && errors.Is(err, store.ErrNoMatch) {
				res, handled, herr := rmUnreadable(s, want, *localOnly, *remoteOnly, *asJSON)
				if herr != nil {
					return herr
				}
				if handled {
					results = append(results, res)
					continue
				}
			}
			return usageErrf("%v", err)
		}
		res := rmResult{ID: m.Inner.ID}
		onRelay := m.StillOnRelay()
		// A sent message is a copy of what was posted to somebody else's
		// mailbox; this identity's mailbox never held it.
		if box == store.Sent {
			if *remoteOnly {
				return usageErrf("%s: a sent message is not in your mailbox on any relay", m.Inner.ID[:12])
			}
			onRelay = false
		}

		if onRelay && !*localOnly {
			r, err := relayOf(s, m, *relayFlagValue)
			if err != nil {
				return err
			}
			res.Relay = r.Name
			c, ok := clients[r.Name]
			if !ok {
				if c, err = dial(s, id, r); err != nil {
					// Everything before this id is done and said; this
					// one's local copy is untouched, so the command can
					// be run again when the relay is back.
					return finishRm(results, *asJSON, transportErr(fmt.Errorf("%s: %w", r.Name, err)))
				}
				clients[r.Name] = c
			}
			// A message the relay no longer has is the state that was
			// asked for; Ack says so by not failing.
			if err := c.Ack(ctx(), m.RelayID); err != nil {
				return finishRm(results, *asJSON, transportErr(fmt.Errorf("%s: %w", r.Name, err)))
			}
			res.RemovedRelay = true
		}

		switch {
		case *remoteOnly:
			if !onRelay {
				// Nothing was asked of the relay, and nothing is asked
				// of the spool: say so and go on. The result entry says
				// it too, so the JSON carries no loose line.
				if !*asJSON {
					fmt.Printf("%s: not on the relay\n", m.Inner.ID[:12])
				}
				results = append(results, res)
				continue
			}
			// The record stays, and no longer claims to be anywhere else. A
			// stream that waited for a newer auu keeps that it did, with
			// the payload it waited on gone, so nothing asks for it again.
			if m.Newer != "" {
				m.OnRelay, m.PayloadGone = false, true
			} else {
				m.OnRelay, m.PayloadOnRelay = false, false
			}
			if err := s.Save(box, m); err != nil {
				return err
			}
		default:
			// Removed here and left there: the record that said so is
			// about to go, so the relay's own copy is remembered in the
			// relay's left-behind file first. Without it the next fetch
			// would find the relay counting mail this machine's cursor is
			// past and call this home damaged — and written afterwards, a
			// write that failed would leave exactly that. Remembered
			// twice over, by the record and the file, is the safe
			// direction; the refresh drops whichever is stale.
			if *localOnly && onRelay {
				r, err := relayOf(s, m, *relayFlagValue)
				if err != nil {
					return err
				}
				res.Relay = r.Name
				if err := s.AddLeftBehind(r.Name, store.LeftEntry{RelayID: m.RelayID, ID: m.Inner.ID,
					Received: m.Received, Size: m.RelaySize, From: m.Inner.From}); err != nil {
					return err
				}
			}
			if err := s.Remove(box, m.Inner.ID); err != nil {
				return err
			}
			res.RemovedLocal = true
		}
		results = append(results, res)
		if !*asJSON {
			fmt.Println(rmLine(m.Inner.ID[:12], res, onRelay))
		}
	}
	return finishRm(results, *asJSON, nil)
}

// rmUnreadable removes a record Load refuses, by its whole id. The relay
// is not asked, since nothing the record says can be trusted; but the
// relay's name and the relay's number, read from the raw record under
// their own rules, are enough to remember the relay's copy as left
// behind, so the next fetch does not find the cursor past mail it cannot
// account for. Without them the local copy goes and the sentence says the
// relay's copy, if any, was not told. --remote-only has nothing it can
// do and is refused. handled is false when no box holds the id.
func rmUnreadable(s *store.Store, id string, localOnly, remoteOnly, asJSON bool) (rmResult, bool, error) {
	if remoteOnly {
		return rmResult{}, false, usageErrf("%s: the record cannot be read, so the relay's copy cannot be named; remove the local copy with '%s rm %s'", id[:12], prog, id)
	}
	box, relay, relayID, from, err := s.RemoveByID(id)
	if errors.Is(err, os.ErrNotExist) {
		return rmResult{}, false, nil
	}
	if err != nil {
		return rmResult{}, false, err
	}
	res := rmResult{ID: id, RemovedLocal: true}
	line := fmt.Sprintf("%s: removed here (the record could not be read)", id[:12])
	if relay != "" && box != store.Sent {
		// The record could not be read, so the relay's time and size for
		// it are not known: zero, which the check before a re-fetch
		// cannot match and the re-fetch matches by the message's own id.
		// The signer is read from the raw record under its rule, and is
		// empty when even that fails.
		if err := s.AddLeftBehind(relay, store.LeftEntry{RelayID: relayID, ID: id, From: from}); err != nil {
			return rmResult{}, false, err
		}
		res.Relay = relay
		line += fmt.Sprintf("; its copy on %s, if there is one, is left there", relay)
	} else if box != store.Sent {
		line += "; the relay's copy, if there is one, was not told"
	}
	if !asJSON {
		fmt.Println(line)
	}
	return res, true, nil
}

// rmLine is what one id's removal says.
func rmLine(short string, res rmResult, onRelay bool) string {
	switch {
	case res.RemovedRelay && res.RemovedLocal:
		return fmt.Sprintf("%s: removed from %s and here", short, res.Relay)
	case res.RemovedRelay:
		return fmt.Sprintf("%s: removed from %s", short, res.Relay)
	case onRelay:
		return fmt.Sprintf("%s: removed here; still on %s, and this machine will not fetch it again", short, res.Relay)
	default:
		return fmt.Sprintf("%s: removed here", short)
	}
}

// finishRm prints the JSON, when it was asked for, and returns the failure
// that ended the run, if one did: what was done before it is said either
// way, so a second run knows where it got to.
func finishRm(results []rmResult, asJSON bool, failure error) error {
	if asJSON {
		if err := printJSON(results); err != nil {
			return err
		}
	}
	return failure
}
