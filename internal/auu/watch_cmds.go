package auu

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdWatch returns when a mailbox gives off an event: a message the relay
// holds past this machine's cursor, or a watched peer replacing their
// channel directory. Every relay the home is on is watched at once, the
// first to find events ends the watch, and every event from that poll is
// reported. Nothing is fetched unless --fetch asks; the watch says what
// the relay said and leaves the mail where it is.
func cmdWatch(args []string) error {
	fs := newFlagSet("watch")
	var events, chans, peers stringList
	fs.Var(&events, "event", "message or directory; repeatable, message when not given")
	fs.Var(&chans, "channel", "report only messages under this channel; repeatable")
	fs.Var(&peers, "peer", "watch this peer's channels, or self; repeatable, every peer and self when not given")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long; 0 for no limit")
	interval := fs.Duration("interval", 20*time.Second, "how often to ask a relay that cannot hold a listing open")
	fetch := fs.Bool("fetch", false, "fetch the messages reported, from the relay that reported them")
	asJSON := fs.Bool("json", false, "machine readable output")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	opts, err := checkWatchFlags(events, chans, peers, *timeout, *interval, *fetch)
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
	return watch(s, id, relays, opts, *asJSON)
}

// checkWatchFlags turns the flags into options, refusing a combination
// that means nothing: a channel filter without message events, a peer
// list or a fetch without the events they apply to.
func checkWatchFlags(events, chans, peers []string, timeout, interval time.Duration, fetch bool) (watchOptions, error) {
	opts := watchOptions{interval: interval, fetch: fetch}
	if len(events) == 0 {
		events = []string{eventMessage}
	}
	for _, e := range events {
		switch e {
		case eventMessage:
			opts.messages = true
		case eventDirectory:
			opts.directories = true
		default:
			return opts, usageErrf("--event must be %s or %s, got %q", eventMessage, eventDirectory, e)
		}
	}
	if len(chans) > 0 {
		if !opts.messages {
			return opts, usageErrf("--channel applies to %s events, and --event %s was not asked for", eventMessage, eventMessage)
		}
		opts.channels = map[string]bool{}
		for _, name := range chans {
			if err := channels.ValidName(name); err != nil {
				return opts, usageErrf("--channel %q: %v", name, err)
			}
			opts.channels[name] = true
		}
	}
	if len(peers) > 0 {
		if !opts.directories {
			return opts, usageErrf("--peer applies to %s events, and --event %s was not asked for", eventDirectory, eventDirectory)
		}
		opts.peers = peers
	}
	if fetch && !opts.messages {
		return opts, usageErrf("--fetch applies to %s events, and --event %s was not asked for", eventMessage, eventMessage)
	}
	if interval < 5*time.Second {
		return opts, usageErrf("--interval must be at least 5s; polling harder does not make replies arrive sooner")
	}
	if timeout < 0 {
		return opts, usageErrf("--timeout must not be negative; 0 means no limit")
	}
	if timeout > 0 {
		opts.deadline = time.Now().Add(timeout)
	}
	return opts, nil
}

// watch is awaitEvents with the printing: the events as a person reads
// them or as --json gives them, and exit 3 when the deadline passed with
// nothing to say.
func watch(s *store.Store, id *identity.Identity, relays []*store.Relay, opts watchOptions, asJSON bool) error {
	start := time.Now()
	o, err := awaitEvents(context.Background(), s, id, relays, opts)
	waited := time.Since(start).Round(time.Second).String()
	switch {
	case err == nil:
		if asJSON {
			return printJSON(watchJSON{Events: o.events, Waited: waited})
		}
		printEvents(s, o.events, o.delivered)
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		if asJSON {
			if err := printJSON(watchJSON{Events: []any{}, Waited: waited}); err != nil {
				return err
			}
		}
		return &exitError{code: exitTimeout, err: fmt.Errorf("nothing happened in %s", waited)}
	default:
		return err
	}
}

// awaitEvents runs one goroutine per relay under one context and returns
// with the first relay's events, or with an error: the context's own when
// the deadline passed or the caller stopped it, and otherwise the first
// relay's, once every relay has ended its watch for a reason no interval
// will change.
//
// It is the whole of what 'auu watch' does up to the point of printing, and
// serve holds on it between rounds. The context it is given is the caller's
// to end; the one the relays run under is derived from it, so that every
// goroutine is ended and waited for before this returns, whichever way it
// returns, and a held request is dropped with it.
func awaitEvents(parent context.Context, s *store.Store, id *identity.Identity,
	relays []*store.Relay, opts watchOptions) (relayOutcome, error) {

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if opts.deadline.IsZero() {
		ctx, cancel = context.WithCancel(parent)
	} else {
		ctx, cancel = context.WithDeadline(parent, opts.deadline)
	}
	var relayWatches sync.WaitGroup
	defer func() {
		cancel()
		relayWatches.Wait()
	}()
	outcomes := make(chan relayOutcome, len(relays))
	for _, r := range relays {
		relayWatches.Add(1)
		go func() {
			defer relayWatches.Done()
			watchRelay(ctx, s, id, r, opts, outcomes)
		}()
	}
	var (
		ended    int
		firstErr error
	)
	for {
		select {
		case o := <-outcomes:
			if o.err != nil {
				var e *exitError
				if errors.As(o.err, &e) && e.code == exitUsage {
					// The flags, not the relay: no other relay will read
					// them differently.
					return relayOutcome{}, o.err
				}
				if firstErr == nil {
					firstErr = o.err
				}
				if ended++; ended == len(relays) {
					// Every relay has ended its watch the same way, and
					// there is nothing left to wait for.
					return relayOutcome{}, firstErr
				}
				continue
			}
			return o, nil
		case <-ctx.Done():
			return relayOutcome{}, ctx.Err()
		}
	}
}
