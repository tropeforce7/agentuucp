package auu

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// fetchKnownNow is what a build does, at the start of each drain of a
// relay, for the streams that wait on that relay for a newer auu (D42) and
// whose section it now knows: a stream waiting for the build this is. The
// payload was left on the relay, so nothing has to be sent again.
//
// It looks at the records alone, so a stream whose section is still unknown
// costs no request. One in the inbox, from an admitted sender, is fetched
// whole and delivered over its record, and acknowledged unless its channel
// keeps it, as quarantine trust fetches one. One in the quarantine, from a
// stranger, loses its mark and stays what any stranger's stream is, waiting
// on a person, since knowing the section is no reason to fetch a stranger's
// payload. A record whose payload is gone from the relay is said once and
// keeps its mark, and is never asked for again.
func fetchKnownNow(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client,
	r *store.Relay, settings store.ChannelSettings, res *fetchResult) error {
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		msgs, err := s.ListQuietly(box)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Newer == "" || m.Relay != r.Name || !wire.Known(m.Newer, wire.AnyPath) || m.PayloadGone {
				continue
			}
			if box == store.Quarantine {
				m.Newer = ""
				if err := s.Save(box, m); err != nil {
					return err
				}
				continue
			}
			// gone marks a record whose payload this fetch found gone, and
			// says so once; the mark keeps it from being asked for again.
			gone := func(why string) error {
				m.PayloadGone = true
				if err := s.Save(box, m); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "%s: message %s waited on %s for a newer auu and %s; ask the sender to send it again\n",
					prog, m.Inner.ID[:12], r.Name, why)
				return nil
			}
			// unreadable keeps the manifest of a stream that will never
			// open under damaged/, acknowledges it, and then lets the record go,
			// as the fetch does for any stream it meets that way: one bad
			// stream must not stop every fetch of the mailbox.
			unreadable := func(manifest []byte, cause string) error {
				if err := keepDamaged(s, r, m.RelayID, m.Received, manifest, cause, res); err != nil {
					return err
				}
				// Acknowledged before the record goes: an acknowledgement that
				// fails leaves the record, and the next drain meets it again,
				// rather than a relay message behind the cursor with nothing
				// here that says what it was.
				if err := c.Ack(ctx, m.RelayID); err != nil {
					return transportErr(err)
				}
				return s.Remove(box, m.Inner.ID)
			}
			opened, manifest, err := fetchManifest(ctx, c, id, m.RelayID)
			switch {
			case errors.Is(err, wire.ErrNeedsNewer):
				// Another critical section this build does not know,
				// beside the one it now does: it waits on.
				continue
			case isMissingOnRelay(err) || isGone(err):
				if err := gone("is no longer there"); err != nil {
					return err
				}
				continue
			case err != nil && isPermanent(err):
				if err := unreadable(manifest, streamCause(err)); err != nil {
					return err
				}
				continue
			case err != nil:
				return transportErr(err)
			}
			if opened.Sender.Fingerprint() != m.Inner.From || opened.Manifest.ID != m.Inner.ID {
				if err := gone("the relay now holds other mail under its id"); err != nil {
					return err
				}
				continue
			}
			if want := stream.Size(opened.SealedManifestBytes, opened.Manifest.PayloadBytes, opened.Manifest.ChunkSize); want != m.RelaySize {
				if err := unreadable(manifest, sizeCause(want, m.RelaySize)); err != nil {
					return err
				}
				continue
			}
			keep := keepFor(settings, channelName(m.Channel))
			if err := deliverStream(ctx, s, id, c, r, relayCopy{m.RelayID, m.Received, m.RelaySize}, opened, box, keep); err != nil {
				switch {
				case isMissingOnRelay(err) || isGone(err):
					if err := gone("is no longer there"); err != nil {
						return err
					}
				case isPermanent(err):
					if err := unreadable(manifest, streamCause(err)); err != nil {
						return err
					}
				default:
					return transportErr(err)
				}
				continue
			}
			if !keep {
				if err := c.Ack(ctx, m.RelayID); err != nil {
					return transportErr(err)
				}
			}
			res.Delivered++
		}
	}
	return nil
}
