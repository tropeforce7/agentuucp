package auu

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
			// Known on the manifest's path, which is the path the mark was
			// made on (OpenManifest's sort) and the one it is lifted on
			// (G23): a name this build knows only on a request or an answer
			// still needs a newer auu here.
			if m.Newer == "" || m.Relay != r.Name || !wire.Known(m.Newer, wire.OnManifest) || m.PayloadGone {
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
			if err := deliverStream(ctx, s, id, c, r, relayCopy{m.RelayID, m.Received, m.RelaySize}, opened, box, keep, m.Arrived); err != nil {
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
			// The record deliverStream saved says the relay holds the
			// message, and owes it an acknowledgement when its channel
			// does not keep; the acknowledgement made, it says the relay
			// does not (G32, R47).
			if err := settleOwedByID(ctx, s, c, box, m.Inner.ID); err != nil {
				return err
			}
			res.Delivered++
		}
	}
	return nil
}

// acknowledgeOwed is the owed acknowledgements of one relay, made at the
// start of each drain of it beside fetchKnownNow: every record of the
// relay, in the inbox or the quarantine, that was fetched whole from a
// channel that does not keep and saved before its acknowledgement, which
// was then refused or cut off (G32, R47). Each is acknowledged by its
// relay id and its record saved to say the relay no longer holds it;
// nothing is downloaded again. The cursor passed the row long ago, so
// nothing else would ever ask, and LeftOn counts the record until then,
// so the relay's count is not taken for mail behind the cursor.
func acknowledgeOwed(ctx context.Context, s *store.Store, c *client.Client, r *store.Relay) error {
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		msgs, err := s.ListQuietly(box)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Relay != r.Name {
				continue
			}
			// A relay that refuses one acknowledgement outright is said and
			// passed over, so the drain goes on: the record still owes it,
			// LeftOn still counts it, and the next fetch asks again. A
			// relay that cannot be reached ends the drain, as it would.
			if err := settleOwed(ctx, s, c, box, m, true); err != nil {
				if refusedOutright(err) {
					fmt.Fprintf(os.Stderr, "%s: the acknowledgement of message %d, %s, was refused (%v); it is asked again next time\n",
						r.Name, m.RelayID, m.Inner.ID[:12], err)
					continue
				}
				return err
			}
		}
	}
	return nil
}

// settleOwedByID is settleOwed for the record just saved under an id.
func settleOwedByID(ctx context.Context, s *store.Store, c *client.Client, box store.Box, id string) error {
	m, err := s.Load(box, id)
	if err != nil {
		return err
	}
	return settleOwed(ctx, s, c, box, m, false)
}

// settleOwed makes the acknowledgement a record owes, when it owes one,
// and only then saves the record without OnRelay and AckOwed: the record
// is never written ahead of the acknowledgement that makes it true. A
// relay that no longer has the row, 404 (which Ack takes as done) or 410,
// is the state the acknowledgement wanted. Any other refusal leaves the
// record as it was, owing, for the next fetch, and is a transport failure;
// a record that cannot be saved is this home's trouble and said as it is.
//
// check asks the relay first whether the row under the record's id is
// still the copy it delivered, by its id, the time the relay received it
// and its size, as every other act on a stored relay id does: a relay
// whose numbering began again since may hold other mail, not yet fetched,
// under that id, and an acknowledgement would remove it. A row that is not
// that copy is one the relay no longer holds, and the record says so with
// no acknowledgement. Only the acknowledgement made straight after the
// delivery, whose row was listed moments before, is spared the ask.
func settleOwed(ctx context.Context, s *store.Store, c *client.Client, box store.Box, m *store.Stored, check bool) error {
	if !m.OnRelay || !m.AckOwed || m.RelayID <= 0 {
		return nil
	}
	held := true
	if check {
		listed, err := stillListed(ctx, c, relayCopy{m.RelayID, m.Received, m.RelaySize})
		if err != nil {
			return transportErr(err)
		}
		held = listed
	}
	if held {
		if err := c.Ack(ctx, m.RelayID); err != nil && !isGone(err) {
			return transportErr(err)
		}
	}
	m.OnRelay, m.AckOwed = false, false
	return s.Save(box, m)
}

// refusedOutright is a relay that answered a request with a refusal no
// wait will change: a 4xx other than a rate limit, which asks for a wait,
// and other than a 401, which is this machine's credentials and ends every
// request alike.
func refusedOutright(err error) bool {
	var he *client.HTTPError
	return errors.As(err, &he) && he.Status >= 400 && he.Status < 500 &&
		he.Status != http.StatusTooManyRequests && he.Status != http.StatusUnauthorized
}
