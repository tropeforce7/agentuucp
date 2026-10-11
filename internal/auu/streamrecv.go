package auu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// Receiving a stream.
//
// The manifest is fetched first, on its own, in two small range requests: the
// header to learn how long chunk 0 is, then chunk 0 itself. That is what lets
// a receiver see who a stream is from before agreeing to download it, so a
// stranger cannot make anybody pull two gigabytes.

// fetchManifest gets the encapsulation and chunk 0 and nothing else.
//
// It returns the bytes it read, whose length the tests assert is small: the
// promise that an unknown sender costs a manifest and no more is only worth
// anything if it is checked. They are also what is kept of a stream that
// will not open: the manifest chunk, and never the payload.
func fetchManifest(ctx context.Context, c *client.Client, id *identity.Identity, relayID int64) (*stream.Opened, []byte, error) {
	header, err := readBlobRange(ctx, c, id, relayID, 0, stream.HeaderSize-1)
	if err != nil {
		return nil, nil, err
	}
	length, err := stream.ManifestLength(header)
	if err != nil {
		return nil, header, err
	}
	chunk0, err := readBlobRange(ctx, c, id, relayID,
		stream.HeaderSize, int64(stream.HeaderSize+length-1))
	if err != nil {
		return nil, header, err
	}
	read := append(append([]byte{}, header...), chunk0...)
	opened, err := stream.OpenManifest(id, header, chunk0)
	if errors.Is(err, wire.ErrNeedsNewer) {
		// The manifest verified and names a critical section this build
		// does not know: the caller needs its sender and its id to leave
		// the stream waiting on the relay (D42).
		return opened, read, err
	}
	if err != nil {
		return nil, read, err
	}
	return opened, read, nil
}

func readBlobRange(ctx context.Context, c *client.Client, id *identity.Identity, relayID, from, to int64) ([]byte, error) {
	body, _, err := c.Blob(ctx, id.Fingerprint(), relayID, from, to)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	// Bounded: the caller has already decided how much it wants, and a relay
	// that sends more does not get to fill memory with it. Reading exactly
	// that much also means a connection that drops part way is an unexpected
	// EOF, which is a transport failure, rather than a short buffer, which
	// would look like a stream nobody can ever open.
	buf := make([]byte, to-from+1)
	n, err := io.ReadFull(body, buf)
	if err != nil {
		return nil, fmt.Errorf("reading %d bytes from the relay at %d: %w", len(buf), from, err)
	}
	return buf[:n], nil
}

// Download budgets. A drop that is followed by progress is a network being a
// network; a drop that is followed by another drop at the same offset is a
// relay that cannot serve this range, and there is no point asking it again.
const (
	maxStalledReconnects = 5
	maxTotalReconnects   = 50
)

// errDownloadInterrupted is what a download that could not be resumed comes
// back as. It exists so that the failure keeps its shape: the stream package
// turns an EOF from its reader into ErrTruncated, which the fetch loop treats
// as a stream nobody will ever open and acknowledges away. A network that gave
// up is the opposite of that, so the cause is put in the message with %v
// rather than wrapped with %w, deliberately, to stop it being mistaken for one.
var errDownloadInterrupted = errors.New("the download from the relay was interrupted")

// resumingReader reads a byte range from the relay, reconnecting from where it
// left off when the connection drops.
//
// A stream's HPKE context advances a nonce on every chunk and cannot be
// rewound, so a download that fails part way cannot simply be started again:
// everything already decrypted would have to be thrown away with it. It does
// not have to be. The relay serves ranges, the bytes are the same bytes, and
// what the caller above sees is one uninterrupted reader.
//
// Knowing where the range ends is what makes this safe. A body that stops
// before it is a connection that dropped, and is reconnected; a body that
// stops at it is the end, and EOF is passed up. Without that distinction a
// download interrupted by the network would arrive at the AEAD as a truncated
// stream, be taken for an attack, and be acknowledged and destroyed — which is
// exactly the wrong answer for the case that actually happens.
type resumingReader struct {
	open  func(from int64) (io.ReadCloser, error)
	from  int64 // absolute offset of the next byte to be delivered
	until int64 // absolute offset one past the last byte of the range

	body    io.ReadCloser
	stalled int
	total   int
}

func (r *resumingReader) Read(p []byte) (int, error) {
	if r.from >= r.until {
		// The range is finished. Saying so here rather than asking the relay
		// keeps the check for bytes after the final chunk from costing a
		// request.
		return 0, io.EOF
	}
	for {
		if r.body == nil {
			body, err := r.open(r.from)
			if err != nil {
				return 0, err
			}
			r.body = body
		}
		n, err := r.body.Read(p)
		if n > 0 {
			// Progress: hand it up and leave the error, if any, for the next
			// call to deal with against a fresh budget.
			r.from += int64(n)
			r.stalled = 0
			return n, nil
		}
		if err == nil {
			return 0, nil
		}
		if errors.Is(err, io.EOF) && r.from >= r.until {
			return 0, io.EOF
		}
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		r.body.Close()
		r.body = nil
		r.stalled++
		r.total++
		if r.stalled >= maxStalledReconnects || r.total >= maxTotalReconnects {
			return 0, fmt.Errorf("%w at byte %d after %d attempts: %v",
				errDownloadInterrupted, r.from, r.total, err)
		}
	}
}

func (r *resumingReader) Close() error {
	if r.body == nil {
		return nil
	}
	err := r.body.Close()
	r.body = nil
	return err
}

// deliverStream fetches a stream's payload and delivers it, atomically.
func deliverStream(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client,
	r *store.Relay, listed relayCopy, opened *stream.Opened, box store.Box, keep bool, arrived time.Time) error {

	relayID := listed.ID
	m := opened.Manifest
	payloadFrom := int64(stream.HeaderSize) + int64(opened.SealedManifestBytes)
	body := &resumingReader{
		from:  payloadFrom,
		until: stream.Size(opened.SealedManifestBytes, m.PayloadBytes, m.ChunkSize),
		open: func(from int64) (io.ReadCloser, error) {
			r, _, err := c.Blob(ctx, id.Fingerprint(), relayID, from, -1)
			return r, err
		},
	}
	defer body.Close()

	dir := s.AttachmentDir(box, m.ID)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	os.RemoveAll(dir)
	if err := opened.ToDirectory(body, dir); err != nil {
		return err
	}

	// The local record mirrors an envelope's.
	inner, dropped := innerFromManifest(m)
	return s.Save(box, &store.Stored{
		RelayID:         relayID,
		Relay:           r.Name,
		Received:        listed.Received,
		Arrived:         arrived,
		RelaySize:       listed.Size,
		Inner:           inner,
		SenderName:      s.PeerName(m.From),
		Streamed:        true,
		Channel:         storedChannel(m.Channel),
		OnRelay:         keep,
		DroppedSections: dropped,
	})
}

// quarantineStream records a stream from somebody unknown without fetching it.
//
// The payload stays on the relay and is not acknowledged, so nothing is lost
// if the recipient later decides to trust the sender. A stranger cannot make
// anyone download anything.
func quarantineStream(s *store.Store, r *store.Relay, listed relayCopy, opened *stream.Opened) error {
	return waitingStream(s, store.Quarantine, r, listed, opened, "")
}

// waitingStream records a stream whose payload is left on the relay: a
// stranger's, in the quarantine, until a person decides; or one with a
// critical section this build does not know, in the box its sender's mail
// goes to, marked with the section, until a build that knows it fetches it
// whole (D42). Nothing of the payload is fetched and nothing acknowledged.
func waitingStream(s *store.Store, box store.Box, r *store.Relay, listed relayCopy, opened *stream.Opened, newer string) error {
	m := opened.Manifest
	inner, dropped := innerFromManifest(m)
	name := ""
	if box == store.Inbox {
		name = s.PeerName(m.From)
	}
	return s.Save(box, &store.Stored{
		RelayID:         listed.ID,
		Relay:           r.Name,
		Received:        listed.Received,
		RelaySize:       listed.Size,
		Inner:           inner,
		SenderName:      name,
		Streamed:        true,
		PayloadOnRelay:  true,
		Channel:         storedChannel(m.Channel),
		Newer:           newer,
		DroppedSections: dropped,
	})
}

// storedChannel is a manifest's channel as the record keeps it: nothing
// for default, as an envelope's record keeps it.
func storedChannel(channel string) string {
	if channel == channels.Default {
		return ""
	}
	return channel
}

// fetchOneStream is the stream branch of fetch.
func fetchOneStream(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client,
	r *store.Relay, m client.Message, directory *channels.Directory, settings store.ChannelSettings,
	res *fetchResult, met *meeter) error {

	relayID := m.ID
	opened, manifest, err := fetchManifest(ctx, c, id, relayID)
	// A stream with a critical section this build does not know waits on
	// the relay, unacknowledged, with a record of it in the box its
	// sender's mail goes to, and the fetch goes on past it: a build that
	// knows the section fetches it whole, since the payload is still
	// there (D42). Its sender is the one the manifest's signature named.
	var newer *wire.NeedsNewerError
	if errors.As(err, &newer) && opened != nil {
		meeting, err := met.meet(ctx, s, c, m, opened.Manifest.ID, opened.Sender.Fingerprint())
		if err != nil {
			return err
		}
		if meeting == collided {
			met.fresh++
			if err := keepCollided(s, r, relayID, m.Received, manifest, res); err != nil {
				return err
			}
			return c.Ack(ctx, relayID)
		}
		if meeting == metAgain {
			res.Duplicate++
		}
		if meeting == metHeld || meeting == metAgain {
			return nil
		}
		met.fresh++
		box := store.Quarantine
		if s.IsAuthorized(opened.Sender.Fingerprint()) {
			box = store.Inbox
		}
		if err := waitingStream(s, box, r, relayCopy{relayID, m.Received, m.Size}, opened, newer.Name); err != nil {
			return err
		}
		res.Newer = append(res.Newer, newer.Name)
		return nil
	}
	if err != nil {
		if isGone(err) {
			return droppedOnRelay(relayID, res)
		}
		// Nobody will ever be able to read this, so leaving it queued would
		// block the mailbox for ever. What is kept is the manifest chunk,
		// which is all that was fetched.
		if isPermanent(err) {
			met.fresh++
			if err := keepDamaged(s, r, relayID, m.Received, manifest, streamCause(err), res); err != nil {
				return err
			}
			return c.Ack(ctx, relayID)
		}
		return err
	}
	// A stream this machine already holds from this relay is met at the
	// manifest, before a byte of payload is asked for.
	meeting, err := met.meet(ctx, s, c, m, opened.Manifest.ID, opened.Sender.Fingerprint())
	if err != nil {
		return err
	}
	if meeting == collided {
		met.fresh++
		if err := keepCollided(s, r, relayID, m.Received, manifest, res); err != nil {
			return err
		}
		return c.Ack(ctx, relayID)
	}
	if meeting == metAgain {
		res.Duplicate++
	}
	if meeting == metHeld || meeting == metAgain {
		return nil
	}
	met.fresh++
	// The manifest's channel against the one the relay listed the stream
	// under: a stream has no outer name, so only a relay that says where it
	// filed it can be found to have filed it elsewhere.
	channel, filedAs, agrees := filedUnder(opened.Manifest.Channel, "", m)
	if !agrees {
		if err := keepMisfiled(s, r, relayID, m.Received, manifest, filedAs, opened.Manifest.Channel, res); err != nil {
			return err
		}
		return c.Ack(ctx, relayID)
	}
	// What the signed manifest says the stream weighs, against what the
	// relay listed the stored file at. They agree for every stream a
	// sender's own client made; one that disagrees was made to — a
	// manifest that declares more than was uploaded used to turn the
	// download's end into a 416 the fetch took as a transport failure,
	// and every later fetch of the mailbox stopped at it. It is the
	// sender's fault and the stream is refused before a byte of payload
	// is asked for, and before anybody is asked whether its sender is
	// admitted, so a stranger's is not quarantined for a person to trust
	// into a fetch that cannot finish: kept under damaged/ with the two
	// numbers, acknowledged, and the fetch goes on.
	if want := stream.Size(opened.SealedManifestBytes, opened.Manifest.PayloadBytes, opened.Manifest.ChunkSize); want != m.Size {
		if err := keepDamaged(s, r, relayID, m.Received, manifest, sizeCause(want, m.Size), res); err != nil {
			return err
		}
		return c.Ack(ctx, relayID)
	}
	if !s.IsAuthorized(opened.Sender.Fingerprint()) {
		// Recorded, not fetched, and deliberately not acknowledged: the
		// payload waits on the relay until a person decides.
		if err := quarantineStream(s, r, relayCopy{relayID, m.Received, m.Size}, opened); err != nil {
			return err
		}
		res.Quarantined++
		return nil
	}
	// Kept on the relay, or acknowledged away, as this machine's setting
	// for the manifest's channel says.
	keep := keepFor(settings, channel)
	if err := deliverStream(ctx, s, id, c, r, relayCopy{relayID, m.Received, m.Size}, opened, store.Inbox, keep, time.Time{}); err != nil {
		if isGone(err) {
			return droppedOnRelay(relayID, res)
		}
		// The manifest chunk alone is kept, never the payload: it says
		// who sent it and what it was, and the payload is what did not
		// survive.
		if isPermanent(err) {
			if err := keepDamaged(s, r, relayID, m.Received, manifest, streamCause(err), res); err != nil {
				return err
			}
			return c.Ack(ctx, relayID)
		}
		return err
	}
	res.Delivered++
	res.noteGone(directory, channel)
	if keep {
		return nil
	}
	return c.Ack(ctx, relayID)
}

// droppedOnRelay is the answer to a 410: the relay found the stored file
// damaged and has dropped it. It is permanent and none of this machine's
// doing, and there is nothing to acknowledge, since the relay has already
// done that; the caller advances the cursor past it.
func droppedOnRelay(relayID int64, res *fetchResult) error {
	res.Unreadable++
	fmt.Fprintf(os.Stderr, "warning: relay message %d was damaged on the relay and has been "+
		"dropped there; ask the sender to send it again\n", relayID)
	return nil
}

// isGone reports a 410 from the relay: the stored stream was damaged and the
// relay dropped it when asked to serve it.
func isGone(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == http.StatusGone
}

// isBeyondTheFile reports a 416 from the relay for a stream's body: the
// receiver asked for a range past the end of the stored file. The manifest
// is checked against the listing before any range is asked for, so this is
// the file having changed under its row since — and either way the stream
// will never open, so it is permanent, kept and acknowledged rather than
// met again on every fetch.
func isBeyondTheFile(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == http.StatusRequestedRangeNotSatisfiable
}

// isMissingOnRelay reports a 404 from the relay for a stream's body: the
// message is not in the mailbox any more, which for a quarantined stream
// means the body it was waiting on has gone — removed by another machine
// of this identity, or purged by an administrator.
func isMissingOnRelay(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound
}

// isPermanent tells a stream that will never open from one that failed to
// arrive. The first is acknowledged and dropped; the second is left for the
// next fetch to resume. A key that is not here — the agent locked — is
// neither, and above all is not permanent: the stream would open with the
// key, and acknowledging it would be losing mail. A stream the relay has
// dropped as damaged is permanent too, and is caught first, since there is
// nothing left to acknowledge.
func isPermanent(err error) bool {
	if isLocked(err) {
		return false
	}
	return isGone(err) || isBeyondTheFile(err) ||
		errors.Is(err, stream.ErrForm) ||
		errors.Is(err, stream.ErrSignature) ||
		errors.Is(err, stream.ErrOpenFailed) ||
		errors.Is(err, stream.ErrDigest) ||
		errors.Is(err, stream.ErrTrailing) ||
		errors.Is(err, stream.ErrTruncated)
}
