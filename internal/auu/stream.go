package auu

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// Sending a stream.
//
// The whole stream is sealed to a file in the outbox before a byte is
// uploaded. That costs one times the payload in disk, which the sender has,
// and it is what makes an interrupted upload resumable: the HPKE context
// advances its nonce on every chunk and cannot be rewound, so chunks the relay
// did not receive could never be sealed identically a second time.

// streamSettings are the two knobs, with the defaults applied.
type streamSettings struct {
	threshold int64
	chunkSize int
}

func settingsFrom(cfg store.Config) (streamSettings, error) {
	s := streamSettings{threshold: cfg.StreamThreshold, chunkSize: cfg.ChunkSize}
	if s.threshold == 0 {
		s.threshold = stream.DefaultThreshold
	}
	if s.chunkSize == 0 {
		s.chunkSize = stream.DefaultChunkSize
	}
	if s.threshold < stream.MinChunkSize {
		return s, usageErrf("stream_threshold must be at least %d, got %d",
			stream.MinChunkSize, s.threshold)
	}
	if s.chunkSize < stream.MinChunkSize || s.chunkSize > stream.MaxChunkSize {
		return s, usageErrf("chunk_size must be between %d and %d, got %d",
			stream.MinChunkSize, stream.MaxChunkSize, s.chunkSize)
	}
	return s, nil
}

// sendStream seals a message to the outbox and uploads it.
func sendStream(s *store.Store, id *identity.Identity, r *store.Relay, recipient *identity.Public,
	body message.Body, paths []string, set streamSettings, channel string) (sentJSON, error) {

	messageID, err := envelope.NewID()
	if err != nil {
		return sentJSON{}, err
	}
	sources, err := sourcesFor(paths)
	if err != nil {
		return sentJSON{}, err
	}
	manifest, err := stream.BuildManifest(id, recipient, messageID, stream.Body{
		Type:      body.Type,
		Subject:   body.Subject,
		Thread:    body.Thread,
		InReplyTo: body.InReplyTo,
		Text:      body.Text,
	}, sources, set.chunkSize)
	if err != nil {
		if errors.Is(err, stream.ErrForm) {
			return sentJSON{}, usageErrf("%v", err)
		}
		return sentJSON{}, err
	}
	// Under the signature, so the receiver can check it against what the
	// relay says; absent for default.
	manifest.Channel = channel
	// The sent copy names the files without carrying them: the bytes are the
	// sender's own, still where they were attached from.
	for _, a := range manifest.Attachments {
		body.Attachments = append(body.Attachments, message.Attachment{
			Name: a.Name, Media: a.Media, Size: a.Size, SHA256: a.SHA256,
		})
	}

	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		return sentJSON{}, err
	}
	path := streamPath(s, messageID)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return sentJSON{}, err
	}
	sealErr := stream.Seal(f, id, recipient, manifest, sources)
	if closeErr := f.Close(); sealErr == nil {
		sealErr = closeErr
	}
	if sealErr != nil {
		os.Remove(path)
		if errors.Is(sealErr, stream.ErrForm) {
			return sentJSON{}, usageErrf("%v", sealErr)
		}
		return sentJSON{}, sealErr
	}

	// The record goes down before the first byte goes up, so an upload
	// interrupted at any point after this can be picked up again.
	p := &pending{
		MessageID: messageID,
		To:        recipient.Fingerprint(),
		ToName:    recipient.Name,
		Relay:     r.Name,
		Channel:   channel,
		Started:   time.Now().UTC().Truncate(time.Second),
		Time:      manifest.Time,
		Body:      body,
		Bytes:     manifest.PayloadBytes,
		Chunks:    manifest.Chunks,
		ChunkSize: manifest.ChunkSize,
	}
	if err := p.save(s); err != nil {
		os.Remove(path)
		return sentJSON{}, err
	}
	return finishStream(s, id, r, p, true)
}

// finishStream uploads a sealed stream and records it as sent. It is the tail
// of sendStream and the whole of --resume: a stream that has been sealed is in
// the same state whether it was sealed a moment ago or before a crash.
//
// fresh says this stream was sealed by this call rather than found in the
// outbox, which decides what a failure leaves behind.
func finishStream(s *store.Store, id *identity.Identity, r *store.Relay, p *pending, fresh bool) (sentJSON, error) {
	c, err := dial(s, id, r)
	if err != nil {
		if fresh {
			p.remove(s)
		}
		return sentJSON{}, err
	}
	relayID, err := uploadStream(c, s, p)
	if err != nil {
		hint := streamFullHint(streamChannelHint(err, s, id, c, r, p), p.label())
		switch {
		case fresh && p.Upload == "":
			// The relay never accepted the upload, so there is nothing on it
			// to resume and the sealed copy would only save the sealing.
			// Leaving gigabytes in the outbox for a message that was refused
			// outright is the worse of the two.
			p.remove(s)
		case isStorageFull(err):
			// The relay ran out of room part way. It keeps what it has and
			// the sealed copy is here, so nothing is lost but time: the
			// sentence says whose problem the room is, and that the upload
			// waits for it.
			hint = fmt.Errorf("%v. The upload is kept; finish it with '%s send --resume' when there is room",
				hint, prog)
		case fresh:
			fmt.Fprintf(os.Stderr,
				"the upload stopped part way; finish it with '%s send --resume'\n", prog)
		}
		return sentJSON{}, transportErr(hint)
	}
	p.remove(s)

	if err := s.Save(store.Sent, &store.Stored{
		RelayID:  relayID,
		Relay:    r.Name,
		Received: time.Now().UTC().Truncate(time.Second),
		Read:     true,
		Streamed: true,
		Inner: &envelope.Inner{
			ID: p.MessageID, From: id.Fingerprint(), FromBundle: id.Public().Bundle(),
			To: p.To, Time: p.Time, Body: p.Body, Channel: p.Channel,
		},
		SenderName: p.ToName,
		Channel:    p.Channel,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: message sent but the local copy failed: %v\n", err)
	}

	return sentJSON{
		ID: p.MessageID, Thread: p.Body.Thread, To: p.To,
		ToName: p.ToName, RelayID: relayID,
		Bytes: int(p.Bytes), InReplyTo: p.Body.InReplyTo,
		Kind: "stream", Chunks: p.Chunks, ChunkSize: p.ChunkSize, Channel: p.Channel,
	}, nil
}

// label names the recipient the way the person typing would recognise them.
func (p *pending) label() string {
	if p.ToName != "" {
		return p.ToName
	}
	if len(p.To) >= 12 {
		return p.To[:12]
	}
	return p.To
}

// resumeStreams finishes every unfinished upload in the outbox. One failure
// does not stop the rest: they are separate messages that happened to be
// interrupted together.
func resumeStreams(s *store.Store, id *identity.Identity, asJSON bool, relay string) error {
	waiting, broken, err := listPending(s)
	if err != nil {
		return err
	}
	for _, b := range broken {
		fmt.Fprintf(os.Stderr,
			"warning: outbox record %s has no sealed stream beside it and cannot be resumed; "+
				"send the message again\n", b)
	}
	if len(waiting) == 0 {
		if !asJSON {
			fmt.Println("nothing to resume")
		}
		return nil
	}
	var failed int
	for _, p := range waiting {
		// The upload was opened on one relay and holds a prefix of these
		// exact bytes; it cannot be finished anywhere else. A record from
		// before a home could know more than one relay names none, and the
		// default is where it was opened.
		r, err := resumeRelay(s, p, relay)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", p.MessageID[:12], err)
			continue
		}
		if !asJSON {
			fmt.Printf("resuming %s to %s on %s (%s)\n",
				p.MessageID[:12], orNone(p.ToName), r.Name, humanBytes(p.Bytes))
		}
		out, err := finishStream(s, id, r, p, false)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", p.MessageID[:12], err)
			continue
		}
		if err := printSent(out, r, false, asJSON); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d streams did not finish", failed, len(waiting))
	}
	return nil
}

// resumeRelay is the relay an interrupted upload has to be finished on.
func resumeRelay(s *store.Store, p *pending, flag string) (*store.Relay, error) {
	if strings.TrimSpace(flag) != "" {
		return selectRelay(s, flag)
	}
	if p.Relay == "" {
		return selectRelay(s, "")
	}
	r, err := s.Relay(p.Relay)
	if errors.Is(err, store.ErrNoSuchRelay) {
		return nil, fmt.Errorf("it was opened on %s, which this home no longer has; "+
			"add it again or send the message afresh", p.Relay)
	}
	return r, err
}

// uploadStream sends a sealed file, resuming from whatever the relay already
// has if a piece fails part way.
//
// A large stream is many requests, so it meets the relay's per-identity
// request rate as a matter of course. A 429 or a 503 is not a failure: it is
// the relay saying when to come back, and this waits exactly that long. Only
// an error that is neither, and makes no progress, gives up.
func uploadStream(c *client.Client, s *store.Store, p *pending) (int64, error) {
	path := streamPath(s, p.MessageID)
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	// An upload this process did not start is resumed rather than reopened:
	// the relay already holds a prefix of these exact bytes, and the sealed
	// file cannot be made a second time.
	var offset int64
	if p.Upload != "" {
		offset, err = c.UploadOffset(ctx(), p.Upload)
		if err != nil {
			// The reservation is gone, most likely expired. Starting over is
			// the only thing left, and the bytes are still on disk to do it
			// with.
			p.Upload, p.MaxRequest = "", 0
		}
	}
	if p.Upload == "" {
		opened, err := c.OpenStream(ctx(), p.To, p.Channel, info.Size())
		if err != nil {
			return 0, err
		}
		p.Upload, p.MaxRequest, offset = opened.Upload, opened.MaxRequest, 0
		if err := p.save(s); err != nil {
			return 0, err
		}
	}
	piece := p.MaxRequest
	if piece <= 0 {
		piece = 4 << 20
	}
	if offset > info.Size() {
		return 0, fmt.Errorf("the relay holds %d bytes of an upload that is only %d; abandon it with '%s send --resume'",
			offset, info.Size(), prog)
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	stalled := 0
	for offset < info.Size() {
		n := info.Size() - offset
		if n > piece {
			n = piece
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return 0, err
		}
		next, err := c.AppendStream(ctx(), p.Upload, offset, io.LimitReader(f, n), n)
		if err == nil {
			offset, stalled = next, 0
			continue
		}

		if wait, ok := relayAskedToWait(err); ok {
			if wait <= 0 {
				wait = time.Second
			}
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			time.Sleep(wait)
			// A refusal is not progress, but it is not a stall either: the
			// relay has told us to come back and we are coming back.
			continue
		}
		if isStorageFull(err) {
			// Retrying will not help: the relay has no room, and it keeps
			// the upload for a resume once somebody has made some.
			return 0, err
		}

		// Anything else: ask where the relay actually got to, and continue
		// from there if that is somewhere new.
		at, offErr := c.UploadOffset(ctx(), p.Upload)
		if offErr != nil {
			return 0, err
		}
		if at == offset {
			stalled++
			if stalled >= 3 {
				return 0, err
			}
		} else {
			stalled = 0
		}
		offset = at
	}
	return c.CompleteStream(ctx(), p.Upload)
}

// sourcesFor turns file paths into stream sources, which are opened twice:
// once to hash, once to seal.
func sourcesFor(paths []string) ([]stream.Source, error) {
	var out []stream.Source
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, usageErrf("attachment %s: %v", p, err)
		}
		if info.IsDir() {
			return nil, usageErrf("attachment %s is a directory; attach files individually", p)
		}
		name := filepath.Base(p)
		if err := message.ValidAttachmentName(name); err != nil {
			return nil, usageErrf("%v", err)
		}
		path := p
		out = append(out, stream.Source{
			Name:  name,
			Media: message.MediaTypeFor(name),
			Size:  info.Size(),
			Open:  func() (io.ReadCloser, error) { return os.Open(path) },
		})
	}
	return out, nil
}
