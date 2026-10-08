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
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/term"
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
			// The relay ran out of room part way. The sealed copy is here,
			// and the relay keeps what its rule keeps for as long as it
			// keeps it, so nothing is lost but time: the sentence says
			// whose problem the room is, and that the sealed copy waits
			// for it.
			hint = fmt.Errorf("%v. The sealed copy is kept; finish it with '%s send --resume' when there is room",
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
				p.MessageID[:12], orNone(p.ToName), r.Name, term.HumanBytes(p.Bytes))
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
// Every record names it; listPending refused one that does not.
func resumeRelay(s *store.Store, p *pending, flag string) (*store.Relay, error) {
	if strings.TrimSpace(flag) != "" {
		return selectRelay(s, flag)
	}
	r, err := s.Relay(p.Relay)
	if errors.Is(err, store.ErrNoSuchRelay) {
		return nil, fmt.Errorf("it was opened on %s, which this home no longer has; "+
			"add it again or send the message afresh", p.Relay)
	}
	return r, err
}

// uploadStream sends the sealed stream in the outbox to the relay, one
// attempt per turn: an open, then a PUT of the whole file from the offset
// the relay reports to the end, streamed from disk. It answers the message
// id the relay placed the stream under.
//
// An attempt that stops short is the relay's to judge: it keeps the
// partial only when the attempt was the first and got past the relay's
// threshold, and then for the resume window. The sender learns what the
// relay kept the only way this wire tells it, by the next attempt: one
// from zero on the same upload is answered 409 with the offset the
// relay's copy ends at when a partial is kept, 404 or 410 when the relay
// has let the upload go, and taken as the fresh attempt it is when the
// upload is untouched. A 409 past zero is resumed from, once; a second
// short attempt has cost the relay's partial and the next answer says so.
// Three attempts that end in an error other than a wait are the turn's
// limit, and the sealed bytes are still on disk to try with.
func uploadStream(c *client.Client, s *store.Store, p *pending) (int64, error) {
	path := streamPath(s, p.MessageID)
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	// Each attempt opens the file afresh at its offset, and reads it by
	// the handle: the outbox is this home's own, but what stands under
	// the record's name is not taken on trust.
	attempt := func(offset int64) (int64, error) {
		f, err := regular.Open(path)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return 0, err
		}
		n := info.Size() - offset
		return c.PutStream(ctx(), p.Upload, offset, io.LimitReader(f, n), n)
	}

	var offset int64
	resumed := false
	for failed := 0; ; {
		if p.Upload == "" {
			opened, err := c.OpenStream(ctx(), p.To, p.Channel, info.Size(), 0)
			if err != nil {
				return 0, err
			}
			p.Upload, offset, resumed = opened.Upload, 0, false
			if err := p.save(s); err != nil {
				return 0, err
			}
		}
		if offset > info.Size() {
			return 0, fmt.Errorf("the relay holds %d bytes of an upload that is only %d; abandon it with '%s send --resume'",
				offset, info.Size(), prog)
		}
		relayID, err := attempt(offset)
		if err == nil {
			return relayID, nil
		}
		if wait, ok := relayAskedToWait(err); ok {
			if wait <= 0 {
				wait = time.Second
			}
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			time.Sleep(wait)
			// A refusal is not progress, but it is not a failure of the
			// upload either: the relay has told us to come back and we are
			// coming back, at whatever offset it then says.
			continue
		}
		if isStorageFull(err) {
			// Retrying will not help: the relay has no room. Whether it
			// kept the partial is its rule's to say, and the next attempt
			// on the same upload is how this side asks, so the id stays
			// with the record for --resume once somebody has made room.
			return 0, err
		}
		var resume *client.ResumeError
		if errors.As(err, &resume) && resume.At > 0 && !resumed {
			// The relay kept the partial and says where it ends: one
			// resumed attempt from there, within the window.
			offset, resumed = resume.At, true
			continue
		}
		if failed++; failed >= 3 {
			return 0, err
		}
		if isGone(err) || isMissingOnRelay(err) || resume != nil {
			// The relay has let the upload go, or holds a partial this
			// process has already had its one resume from: the next
			// attempt is a new upload from zero, and a partial nobody
			// will resume is let go now rather than at the window's end.
			if resume != nil {
				c.AbortStream(ctx(), p.Upload)
			}
			p.Upload = ""
			if err := p.save(s); err != nil {
				return 0, err
			}
			continue
		}
		// Anything else — the link dropped, the relay refused the attempt,
		// the one resume stopped short — is tried again from zero on the
		// same upload, and the relay's answer to that says what it holds.
		offset = 0
	}
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
