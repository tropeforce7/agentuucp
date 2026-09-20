package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The stream half of the relay API.
//
// These requests carry a payload rather than a JSON body, so they are signed
// over an empty body and the bytes travel underneath. The relay never opens
// them; what it enforces is who may append, how far they have got, and how
// much they said they would send.

// OpenStream reserves room on the relay for a stream of the given size, for
// a channel of the recipient's, and returns the upload to append to. An
// empty channel means default and puts nothing on the wire; the relay
// checks the name at open, as it checks an envelope's at post.
func (c *Client) OpenStream(ctx context.Context, toFP, channel string, size int64) (*relayapi.OpenStreamResponse, error) {
	var out relayapi.OpenStreamResponse
	err := c.do(ctx, "POST", "/v1/mailbox/"+toFP+"/streams",
		relayapi.OpenStreamRequest{Size: size, Channel: channel}, &out, nil)
	if err != nil {
		return nil, err
	}
	if err := c.checkOpenStream(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// streamAnswerHold is the most of a stream route's answer the client
// holds: the placed stream's id, or an error's sentence, neither of which
// a relay of ours writes at a hundredth of this. An answer over it is
// refused by name, as doWithin refuses one over its route's hold, rather
// than read short and failed as JSON.
const streamAnswerHold = 1 << 16

// PutStream is one attempt at an upload: the sealed stream from offset to
// the end, streamed from body with its length declared, in one request.
// It answers the message's id when the attempt reached the end. When it
// did not, the error carries what the relay said: a 409 whose Upload-Offset
// is where the relay's copy ends, from which a sender resumes once within
// the window when the relay kept the partial, and everything else means
// nothing is kept and the sender opens anew.
//
// body is read straight onto the wire: nothing is buffered, so a
// gigabyte costs a gigabyte of reading and not of memory. The signature
// covers an empty body, since the payload cannot be held to be signed.
func (c *Client) PutStream(ctx context.Context, upload string, offset int64, body io.Reader, length int64) (int64, error) {
	// The stall rule: the transport reads the body as it writes the wire,
	// so a relay that stops taking bytes is a body nobody reads; when no
	// byte is read for the window the request's context is cancelled and
	// the attempt ends as a cut, which the sender's loop treats as one.
	watch := c.watchStall(ctx, "the relay stopped taking the upload: no byte was read for")
	defer watch.stop()
	req, err := c.signedRequest(watch.ctx, "PUT", "/v1/uploads/"+upload, nil)
	if err != nil {
		return 0, err
	}
	req.Body = io.NopCloser(&stallReader{r: body, watch: watch})
	req.ContentLength = length
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(relayapi.UploadOffsetHeader, strconv.FormatInt(offset, 10))

	resp, err := c.stream.Do(req)
	if err != nil {
		return 0, watch.wrap(fmt.Errorf("contacting relay: %w", err))
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, streamAnswerHold+1))
	if int64(len(payload)) > streamAnswerHold {
		return 0, c.malformed("the answer", "the body", fmt.Sprintf("under %d bytes, the most this route holds", streamAnswerHold))
	}

	if resp.StatusCode == http.StatusCreated {
		var out relayapi.PutStreamResponse
		if err := json.Unmarshal(payload, &out); err != nil {
			return 0, c.malformed("the placed stream", "body", "JSON")
		}
		if err := c.checkID("the placed stream", out.ID); err != nil {
			return 0, err
		}
		return out.ID, nil
	}
	httpErr := httpError(resp, payload)
	// A conflict carries the truth about where the upload actually is, which
	// is what makes it resumable rather than fatal.
	if resp.StatusCode == http.StatusConflict {
		if at, convErr := c.parseOffset(resp.Header.Get(relayapi.UploadOffsetHeader)); convErr == nil {
			return 0, &ResumeError{At: at, HTTPError: httpErr}
		}
	}
	return 0, httpErr
}

// ResumeError is a 409 from an attempt: the relay's copy ends at At, and an
// attempt from there is what it will take.
type ResumeError struct {
	At int64
	*HTTPError
}

func (e *ResumeError) Unwrap() error { return e.HTTPError }

// AbortStream throws an unfinished upload away.
func (c *Client) AbortStream(ctx context.Context, upload string) error {
	err := c.do(ctx, "DELETE", "/v1/uploads/"+upload, nil, nil, nil)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && (httpErr.Status == http.StatusNotFound || httpErr.Status == http.StatusGone) {
		return nil // already gone, or expired and gone with the answer, is the state we wanted
	}
	return err
}

// Blob fetches part of a stored stream. from and to are a byte range; a
// negative to means "to the end".
//
// The reader must be closed by the caller. Nothing is buffered here: a
// gigabyte arrives as a gigabyte of reading, not of memory.
func (c *Client) Blob(ctx context.Context, fp string, id int64, from, to int64) (io.ReadCloser, int64, error) {
	path := "/v1/mailbox/" + fp + "/" + strconv.FormatInt(id, 10) + "/blob"
	// The stall rule on the response: the body handed back reads under
	// the watch, and no byte arriving for the window cancels the request
	// so the next Read ends as a cut, which the resuming reader reopens
	// from where it stood. Closing the body ends the watch.
	watch := c.watchStall(ctx, "the relay stopped sending the stream: no byte arrived for")
	req, err := c.signedRequest(watch.ctx, "GET", path, nil)
	if err != nil {
		watch.stop()
		return nil, 0, err
	}
	if from > 0 || to >= 0 {
		spec := strconv.FormatInt(from, 10) + "-"
		if to >= 0 {
			spec += strconv.FormatInt(to, 10)
		}
		req.Header.Set("Range", "bytes="+spec)
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		watch.stop()
		return nil, 0, watch.wrap(fmt.Errorf("contacting relay: %w", err))
	}
	// A refusal for now is worth waiting out, exactly as on any other route.
	for attempt := 0; attempt < maxRetries && retryable(resp.StatusCode); attempt++ {
		wait := retryWait(&HTTPError{RetryAfter: retryAfter(resp.Header)})
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err := c.sleep(ctx, wait); err != nil {
			break
		}
		retry, buildErr := c.signedRequest(watch.ctx, "GET", path, nil)
		if buildErr != nil {
			watch.stop()
			return nil, 0, buildErr
		}
		retry.Header = req.Header.Clone()
		if err := relayapi.SignRequest(c.id, retry, nil); err != nil {
			watch.stop()
			return nil, 0, err
		}
		watch.reset()
		if resp, err = c.stream.Do(retry); err != nil {
			watch.stop()
			return nil, 0, watch.wrap(fmt.Errorf("contacting relay: %w", err))
		}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		defer resp.Body.Close()
		defer watch.stop()
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, streamAnswerHold+1))
		if int64(len(payload)) > streamAnswerHold {
			return nil, 0, c.malformed("the answer", "the body", fmt.Sprintf("under %d bytes, the most this route holds", streamAnswerHold))
		}
		return nil, 0, httpError(resp, payload)
	}
	return &stallBody{ReadCloser: resp.Body, watch: watch}, resp.ContentLength, nil
}

// stallWatch is the stream rule's clock for one request: a timer of the
// window, moved on by every delivering read, that cancels the request's
// context when it runs out, and the sentence the cut is then given.
type stallWatch struct {
	ctx     context.Context
	cancel  context.CancelFunc
	timer   *time.Timer
	window  time.Duration
	prefix  string
	stalled atomic.Bool
}

// watchStall starts a watch over ctx: the timer runs from here.
func (c *Client) watchStall(ctx context.Context, prefix string) *stallWatch {
	w := &stallWatch{window: c.stall, prefix: prefix}
	w.ctx, w.cancel = context.WithCancel(ctx)
	w.timer = time.AfterFunc(w.window, func() {
		w.stalled.Store(true)
		w.cancel()
	})
	return w
}

// reset moves the window on: a byte was delivered.
func (w *stallWatch) reset() { w.timer.Reset(w.window) }

// stop ends the watch; the request's context is released with it.
func (w *stallWatch) stop() {
	w.timer.Stop()
	w.cancel()
}

// wrap turns an error that ended a stalled request into the stall's own
// sentence, the window in whole seconds, wrapped as the transport failure
// it is; any other error is returned as it came.
func (w *stallWatch) wrap(err error) error {
	if err == nil || !w.stalled.Load() {
		return err
	}
	return fmt.Errorf("%s %d seconds: %w", w.prefix, int64(w.window/time.Second), err)
}

// stallReader is a request body under the watch: every delivering read
// moves the window on, and the end of the body ends the watch — from
// there the transport is waiting for the relay's answer, which its
// ResponseHeaderTimeout bounds, and the relay's own stall deadline ends a
// relay that took the body and says nothing. The watch sees the relay
// through the transport's reads of the body: the transport reads as it
// writes the wire, so a relay that stops taking bytes fills the socket's
// buffers, the writes block, and the reads stop.
type stallReader struct {
	r     io.Reader
	watch *stallWatch
}

func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.watch.reset()
	}
	if errors.Is(err, io.EOF) {
		s.watch.timer.Stop()
	}
	return n, err
}

// stallBody is a response body under the watch: every delivering read
// moves the window on, a read that ends by the watch is given the stall's
// sentence, and Close ends the watch.
type stallBody struct {
	io.ReadCloser
	watch *stallWatch
}

func (s *stallBody) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	if n > 0 {
		s.watch.reset()
	}
	return n, s.watch.wrap(err)
}

func (s *stallBody) Close() error {
	s.watch.stop()
	return s.ReadCloser.Close()
}

// signedRequest builds a request signed over the given body bytes. The stream
// routes sign an empty body because the payload is too large to hash twice;
// what authenticates them is the same identity and the same replay nonce.
func (c *Client) signedRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	if c.id != nil {
		if err := relayapi.SignRequest(c.id, req, body); err != nil {
			return nil, err
		}
	}
	return req, nil
}
