package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
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
// recipientCount is how many recipients the message this stream is a copy
// of went to; 0 or 1 is a stream to one.
func (c *Client) OpenStream(ctx context.Context, toFP, channel string, size int64, recipientCount int) (*relayapi.OpenStreamResponse, error) {
	// A copy of a message to several says how many it went to, for the
	// relay to hold to its max_recipients; a stream to one says nothing,
	// and its request is the bytes it always was.
	count, err := recipients.CountSection(recipientCount)
	if err != nil {
		return nil, err
	}
	var out relayapi.OpenStreamResponse
	err = c.do(ctx, "POST", "/v1/mailbox/"+toFP+"/streams",
		relayapi.OpenStreamRequest{Sections: relayapi.Sections{Sections: count}, Size: size, Channel: channel}, &out, nil)
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
		if err := wire.Decode(payload, &out); err != nil {
			return 0, c.malformed("the placed stream", "body", "JSON")
		}
		if err := c.checkSections("PUT", "/v1/uploads/"+upload, &out); err != nil {
			return 0, err
		}
		if err := c.checkID("the placed stream", out.ID); err != nil {
			return 0, err
		}
		return out.ID, nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return 0, c.redirected("PUT", "/v1/uploads/"+upload, resp.StatusCode)
	}
	httpErr := httpError(resp, payload)
	httpErr.Relay = c.base
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
	for attempt := 0; attempt < maxRetries; attempt++ {
		refusal := &HTTPError{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header)}
		if !retryable(refusal) {
			break
		}
		wait := retryWait(refusal)
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
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			return nil, 0, c.redirected("GET", path, resp.StatusCode)
		}
		he := httpError(resp, payload)
		he.Relay = c.base
		return nil, 0, he
	}
	// A range asked for is answered as that range or not at all. A relay,
	// or a proxy or a cache between, that ignores Range answers 200 with
	// the whole blob, which read as the range would not open: a stream
	// damaged for good and acknowledged away. So the answer is held to the
	// span asked for, and anything else is a malformed answer, a transport
	// failure, and the stream waits on the relay for the next fetch. What
	// is read of it is the span and no more, whatever length the answer
	// gave or left out.
	body := resp.Body
	length := resp.ContentLength
	if from > 0 || to >= 0 {
		span, err := c.checkRange(resp, from, to)
		if err != nil {
			resp.Body.Close()
			watch.stop()
			return nil, 0, err
		}
		body = struct {
			io.Reader
			io.Closer
		}{io.LimitReader(resp.Body, span), resp.Body}
		length = span
	}
	return &stallBody{ReadCloser: body, watch: watch}, length, nil
}

// checkRange holds an answer to a range request to the span asked for: a
// 206 whose Content-Range is bytes from-end/size, end being to, or the
// file's last byte where the file ends sooner or where no end was asked
// for, and whose length, when the answer gives one, is the span's; it
// says the span's length, which is all that is read of the body. The
// three numbers come from the wire and are held to their shape before
// any is compared.
func (c *Client) checkRange(resp *http.Response, from, to int64) (int64, error) {
	asked := fmt.Sprintf("bytes %d-", from)
	if to >= 0 {
		asked += strconv.FormatInt(to, 10)
	}
	want := func(what string) error {
		return c.malformed("the answer to a range request ("+asked+")", what,
			"the range asked for; a relay, or a proxy between, that does not honour a range is a "+
				"transport failure, and the stream waits on the relay for the next fetch")
	}
	if resp.StatusCode != http.StatusPartialContent {
		return 0, want(fmt.Sprintf("the status %d", resp.StatusCode))
	}
	start, end, size, ok := parseContentRange(resp.Header.Get("Content-Range"))
	if !ok {
		return 0, want("the Content-Range header")
	}
	last := size - 1
	if to >= 0 && to < last {
		last = to
	}
	if start != from || end != last {
		return 0, want(fmt.Sprintf("the span %d-%d of %d", start, end, size))
	}
	span := end - start + 1
	if resp.ContentLength >= 0 && resp.ContentLength != span {
		return 0, want(fmt.Sprintf("the length %d for a span of %d", resp.ContentLength, span))
	}
	return span, nil
}

// parseContentRange reads "bytes start-end/size", the one form a 206 for a
// single range carries, each number a decimal at or above zero, end at or
// above start and size above end. Anything else, an unknown size, a list,
// a sign, is not it.
func parseContentRange(v string) (start, end, size int64, ok bool) {
	rest, found := strings.CutPrefix(v, "bytes ")
	if !found {
		return 0, 0, 0, false
	}
	span, total, found := strings.Cut(rest, "/")
	if !found {
		return 0, 0, 0, false
	}
	a, b, found := strings.Cut(span, "-")
	if !found {
		return 0, 0, 0, false
	}
	// A leading digit is what keeps a sign out, and with it any number
	// below zero: ParseInt would take "+1" and "-1".
	parse := func(s string) (int64, bool) {
		if s == "" || s[0] < '0' || s[0] > '9' {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	}
	var okA, okB, okS bool
	start, okA = parse(a)
	end, okB = parse(b)
	size, okS = parse(total)
	if !okA || !okB || !okS || end < start || size <= end {
		return 0, 0, 0, false
	}
	return start, end, size, true
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
// ResponseHeaderTimeout bounds, and the relay's own deadline ends a
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
