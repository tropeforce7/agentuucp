package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

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
	req, err := c.signedRequest(ctx, "PUT", "/v1/uploads/"+upload, nil)
	if err != nil {
		return 0, err
	}
	req.Body = io.NopCloser(body)
	req.ContentLength = length
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(relayapi.UploadOffsetHeader, strconv.FormatInt(offset, 10))

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("contacting relay: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

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
	req, err := c.signedRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, 0, err
	}
	if from > 0 || to >= 0 {
		spec := strconv.FormatInt(from, 10) + "-"
		if to >= 0 {
			spec += strconv.FormatInt(to, 10)
		}
		req.Header.Set("Range", "bytes="+spec)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("contacting relay: %w", err)
	}
	// A refusal for now is worth waiting out, exactly as on any other route.
	for attempt := 0; attempt < maxRetries && retryable(resp.StatusCode); attempt++ {
		wait := retryWait(&HTTPError{RetryAfter: retryAfter(resp.Header)})
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err := c.sleep(ctx, wait); err != nil {
			break
		}
		retry, buildErr := c.signedRequest(ctx, "GET", path, nil)
		if buildErr != nil {
			return nil, 0, buildErr
		}
		retry.Header = req.Header.Clone()
		if err := relayapi.SignRequest(c.id, retry, nil); err != nil {
			return nil, 0, err
		}
		if resp, err = c.http.Do(retry); err != nil {
			return nil, 0, fmt.Errorf("contacting relay: %w", err)
		}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		defer resp.Body.Close()
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, 0, httpError(resp, payload)
	}
	return resp.Body, resp.ContentLength, nil
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
