package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

func TestAListingCannotExceedTheRequestedRowLimit(t *testing.T) {
	for _, limit := range []int{1, relayapi.MaxListLimit} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("limit_%d_extra_%d", limit, extra), func(t *testing.T) {
				first, last := int64(1), int64(limit+extra)
				page := relayapi.ListResponse{Queued: last, First: &first, Last: &last,
					Allow: relayapi.AllowNone, Card: relayapi.CardNone, Directory: relayapi.DirectoryNone}
				for i := 1; i <= limit+extra; i++ {
					page.Messages = append(page.Messages, relayapi.StoredMessage{ID: int64(i),
						Received: time.Now().UTC(), Size: 10, Kind: relayapi.KindStream, Channel: "default"})
				}
				rec := &recorder{replies: []reply{{status: http.StatusOK, body: page}}}
				c, _ := newTestClient(t, rec)
				got, err := c.List(t.Context(), 0, limit)
				if extra == 0 {
					if err != nil || len(got.Messages) != limit {
						t.Fatalf("honest boundary: rows=%d err=%v", len(got.Messages), err)
					}
					return
				}
				if !errors.Is(err, ErrMalformedAnswer) || len(got.Messages) != 0 {
					t.Fatalf("requested %d rows, accepted %d err=%v; want malformed answer with no rows", limit, len(got.Messages), err)
				}
			})
		}
	}
}

type reviewRoundTrip func(*http.Request) (*http.Response, error)

func (f reviewRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type reviewCountBody struct {
	io.Reader
	read int
}

func (b *reviewCountBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *reviewCountBody) Close() error { return nil }

func TestABlobRetryRefusesAnErrorBodyOverItsHold(t *testing.T) {
	for _, size := range []int{32, streamAnswerHold + 1, 16 * streamAnswerHold} {
		t.Run(fmt.Sprintf("body_%d", size), func(t *testing.T) {
			c, id := rangeClient(t, "http://relay.invalid")
			c.sleep = func(context.Context, time.Duration) error { return nil }
			body := &reviewCountBody{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), size))}
			calls := 0
			c.stream.Transport = reviewRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					h := make(http.Header)
					h.Set("Retry-After", "1")
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: h,
						Body: body, ContentLength: int64(size), Request: r}, nil
				}
				h := make(http.Header)
				h.Set("Content-Range", "bytes 0-0/1")
				return &http.Response{StatusCode: http.StatusPartialContent, Header: h,
					Body: io.NopCloser(bytes.NewReader([]byte("z"))), ContentLength: 1, Request: r}, nil
			})
			got, _, err := c.Blob(t.Context(), id.Fingerprint(), 1, 0, 0)
			if got != nil {
				defer got.Close()
			}
			if size <= streamAnswerHold {
				if err != nil || calls != 2 || got == nil {
					t.Fatalf("ordinary retry: calls=%d err=%v body=%v", calls, err, got != nil)
				}
				return
			}
			if !errors.Is(err, ErrMalformedAnswer) || got != nil || calls != 1 || body.read > streamAnswerHold+1 {
				t.Fatalf("oversized refusal read %d bytes, calls=%d err=%v body=%v; want bounded refusal before retry", body.read, calls, err, got != nil)
			}
		})
	}
}
