package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The third adversarial trace, at v0.17.0: an answer to a range request
// that is not the range. A relay, or a proxy or a cache between it and the
// client, may ignore Range and answer 200 with the whole blob, which HTTP
// allows; read as the range, it made a stream's manifest fail to open and
// the stream be kept as damaged and acknowledged away. Its tests are here
// as the regression tests, each renamed for what it proves.

// rangeClient is a client of the server given, under a fresh identity.
func rangeClient(t *testing.T, url string) (*Client, *identity.Identity) {
	t.Helper()
	id, err := identity.Generate("tester")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(url, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, id
}

// The trace's scenario: bytes 10-19 of a 100-byte blob asked for, and a
// server that ignores Range and answers 200 with the whole of it. Blob
// refuses the answer as malformed, naming the relay and the range, and
// hands back no body, so nothing reads the wrong bytes as the range; the
// error is ErrMalformedAnswer, which a fetch treats as a transport failure
// and not as a stream nobody can read. The same request answered with the
// 206 it asked for is taken, and reads bytes 10-19.
func TestABlobAnswerThatIgnoresTheRangeIsATransportFailure(t *testing.T) {
	file := make([]byte, 100) // byte i is 'A'+i%26, so bytes 10-19 differ from 0-9
	for i := range file {
		file[i] = 'A' + byte(i%26)
	}
	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ranges = append(ranges, r.Header.Get("Range"))
		// Range ignored, as RFC 9110 permits a server to do.
		w.WriteHeader(http.StatusOK)
		w.Write(file)
	}))
	defer srv.Close()
	c, id := rangeClient(t, srv.URL)
	body, n, err := c.Blob(t.Context(), id.Fingerprint(), 1, 10, 19)
	if body != nil {
		body.Close()
	}
	if !errors.Is(err, ErrMalformedAnswer) {
		t.Fatalf("a 200 to a range request: body=%v n=%d err=%v; want ErrMalformedAnswer", body != nil, n, err)
	}
	if body != nil || n != 0 {
		t.Errorf("a refused answer still handed back a body (%v) of %d bytes", body != nil, n)
	}
	for _, want := range []string{srv.URL, "range", "bytes 10-19", "the status 200", "transport failure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
	if len(ranges) != 1 || ranges[0] != "bytes=10-19" {
		t.Errorf("the requests sent Range %q; want one, bytes=10-19", ranges)
	}

	honest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=10-19" {
			t.Errorf("Range %q, want bytes=10-19", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Range", "bytes 10-19/100")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(file[10:20])
	}))
	defer honest.Close()
	c, id = rangeClient(t, honest.URL)
	body, n, err = c.Blob(t.Context(), id.Fingerprint(), 1, 10, 19)
	if err != nil {
		t.Fatalf("a 206 of the range asked for: %v", err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 || !bytes.Equal(got, file[10:20]) {
		t.Errorf("a 206 of bytes 10-19 read as %d bytes %q; want 10, %q", n, got, file[10:20])
	}
}
