package client

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The second review's F3, kept: Blob against hostile 206 answers, sixteen
// shapes. Every answer that is not exactly the span asked for must be
// refused, or, when accepted, yield exactly the span's bytes, never more; a
// short body must not end in a clean EOF before the span unless a caller
// catches it, which TestAShortChunkedRangeIsATransportFailure in
// internal/auu holds end to end.
func TestBlobRangeEdges(t *testing.T) {
	file := make([]byte, 100)
	for i := range file {
		file[i] = 'A' + byte(i%26)
	}
	type answer struct {
		name    string
		from    int64
		to      int64
		status  int
		cr      string
		body    []byte
		chunked bool
		accept  bool // true: Blob may accept, and must then yield exactly the span
	}
	cases := []answer{
		{"size star", 10, 19, 206, "bytes 10-19/*", file[10:20], false, false},
		{"end past size", 10, 19, 206, "bytes 10-19/15", file[10:20], false, false},
		{"two ranges", 10, 19, 206, "bytes 10-19/100, 20-29/100", file[10:20], false, false},
		{"leading zeros", 10, 19, 206, "bytes 010-019/100", file[10:20], false, true},
		{"plus sign", 10, 19, 206, "bytes +10-19/100", file[10:20], false, false},
		{"spaces", 10, 19, 206, "bytes 10 - 19/100", file[10:20], false, false},
		{"uppercase unit", 10, 19, 206, "Bytes 10-19/100", file[10:20], false, false},
		{"start shifted", 10, 19, 206, "bytes 0-9/100", file[0:10], false, false},
		{"longer body, chunked", 10, 19, 206, "bytes 10-19/100", file[10:40], true, true},
		{"shorter body, chunked", 10, 19, 206, "bytes 10-19/100", file[10:15], true, true},
		{"open end, right", 10, -1, 206, "bytes 10-99/100", file[10:], false, true},
		{"open end, shorter size", 10, -1, 206, "bytes 10-49/50", file[10:50], false, true},
		{"200 open end", 10, -1, 200, "", file, false, false},
		{"206 no header", 10, 19, 206, "", file[10:20], false, false},
		{"huge size", 10, 19, 206, "bytes 10-19/9223372036854775807", file[10:20], false, true},
		{"overflow size", 10, 19, 206, "bytes 10-19/9223372036854775808", file[10:20], false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.cr != "" {
					w.Header().Set("Content-Range", tc.cr)
				}
				if !tc.chunked {
					w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)))
				}
				w.WriteHeader(tc.status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				w.Write(tc.body)
			}))
			defer srv.Close()
			id, _ := identity.Generate("tester")
			c, err := New(srv.URL, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, n, err := c.Blob(t.Context(), id.Fingerprint(), 1, tc.from, tc.to)
			if err != nil {
				if !errors.Is(err, ErrMalformedAnswer) {
					t.Errorf("refused, but not as a malformed answer: %v", err)
				}
				if tc.accept && !strings.Contains(tc.name, "chunked") {
					t.Logf("refused (stricter than needed): %v", err)
				}
				return
			}
			defer body.Close()
			if !tc.accept {
				t.Fatalf("Blob accepted %q (status %d) for %d-%d", tc.cr, tc.status, tc.from, tc.to)
			}
			got, rerr := io.ReadAll(body)
			t.Logf("accepted: n=%d, read %d bytes, err=%v", n, len(got), rerr)
			if int64(len(got)) > n {
				t.Errorf("read %d bytes past the span of %d", len(got), n)
			}
			if int64(len(got)) < n && rerr == nil {
				// Blob does not promise to detect a short body; its callers
				// do (streamrecv.go readBlobRange's ReadFull and
				// resumingReader's until), which TestAShortChunkedRangeIsATransportFailure
				// holds end to end.
				t.Logf("body ended at %d of a %d-byte span with a clean EOF; left to the caller", len(got), n)
			}
		})
	}
}
