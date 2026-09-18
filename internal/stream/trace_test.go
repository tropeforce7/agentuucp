package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The adversarial trace of v0.8.1 (reviews/trace/): its stream-format
// tests are here as the regression tests, renamed for what they prove and
// adjusted only as far as their fixes needed.

type memSource struct {
	name string
	data []byte
}

func sourcesOf(files ...memSource) []Source {
	var out []Source
	for _, f := range files {
		data := f.data
		out = append(out, Source{
			Name: f.name, Media: "application/octet-stream", Size: int64(len(data)),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
		})
	}
	return out
}

// sealAndOpen seals a stream and opens it again, returning what arrived.
func sealAndOpen(t *testing.T, files ...memSource) (map[string][]byte, error) {
	t.Helper()
	from, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	to, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	sources := sourcesOf(files...)
	m, err := BuildManifest(from, to.Public(), hex.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: "s", Text: "hello"}, sources, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := Seal(&blob, from, to.Public(), m, sources); err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw := blob.Bytes()
	header := raw[:HeaderSize]
	n, err := ManifestLength(header)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenManifest(to, header, raw[HeaderSize:HeaderSize+n])
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	got := map[string][]byte{}
	err = opened.OpenPayload(bytes.NewReader(raw[HeaderSize+n:]), func(a Attachment) (io.WriteCloser, error) {
		buf := &bytes.Buffer{}
		got[a.Name] = nil
		return &closer{buf, func() { got[a.Name] = buf.Bytes() }}, nil
	})
	return got, err
}

type closer struct {
	*bytes.Buffer
	done func()
}

func (c *closer) Close() error { c.done(); return nil }

// TestAnEmptyAttachmentArrivesWhereverItStands: an attachment of zero
// bytes is one the sender's command accepts and the sealer writes, and the
// opener could not receive when nothing followed it: it opened a writer
// only when plaintext arrived for it, so an empty attachment at the end of
// a stream, or alone in one, was never written and the stream was refused
// as truncated, which the receiver took as permanent, keeping the manifest
// and acknowledging the message away — silent loss of a sent message. Now
// every empty attachment still unwritten when the final chunk has opened
// is made empty; one with bytes still unwritten is truncated as before.
func TestAnEmptyAttachmentArrivesWhereverItStands(t *testing.T) {
	for _, tc := range []struct {
		what  string
		files []memSource
	}{
		{"alone", []memSource{{"empty", nil}}},
		{"last", []memSource{{"a.txt", []byte("some bytes")}, {"empty", nil}}},
		{"first", []memSource{{"empty", nil}, {"a.txt", []byte("some bytes")}}},
		{"in the middle", []memSource{{"a.txt", []byte("some bytes")}, {"empty", nil}, {"b.txt", []byte("more")}}},
		{"two at the end", []memSource{{"a.txt", []byte("some bytes")}, {"e1", nil}, {"e2", nil}}},
		{"only empties", []memSource{{"e1", nil}, {"e2", nil}, {"e3", nil}}},
		{"no attachments", nil},
	} {
		got, err := sealAndOpen(t, tc.files...)
		if err != nil {
			t.Errorf("%s: a stream with an empty attachment did not open: %v", tc.what, err)
			continue
		}
		for _, f := range tc.files {
			if data, ok := got[f.name]; !ok || !bytes.Equal(data, f.data) {
				t.Errorf("%s: attachment %q arrived as %q, want %q", tc.what, f.name, data, f.data)
			}
		}
	}
}

// TestValidateRefusesSizesThatWrap: Validate summed the attachment sizes
// and counted the chunks in int64 with no guard, so sizes that wrapped
// past MaxInt64 passed — three attachments summing to zero beside
// payload_bytes 0, or payload_bytes MaxInt64 for which ChunkCount wrapped
// to two chunks — and were refused only later, as truncated, after the
// receiver had asked the relay for the payload. A manifest whose declared
// sizes cannot agree with any chunks is malformed where it is read: now
// payload_bytes and the attachments' running total are bounded at
// MaxPayloadBytes, 2^62, before anything is added, and the chunk count and
// the size on the wire cannot wrap for what Validate accepts.
func TestValidateRefusesSizesThatWrap(t *testing.T) {
	from, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	to, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(sha256.New().Sum(nil))
	base := func() *Manifest {
		m, err := BuildManifest(from, to.Public(), hex.EncodeToString(bytes.Repeat([]byte{2}, 16)),
			Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: "s", Text: "hello"},
			sourcesOf(memSource{"a", []byte("x")}), MinChunkSize)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	wrapped := base()
	wrapped.Attachments = []Attachment{
		{Name: "a", Media: "x", Size: math.MaxInt64, SHA256: digest},
		{Name: "b", Media: "x", Size: math.MaxInt64, SHA256: digest},
		{Name: "c", Media: "x", Size: 2, SHA256: digest},
	}
	wrapped.PayloadBytes = 0
	wrapped.Chunks = ChunkCount(0, wrapped.ChunkSize)
	if err := wrapped.Validate(); !errors.Is(err, ErrForm) {
		t.Errorf("attachments of %d, %d and 2 bytes beside payload_bytes 0: %v, want ErrForm", int64(math.MaxInt64), int64(math.MaxInt64), err)
	}

	huge := base()
	huge.Attachments = []Attachment{{Name: "a", Media: "x", Size: math.MaxInt64, SHA256: digest}}
	huge.PayloadBytes = math.MaxInt64
	huge.Chunks = ChunkCount(math.MaxInt64, huge.ChunkSize)
	if err := huge.Validate(); !errors.Is(err, ErrForm) {
		t.Errorf("payload_bytes %d at chunk_size %d: %v, want ErrForm (ChunkCount had wrapped to %d chunks)",
			int64(math.MaxInt64), huge.ChunkSize, err, huge.Chunks)
	}
	// At the bound and one over: the largest payload the format carries is
	// accepted, and its chunk count and size on the wire are positive.
	edge := base()
	edge.Attachments = []Attachment{{Name: "a", Media: "x", Size: MaxPayloadBytes, SHA256: digest}}
	edge.PayloadBytes = MaxPayloadBytes
	edge.Chunks = ChunkCount(MaxPayloadBytes, edge.ChunkSize)
	if err := edge.Validate(); err != nil {
		t.Errorf("payload_bytes at the bound: %v, want accepted", err)
	}
	if edge.Chunks <= 0 || Size(MaxChunk0, MaxPayloadBytes, edge.ChunkSize) <= 0 {
		t.Errorf("at the bound the chunk count is %d and the size on the wire %d; neither may wrap",
			edge.Chunks, Size(MaxChunk0, MaxPayloadBytes, edge.ChunkSize))
	}
	over := base()
	over.Attachments = []Attachment{{Name: "a", Media: "x", Size: MaxPayloadBytes + 1, SHA256: digest}}
	over.PayloadBytes = MaxPayloadBytes + 1
	over.Chunks = ChunkCount(MaxPayloadBytes+1, over.ChunkSize)
	if err := over.Validate(); !errors.Is(err, ErrForm) {
		t.Errorf("payload_bytes one over the bound: %v, want ErrForm", err)
	}
	// Two attachments that together pass the bound though each is under
	// it, beside a payload_bytes that agrees with the wrapped total.
	pair := base()
	pair.Attachments = []Attachment{
		{Name: "a", Media: "x", Size: MaxPayloadBytes, SHA256: digest},
		{Name: "b", Media: "x", Size: MaxPayloadBytes, SHA256: digest},
	}
	pair.PayloadBytes = MaxPayloadBytes
	pair.Chunks = ChunkCount(MaxPayloadBytes, pair.ChunkSize)
	if err := pair.Validate(); !errors.Is(err, ErrForm) {
		t.Errorf("two attachments of the bound each: %v, want ErrForm", err)
	}
}

// A manifest's body is never opened as an envelope's is, so the message
// rules are applied to it here: a known type, a thread and an in_reply_to
// that are message ids, a subject under the limit. Without this the stream
// path was a second door for a thread id that is a path: an envelope with
// `--thread "../../outside"` was refused at Validate while the same message
// with a large attachment was sealed, sent and handed to an expert host.
func TestValidateHoldsTheManifestBodyToTheMessageRules(t *testing.T) {
	from, to := pair(t)
	build := func(body Body) error {
		_, err := BuildManifest(from, to.Public(), "0123456789abcdef0123456789abcdef", body,
			sourcesOf(memSource{"a", []byte("x")}), MinChunkSize)
		return err
	}
	good := Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: "s", Text: "hello"}
	if err := build(good); err != nil {
		t.Fatalf("a manifest whose body meets the rules was refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		body Body
	}{
		{"a thread id that is a path", Body{Type: "ask", Thread: "../../outside", Text: "hello"}},
		{"a short thread id", Body{Type: "ask", Thread: "t1", Text: "hello"}},
		{"an empty thread", Body{Type: "ask", Text: "hello"}},
		{"an in_reply_to that is a path", Body{Type: "reply", Thread: good.Thread, InReplyTo: "../x", Text: "hello"}},
		{"a type nobody knows", Body{Type: "exec", Thread: good.Thread, Text: "hello"}},
		{"a subject over the limit", Body{Type: "ask", Thread: good.Thread, Subject: strings.Repeat("s", 4097), Text: "hello"}},
	} {
		if err := build(tc.body); !errors.Is(err, ErrForm) {
			t.Errorf("%s: %v, want ErrForm", tc.name, err)
		}
	}
}
