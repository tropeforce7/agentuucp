package stream

import (
	"bytes"
	"encoding/hex"
	"io"
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
		Body{Type: "ask", Thread: "t1", Subject: "s", Text: "hello"}, sources, MinChunkSize)
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
