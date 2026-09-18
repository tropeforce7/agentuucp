package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
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

// Two attachment names that differ only in case are one file on a disk
// that folds case, which macOS does by default and Windows always: the
// second O_EXCL open failed with an error the receiver did not know, so the
// stream was neither delivered nor refused, and every fetch of that mailbox
// stopped at it. Now Validate refuses the pair, on the sender's side before
// anything leaves and on the receiver's when the manifest is opened; a
// Linux sender with Makefile and makefile is told at send.
func TestNamesThatAreOneFileWhereCaseDoesNotCountAreRefused(t *testing.T) {
	from, to := pair(t)
	for _, pairOfNames := range [][2]string{{"Report.txt", "report.txt"}, {"Makefile", "makefile"}, {"K.txt", "k.txt"}} {
		_, err := BuildManifest(from, to.Public(), "0123456789abcdef0123456789abcdef",
			Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Text: "x"},
			sourcesOf(memSource{pairOfNames[0], []byte("upper")}, memSource{pairOfNames[1], []byte("lower")}), MinChunkSize)
		if !errors.Is(err, ErrForm) {
			t.Errorf("%q beside %q: %v, want ErrForm", pairOfNames[0], pairOfNames[1], err)
		} else if !strings.Contains(err.Error(), "are one file where case does not count") {
			t.Errorf("%q beside %q: %v, want the sentence naming the rule", pairOfNames[0], pairOfNames[1], err)
		}
	}
	// Names that differ in more than case are still two files.
	if _, err := BuildManifest(from, to.Public(), "0123456789abcdef0123456789abcdef",
		Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Text: "x"},
		sourcesOf(memSource{"Report.txt", []byte("a")}, memSource{"report.md", []byte("b")}), MinChunkSize); err != nil {
		t.Errorf("two names that are two files were refused: %v", err)
	}
}

// What a filesystem folds beyond case, Validate cannot foresee, so the
// open is where it is caught: an O_EXCL open that finds the file already
// there is the manifest's fault, refused as ErrForm, which the receiver
// keeps under damaged and acknowledges rather than meeting again at every
// fetch. The manifest here passed Validate with two names and is changed
// under the opened stream to two the disk spells as one, which is what a
// pair Validate cannot tell apart looks like at this point; the test skips
// itself where the disk keeps Probe and probe apart, so that a pass on
// Linux is a skip and not a false proof.
func TestNamesTheDiskSpellsAsOneAreRefusedAtTheOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Probe"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "probe")); err != nil {
		t.Skip("this filesystem tells Probe from probe; the collision this test is about cannot happen here")
	}

	from, to := pair(t)
	blob, _ := build(t, from, to, DefaultChunkSize, map[string][]byte{
		"Report.txt": []byte("upper"),
		"z.txt":      []byte("lower"),
	})
	n, err := ManifestLength(blob[:HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenManifest(to, blob[:HeaderSize], blob[HeaderSize:HeaderSize+n])
	if err != nil {
		t.Fatal(err)
	}
	// Past Validate: the second name is now the first with its case
	// changed, which the digests, being over the bytes, do not notice.
	o.Manifest.Attachments[1].Name = "report.txt"
	err = o.ToDirectory(bytes.NewReader(blob[HeaderSize+n:]), filepath.Join(dir, "out"))
	if !errors.Is(err, ErrForm) {
		t.Fatalf("ToDirectory: %v; expected the stream refused as malformed (ErrForm) so that the receiver drops it and moves on", err)
	}
	if !strings.Contains(err.Error(), `attachment "report.txt" is one file with another on this disk`) {
		t.Errorf("the refusal does not name the attachment: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out")); statErr == nil {
		t.Error("the output directory was made for a refused stream")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.part")); statErr == nil {
		t.Error("the temporary directory was left behind")
	}
}
