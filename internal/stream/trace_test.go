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
	"time"

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
	buildWith := func(body Body) error {
		_, err := BuildManifest(from, to.Public(), "0123456789abcdef0123456789abcdef", body,
			sourcesOf(memSource{"a", []byte("x")}), MinChunkSize)
		return err
	}
	good := Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Subject: "s", Text: "hello"}
	if err := buildWith(good); err != nil {
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
		// A knock carries no attachment, so a manifest that says knock is
		// a knock with attachments by another door.
		{"a knock", Body{Type: "knock", Thread: good.Thread, Text: "hello"}},
	} {
		if err := buildWith(tc.body); !errors.Is(err, ErrForm) {
			t.Errorf("%s: %v, want ErrForm", tc.name, err)
		}
	}
	if err := buildWith(Body{Type: "knock", Thread: good.Thread, Text: "hello"}); err == nil || !strings.Contains(err.Error(), "a knock is one envelope, never a stream") {
		t.Errorf("a knock manifest: %v; want the sentence", err)
	}
	// An attachment's media type, which an envelope's Open refuses empty
	// and the sender never writes empty: crafted past BuildManifest, as a
	// stranger's client would, and refused where the manifest is read, so
	// that no stream is taken whose record Load would then refuse.
	_, m := build(t, from, to, MinChunkSize, map[string][]byte{"a.bin": []byte("hello")})
	m.Attachments[0].Media = ""
	if err := m.Validate(); !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), `attachment "a.bin" has no media type`) {
		t.Errorf("a received manifest with an empty media type: %v, want ErrForm naming it", err)
	}
	m.Attachments[0].Media = "application/octet-stream"
	if err := m.Validate(); err != nil {
		t.Errorf("the manifest with its media type back: %v", err)
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

// What a filesystem folds beyond case, no rule at Validate can foresee,
// and the spool no longer needs to: attachments are kept by their index in
// the manifest, so two names the disk spells as one — a pair changed under
// the opened stream here to what a pair Validate cannot tell apart looks
// like at this point — are two files in the spool with their own bytes,
// and the write under --out settles the collision with a numbered suffix
// (the extraction test in internal/auu). Before the positional spool the
// second O_EXCL open found the first's file and the stream was refused as
// malformed; the test then proved the refusal, and now proves the two
// files. It skips itself where the disk keeps Probe and probe apart, so
// that a pass on Linux says nothing it cannot.
func TestNamesTheDiskSpellsAsOneAreTwoFilesInTheSpool(t *testing.T) {
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
	out := filepath.Join(dir, "out")
	if err := o.ToDirectory(bytes.NewReader(blob[HeaderSize+n:]), out); err != nil {
		t.Fatalf("ToDirectory: %v; two names the disk spells as one are two files in a positional spool", err)
	}
	for i, want := range []string{"upper", "lower"} {
		got, err := os.ReadFile(filepath.Join(out, SpoolName(i)))
		if err != nil || string(got) != want {
			t.Errorf("attachment %d: %q, %v; want %q", i, got, err, want)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.part")); statErr == nil {
		t.Error("the temporary directory was left behind")
	}
}

// The manifest's body is held to the same table Body.Validate is: what a
// subject, a text or an attachment name may carry is one rule on both
// paths. The rows are the message package's, written again here since a
// test cannot import another's.
func TestValidateHoldsTheManifestBodyToWhatATerminalShows(t *testing.T) {
	from, to := pair(t)
	const id = "0123456789abcdef0123456789abcdef"
	build := func(subject, text, name string) error {
		_, err := BuildManifest(from, to.Public(), id, Body{Type: "ask", Thread: id, Subject: subject, Text: text},
			sourcesOf(memSource{name, []byte("x")}), MinChunkSize)
		return err
	}
	for _, tc := range []struct {
		name, bytes               string
		inSubject, inText, inName bool
	}{
		{"an escape", "\x1b[2K", false, false, false},
		{"a carriage return", "\r", false, false, false},
		{"a bidi override", "\u202e", false, false, false},
		{"a private-use rune", "\ue000", false, false, false},
		{"a line separator", "\u2028", false, false, false},
		{"a newline", "\n", false, true, false},
		{"a tab", "\t", false, true, false},
		{"a byte that is not UTF-8", "\xff", false, false, false},
		{"plain prose", "hello, world", true, true, true},
		{"letters beyond ASCII", "café 中文", true, true, true},
	} {
		if err := build("s"+tc.bytes+"s", "x", "a"); (err == nil) != tc.inSubject {
			t.Errorf("subject with %s: %v, want accepted=%v", tc.name, err, tc.inSubject)
		} else if err != nil && !errors.Is(err, ErrForm) {
			t.Errorf("subject with %s: %v is not ErrForm", tc.name, err)
		}
		if err := build("s", "x"+tc.bytes+"x", "a"); (err == nil) != tc.inText {
			t.Errorf("text with %s: %v, want accepted=%v", tc.name, err, tc.inText)
		} else if err != nil && !errors.Is(err, ErrForm) {
			t.Errorf("text with %s: %v is not ErrForm", tc.name, err)
		}
		if err := build("s", "x", "n"+tc.bytes+"n"); (err == nil) != tc.inName {
			t.Errorf("attachment name with %s: %v, want accepted=%v", tc.name, err, tc.inName)
		} else if err != nil && !errors.Is(err, ErrForm) {
			t.Errorf("attachment name with %s: %v is not ErrForm", tc.name, err)
		}
	}
}

// A manifest stamped in the future is malformed at open, as an envelope's
// inner is; one stamped a year ago opens. The stamp is set after
// BuildManifest and before Seal, which Validate does not read.
func TestAManifestStampedInTheFutureIsMalformed(t *testing.T) {
	from, to := pair(t)
	open := func(when time.Time) error {
		t.Helper()
		sources := sourcesOf(memSource{"a", []byte("x")})
		m, err := BuildManifest(from, to.Public(), "0123456789abcdef0123456789abcdef",
			Body{Type: "ask", Thread: "0123456789abcdef0123456789abcdef", Text: "x"}, sources, MinChunkSize)
		if err != nil {
			t.Fatal(err)
		}
		m.Time = when
		var buf bytes.Buffer
		if err := Seal(&buf, from, to.Public(), m, sources); err != nil {
			t.Fatal(err)
		}
		blob := buf.Bytes()
		n, err := ManifestLength(blob[:HeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenManifest(to, blob[:HeaderSize], blob[HeaderSize:HeaderSize+n])
		return err
	}
	if err := open(time.Now().Add(24 * time.Hour)); !errors.Is(err, ErrForm) {
		t.Errorf("a day ahead: %v, want ErrForm", err)
	}
	if err := open(time.Now().Add(-365 * 24 * time.Hour)); err != nil {
		t.Errorf("a year ago: %v, want opened", err)
	}
}

// The manifest's attachment names are held to the same Windows rows
// ValidAttachmentName is, on this path as on the envelope's: at
// BuildManifest, the sender's side; a received manifest takes every row
// and the receiver writes under SafeName.
func TestValidateHoldsTheManifestNamesToWindowsToo(t *testing.T) {
	from, to := pair(t)
	const id = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name    string
		allowed bool
	}{
		{"CON", false},
		{"con", false},
		{"con.txt", false},
		{"Con.tar.gz", false},
		{"COM1", false},
		{"com9.log", false},
		{"LPT1", false},
		{"lpt0", false},
		{"COM0", false},
		{"COM\u00b9", false},
		{"lpt\u00b3", false},
		{"COM10", true},
		{"nul", false},
		{"aux.", false},
		{"report.txt.", false},
		{"report.txt ", false},
		{".hidden", false},
		{"console.txt", true},
		{"CONIN$", false},
		{"conout$.txt", false},
		{"conin", true},
		{"CON .txt", false},
		{"a<b.txt", false},
		{"a>b.txt", false},
		{"a\"b.txt", false},
		{"a|b.txt", false},
		{"a?b.txt", false},
		{"a*b.txt", false},
		{"a'b.txt", true},
	} {
		_, err := BuildManifest(from, to.Public(), id, Body{Type: "ask", Thread: id, Text: "x"},
			sourcesOf(memSource{tc.name, []byte("x")}), MinChunkSize)
		if (err == nil) != tc.allowed {
			t.Errorf("%q: %v, want accepted=%v", tc.name, err, tc.allowed)
		} else if err != nil && !errors.Is(err, ErrForm) {
			t.Errorf("%q: %v is not ErrForm", tc.name, err)
		}
	}
}
