package stream

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/message"
)

// TestLimitManifestIntegers: every integer a manifest carries, at the
// edges of what Validate allows and one step past, and at the type's
// extremes. V is 1; chunk_size is within [MinChunkSize, MaxChunkSize];
// payload_bytes within [0, MaxPayloadBytes]; chunks is exactly what the
// payload and the chunk size need, so one more or one fewer is refused;
// an attachment's size is within [0, MaxPayloadBytes] and the sizes must
// add up to payload_bytes.
func TestLimitManifestIntegers(t *testing.T) {
	from, to := pair(t)
	fresh := func() *Manifest {
		_, m := build(t, from, to, MinChunkSize, map[string][]byte{"a.bin": []byte("hello"), "b.bin": []byte("world")})
		return m
	}
	refused := func(t *testing.T, what string, m *Manifest, says string) {
		t.Helper()
		err := m.Validate()
		if err == nil {
			t.Errorf("%s was accepted", what)
			return
		}
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), says) {
			t.Errorf("%s: %v; want ErrForm saying %q", what, err, says)
		}
	}
	accepted := func(t *testing.T, what string, m *Manifest) {
		t.Helper()
		if err := m.Validate(); err != nil {
			t.Errorf("%s was refused: %v", what, err)
		}
	}

	t.Run("v", func(t *testing.T) {
		for _, v := range []int{0, 2, math.MinInt, math.MaxInt} {
			m := fresh()
			m.V = v
			refused(t, "v "+itoa(int64(v)), m, "unsupported manifest version")
		}
		accepted(t, "v 1", fresh())
	})

	t.Run("chunk_size", func(t *testing.T) {
		for _, n := range []int{MinChunkSize - 1, MaxChunkSize + 1, 0, -1, math.MinInt, math.MaxInt} {
			m := fresh()
			m.ChunkSize = n
			refused(t, "chunk_size "+itoa(int64(n)), m, "chunk_size")
		}
		for _, n := range []int{MinChunkSize, MaxChunkSize} {
			m := fresh()
			m.ChunkSize = n
			m.Chunks = ChunkCount(m.PayloadBytes, n)
			accepted(t, "chunk_size "+itoa(int64(n)), m)
		}
	})

	t.Run("payload_bytes", func(t *testing.T) {
		for _, n := range []int64{-1, math.MinInt64, MaxPayloadBytes + 1, math.MaxInt64} {
			m := fresh()
			m.PayloadBytes = n
			m.Chunks = ChunkCount(n, m.ChunkSize)
			refused(t, "payload_bytes "+itoa(n), m, "payload_bytes")
		}
		// Zero, with no attachments to add up: one empty final chunk.
		m := fresh()
		m.Attachments = nil
		m.PayloadBytes = 0
		m.Chunks = ChunkCount(0, m.ChunkSize)
		accepted(t, "payload_bytes 0", m)
		// The ceiling, with one attachment that is all of it.
		m = fresh()
		m.Attachments = m.Attachments[:1]
		m.Attachments[0].Size = MaxPayloadBytes
		m.PayloadBytes = MaxPayloadBytes
		m.Chunks = ChunkCount(MaxPayloadBytes, m.ChunkSize)
		accepted(t, "payload_bytes MaxPayloadBytes", m)
	})

	t.Run("chunks", func(t *testing.T) {
		want := fresh().Chunks
		for _, n := range []int64{want - 1, want + 1, 0, -1, math.MinInt64, math.MaxInt64} {
			m := fresh()
			m.Chunks = n
			refused(t, "chunks "+itoa(n), m, "chunks is")
		}
		accepted(t, "chunks as counted", fresh())
		if want < 1 {
			t.Errorf("a stream with a payload counts %d chunks; every stream has at least the empty final one", want)
		}
	})

	t.Run("attachment size", func(t *testing.T) {
		for _, n := range []int64{-1, math.MinInt64} {
			m := fresh()
			m.Attachments[0].Size = n
			refused(t, "attachment size "+itoa(n), m, "negative size")
		}
		for _, n := range []int64{MaxPayloadBytes + 1, math.MaxInt64} {
			m := fresh()
			m.Attachments[0].Size = n
			refused(t, "attachment size "+itoa(n), m, "more than the")
		}
		// Two attachments that each fit but together pass the ceiling:
		// checked before the sum wraps.
		m := fresh()
		m.Attachments[0].Size = MaxPayloadBytes
		m.Attachments[1].Size = math.MaxInt64 - MaxPayloadBytes + 1
		refused(t, "attachment sizes that wrap", m, "more than the")
		// One more or one fewer byte than payload_bytes says.
		for _, delta := range []int64{-1, 1} {
			m := fresh()
			m.Attachments[0].Size += delta
			refused(t, "attachment size off by "+itoa(delta), m, "payload_bytes says")
		}
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TestLimitManifestLength: the length the header declares for the manifest
// chunk is within [MinChunk0, MaxChunk0], read from four bytes before
// anything is allocated from it: zero, one under, one over and the type's
// maximum are refused naming the bounds; the bounds are taken.
func TestLimitManifestLength(t *testing.T) {
	header := func(n uint32) []byte {
		h := make([]byte, HeaderSize)
		binary.BigEndian.PutUint32(h[EncSize:], n)
		return h
	}
	for _, n := range []uint32{0, MinChunk0 - 1, MaxChunk0 + 1, math.MaxUint32} {
		_, err := ManifestLength(header(n))
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "outside ["+strconv.Itoa(MinChunk0)+", "+strconv.Itoa(MaxChunk0)+"]") {
			t.Errorf("length %d: %v; want ErrForm naming the bounds", n, err)
		}
	}
	for _, n := range []uint32{MinChunk0, MaxChunk0} {
		got, err := ManifestLength(header(n))
		if err != nil || got != int(n) {
			t.Errorf("length %d: %d %v; want it read", n, got, err)
		}
	}
	if _, err := ManifestLength(header(MinChunk0)[:HeaderSize-1]); !errors.Is(err, ErrTruncated) {
		t.Errorf("a header one byte short: %v; want ErrTruncated", err)
	}
}

// TestLimitNamesAreNotPathsAtManifestValidate: a manifest's id and its
// thread become a record's file and a thread directory on the receiver;
// Manifest.Validate runs message.ValidID on each, so a value from the
// limit guide's traversal set is refused as ErrForm before anything is
// opened. An attachment name is a file on the receiver and is not
// refused but made safe: a received manifest takes each value (but a NUL
// and the 300 bytes, which the text rule refuses), SafeName of it is a
// base name, and BuildManifest, the sender's side, refuses the value.
func TestLimitNamesAreNotPathsAtManifestValidate(t *testing.T) {
	from, to := pair(t)
	set := []string{"..", "../x", "x/../../y", "a/b", "/etc/passwd", `..\x`, `C:\x`, "C:x", "CON", "com1.txt", "\x00", "", ".", strings.Repeat("a", 300)}
	fresh := func() *Manifest {
		_, m := build(t, from, to, MinChunkSize, map[string][]byte{"a.bin": []byte("hello")})
		return m
	}
	for _, v := range set {
		m := fresh()
		m.ID = v
		if err := m.Validate(); !errors.Is(err, ErrForm) {
			t.Errorf("id %q: %v; want ErrForm", v, err)
		}
		m = fresh()
		m.Body.Thread = v
		if err := m.Validate(); !errors.Is(err, ErrForm) {
			t.Errorf("thread %q: %v; want ErrForm", v, err)
		}
		m = fresh()
		m.Attachments[0].Name = v
		text := v != "\x00" && len(v) <= 255
		if err := m.Validate(); (err == nil) != text {
			t.Errorf("attachment name %q at a received manifest: %v; want taken=%v", v, err, text)
		}
		if safe := message.SafeName(v); strings.ContainsAny(safe, `/\`) || message.ValidAttachmentName(safe) != nil {
			t.Errorf("SafeName(%q) = %q is not a name the sender's rule takes", v, safe)
		}
		if _, err := BuildManifest(from, to.Public(), strings.Repeat("a", 32), Body{Type: "ask", Thread: strings.Repeat("a", 32), Text: "x"},
			sourcesOf(memSource{v, []byte("x")}), MinChunkSize); !errors.Is(err, ErrForm) {
			t.Errorf("BuildManifest took the attachment name %q: %v", v, err)
		}
	}
}
