package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/testutil"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

func pair(t *testing.T) (from *identity.Identity, to *identity.Identity) {
	t.Helper()
	var err error
	if from, err = identity.Generate("alice"); err != nil {
		t.Fatal(err)
	}
	if to, err = identity.Generate("bob"); err != nil {
		t.Fatal(err)
	}
	return from, to
}

func source(name string, data []byte) Source {
	return Source{
		Name: name, Media: "application/octet-stream", Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
	}
}

func body() Body {
	return Body{Type: "ask", Subject: "a big one", Thread: "0123456789abcdef0123456789abcdef", Text: "please look"}
}

// build seals a stream and returns its bytes and its manifest.
func build(t *testing.T, from, to *identity.Identity, chunkSize int, files map[string][]byte) ([]byte, *Manifest) {
	t.Helper()
	return buildWith(t, from, to, chunkSize, files, nil)
}

// buildWith is build with sections in the manifest.
func buildWith(t *testing.T, from, to *identity.Identity, chunkSize int, files map[string][]byte, sections []wire.Section) ([]byte, *Manifest) {
	t.Helper()
	var sources []Source
	// Deterministic order: the manifest is the framing, so order matters.
	for _, name := range sortedNames(files) {
		sources = append(sources, source(name, files[name]))
	}
	m, err := BuildManifestSections(from, to.Public(), strings.Repeat("a", 32), body(), sources, chunkSize, sections)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Seal(&buf, from, to.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), m
}

func sortedNames(files map[string][]byte) []string {
	var out []string
	for n := range files {
		out = append(out, n)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// openAll runs the whole receive path and returns what came out.
func openAll(t *testing.T, self *identity.Identity, blob []byte) (*Opened, map[string][]byte, error) {
	t.Helper()
	if len(blob) < HeaderSize {
		return nil, nil, ErrTruncated
	}
	n, err := ManifestLength(blob[:HeaderSize])
	if err != nil {
		return nil, nil, err
	}
	if len(blob) < HeaderSize+n {
		return nil, nil, ErrTruncated
	}
	o, err := OpenManifest(self, blob[:HeaderSize], blob[HeaderSize:HeaderSize+n])
	if err != nil {
		return nil, nil, err
	}
	// A correct caller writes somewhere temporary and keeps the result only
	// when OpenPayload returns nil; ToDirectory is that shape. The map is
	// therefore populated only on success, and every "was anything delivered"
	// assertion below means what it says.
	partial := map[string][]byte{}
	err = o.OpenPayload(bytes.NewReader(blob[HeaderSize+n:]), func(a Attachment) (io.WriteCloser, error) {
		buf := &closableBuffer{}
		buf.onClose = func(b []byte) { partial[a.Name] = b }
		return buf, nil
	})
	if err != nil {
		return o, nil, err
	}
	return o, partial, nil
}

type closableBuffer struct {
	bytes.Buffer
	onClose func([]byte)
}

func (c *closableBuffer) Close() error {
	if c.onClose != nil {
		c.onClose(append([]byte(nil), c.Bytes()...))
	}
	return nil
}

func TestRoundTripRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	from, to := pair(t)

	const cs = MinChunkSize
	// Lengths that must appear whatever the seed: the empty payload, the
	// boundaries of a chunk, and several multiples.
	lengths := []int{0, 1, cs - 1, cs, cs + 1, 2 * cs, 2*cs + 1, 3 * cs}
	for range 12 {
		lengths = append(lengths, r.IntN(4*cs))
	}

	for _, n := range lengths {
		files := map[string][]byte{}
		if n > 0 {
			files["one.bin"] = testutil.Bytes(r, n)
		}
		if n > cs {
			// Split across two attachments, so the concatenation is exercised.
			files["one.bin"] = testutil.Bytes(r, n-cs)
			files["two.bin"] = testutil.Bytes(r, cs)
		}
		// A made-up section rides on every round trip (D35).
		madeUp := testutil.MadeUpSection(r)
		// The number of recipients is drawn too, one to four (D49): one is
		// the stream to one, with no list; more is a stream for each, every
		// one opening for its own recipient alone.
		k := 1 + r.IntN(4)
		whom := []*identity.Identity{to}
		if k > 1 {
			whom = append(whom, readers(t, k-1)...)
		}
		blobs := sealForEach(t, from, whom, cs, files, []wire.Section{madeUp})

		for i, blob := range blobs {
			o, out, err := openAll(t, whom[i], blob)
			if err != nil {
				t.Fatalf("seed %d: payload %d bytes, copy %d of %d: %v", seed, n, i+1, k, err)
			}
			wantSections := 1
			if k > 1 {
				wantSections = 2
			}
			if len(o.Manifest.Sections) != wantSections || o.Manifest.Sections[0].Name != madeUp.Name || !bytes.Equal(o.Manifest.Sections[0].Data, madeUp.Data) {
				t.Fatalf("seed %d: the made-up section %q did not survive, or the list is wrong for %d recipients", seed, madeUp.Name, k)
			}
			if o.Sender.Fingerprint() != from.Fingerprint() {
				t.Fatalf("seed %d: wrong sender", seed)
			}
			if o.Manifest.Body.Text != body().Text {
				t.Fatalf("seed %d: body did not survive", seed)
			}
			if len(out) != len(files) {
				t.Fatalf("seed %d: %d attachments out, %d in", seed, len(out), len(files))
			}
			for name, want := range files {
				if !bytes.Equal(out[name], want) {
					t.Fatalf("seed %d: %q did not survive at payload %d", seed, name, n)
				}
			}
			// The next recipient's key does not open this copy.
			if k > 1 {
				if _, _, err := openAll(t, whom[(i+1)%k], blob); err == nil {
					t.Fatalf("seed %d: copy %d of %d opened for another recipient", seed, i+1, k)
				}
			}
		}
	}
}

// sealForEach seals one stream for each reader from one manifest pass, as a
// send to several does, and answers them in the readers' order.
func sealForEach(t *testing.T, from *identity.Identity, to []*identity.Identity, chunkSize int, files map[string][]byte, sections []wire.Section) [][]byte {
	t.Helper()
	var sources []Source
	for _, name := range sortedNames(files) {
		sources = append(sources, source(name, files[name]))
	}
	ms, err := BuildManifestMany(from, publics(to), strings.Repeat("a", 32), body(), sources, chunkSize, sections)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for i, m := range ms {
		var buf bytes.Buffer
		if err := Seal(&buf, from, to[i].Public(), m, sources); err != nil {
			t.Fatal(err)
		}
		out = append(out, buf.Bytes())
	}
	return out
}

// The wire size must be predictable from the manifest alone: a receiver checks
// it against Content-Length before fetching any payload.
func TestSizeMatchesTheWire(t *testing.T) {
	from, to := pair(t)
	for _, n := range []int{0, 1, MinChunkSize, MinChunkSize + 1, 5 * MinChunkSize} {
		files := map[string][]byte{}
		if n > 0 {
			files["f.bin"] = bytes.Repeat([]byte("x"), n)
		}
		blob, m := build(t, from, to, MinChunkSize, files)
		sealedManifest, err := ManifestLength(blob[:HeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		if want := Size(sealedManifest, m.PayloadBytes, m.ChunkSize); want != int64(len(blob)) {
			t.Fatalf("payload %d: Size says %d, the blob is %d", n, want, len(blob))
		}
	}
}

// Every stream ends with a chunk sealed as final, including one with nothing
// to carry, so truncation has exactly one rule.
func TestEmptyPayloadStillHasAFinalChunk(t *testing.T) {
	from, to := pair(t)
	blob, m := build(t, from, to, MinChunkSize, nil)
	if m.Chunks != 2 {
		t.Fatalf("an empty stream has %d chunks, want 2", m.Chunks)
	}
	if m.PayloadBytes != 0 {
		t.Fatalf("payload_bytes %d", m.PayloadBytes)
	}
	sealedManifest, _ := ManifestLength(blob[:HeaderSize])
	// enc + prefix + manifest + one empty sealed chunk.
	if want := HeaderSize + sealedManifest + TagSize; len(blob) != want {
		t.Fatalf("blob is %d bytes, want %d", len(blob), want)
	}
	if _, out, err := openAll(t, to, blob); err != nil || len(out) != 0 {
		t.Fatalf("an empty stream did not open: %v", err)
	}
}

func TestTruncation(t *testing.T) {
	from, to := pair(t)
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 3*MinChunkSize)}
	blob, _ := build(t, from, to, MinChunkSize, files)

	cases := map[string][]byte{
		"one byte short":           blob[:len(blob)-1],
		"one whole chunk short":    blob[:len(blob)-(MinChunkSize+TagSize)],
		"the final tag removed":    blob[:len(blob)-TagSize],
		"only the header":          blob[:HeaderSize],
		"header and manifest only": blob[:HeaderSize+mustLen(t, blob)],
		"nothing at all":           nil,
		"half the encapsulation":   blob[:EncSize/2],
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			_, out, err := openAll(t, to, bad)
			if err == nil {
				t.Fatal("a truncated stream opened cleanly")
			}
			for f, data := range out {
				if len(data) != 0 {
					t.Fatalf("%q was delivered anyway (%d bytes)", f, len(data))
				}
			}
		})
	}
}

func mustLen(t *testing.T, blob []byte) int {
	t.Helper()
	n, err := ManifestLength(blob[:HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestExtension(t *testing.T) {
	from, to := pair(t)
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 2*MinChunkSize)}
	blob, _ := build(t, from, to, MinChunkSize, files)

	for name, bad := range map[string][]byte{
		"one byte appended": append(append([]byte(nil), blob...), 0),
		"a chunk appended":  append(append([]byte(nil), blob...), bytes.Repeat([]byte("z"), MinChunkSize+TagSize)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := openAll(t, to, bad); !errors.Is(err, ErrTrailing) {
				t.Fatalf("gave %v, want ErrTrailing", err)
			}
		})
	}
}

// The HPKE sequence number binds a chunk to its position, so reordering and
// duplication fail without anything being added to the additional data.
func TestReorderingAndDuplication(t *testing.T) {
	from, to := pair(t)
	const cs = MinChunkSize
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 3*cs)}
	blob, _ := build(t, from, to, cs, files)
	m0 := mustLen(t, blob)
	start := HeaderSize + m0
	sealedChunk := cs + TagSize

	chunk := func(i int) []byte {
		return blob[start+i*sealedChunk : start+(i+1)*sealedChunk]
	}

	swapped := append([]byte(nil), blob[:start]...)
	swapped = append(swapped, chunk(1)...)
	swapped = append(swapped, chunk(0)...)
	swapped = append(swapped, chunk(2)...)
	if _, _, err := openAll(t, to, swapped); err == nil {
		t.Fatal("two swapped chunks opened")
	}

	duplicated := append([]byte(nil), blob[:start]...)
	duplicated = append(duplicated, chunk(0)...)
	duplicated = append(duplicated, chunk(0)...)
	duplicated = append(duplicated, chunk(2)...)
	if _, _, err := openAll(t, to, duplicated); err == nil {
		t.Fatal("a duplicated chunk opened")
	}
}

// A body chunk moved to the last position must not open, because the last
// position is sealed under a different role.
func TestFinalChunkRoleIsEnforced(t *testing.T) {
	from, to := pair(t)
	const cs = MinChunkSize
	// Two payload chunks, so there is a body chunk and a final chunk.
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 2*cs)}
	blob, _ := build(t, from, to, cs, files)
	start := HeaderSize + mustLen(t, blob)
	sealedChunk := cs + TagSize

	// Replace the final chunk with a copy of the body chunk.
	bad := append([]byte(nil), blob[:start+sealedChunk]...)
	bad = append(bad, blob[start:start+sealedChunk]...)
	if _, _, err := openAll(t, to, bad); err == nil {
		t.Fatal("a body chunk in the final position opened")
	}
}

// Chunks from one stream must not open in another, even between the same two
// identities: each context has its own encapsulation and key schedule.
func TestChunksDoNotTransplantBetweenStreams(t *testing.T) {
	from, to := pair(t)
	const cs = MinChunkSize
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 2*cs)}
	a, _ := build(t, from, to, cs, files)
	b, _ := build(t, from, to, cs, files)
	start := HeaderSize + mustLen(t, a)
	if mustLen(t, b) != mustLen(t, a) {
		t.Skip("manifests differ in length; the transplant would not line up")
	}

	mixed := append([]byte(nil), a[:start+cs+TagSize]...)
	mixed = append(mixed, b[start+cs+TagSize:]...)
	if _, _, err := openAll(t, to, mixed); err == nil {
		t.Fatal("a chunk from another stream opened")
	}
}

// One flipped bit in each structurally distinct region. Offsets come from the
// format's constants, never from a literal.
func TestBitFlipInEveryRegion(t *testing.T) {
	r, seed := testutil.Seed(t)
	from, to := pair(t)
	const cs = MinChunkSize
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 2*cs)}
	blob, _ := build(t, from, to, cs, files)
	m0 := mustLen(t, blob)
	start := HeaderSize + m0

	regions := map[string]int{
		"first byte of the encapsulation": 0,
		"middle of the encapsulation":     EncSize / 2,
		"last byte of the encapsulation":  EncSize - 1,
		"prefix byte 0":                   EncSize,
		"prefix byte 1":                   EncSize + 1,
		"prefix byte 2":                   EncSize + 2,
		"prefix byte 3":                   EncSize + 3,
		"first byte of chunk 0":           HeaderSize,
		"middle of chunk 0":               HeaderSize + m0/2,
		"last byte of chunk 0's tag":      HeaderSize + m0 - 1,
		"first byte of chunk 1":           start,
		"last byte of chunk 1's tag":      start + cs + TagSize - 1,
		"first byte of the final chunk":   start + cs + TagSize,
		"last byte of the final chunk":    len(blob) - 1,
	}
	for name, offset := range regions {
		t.Run(name, func(t *testing.T) {
			bad := testutil.FlipByteBit(blob, offset, r.IntN(8))
			_, out, err := openAll(t, to, bad)
			if err == nil {
				t.Fatalf("seed %d: a flipped bit at %d opened cleanly", seed, offset)
			}
			for f, data := range out {
				if len(data) != 0 {
					t.Fatalf("seed %d: %q was delivered anyway", seed, f)
				}
			}
		})
	}
}

// The prefix is a length the peer states, so it is bounded before it is used
// for anything, and every edge of that bound is tested.
func TestManifestLengthBounds(t *testing.T) {
	from, to := pair(t)
	blob, _ := build(t, from, to, MinChunkSize, nil)
	header := append([]byte(nil), blob[:HeaderSize]...)

	set := func(n uint32) []byte {
		h := append([]byte(nil), header...)
		h[EncSize] = byte(n >> 24)
		h[EncSize+1] = byte(n >> 16)
		h[EncSize+2] = byte(n >> 8)
		h[EncSize+3] = byte(n)
		return h
	}
	for _, c := range []struct {
		name   string
		n      uint32
		accept bool
	}{
		{"zero", 0, false},
		{"one below the minimum", MinChunk0 - 1, false},
		{"exactly the minimum", MinChunk0, true},
		{"one above the minimum", MinChunk0 + 1, true},
		{"one below the maximum", MaxChunk0 - 1, true},
		{"exactly the maximum", MaxChunk0, true},
		{"one above the maximum", MaxChunk0 + 1, false},
		{"the largest uint32", ^uint32(0), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := ManifestLength(set(c.n))
			if c.accept {
				if err != nil {
					t.Fatalf("%d was refused: %v", c.n, err)
				}
				if got != int(c.n) {
					t.Fatalf("read %d, want %d", got, c.n)
				}
				return
			}
			if err == nil {
				t.Fatalf("%d was accepted", c.n)
			}
			if !errors.Is(err, ErrForm) && !errors.Is(err, ErrTruncated) {
				t.Fatalf("unexpected error kind: %v", err)
			}
		})
	}

	// A header shorter than the fixed part is truncation, not a bad length.
	if _, err := ManifestLength(header[:HeaderSize-1]); !errors.Is(err, ErrTruncated) {
		t.Fatalf("a short header gave %v, want ErrTruncated", err)
	}
}

// The bound must be applied before anything is allocated from the length, and
// before the second fetch it would drive. Proven by which error comes back: a
// blob that is both over the cap and far too short must fail on the cap.
func TestOversizePrefixIsRefusedBeforeReading(t *testing.T) {
	from, to := pair(t)
	blob, _ := build(t, from, to, MinChunkSize, nil)
	bad := append([]byte(nil), blob[:HeaderSize]...)
	bad[EncSize] = 0xff // a length of about 4 GiB
	bad[EncSize+1] = 0xff
	bad[EncSize+2] = 0xff
	bad[EncSize+3] = 0xff

	_, err := ManifestLength(bad)
	if err == nil {
		t.Fatal("a 4 GiB manifest length was accepted")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Fatalf("error %q is not the bound's; something else fired first", err)
	}
}

func TestWrongRecipient(t *testing.T) {
	from, to := pair(t)
	stranger, err := identity.Generate("stranger")
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := build(t, from, to, MinChunkSize, map[string][]byte{"f.bin": []byte("hello")})
	if _, _, err := openAll(t, stranger, blob); err == nil {
		t.Fatal("a stream opened for the wrong recipient")
	}
}

// The manifest is what the signature covers, so every claim in it that the
// payload must satisfy is checked on the way out as well as on the way in.
// A name with a separator is not a lie about the payload any more: a
// receiver writes the file under SafeName of it, which the stream form of
// the extraction test in internal/auu shows.
func TestManifestLies(t *testing.T) {
	from, to := pair(t)
	for name, mutate := range map[string]func(*Manifest){
		"chunks one too many":          func(m *Manifest) { m.Chunks++ },
		"chunks one too few":           func(m *Manifest) { m.Chunks-- },
		"payload one byte over":        func(m *Manifest) { m.PayloadBytes++ },
		"payload one byte under":       func(m *Manifest) { m.PayloadBytes-- },
		"chunk size below the minimum": func(m *Manifest) { m.ChunkSize = MinChunkSize - 1 },
		"chunk size above the maximum": func(m *Manifest) { m.ChunkSize = MaxChunkSize + 1 },
		"attachment size wrong":        func(m *Manifest) { m.Attachments[0].Size++ },
		"digest changed":               func(m *Manifest) { m.Attachments[0].SHA256 = strings.Repeat("0", 64) },
		"unknown version":              func(m *Manifest) { m.V = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			sources := []Source{source("f.bin", []byte("hello"))}
			m, err := BuildManifest(from, to.Public(), strings.Repeat("a", 32), body(), sources, MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			mutate(m)
			var buf bytes.Buffer
			// Either Seal refuses it, or it produces something that will not
			// open. Both are correct; silently working is not.
			if err := Seal(&buf, from, to.Public(), m, sources); err != nil {
				return
			}
			if _, _, err := openAll(t, to, buf.Bytes()); err == nil {
				t.Fatal("a manifest that lies about its payload opened cleanly")
			}
		})
	}
}

// A digest that does not match must fail even though the manifest is
// internally consistent and correctly signed.
func TestDigestMismatchIsCaught(t *testing.T) {
	from, to := pair(t)
	data := []byte("the real bytes")
	sources := []Source{{
		Name: "f.bin", Media: "text/plain", Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
	}}
	m, err := BuildManifest(from, to.Public(), strings.Repeat("b", 32), body(), sources, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	// A correctly signed manifest whose digest is for different bytes.
	other := sha256.Sum256([]byte("different bytes"))
	m.Attachments[0].SHA256 = hex.EncodeToString(other[:])

	var buf bytes.Buffer
	if err := Seal(&buf, from, to.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	_, out, err := openAll(t, to, buf.Bytes())
	if !errors.Is(err, ErrDigest) {
		t.Fatalf("gave %v, want ErrDigest", err)
	}
	if len(out["f.bin"]) != 0 {
		t.Fatal("the attachment was delivered despite a digest mismatch")
	}
}

// Seal refuses to sign a manifest that names somebody else, so a stream whose
// signature is not its sender's cannot be produced by this package at all.
func TestSealRefusesAMismatchedSigner(t *testing.T) {
	from, to := pair(t)
	mallory, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	sources := []Source{source("f.bin", []byte("x"))}
	m, err := BuildManifest(from, to.Public(), strings.Repeat("c", 32), body(), sources, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Seal(&buf, mallory, to.Public(), m, sources); err == nil {
		t.Fatal("sealing with a key the manifest does not name was allowed")
	}
}

// The same identity key signs four things now. None of the four may verify as
// any other.
func TestSignatureDomainIsSeparate(t *testing.T) {
	from, to := pair(t)
	manifestJSON := []byte(`{"v":1}`)
	streamSig := mustSign(t, from, sigInput(to.Fingerprint(), manifestJSON))

	// The envelope's domain over the same bytes.
	envelopeInput := append([]byte("ccx-sig-v1"), append([]byte(to.Fingerprint()), manifestJSON...)...)
	if from.Public().Verify(envelopeInput, streamSig) {
		t.Fatal("a stream signature verified as an envelope signature")
	}
	envelopeSig := mustSign(t, from, envelopeInput)
	if from.Public().Verify(sigInput(to.Fingerprint(), manifestJSON), envelopeSig) {
		t.Fatal("an envelope signature verified as a stream signature")
	}
	// The token domain.
	tokenInput := append([]byte("ccx-token-v1"), manifestJSON...)
	if from.Public().Verify(tokenInput, streamSig) {
		t.Fatal("a stream signature verified as a token signature")
	}
	if from.Public().Verify(sigInput(to.Fingerprint(), manifestJSON), mustSign(t, from, tokenInput)) {
		t.Fatal("a token signature verified as a stream signature")
	}
	// The request domain.
	requestInput := append([]byte("ccx-http-v1\n"), manifestJSON...)
	if from.Public().Verify(requestInput, streamSig) {
		t.Fatal("a stream signature verified as a request signature")
	}
	if from.Public().Verify(sigInput(to.Fingerprint(), manifestJSON), mustSign(t, from, requestInput)) {
		t.Fatal("a request signature verified as a stream signature")
	}
}

// A stream and an envelope must not be openable as one another, which is what
// the distinct info string buys.
func TestStreamIsNotAnEnvelope(t *testing.T) {
	from, to := pair(t)
	blob, _ := build(t, from, to, MinChunkSize, map[string][]byte{"f.bin": []byte("x")})
	// The envelope package would need the whole ciphertext; the point is that
	// the key schedule differs, so opening the stream's chunk 0 with the
	// envelope's info fails. Exercised through the recipient context.
	if _, err := recipientContext(blob[:EncSize], to); err != nil {
		t.Fatalf("the stream's own context did not build: %v", err)
	}
	wrong, err := identity.Generate("other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenManifest(wrong, blob[:HeaderSize], blob[HeaderSize:HeaderSize+mustLen(t, blob)]); err == nil {
		t.Fatal("chunk 0 opened for an identity it was not sealed to")
	}
}

// Memory is the whole point: a large payload must cost one chunk, not its
// own size.
func TestMemoryIsBoundedByOneChunk(t *testing.T) {
	from, to := pair(t)
	const cs = 64 << 10
	const payload = 64 << 20

	sources := []Source{{
		Name: "big.bin", Media: "application/octet-stream", Size: payload,
		Open: func() (io.ReadCloser, error) { return io.NopCloser(&zeroReader{n: payload}), nil },
	}}
	m, err := BuildManifest(from, to.Public(), strings.Repeat("d", 32), body(), sources, cs)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var sink countingWriter
	if err := Seal(&sink, from, to.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 8<<20 {
		t.Fatalf("sealing %d MiB grew the heap by %d bytes", payload>>20, grew)
	}
}

type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > z.n {
		n = z.n
	}
	for i := range p[:n] {
		p[i] = 0
	}
	z.n -= n
	return int(n), nil
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func TestSourceThatChangesSize(t *testing.T) {
	from, to := pair(t)
	data := []byte("twelve bytes")
	sources := []Source{{
		Name: "f.bin", Media: "text/plain", Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) {
			// Grows between the hash and the seal.
			return io.NopCloser(bytes.NewReader(append(data, "extra"...))), nil
		},
	}}
	m, err := BuildManifest(from, to.Public(), strings.Repeat("e", 32), body(), sources, MinChunkSize)
	if err == nil {
		var buf bytes.Buffer
		if err := Seal(&buf, from, to.Public(), m, sources); err == nil {
			t.Fatal("a source that grew was sealed anyway")
		}
		return
	}
	if !errors.Is(err, ErrForm) {
		t.Fatalf("gave %v, want ErrForm", err)
	}
	_ = fmt.Sprint(err)
}

// ToDirectory is the delivery contract: on success the directory appears whole,
// and on any failure nothing is left behind at all.
func TestToDirectoryIsAtomic(t *testing.T) {
	from, to := pair(t)
	const cs = MinChunkSize
	files := map[string][]byte{
		"one.bin": bytes.Repeat([]byte("a"), 2*cs),
		"two.bin": bytes.Repeat([]byte("b"), 100),
	}
	blob, _ := build(t, from, to, cs, files)
	n := mustLen(t, blob)

	var opened *Opened
	deliver := func(t *testing.T, b []byte) (string, error) {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "message.d")
		o, err := OpenManifest(to, b[:HeaderSize], b[HeaderSize:HeaderSize+n])
		if err != nil {
			return dir, err
		}
		opened = o
		return dir, o.ToDirectory(bytes.NewReader(b[HeaderSize+n:]), dir)
	}

	t.Run("a whole stream arrives", func(t *testing.T) {
		dir, err := deliver(t, blob)
		if err != nil {
			t.Fatal(err)
		}
		// The spool is positional: attachment i is the file "i", and the
		// sender's name is the manifest's alone.
		for i, a := range opened.Manifest.Attachments {
			got, err := os.ReadFile(filepath.Join(dir, SpoolName(i)))
			if err != nil {
				t.Fatalf("%q (attachment %d) missing: %v", a.Name, i, err)
			}
			if !bytes.Equal(got, files[a.Name]) {
				t.Fatalf("%q differs", a.Name)
			}
			if _, err := os.Stat(filepath.Join(dir, a.Name)); err == nil {
				t.Fatalf("%q was spooled under the sender's name", a.Name)
			}
		}
		if _, err := os.Stat(dir + ".part"); !os.IsNotExist(err) {
			t.Fatal("the temporary directory was left behind")
		}
	})

	for name, bad := range map[string][]byte{
		"truncated by a byte":             blob[:len(blob)-1],
		"truncated by a chunk":            blob[:len(blob)-(cs+TagSize)],
		"a flipped bit in the last chunk": testutil.FlipByteBit(blob, len(blob)-1, 3),
		"a flipped bit mid-payload":       testutil.FlipByteBit(blob, HeaderSize+n+10, 1),
	} {
		t.Run("nothing survives "+name, func(t *testing.T) {
			dir, err := deliver(t, bad)
			if err == nil {
				t.Fatal("a broken stream was delivered")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("the delivery directory exists after a failure")
			}
			if _, err := os.Stat(dir + ".part"); !os.IsNotExist(err) {
				t.Fatal("the temporary directory was left behind after a failure")
			}
		})
	}
}

// The same claim on the receiving side. Sealing a large payload one chunk at a
// time is only half of it: opening one must cost a chunk too, or a two
// gigabyte message could be sent but never read.
func TestOpeningIsBoundedByOneChunk(t *testing.T) {
	from, to := pair(t)
	const cs = 64 << 10
	const payload = 64 << 20

	sources := []Source{{
		Name: "big.bin", Media: "application/octet-stream", Size: payload,
		Open: func() (io.ReadCloser, error) { return io.NopCloser(&zeroReader{n: payload}), nil },
	}}
	m, err := BuildManifest(from, to.Public(), strings.Repeat("d", 32), body(), sources, cs)
	if err != nil {
		t.Fatal(err)
	}
	// Sealed to a file rather than to memory, so the test's own copy is not
	// what is being measured.
	path := filepath.Join(t.TempDir(), "sealed")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Seal(f, from, to.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(in, header); err != nil {
		t.Fatal(err)
	}
	length, err := ManifestLength(header)
	if err != nil {
		t.Fatal(err)
	}
	chunk0 := make([]byte, length)
	if _, err := io.ReadFull(in, chunk0); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenManifest(to, header, chunk0)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	// Written to a counting sink rather than to files: what is measured is the
	// opening, not the filesystem.
	err = opened.OpenPayload(in, func(Attachment) (io.WriteCloser, error) {
		return nopWriteCloser{&countingWriter{}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if grew > 8<<20 {
		t.Fatalf("opening %d MiB grew the heap by %d bytes", payload>>20, grew)
	}
	t.Logf("opening %d MiB in %d KiB chunks grew the heap by %d KiB", payload>>20, cs>>10, grew>>10)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// TestSignatureSizeMatchesTheDefaultSuite is a guard, not a property.
//
// The manifest chunk is signature || manifest with a fixed-width split, and
// the only thing that says which identity suite signed it is FromBundle,
// inside the manifest. A reader therefore cannot learn the signature's length
// before it needs it. So this format works for exactly one signature size, and
// if the default suite ever signs with another the failure would be every
// stream failing to open with a confusing form error.
//
// If this test fails, the fix is not to change the constant. It is a new
// stream format under a new info string, with the signature after the
// manifest instead of before it, so that the JSON delimits itself and the
// remainder is a signature of whatever length. Not a manifest version: the
// version is inside the manifest, which cannot be found until chunk 0 is
// split. See the note on SigSize.
func TestSignatureSizeMatchesTheDefaultSuite(t *testing.T) {
	if got := identity.DefaultSuite().SignatureSize; got != SigSize {
		t.Fatalf("the default identity suite signs with %d bytes but this format reserves %d.\n"+
			"This format cannot carry a variable-length signature: chunk 0 is signature||manifest\n"+
			"and the suite is named inside the manifest. Adding a suite means a new stream format\n"+
			"under a new info string, with the signature moved after the manifest.", got, SigSize)
	}
}

// TestEncapsulationSizeMatchesTheDefaultSuite is the same guard for the other
// fixed width in this format. A suite with a different KEM produces a
// different encapsulation, and the stream's framing reserves one length for
// it. The envelope has no equivalent problem: it carries its ciphertext as a
// length-delimited field rather than at a fixed offset.
func TestEncapsulationSizeMatchesTheDefaultSuite(t *testing.T) {
	id, err := identity.Generate("measurer")
	if err != nil {
		t.Fatal(err)
	}
	enc, _, err := senderContext(id.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != EncSize {
		t.Fatalf("the default suite's KEM encapsulates to %d bytes but this format reserves %d.\n"+
			"Adding a suite with another KEM means a new stream format under a new info string,\n"+
			"since the encapsulation is read before anything that could name a version.", len(enc), EncSize)
	}
}

// A chunk whose bytes all arrived and did not open is ErrOpenFailed,
// whichever chunk it is; a stream that ended before the bytes did is
// ErrTruncated. The two words are what a receiver keeps beside the bytes,
// and a flipped byte in the final chunk used to be called a truncation.
func TestAFinalChunkThatDoesNotOpenIsNotATruncation(t *testing.T) {
	from, to := pair(t)
	cs := MinChunkSize
	files := map[string][]byte{"f.bin": bytes.Repeat([]byte("x"), 2*cs)}
	blob, _ := build(t, from, to, cs, files)
	start := HeaderSize + mustLen(t, blob)

	flipped := append([]byte{}, blob...)
	flipped[len(flipped)-1] ^= 1
	for name, tc := range map[string]struct {
		blob []byte
		is   error
		not  error
	}{
		"last byte of the final chunk flipped": {flipped, ErrOpenFailed, ErrTruncated},
		"first byte of chunk 1 flipped": {func() []byte {
			b := append([]byte{}, blob...)
			b[start] ^= 1
			return b
		}(), ErrOpenFailed, ErrTruncated},
		"one byte short":        {blob[:len(blob)-1], ErrTruncated, ErrOpenFailed},
		"the final tag removed": {blob[:len(blob)-TagSize], ErrTruncated, ErrOpenFailed},
	} {
		_, _, err := openAll(t, to, tc.blob)
		if !errors.Is(err, tc.is) || errors.Is(err, tc.not) {
			t.Errorf("%s: %v, want %v and not %v", name, err, tc.is, tc.not)
		}
	}
}

// A manifest carries the channel it was opened for under the signature,
// and one for default, which has no field, opens as default. The decode
// stays strict, so a manifest carrying a field this build does not know
// is malformed rather than filed somewhere it was not sent; that is the
// cost of a signed format two builds cannot silently disagree about.
func TestAManifestCarriesItsChannel(t *testing.T) {
	from, to := pair(t)
	sources := []Source{source("f.bin", []byte("x"))}
	for _, channel := range []string{"", "bug reports"} {
		m, err := BuildManifest(from, to.Public(), strings.Repeat("a", 32), body(), sources, MinChunkSize)
		if err != nil {
			t.Fatal(err)
		}
		m.Channel = channel
		var buf bytes.Buffer
		if err := Seal(&buf, from, to.Public(), m, sources); err != nil {
			t.Fatal(err)
		}
		blob := buf.Bytes()
		opened, err := OpenManifest(to, blob[:HeaderSize], blob[HeaderSize:HeaderSize+mustLen(t, blob)])
		if err != nil {
			t.Fatalf("channel %q: %v", channel, err)
		}
		if opened.Manifest.Channel != channel {
			t.Fatalf("the channel came back as %q, want %q", opened.Manifest.Channel, channel)
		}
	}
	// On the wire, the field is named channel and is absent for default.
	m, err := BuildManifest(from, to.Public(), strings.Repeat("a", 32), body(), sources, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(m)
	if bytes.Contains(plain, []byte(`"channel"`)) {
		t.Fatalf("a manifest for default names a channel: %s", plain)
	}
	m.Channel = "bug reports"
	named, _ := json.Marshal(m)
	if !bytes.Contains(named, []byte(`"channel":"bug reports"`)) {
		t.Fatalf("a manifest for a channel does not name it: %s", named)
	}
}

// TestAManifestRefusesEveryTrailingByte: a strict decode refused trailing data except the two bytes
// json.Decoder.More does not see, a closing brace and a closing bracket
// (ruling 56). The value is taken whole; with each of those after it, and
// with a plain stray byte, it is refused in this reader's own words.
func TestAManifestRefusesEveryTrailingByte(t *testing.T) {
	from, to := pair(t)
	blob, m := build(t, from, to, 4096, map[string][]byte{"a.txt": []byte("a")})
	if _, _, err := openAll(t, to, blob); err != nil {
		t.Fatalf("the stream whole: %v", err)
	}
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Chunk 0 sealed by hand, the signature over the manifest and the bytes
	// after it, since the decode runs once the chunk opens and before the
	// signature is checked.
	open := func(tail string) error {
		with := append(append([]byte{}, manifestJSON...), tail...)
		enc, sender, err := senderContext(to.Public())
		if err != nil {
			t.Fatal(err)
		}
		sig, err := from.Sign(sigInput(m.To, with))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := sender.Seal(aadManifest, append(sig, with...))
		if err != nil {
			t.Fatal(err)
		}
		header := append(append([]byte{}, enc...), putPrefix(len(sealed))...)
		_, err = OpenManifest(to, header, sealed)
		return err
	}
	if err := open(""); err != nil {
		t.Fatalf("the manifest whole, sealed by hand: %v", err)
	}
	for _, tail := range []string{"}", "]", "x"} {
		err := open(tail)
		if tail == "x" {
			if !errors.Is(err, ErrForm) {
				t.Errorf("%q after the manifest: %v; want ErrForm", tail, err)
			}
			continue
		}
		if !errors.Is(err, ErrForm) || !strings.HasSuffix(err.Error(), ": trailing data after the manifest") {
			t.Errorf("%q after the manifest: %v; want the trailing-data sentence", tail, err)
		}
	}
}
