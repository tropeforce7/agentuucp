package stream

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// Source is one attachment waiting to be sealed: its metadata, and something
// that will produce exactly Size bytes when asked.
type Source struct {
	Name  string
	Media string
	Size  int64
	// Open is called once, when the payload reaches this attachment. Keeping
	// it a function rather than a reader means nothing is held open while the
	// manifest is being built, and a file can be hashed and then re-read.
	Open func() (io.ReadCloser, error)
}

// Hash reads a source once and returns its digest, for building a manifest.
func (s Source) Hash() (string, error) {
	r, err := s.Open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", err
	}
	if n != s.Size {
		return "", fmt.Errorf("%w: %q changed size while it was being read: %d, expected %d",
			ErrForm, s.Name, n, s.Size)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BuildManifest hashes every source and assembles the manifest that will be
// signed. Each source is read once, in a streaming pass, so a two gigabyte
// attachment costs one buffer.
func BuildManifest(from *identity.Identity, to *identity.Public, id string,
	body Body, sources []Source, chunkSize int) (*Manifest, error) {

	m := &Manifest{
		V:          Version,
		ID:         id,
		From:       from.Fingerprint(),
		FromBundle: from.Public().Bundle(),
		To:         to.Fingerprint(),
		Time:       time.Now().UTC().Truncate(time.Second),
		ChunkSize:  chunkSize,
		Body:       body,
	}
	for _, src := range sources {
		digest, err := src.Hash()
		if err != nil {
			return nil, err
		}
		m.Attachments = append(m.Attachments, Attachment{
			Name: src.Name, Media: src.Media, Size: src.Size, SHA256: digest,
		})
		m.PayloadBytes += src.Size
	}
	m.Chunks = ChunkCount(m.PayloadBytes, chunkSize)
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Seal writes a whole stream to w.
//
// It holds one chunk of plaintext and one of ciphertext at a time, whatever
// the payload weighs. The sources are opened one after another and their bytes
// concatenated: the manifest's sizes are the only framing between them.
func Seal(w io.Writer, from *identity.Identity, to *identity.Public,
	m *Manifest, sources []Source) error {

	if err := m.Validate(); err != nil {
		return err
	}
	if m.From != from.Fingerprint() || m.To != to.Fingerprint() {
		return fmt.Errorf("%w: the manifest names a different sender or recipient", ErrForm)
	}
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if max := MaxChunk0 - TagSize - SigSize; len(manifestJSON) > max {
		return fmt.Errorf("%w: the manifest is %d bytes, over the %d byte limit; "+
			"attach long text as a file instead", ErrForm, len(manifestJSON), max)
	}

	enc, sender, err := senderContext(to)
	if err != nil {
		return err
	}
	if len(enc) != EncSize {
		return fmt.Errorf("%w: encapsulation is %d bytes, expected %d", ErrForm, len(enc), EncSize)
	}
	if _, err := w.Write(enc); err != nil {
		return err
	}

	// Chunk 0: the signature and the manifest, sealed under the manifest role.
	sig, err := from.Sign(sigInput(m.To, manifestJSON))
	if err != nil {
		return err
	}
	plaintext := make([]byte, 0, len(sig)+len(manifestJSON))
	plaintext = append(plaintext, sig...)
	plaintext = append(plaintext, manifestJSON...)
	sealed, err := sender.Seal(aadManifest, plaintext)
	if err != nil {
		return err
	}
	if len(sealed) > MaxChunk0 {
		return fmt.Errorf("%w: sealed manifest is %d bytes, over the %d byte limit",
			ErrForm, len(sealed), MaxChunk0)
	}
	if _, err := w.Write(putPrefix(len(sealed))); err != nil {
		return err
	}
	if _, err := w.Write(sealed); err != nil {
		return err
	}

	return sealPayload(w, sender, m, sources)
}

// sealPayload writes the body chunks. The last one carries the final marker,
// and there is always at least one even when there is nothing to send.
func sealPayload(w io.Writer, sender *hpke.Sender, m *Manifest, sources []Source) error {
	payload := &sourceReader{sources: sources}
	defer payload.Close()

	buf := make([]byte, m.ChunkSize)
	remaining := m.PayloadBytes
	bodyChunks := m.Chunks - 1

	for i := int64(0); i < bodyChunks; i++ {
		n := int64(m.ChunkSize)
		if n > remaining {
			n = remaining
		}
		if err := readFull(payload, buf[:n]); err != nil {
			return err
		}
		remaining -= n
		aad := aadBody
		if i == bodyChunks-1 {
			aad = aadFinal
		}
		sealed, err := sender.Seal(aad, buf[:n])
		if err != nil {
			return err
		}
		if _, err := w.Write(sealed); err != nil {
			return err
		}
	}
	if remaining != 0 {
		return fmt.Errorf("%w: %d payload bytes were not sealed", ErrForm, remaining)
	}
	// Anything left over means a source grew while it was being read, which
	// would have produced a stream that does not match its own manifest.
	var extra [1]byte
	if n, _ := payload.Read(extra[:]); n != 0 {
		return fmt.Errorf("%w: the attachments produced more bytes than the manifest declares", ErrForm)
	}
	return nil
}

// sourceReader concatenates the sources, opening each as it is reached.
type sourceReader struct {
	sources []Source
	current io.ReadCloser
	index   int
}

func (s *sourceReader) Read(p []byte) (int, error) {
	for {
		if s.current == nil {
			if s.index >= len(s.sources) {
				return 0, io.EOF
			}
			r, err := s.sources[s.index].Open()
			if err != nil {
				return 0, err
			}
			s.current = r
			s.index++
		}
		n, err := s.current.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			s.current.Close()
			s.current = nil
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (s *sourceReader) Close() error {
	if s.current != nil {
		err := s.current.Close()
		s.current = nil
		return err
	}
	return nil
}
