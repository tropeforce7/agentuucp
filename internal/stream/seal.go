package stream

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/wire"
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
	return BuildManifestSections(from, to, id, body, sources, chunkSize, nil)
}

// BuildManifestSections is BuildManifest with sections: held to wire.Check
// by Validate, and the manifest is VersionSections exactly when there is any
// (D30). It is BuildManifestMany for one recipient, which writes no
// recipients section of its own.
func BuildManifestSections(from *identity.Identity, to *identity.Public, id string,
	body Body, sources []Source, chunkSize int, sections []wire.Section) (*Manifest, error) {
	ms, err := buildManifests(from, []*identity.Public{to}, id, body, sources, chunkSize, sections)
	if err != nil {
		return nil, err
	}
	return ms[0], nil
}

// BuildManifestMany is one stream's manifest for each of several
// recipients (P2, D49): one id, one time, one body and one list of sections
// for every copy, and the sources hashed once, however many copies there
// are. With more than one recipient it adds the recipients section, naming
// every recipient in the order given; with one it adds nothing. The
// manifests come back in the recipients' order, each to be signed and
// sealed for its own recipient by Seal.
func BuildManifestMany(from *identity.Identity, to []*identity.Public, id string,
	body Body, sources []Source, chunkSize int, sections []wire.Section) ([]*Manifest, error) {
	if len(to) == 0 {
		return nil, fmt.Errorf("%w: a stream to nobody", ErrForm)
	}
	if len(to) > 1 {
		for _, s := range sections {
			if s.Name == recipients.Name {
				return nil, fmt.Errorf("%w: the %s section is written by BuildManifestMany from the recipients it is given", ErrForm, recipients.Name)
			}
		}
		fps := make([]string, len(to))
		for i, r := range to {
			fps[i] = r.Fingerprint()
		}
		list, err := recipients.Section(fps)
		if err != nil {
			return nil, err
		}
		sections = append(append([]wire.Section{}, sections...), list)
	}
	return buildManifests(from, to, id, body, sources, chunkSize, sections)
}

// buildManifests is every copy's manifest. Each is held to Validate and
// its list to the rule for its own recipient, so a list given by hand is
// held as BuildManifestMany's is.
func buildManifests(from *identity.Identity, to []*identity.Public, id string,
	body Body, sources []Source, chunkSize int, sections []wire.Section) ([]*Manifest, error) {

	v := Version
	if len(sections) > 0 {
		v = VersionSections
	}
	var attachments []Attachment
	var payload int64
	for _, src := range sources {
		digest, err := src.Hash()
		if err != nil {
			return nil, err
		}
		attachments = append(attachments, Attachment{
			Name: src.Name, Media: src.Media, Size: src.Size, SHA256: digest,
		})
		payload += src.Size
	}
	// The sender's rule for attachment names runs here, where every
	// stream leaves, and nowhere on the receiving path: a receiver
	// writes whatever name arrives under SafeName of it.
	names := make([]string, 0, len(attachments))
	for _, a := range attachments {
		names = append(names, a.Name)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ms := make([]*Manifest, 0, len(to))
	for _, r := range to {
		m := &Manifest{
			V:            v,
			Sections:     sections,
			ID:           id,
			From:         from.Fingerprint(),
			FromBundle:   from.Public().Bundle(),
			To:           r.Fingerprint(),
			Time:         now,
			ChunkSize:    chunkSize,
			Body:         body,
			Attachments:  append([]Attachment(nil), attachments...),
			PayloadBytes: payload,
		}
		m.Chunks = ChunkCount(m.PayloadBytes, chunkSize)
		if err := m.Validate(); err != nil {
			return nil, err
		}
		if err := message.ValidAttachmentNames(names); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrForm, err)
		}
		if _, err := recipients.CheckSections(m.Sections, m.Body.Type, m.To); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrForm, err)
		}
		ms = append(ms, m)
	}
	return ms, nil
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
	if len(sources) != len(m.Attachments) {
		return fmt.Errorf("%w: %d sources for a manifest of %d attachments", ErrForm, len(sources), len(m.Attachments))
	}
	payload := &sourceReader{sources: sources, attachments: m.Attachments}
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
	// The read past the end is also what ends the last attachment and
	// holds it to its manifest entry.
	var extra [1]byte
	n, err := payload.Read(extra[:])
	if n != 0 {
		return fmt.Errorf("%w: the attachments produced more bytes than the manifest declares", ErrForm)
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

// ErrChanged is an attachment whose bytes, as sealed, are not the ones its
// manifest entry was made from: the file changed between its hashing and
// its sealing (G34, R49). The stream would be refused by its recipient as
// damaged after the send had said it went, so it is refused here, before
// anything is uploaded.
var ErrChanged = errors.New("changed while it was being sent; send it again")

// holdSources is the check above; a test of the receiver's own digest
// check turns it off to seal the stream it needs, which this package
// would otherwise refuse to make.
var holdSources = true

// sourceReader concatenates the sources, opening each as it is reached,
// and holds each, as it ends, to its manifest entry's size and digest, so
// what is sealed is what the manifest signs.
type sourceReader struct {
	sources     []Source
	attachments []Attachment
	current     io.ReadCloser
	index       int
	hash        hash.Hash
	read        int64
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
			s.hash, s.read = sha256.New(), 0
		}
		n, err := s.current.Read(p)
		if n > 0 {
			s.hash.Write(p[:n])
			s.read += int64(n)
			return n, nil
		}
		if err == io.EOF {
			s.current.Close()
			s.current = nil
			a := s.attachments[s.index-1]
			if holdSources && (s.read != a.Size || hex.EncodeToString(s.hash.Sum(nil)) != a.SHA256) {
				return 0, fmt.Errorf("%w: %s %w", ErrForm, a.Name, ErrChanged)
			}
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
