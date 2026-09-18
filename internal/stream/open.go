package stream

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// HeaderSize is what a receiver must read before it knows anything: the
// encapsulation and the length of the manifest chunk.
const HeaderSize = EncSize + PrefixSize

// ManifestLength reads the sealed manifest's length out of the first
// HeaderSize bytes and checks it against the bounds.
//
// The prefix is outside the AEAD, as a TLS record length is. A tampered prefix
// makes the receiver read the wrong bytes as chunk 0, and the AEAD refuses
// them; what the prefix must not be allowed to do is cause a large allocation
// before anything has been verified, which is why it is bounded here, before
// it is used for anything at all.
func ManifestLength(header []byte) (int, error) {
	if len(header) < HeaderSize {
		return 0, fmt.Errorf("%w: header is %d bytes, want %d", ErrTruncated, len(header), HeaderSize)
	}
	n := int(binary.BigEndian.Uint32(header[EncSize:HeaderSize]))
	if n < MinChunk0 || n > MaxChunk0 {
		return 0, fmt.Errorf("%w: manifest chunk claims %d bytes, outside [%d, %d]",
			ErrForm, n, MinChunk0, MaxChunk0)
	}
	return n, nil
}

// Opened is a verified manifest and the context that will open the payload.
type Opened struct {
	Manifest *Manifest
	// SealedManifestBytes is how long chunk 0 was on the wire, which is where
	// the payload begins. A receiver fetching the rest needs it and would
	// otherwise have to keep the header around to read the prefix again.
	SealedManifestBytes int
	// Sender is the key that signed the manifest, recomputed from the bundle
	// inside it. The caller decides whether that identity is one it will
	// accept; this package says only that the signature is theirs.
	Sender *identity.Public

	recipient *hpke.Recipient
}

// OpenManifest verifies chunk 0 and returns what it says.
//
// header is the first HeaderSize bytes and sealed is exactly the number of
// bytes ManifestLength reported. Nothing else has been read yet, so a caller
// can stop here: this is what makes it possible to see who a stream is from
// without downloading it.
func OpenManifest(self *identity.Identity, header, sealed []byte) (*Opened, error) {
	n, err := ManifestLength(header)
	if err != nil {
		return nil, err
	}
	if len(sealed) != n {
		return nil, fmt.Errorf("%w: manifest chunk is %d bytes, the prefix said %d",
			ErrTruncated, len(sealed), n)
	}
	recipient, err := recipientContext(header[:EncSize], self)
	if errors.Is(err, identity.ErrLocked) {
		// Not a stream that will not open: a key that is not here. The
		// chain is kept so the caller can tell, and nothing is dropped.
		return nil, fmt.Errorf("stream: opening the manifest: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpenFailed, err)
	}
	plaintext, err := recipient.Open(aadManifest, sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpenFailed, err)
	}
	if len(plaintext) < SigSize {
		return nil, fmt.Errorf("%w: manifest chunk is too short to hold a signature", ErrForm)
	}
	sig, manifestJSON := plaintext[:SigSize], plaintext[SigSize:]

	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifestJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the manifest", ErrForm)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.To != self.Fingerprint() {
		return nil, fmt.Errorf("%w: %w: manifest is addressed to %s", ErrForm, ErrNotForUs, m.To)
	}
	// Old is fine, the future is not: the same bound the envelope keeps.
	if m.Time.After(time.Now().Add(relayapi.MaxSkew)) {
		return nil, fmt.Errorf("%w: manifest is stamped %s, in the future", ErrForm, m.Time.UTC().Format(time.RFC3339))
	}

	// The claimed sender must be the one its own key material produces,
	// otherwise `from` is decoration.
	sender, err := identity.ParseBundle(m.FromBundle)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if sender.Fingerprint() != m.From {
		return nil, fmt.Errorf("%w: sender fingerprint does not match the bundle", ErrForm)
	}
	if !sender.Verify(sigInput(m.To, manifestJSON), sig) {
		return nil, ErrSignature
	}
	// Names come from the local peer list, never from the wire.
	sender.Name = ""
	return &Opened{
		Manifest: &m, SealedManifestBytes: n, Sender: sender, recipient: recipient,
	}, nil
}

// Writers is how a caller receives the payload: one io.Writer per attachment,
// created as each is reached, so nothing is opened until it is needed.
type Writers func(a Attachment) (io.WriteCloser, error)

// OpenPayload decrypts the body chunks from r and writes each attachment
// through Writers, verifying its digest as it goes.
//
// Nothing is buffered beyond one chunk. The caller is expected to write into a
// temporary place and move it only once this returns without error: a stream
// that fails at its last chunk must deliver nothing.
func (o *Opened) OpenPayload(r io.Reader, out Writers) error {
	m := o.Manifest
	sealed := make([]byte, m.ChunkSize+TagSize)
	bodyChunks := m.Chunks - 1
	remaining := m.PayloadBytes

	// The attachment being written, and how much of it is still to come.
	var (
		w      io.WriteCloser
		digest = sha256.New()
		left   int64
		next   int
	)
	closeCurrent := func() error {
		if w == nil {
			return nil
		}
		err := w.Close()
		w = nil
		return err
	}
	defer closeCurrent()

	for i := int64(0); i < bodyChunks; i++ {
		n := int64(m.ChunkSize)
		if n > remaining {
			n = remaining
		}
		if err := readFull(r, sealed[:n+TagSize]); err != nil {
			return err
		}
		aad := aadBody
		if i == bodyChunks-1 {
			aad = aadFinal
		}
		plain, err := o.recipient.Open(aad, sealed[:n+TagSize])
		if err != nil {
			// The last chunk is sealed under a different role, so a body
			// chunk passed off as the end fails exactly here. The bytes
			// were all read, so this is a chunk that did not open, not a
			// stream that ended early: readFull says that, before this.
			if i == bodyChunks-1 {
				return fmt.Errorf("%w: the final chunk did not open", ErrOpenFailed)
			}
			return fmt.Errorf("%w: chunk %d", ErrOpenFailed, i+1)
		}
		remaining -= n

		for len(plain) > 0 {
			if w == nil {
				if next >= len(m.Attachments) {
					return fmt.Errorf("%w: more payload than the manifest declares", ErrForm)
				}
				a := m.Attachments[next]
				next++
				wc, err := out(a)
				if err != nil {
					return err
				}
				w, left, digest = wc, a.Size, sha256.New()
			}
			take := int64(len(plain))
			if take > left {
				take = left
			}
			if _, err := w.Write(plain[:take]); err != nil {
				return err
			}
			digest.Write(plain[:take])
			plain = plain[take:]
			left -= take
			if left == 0 {
				a := m.Attachments[next-1]
				if got := hex.EncodeToString(digest.Sum(nil)); got != a.SHA256 {
					return fmt.Errorf("%w: %q", ErrDigest, a.Name)
				}
				if err := closeCurrent(); err != nil {
					return err
				}
			}
		}
	}

	if remaining != 0 {
		return fmt.Errorf("%w: %d payload bytes never arrived", ErrTruncated, remaining)
	}
	// An attachment of no bytes has no chunk to arrive in, so the loop above
	// never opened it unless bytes for a later one followed: every one the
	// manifest still names that is empty is made here, empty, its digest
	// checked like any other's, now that the final chunk has opened and
	// everything with bytes has landed. A stream that ended with an empty
	// attachment, or was one, used to be refused as truncated, and the
	// receiver acknowledged it away as damaged. One with bytes still
	// unwritten is truncated, below, as before.
	for next < len(m.Attachments) && m.Attachments[next].Size == 0 {
		a := m.Attachments[next]
		next++
		if got := hex.EncodeToString(sha256.New().Sum(nil)); got != a.SHA256 {
			return fmt.Errorf("%w: %q", ErrDigest, a.Name)
		}
		wc, err := out(a)
		if err != nil {
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
	}
	if next != len(m.Attachments) {
		return fmt.Errorf("%w: %d attachments were never written", ErrTruncated,
			len(m.Attachments)-next)
	}
	// Anything after the final chunk is somebody appending to a stream that
	// has already ended.
	var extra [1]byte
	if n, _ := io.ReadFull(r, extra[:]); n != 0 {
		return ErrTrailing
	}
	return closeCurrent()
}

// ToDirectory receives a payload into dir, atomically.
//
// OpenPayload writes as it decrypts, because a two gigabyte attachment cannot
// be held anywhere else, so a stream that fails at its last chunk has already
// handed some bytes to its writers. This is the shape that makes that safe:
// everything lands in a sibling temporary directory, and dir appears in one
// rename only after the final chunk has opened and every digest has matched.
// A failure leaves nothing but the removed temporary.
//
// dir must not already exist.
func (o *Opened) ToDirectory(r io.Reader, dir string) (err error) {
	if _, statErr := os.Stat(dir); statErr == nil {
		return fmt.Errorf("%w: %s already exists", ErrForm, dir)
	}
	tmp := dir + ".part"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmp)
		}
	}()

	if err := o.OpenPayload(r, func(a Attachment) (io.WriteCloser, error) {
		// The name has already been through ValidAttachmentName in Validate,
		// so it is a base name; Base is belt and braces.
		f, err := os.OpenFile(filepath.Join(tmp, filepath.Base(a.Name)),
			os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			// Two names Validate told apart are one file on this disk:
			// case folding it foresaw and refused, but a filesystem may
			// fold more, such as Unicode normalisation on APFS. That is
			// the manifest's fault, not the transport's, so it is refused
			// as malformed, and the receiver keeps the stream under
			// damaged and acknowledges it rather than meeting it again at
			// every fetch.
			return nil, fmt.Errorf("%w: attachment %q is one file with another on this disk", ErrForm, a.Name)
		}
		return f, err
	}); err != nil {
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return err
	}
	return nil
}
