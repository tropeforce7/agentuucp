// Package stream carries a message too large to seal in one piece.
//
// A stream is one HPKE context and a sequence of chunks: a signed manifest
// first, then the attachment bytes concatenated in manifest order. Sealing and
// opening both work over an io.Reader and an io.Writer and never hold more
// than one chunk, so a two gigabyte message costs a few hundred kilobytes of
// memory at either end.
//
// The construction is deliberately the shape of age's STREAM. The standard
// library's crypto/hpke provides the stateful multi-shot context, which
// advances a nonce counter on every Seal and only on a successful Open, so
// reordering, duplication and cross-stream substitution all fail closed
// without anything being added here. What this package adds is a marker on the
// final chunk, so that a truncated stream is refused by the AEAD rather than
// by a length field, and a manifest whose signature covers what the payload
// must hash to.
package stream

import (
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
)

const (
	// Version is the manifest version. The stream format as a whole is named
	// by its info string, so an incompatible change moves that instead.
	Version = 1

	// infoDomain binds a stream to its recipient and separates it from an
	// envelope: neither can be opened as the other.
	infoDomain = "ccx-stream-v1"
	// sigDomain is the fourth thing an identity key signs, after requests,
	// envelopes and tokens.
	sigDomain = "ccx-stream-sig-v1"

	// chunkDomain prefixes the additional data that tells the three kinds of
	// chunk apart.
	chunkDomain = "ccx-chunk-v1"

	// EncSize is the X-Wing encapsulation the context begins with.
	EncSize = 1120
	// PrefixSize is the big-endian length of the sealed manifest chunk.
	PrefixSize = 4
	// TagSize is what AES-256-GCM appends to every chunk.
	TagSize = 16
	// SigSize is the signature at the front of chunk 0's plaintext.
	//
	// It is fixed, and that is a constraint on the identity suite rather than
	// an accident. Chunk 0 is signature || manifest, so a reader must know
	// the signature's length before it can find the manifest — and the
	// manifest is the only thing that says which suite the sender used, in
	// FromBundle. A suite whose signatures are not this length therefore
	// cannot be read by this format at all.
	//
	// Fixing it is a manifest version bump, not a constant: put the signature
	// after the manifest rather than before it, so the JSON delimits itself
	// and whatever remains is the signature of whatever length. Version 2 of
	// this format should do that. Until then TestSignatureSizeMatchesTheDefaultSuite
	// is what tells whoever adds a suite that this is waiting for them.
	SigSize = ed25519.SignatureSize

	// MinChunk0 is a tag, a signature and an empty object: the smallest a
	// sealed manifest chunk could conceivably be.
	MinChunk0 = TagSize + SigSize + 2
	// MaxChunk0 caps the sealed manifest chunk, and with it the message text,
	// at a megabyte. It is independent of ChunkSize so that a small body chunk
	// does not mean a small message.
	MaxChunk0 = 1 << 20

	// MaxPayloadBytes bounds what a manifest may declare, 2^62 bytes: the
	// same order as the relay's own cap on a stream, and what keeps every
	// sum made from a validated manifest — the chunk count, the size on
	// the wire, the attachments' total — inside int64 without a guard at
	// each addition. A manifest that declared MaxInt64 used to wrap
	// ChunkCount to two chunks and Size negative, and was refused only
	// later, as truncated, after the receiver had asked the relay for a
	// payload.
	MaxPayloadBytes int64 = 1 << 62

	// MinChunkSize and MaxChunkSize bound the payload chunk. The useful
	// property is that ChunkSize+TagSize fits the buffer a receiver reads
	// into, not that the plaintext is round.
	MinChunkSize = 4096
	MaxChunkSize = 16 << 20

	// DefaultChunkSize is 64 KiB less the tag, rounded down to a whole KiB, so
	// a sealed chunk is 64,528 bytes and fits a 64 KiB buffer.
	DefaultChunkSize = 63 << 10
	// DefaultThreshold is where auu switches from an envelope to a stream.
	DefaultThreshold = 64 << 10
)

// Additional data, one constant per role. The final chunk is sealed under
// aadFinal, so a stream that stops early cannot be opened to completion: the
// chunk the receiver expects to be last will not open as a body chunk, and a
// body chunk will not open as the last.
var (
	aadManifest = []byte(chunkDomain + "\x00")
	aadBody     = []byte(chunkDomain + "\x01")
	aadFinal    = []byte(chunkDomain + "\x02")
)

// Failures a caller can tell apart.
var (
	ErrForm      = errors.New("stream: malformed")
	ErrSignature = errors.New("stream: signature does not verify")
	// ErrNotForUs is a manifest that names another recipient. It is a form
	// failure and carries ErrForm too; it has a name so that a receiver
	// keeping the stream can say why in the envelope's words.
	ErrNotForUs   = errors.New("stream: addressed to somebody else")
	ErrTruncated  = errors.New("stream: ends early")
	ErrTrailing   = errors.New("stream: has bytes after its final chunk")
	ErrOpenFailed = errors.New("stream: could not be opened")
	ErrDigest     = errors.New("stream: attachment does not match its digest")
)

// Attachment is one file in a manifest. The data is not here; it is in the
// payload chunks, and the digest is what proves it arrived intact.
type Attachment struct {
	Name   string `json:"name"`
	Media  string `json:"media"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Body is the message itself, without attachment data.
type Body struct {
	Type      string `json:"type"`
	Subject   string `json:"subject"`
	Thread    string `json:"thread"`
	InReplyTo string `json:"in_reply_to"`
	Text      string `json:"text"`
}

// Manifest is chunk 0: what the message is, who wrote it, and what the payload
// must hash to. It is signed, and the signature travels inside the ciphertext,
// so the relay learns nothing about the sender from carrying it.
type Manifest struct {
	V            int          `json:"v"`
	ID           string       `json:"id"`
	From         string       `json:"from"`
	FromBundle   []byte       `json:"from_bundle"`
	To           string       `json:"to"`
	Time         time.Time    `json:"time"`
	ChunkSize    int          `json:"chunk_size"`
	Chunks       int64        `json:"chunks"`
	PayloadBytes int64        `json:"payload_bytes"`
	Body         Body         `json:"body"`
	Attachments  []Attachment `json:"attachments"`
	// Channel is the recipient's channel the stream was opened for, absent
	// for default, signed with the rest so the receiver can check it
	// against what the relay says. The manifest is decoded strictly, so a
	// name is one this build knows or the manifest is malformed.
	Channel string `json:"channel,omitempty"`
}

// ChunkCount is how many chunks a payload of n bytes takes, including the
// manifest. A stream with no payload still has one, empty, final chunk, so
// that every stream ends the same way and truncation has one rule. The
// arithmetic cannot wrap for a payload Validate accepts, which is at most
// MaxPayloadBytes; for one it would not, the answer means nothing.
func ChunkCount(payloadBytes int64, chunkSize int) int64 {
	if chunkSize <= 0 {
		return 0
	}
	body := (payloadBytes + int64(chunkSize) - 1) / int64(chunkSize)
	if body < 1 {
		body = 1
	}
	return 1 + body
}

// Size is the number of bytes a stream occupies on the wire, given the sealed
// length of its manifest chunk. Callers check it against what the relay says
// before fetching a payload.
func Size(sealedManifest int, payloadBytes int64, chunkSize int) int64 {
	chunks := ChunkCount(payloadBytes, chunkSize)
	return EncSize + PrefixSize + int64(sealedManifest) + (chunks-1)*TagSize + payloadBytes
}

// sigInput is the exact bytes an identity signs for a stream.
func sigInput(toFP string, manifest []byte) []byte {
	buf := make([]byte, 0, len(sigDomain)+len(toFP)+len(manifest))
	buf = append(buf, sigDomain...)
	buf = append(buf, toFP...)
	return append(buf, manifest...)
}

func info(toFP string) []byte { return []byte(infoDomain + toFP) }

// Validate applies every rule the format places on a manifest. It is called
// when one is built and again when one is opened, because the second time it
// has come from the wire.
func (m *Manifest) Validate() error {
	if m.V != Version {
		return fmt.Errorf("%w: unsupported manifest version %d", ErrForm, m.V)
	}
	if message.ValidID(m.ID) != nil {
		return fmt.Errorf("%w: id is not 32 lowercase hex characters", ErrForm)
	}
	if !identity.ValidFingerprint(m.From) || !identity.ValidFingerprint(m.To) {
		return fmt.Errorf("%w: from and to must be fingerprints", ErrForm)
	}
	if len(m.FromBundle) != identity.BundleSize {
		return fmt.Errorf("%w: from_bundle is %d bytes, want %d",
			ErrForm, len(m.FromBundle), identity.BundleSize)
	}
	if m.ChunkSize < MinChunkSize || m.ChunkSize > MaxChunkSize {
		return fmt.Errorf("%w: chunk_size %d is outside [%d, %d]",
			ErrForm, m.ChunkSize, MinChunkSize, MaxChunkSize)
	}
	if m.PayloadBytes < 0 {
		return fmt.Errorf("%w: payload_bytes is negative", ErrForm)
	}
	if m.PayloadBytes > MaxPayloadBytes {
		return fmt.Errorf("%w: payload_bytes %d is over the %d the format carries",
			ErrForm, m.PayloadBytes, MaxPayloadBytes)
	}
	if want := ChunkCount(m.PayloadBytes, m.ChunkSize); m.Chunks != want {
		return fmt.Errorf("%w: chunks is %d, but %d bytes at %d each needs %d",
			ErrForm, m.Chunks, m.PayloadBytes, m.ChunkSize, want)
	}
	var total int64
	for _, a := range m.Attachments {
		// The name is held to what any text is held to; a receiver
		// writes it under SafeName, and the sender's rule ran at
		// BuildManifest.
		if err := message.ValidAttachmentText(a.Name); err != nil {
			return fmt.Errorf("%w: %v", ErrForm, err)
		}
		// As an envelope's attachment is held at Open: the record a
		// receiver writes is held to the same at Load, and a stream
		// taken here with no media type would be a record refused there.
		if a.Media == "" {
			return fmt.Errorf("%w: attachment %q has no media type", ErrForm, a.Name)
		}
		if a.Size < 0 {
			return fmt.Errorf("%w: attachment %q has a negative size", ErrForm, a.Name)
		}
		if len(a.SHA256) != 64 || !isLowerHex(a.SHA256) {
			return fmt.Errorf("%w: attachment %q has no valid digest", ErrForm, a.Name)
		}
		// Checked before adding: sizes that wrapped the total back round
		// to payload_bytes were accepted, and the stream refused only after
		// the receiver had asked for a payload.
		if a.Size > MaxPayloadBytes-total {
			return fmt.Errorf("%w: attachments total more than the %d bytes the format carries",
				ErrForm, MaxPayloadBytes)
		}
		total += a.Size
	}
	if total != m.PayloadBytes {
		return fmt.Errorf("%w: attachments total %d bytes, payload_bytes says %d",
			ErrForm, total, m.PayloadBytes)
	}
	// The body is held to the message rules here, since a manifest's is
	// never opened as an envelope's is: without this the stream path was
	// a second door for a thread id that is a path, and would be one for
	// a subject or a text that drives a terminal.
	if err := message.ValidHeader(m.Body.Type, m.Body.Thread, m.Body.InReplyTo, m.Body.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrForm, err)
	}
	// A knock carries no attachment, so it is never a stream: a manifest
	// that says knock is a knock with attachments by another door.
	if m.Body.Type == message.TypeKnock {
		return fmt.Errorf("%w: a knock is one envelope, never a stream", ErrForm)
	}
	// A vouch and a vouch question are one envelope for the same reason:
	// a manifest's body has no field for the document or the fingerprint
	// asked about, so one that says either type is that type with nothing
	// in it, by another door.
	if m.Body.Type == message.TypeVouch || m.Body.Type == message.TypeVouchAsk {
		return fmt.Errorf("%w: a %s message is one envelope, never a stream", ErrForm, m.Body.Type)
	}
	if err := message.ValidText(m.Body.Text); err != nil {
		return fmt.Errorf("%w: %v", ErrForm, err)
	}
	return nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ValidateRelay is exported for the client, which checks a stream's audience
// the same way a token's is checked.
func ValidateRelay(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: relay is not a URL", ErrForm)
	}
	return nil
}

// readFull is io.ReadFull with a truncation error of this package's own, so a
// short stream is reported as such rather than as an unexpected EOF.
func readFull(r io.Reader, buf []byte) error {
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return err
	}
	return nil
}

func putPrefix(n int) []byte {
	var b [PrefixSize]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return b[:]
}

// senderContext and recipientContext exist so the tests can be explicit about
// which half they are exercising.
func senderContext(to *identity.Public) ([]byte, *hpke.Sender, error) {
	return hpke.NewSender(to.KEM, hpke.HKDFSHA256(), hpke.AES256GCM(), info(to.Fingerprint()))
}

func recipientContext(enc []byte, self *identity.Identity) (*hpke.Recipient, error) {
	return hpke.NewRecipient(enc, self.KEM(), hpke.HKDFSHA256(), hpke.AES256GCM(),
		info(self.Fingerprint()))
}
