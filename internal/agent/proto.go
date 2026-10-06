package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"io"
)

// The protocol: a 4-byte big-endian length, at most MaxFrame, and one JSON
// object; the same framing back. One request per connection.
//
// The wire is local and both ends are this binary, so the structs carry
// every field of every operation rather than a shape per operation, and a
// field that does not apply is empty. Unknown fields and unknown ops are
// refused, so a request from a newer build is an error rather than an
// operation with a field silently ignored.

// Operations.
const (
	OpStatus      = "status"
	OpUnlock      = "unlock"
	OpLock        = "lock"
	OpStop        = "stop"
	OpSign        = "sign"
	OpDecapsulate = "decapsulate"
	OpExchange    = "exchange"
	OpGenerate    = "generate"
)

// request is one message from a client.
type request struct {
	Op string `json:"op"`
	// Key names the key an operation is over: KeyIdentity, or CertPrefix
	// and a relay name, or PendingPrefix and a relay name.
	Key string `json:"key"`
	// Passphrase is unlock's. It is bytes, not a string, so that it can be
	// overwritten once the home key is out.
	Passphrase []byte `json:"passphrase"`
	// TTL is unlock's, in seconds; zero means until lock or exit.
	TTL int64 `json:"ttl"`
	// Send is read by two operations. On unlock it is the scope: false is
	// receive, true is send, and TTL is then the send scope's. On lock it
	// narrows rather than locks: true drops send scope and keeps receive.
	Send bool `json:"send"`
	// Message and Context are sign's: the message, and for an ML-DSA key
	// the context string, empty for none.
	Message []byte `json:"message"`
	Context []byte `json:"context"`
	// Ciphertext is decapsulate's: the ML-KEM-768 ciphertext.
	Ciphertext []byte `json:"ciphertext"`
	// Public is exchange's: the peer's X25519 point.
	Public []byte `json:"public"`
	// Params is generate's: the ML-DSA parameter set, 44, 65 or 87.
	Params int `json:"params"`
}

// response is one reply. Error is empty when OK is true.
type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`

	// status
	Locked bool     `json:"locked"`
	Until  string   `json:"until"`
	Keys   []string `json:"keys"`
	// Scope is receive or send while unlocked, and SendUntil is when send
	// scope ends; empty when it will not, or when the scope is receive.
	Scope     string `json:"scope"`
	SendUntil string `json:"send_until"`

	// sign
	Signature []byte `json:"signature"`
	// decapsulate and exchange
	Shared []byte `json:"shared"`
	// generate
	PublicKey []byte `json:"public_key"`
	Wrapped   []byte `json:"wrapped"`
	Handle    string `json:"handle"`
}

// ErrFrame is a frame that is not one: too long, or shorter than its
// prefix says.
var ErrFrame = errors.New("agent: bad frame")

// readFrame reads one length-prefixed message. The length is checked
// against MaxFrame before anything is allocated from it.
func readFrame(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes, over the %d byte limit", ErrFrame, n, MaxFrame)
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: empty", ErrFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFrame, err)
	}
	return buf, nil
}

// writeFrame writes one length-prefixed message.
func writeFrame(w io.Writer, body []byte) error {
	if len(body) > MaxFrame {
		return fmt.Errorf("%w: %d bytes to write, over the %d byte limit", ErrFrame, len(body), MaxFrame)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// decodeRequest parses a frame, refusing anything it does not know.
func decodeRequest(frame []byte) (*request, error) {
	var req request
	err := wire.Decode(frame, &req)
	if errors.Is(err, wire.ErrTrailing) {
		return nil, errors.New("agent: bad request: trailing data")
	}
	if err != nil {
		return nil, fmt.Errorf("agent: bad request: %v", err)
	}
	return &req, nil
}

// zero overwrites a byte slice. Go cannot promise the bytes were never
// copied elsewhere — a garbage collector moves nothing, but a JSON decoder
// allocates — so this is what can be done, done everywhere it can be.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
