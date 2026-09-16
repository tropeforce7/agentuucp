package agent

import (
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// dialTimeout bounds connecting to the socket and each request over it. The
// agent answers in microseconds; anything longer is an agent that is not
// there.
const dialTimeout = 10 * time.Second

// Client talks to one home's agent, one connection per request, caching
// nothing but the socket's path.
type Client struct {
	socket string
}

// NewClient is a client for the agent of a home. Nothing is connected until
// an operation; opening a home is free.
func NewClient(home string) (*Client, error) {
	socket, err := SocketPath(home)
	if err != nil {
		return nil, err
	}
	return &Client{socket: socket}, nil
}

// Socket is the path this client connects to.
func (c *Client) Socket() string { return c.socket }

// call sends one request and reads its reply. A socket nobody answers on
// is ErrNotRunning; an error the agent sent back is returned as its text.
func (c *Client) call(req *request) (*response, error) {
	conn, err := net.DialTimeout("unix", c.socket, dialTimeout)
	if err != nil {
		if isNotRunning(err) {
			return nil, ErrNotRunning
		}
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout))
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	// The agent closes a connection from another user without a word, and
	// that shows up here as a failed write, a reset or an EOF depending on
	// which side got there first; all of them are the one condition.
	refused := func(err error) error {
		return fmt.Errorf("agent: the agent closed the connection without answering (%v); "+
			"is it running as a different user?", err)
	}
	if err := writeFrame(conn, body); err != nil {
		return nil, refused(err)
	}
	zero(body)
	frame, err := readFrame(conn)
	if err != nil {
		var ne net.Error
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || !errors.As(err, &ne) || !ne.Timeout() {
			return nil, refused(err)
		}
		return nil, fmt.Errorf("agent: reading the reply: %w", err)
	}
	var resp response
	if err := json.Unmarshal(frame, &resp); err != nil {
		return nil, fmt.Errorf("agent: bad reply: %w", err)
	}
	if !resp.OK {
		if resp.Error == LockedMessage {
			return nil, fmt.Errorf("%w: %s", identity.ErrLocked, resp.Error)
		}
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}

// isNotRunning tells "no agent" from "something is wrong": the socket file
// is missing, or exists and nothing is listening on it. The errnos are per
// platform (refusedErrnos); the text is a second line for a wrapper that
// dropped the errno.
func isNotRunning(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	for _, e := range refusedErrnos {
		if errors.Is(err, e) {
			return true
		}
	}
	return strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no such file") ||
		strings.Contains(err.Error(), "actively refused")
}

// Status asks whether the agent is locked and what it holds. ErrNotRunning
// when there is none.
func (c *Client) Status() (Status, error) {
	resp, err := c.call(&request{Op: OpStatus})
	if err != nil {
		return Status{}, err
	}
	st := Status{Locked: resp.Locked, Keys: resp.Keys}
	if resp.Until != "" {
		if st.Until, err = time.Parse(time.RFC3339, resp.Until); err != nil {
			return Status{}, fmt.Errorf("agent: bad until %q: %w", resp.Until, err)
		}
	}
	return st, nil
}

// Unlock hands the agent the passphrase and how long to stay unlocked. It
// is the one operation that carries a passphrase, and only auu unlock and
// auu passphrase call it.
func (c *Client) Unlock(passphrase []byte, ttl time.Duration) error {
	if ttl < 0 {
		return errors.New("agent: ttl must not be negative")
	}
	_, err := c.call(&request{Op: OpUnlock, Passphrase: passphrase, TTL: int64(ttl / time.Second)})
	return err
}

// Lock tells the agent to drop what it holds.
func (c *Client) Lock() error {
	_, err := c.call(&request{Op: OpLock})
	return err
}

// Stop tells the agent to lock and exit.
func (c *Client) Stop() error {
	_, err := c.call(&request{Op: OpStop})
	return err
}

// keyErr is what a key operation returns when the agent is not there:
// locked, as far as any command is concerned.
func keyErr(err error) error {
	if errors.Is(err, ErrNotRunning) {
		return fmt.Errorf("%w: %w", identity.ErrLocked, err)
	}
	return err
}

// Sign asks for a signature over message by the named key. context is for
// an ML-DSA key and must be empty for the identity.
func (c *Client) Sign(key string, message, context []byte) ([]byte, error) {
	resp, err := c.call(&request{Op: OpSign, Key: key, Message: message, Context: context})
	if err != nil {
		return nil, keyErr(err)
	}
	return resp.Signature, nil
}

// Decapsulate asks the identity's ML-KEM half for the shared secret in a
// ciphertext.
func (c *Client) Decapsulate(key string, ciphertext []byte) ([]byte, error) {
	resp, err := c.call(&request{Op: OpDecapsulate, Key: key, Ciphertext: ciphertext})
	if err != nil {
		return nil, keyErr(err)
	}
	return resp.Shared, nil
}

// Exchange asks the identity's X25519 half for the shared secret with a
// peer's point.
func (c *Client) Exchange(key string, public []byte) ([]byte, error) {
	resp, err := c.call(&request{Op: OpExchange, Key: key, Public: public})
	if err != nil {
		return nil, keyErr(err)
	}
	return resp.Shared, nil
}

// Generated is a machine key the agent has made and holds.
type Generated struct {
	// Public is the key's public half.
	Public *mldsa.PublicKey
	// Wrapped is the PEM cert.json carries once the relay has issued the
	// certificate.
	Wrapped []byte
	// Handle is the name to sign the certificate request under.
	Handle string
}

// Generate asks the agent to make a machine key for a relay: key is
// CertPrefix and the relay name, params the ML-DSA parameter set.
func (c *Client) Generate(key string, params int) (*Generated, error) {
	resp, err := c.call(&request{Op: OpGenerate, Key: key, Params: params})
	if err != nil {
		return nil, keyErr(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("agent: the generated public key: %w", err)
	}
	pub, ok := parsed.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("agent: the generated public key is %T, not ML-DSA", parsed)
	}
	return &Generated{Public: pub, Wrapped: resp.Wrapped, Handle: resp.Handle}, nil
}

// The remote halves an identity is composed from.

// identitySigner is identity.Signer over the agent.
type identitySigner struct {
	c   *Client
	pub []byte
}

func (s identitySigner) Public() []byte { return append([]byte{}, s.pub...) }
func (s identitySigner) Sign(msg []byte) ([]byte, error) {
	return s.c.Sign(KeyIdentity, msg, nil)
}

// IdentitySigner is the identity's signing half, performed by the agent,
// with the public key as the bundle carries it.
func (c *Client) IdentitySigner(pub []byte) identity.Signer {
	return identitySigner{c: c, pub: append([]byte{}, pub...)}
}

// decapsulator is crypto.Decapsulator over the agent's ML-KEM-768 half.
type decapsulator struct {
	c  *Client
	ek *mlkem.EncapsulationKey768
}

func (d decapsulator) Encapsulator() crypto.Encapsulator { return d.ek }
func (d decapsulator) Decapsulate(ciphertext []byte) ([]byte, error) {
	return d.c.Decapsulate(KeyIdentity, ciphertext)
}

// exchanger is ecdh.KeyExchanger over the agent's X25519 half.
type exchanger struct {
	c   *Client
	pub *ecdh.PublicKey
}

func (e exchanger) PublicKey() *ecdh.PublicKey { return e.pub }
func (e exchanger) Curve() ecdh.Curve          { return ecdh.X25519() }
func (e exchanger) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	return e.c.Exchange(KeyIdentity, peer.Bytes())
}

// IdentityKEM is the identity's KEM, performed by the agent: an X-Wing
// private key composed by crypto/hpke from a remote decapsulator and a
// remote exchanger, with the public halves as the bundle carries them.
func (c *Client) IdentityKEM(kemPub []byte) (hpke.PrivateKey, error) {
	ek, x, err := identity.SplitKEMPublic(kemPub)
	if err != nil {
		return nil, err
	}
	return hpke.NewHybridPrivateKey(decapsulator{c: c, ek: ek}, exchanger{c: c, pub: x})
}

// Identity is the whole identity over the agent: FromRemote with both
// halves from this client, for the bundle identity.json carries.
func (c *Client) Identity(suite *identity.Suite, name string, bundle []byte) (*identity.Identity, error) {
	pub, err := identity.ParseBundle(bundle)
	if err != nil {
		return nil, err
	}
	kem, err := c.IdentityKEM(pub.KEM.Bytes())
	if err != nil {
		return nil, err
	}
	return identity.FromRemote(suite, name, bundle, c.IdentitySigner(pub.SignPublic()), kem)
}

// certSigner is crypto.Signer over a machine key the agent holds or can
// read. crypto/tls and crypto/x509 both sign ML-DSA through
// crypto.SignMessage with the raw message and no hash, which is exactly
// what is forwarded; a context in *mldsa.Options goes with it.
type certSigner struct {
	c   *Client
	key string
	pub *mldsa.PublicKey
}

func (s certSigner) Public() crypto.PublicKey { return s.pub }
func (s certSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var context []byte
	if o, ok := opts.(*mldsa.Options); ok && o != nil {
		context = []byte(o.Context)
	} else if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("agent: ML-DSA signs the message, not a %s digest", opts.HashFunc())
	}
	return s.c.Sign(s.key, message, context)
}

// CertSigner is a machine key's signing half, performed by the agent: key
// is CertPrefix and the relay name, or the Handle Generate returned.
func (c *Client) CertSigner(key string, pub *mldsa.PublicKey) crypto.Signer {
	return certSigner{c: c, key: key, pub: pub}
}
