package agent

import (
	"crypto"
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// connTimeout bounds one connection. A client sends one request and reads
// one reply; a peer that connects and says nothing must not hold a
// goroutine for ever.
const connTimeout = 30 * time.Second

// identityKeys is what the agent holds for the identity between unlock and
// lock: the seeds' halves as bytes, so that lock can overwrite them. The key
// objects are built per operation from these and dropped; see IMPLEMENTATION
// _NOTES.md for what that does and does not guarantee.
type identityKeys struct {
	suite     *identity.Suite
	signSeed  []byte
	mlkemSeed []byte
	x25519Key []byte
}

func (k *identityKeys) zero() {
	zero(k.signSeed)
	zero(k.mlkemSeed)
	zero(k.x25519Key)
}

// certKey is a machine key generate has made and nobody has written to disk
// yet: the ML-DSA seed and its parameter set.
type certKey struct {
	seed   []byte
	params mldsa.Parameters
}

// Server is one home's agent.
type Server struct {
	home Home
	now  func() time.Time
	log  *log.Logger
	uid  int

	mu      sync.Mutex
	homeKey []byte
	until   time.Time
	timer   *time.Timer
	ident   *identityKeys
	pending map[string]*certKey

	stopOnce sync.Once
	stopped  chan struct{}
}

// Options configures a Server. Every field is optional.
type Options struct {
	// Now is the clock. The tests inject one; the agent uses it for every
	// decision about the TTL, so a test can move time without waiting.
	Now func() time.Time
	// Log is where the agent says what it did. Never a key, never a
	// passphrase.
	Log *log.Logger
	// UID is whose connections are accepted. Zero means this process's.
	UID int
}

// NewServer makes an agent for a home. It holds nothing until Unlock.
func NewServer(home Home, opts Options) *Server {
	s := &Server{
		home:    home,
		now:     opts.Now,
		log:     opts.Log,
		uid:     opts.UID,
		pending: map[string]*certKey{},
		stopped: make(chan struct{}),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = log.New(io.Discard, "", 0)
	}
	if opts.UID == 0 {
		s.uid = os.Getuid()
	}
	return s
}

// Status is what status answers.
type Status struct {
	Locked bool
	// Until is when the agent will lock, and zero when it will not.
	Until time.Time
	// Keys names what is held: KeyIdentity when unlocked, and every
	// PendingPrefix key generate has made.
	Keys []string
}

// Serve answers connections on l until Stop, or until l is closed. It
// returns once every connection it accepted has been answered, so that a
// process which exits when Serve returns does not take a reply with it.
func (s *Server) Serve(l net.Listener) error {
	go func() {
		<-s.stopped
		l.Close()
	}()
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.stopped:
				return nil
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.Handle(conn)
		}()
	}
}

// Stopped is closed when the agent has been told to stop.
func (s *Server) Stopped() <-chan struct{} { return s.stopped }

// Stop locks and stops. Serve returns after it.
func (s *Server) Stop() {
	s.Lock()
	s.stopOnce.Do(func() { close(s.stopped) })
}

// Handle answers one connection: checks who connected, reads one request,
// writes one reply, closes.
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(s.now().Add(connTimeout))
	if uc, ok := conn.(*net.UnixConn); ok {
		uid, err := peerUID(uc)
		if err != nil || uid != s.uid {
			// Closed without a reply: a process of another user gets no
			// conversation at all, not even a refusal.
			s.log.Printf("refused a connection from uid %d (%v)", uid, err)
			return
		}
	}
	frame, err := readFrame(conn)
	if err != nil {
		s.reply(conn, &response{Error: err.Error()})
		return
	}
	req, err := decodeRequest(frame)
	if err != nil {
		zero(frame)
		s.reply(conn, &response{Error: err.Error()})
		return
	}
	resp := s.dispatch(req)
	zero(frame)
	zero(req.Passphrase)
	s.reply(conn, resp)
	// Stop is acknowledged and then acted on, in that order: the reply is
	// written before the listener closes and the process goes, so the
	// client that asked reads "ok" rather than a closed socket.
	if req.Op == OpStop && resp.OK {
		s.stopOnce.Do(func() { close(s.stopped) })
	}
}

func (s *Server) reply(conn net.Conn, resp *response) {
	if resp.Error == "" {
		resp.OK = true
	}
	body, err := json.Marshal(resp)
	if err != nil {
		return
	}
	writeFrame(conn, body)
	zero(resp.Shared)
}

// dispatch runs one request. It holds the mutex for the whole operation:
// every operation is short, and the key material is read by one at a time.
func (s *Server) dispatch(req *request) *response {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	switch req.Op {
	case OpStatus:
		st := s.statusLocked()
		r := &response{Locked: st.Locked, Keys: st.Keys}
		if !st.Until.IsZero() {
			r.Until = st.Until.Format(time.RFC3339)
		}
		return r
	case OpUnlock:
		if req.TTL < 0 {
			return &response{Error: "ttl must not be negative"}
		}
		if err := s.unlockLocked(req.Passphrase, time.Duration(req.TTL)*time.Second); err != nil {
			return &response{Error: err.Error()}
		}
		return &response{}
	case OpLock:
		s.lockLocked("lock")
		return &response{}
	case OpStop:
		// Locked here; stopped by Handle, after the reply.
		s.lockLocked("stop")
		return &response{}
	case OpSign:
		sig, err := s.signLocked(req.Key, req.Message, req.Context)
		if err != nil {
			return &response{Error: err.Error()}
		}
		return &response{Signature: sig}
	case OpDecapsulate:
		shared, err := s.decapsulateLocked(req.Key, req.Ciphertext)
		if err != nil {
			return &response{Error: err.Error()}
		}
		return &response{Shared: shared}
	case OpExchange:
		shared, err := s.exchangeLocked(req.Key, req.Public)
		if err != nil {
			return &response{Error: err.Error()}
		}
		return &response{Shared: shared}
	case OpGenerate:
		pub, wrapped, handle, err := s.generateLocked(req.Key, req.Params)
		if err != nil {
			return &response{Error: err.Error()}
		}
		return &response{PublicKey: pub, Wrapped: wrapped, Handle: handle}
	default:
		return &response{Error: fmt.Sprintf("unknown operation %q", req.Op)}
	}
}

// Unlock decrypts the home key with the passphrase, reads the identity, and
// holds both for ttl, or until Lock when ttl is zero. A wrong passphrase is
// refused now, and nothing is held after a failure.
func (s *Server) Unlock(passphrase []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlockLocked(passphrase, ttl)
}

func (s *Server) unlockLocked(passphrase []byte, ttl time.Duration) error {
	if ttl < 0 {
		return errors.New("ttl must not be negative")
	}
	// Whatever was held goes first, so that a failed unlock leaves nothing.
	s.lockLocked("unlock")
	encrypted, err := s.home.HomeKey()
	if err != nil {
		return fmt.Errorf("reading the home key: %v", err)
	}
	homeKey, err := keyfile.Decrypt(encrypted, passphrase)
	if err != nil {
		return err
	}
	suiteID, wrapped, err := s.home.IdentityKey()
	if err != nil {
		zero(homeKey)
		return fmt.Errorf("reading the identity key: %v", err)
	}
	suite, ok := identity.SuiteByID(identity.SuiteID(suiteID))
	if !ok {
		zero(homeKey)
		return fmt.Errorf("the identity uses suite %d, which this build does not know", suiteID)
	}
	if suite.ID != identity.SuiteEd25519XWing {
		// The KEM split below is X-Wing's. A suite with another KEM needs
		// its own, and until one exists this is where it would be missed.
		zero(homeKey)
		return fmt.Errorf("the agent cannot hold a %s identity", suite.Name)
	}
	der, err := keyfile.Unwrap(wrapped, homeKey)
	if err != nil {
		zero(homeKey)
		return fmt.Errorf("the identity key: %v", err)
	}
	signSeed, kemSeed, err := identity.ParseSecrets(der)
	zero(der)
	if err != nil {
		zero(homeKey)
		return err
	}
	if len(signSeed) != suite.SignSeedSize {
		zero(homeKey)
		zero(signSeed)
		zero(kemSeed)
		return fmt.Errorf("the identity key holds a %d-byte signing seed, not %d", len(signSeed), suite.SignSeedSize)
	}
	mlkemSeed, x25519Key, err := identity.SplitKEMSeed(kemSeed)
	zero(kemSeed)
	if err != nil {
		zero(homeKey)
		zero(signSeed)
		return err
	}
	s.homeKey = homeKey
	s.ident = &identityKeys{suite: suite, signSeed: signSeed, mlkemSeed: mlkemSeed, x25519Key: x25519Key}
	s.until = time.Time{}
	if ttl > 0 {
		s.until = s.now().Add(ttl)
		// The timer runs on the real clock and the decision on the injected
		// one, so a test with a moved clock is refused by the check every
		// request makes, and a real agent zeroes on time even when idle.
		s.timer = time.AfterFunc(ttl, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.expireLocked()
		})
		s.log.Printf("unlocked until %s", s.until.Format(time.RFC3339))
	} else {
		s.log.Printf("unlocked until lock or exit")
	}
	return nil
}

// Lock overwrites every byte of key material held and drops it.
func (s *Server) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked("lock")
}

func (s *Server) lockLocked(why string) {
	held := s.homeKey != nil
	zero(s.homeKey)
	s.homeKey = nil
	if s.ident != nil {
		s.ident.zero()
		s.ident = nil
	}
	for name, k := range s.pending {
		zero(k.seed)
		delete(s.pending, name)
	}
	s.until = time.Time{}
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if held {
		s.log.Printf("locked (%s)", why)
	}
}

// expireLocked locks if the TTL has passed. It is called on every request,
// so a request a millisecond after expiry is refused whether or not the
// timer has fired.
func (s *Server) expireLocked() {
	if s.homeKey != nil && !s.until.IsZero() && !s.now().Before(s.until) {
		s.lockLocked("ttl")
	}
}

// Status is what the agent holds.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	return s.statusLocked()
}

func (s *Server) statusLocked() Status {
	st := Status{Locked: s.homeKey == nil, Until: s.until}
	if s.ident != nil {
		st.Keys = append(st.Keys, KeyIdentity)
	}
	for name := range s.pending {
		st.Keys = append(st.Keys, name)
	}
	return st
}

// errLocked is the reply to every operation that needs a key.
var errLocked = errors.New(LockedMessage)

func (s *Server) signLocked(key string, message, context []byte) ([]byte, error) {
	if s.homeKey == nil {
		return nil, errLocked
	}
	switch {
	case key == KeyIdentity:
		if len(context) != 0 {
			return nil, errors.New("the identity's signatures take no context")
		}
		signer, err := s.ident.suite.NewSigner(s.ident.signSeed)
		if err != nil {
			return nil, err
		}
		return signer.Sign(message)
	case strings.HasPrefix(key, CertPrefix):
		relay, err := relayName(key, CertPrefix)
		if err != nil {
			return nil, err
		}
		k, err := s.certKeyFromDisk(relay)
		if err != nil {
			return nil, err
		}
		defer zero(k.seed)
		return signMLDSA(k, message, context)
	case strings.HasPrefix(key, PendingPrefix):
		relay, err := relayName(key, PendingPrefix)
		if err != nil {
			return nil, err
		}
		k, ok := s.pending[PendingPrefix+relay]
		if !ok {
			return nil, fmt.Errorf("no key %q: generate one first", key)
		}
		return signMLDSA(k, message, context)
	default:
		return nil, fmt.Errorf("unknown key %q", key)
	}
}

// signMLDSA signs with a machine key, under the context the request named.
func signMLDSA(k *certKey, message, context []byte) ([]byte, error) {
	priv, err := mldsa.NewPrivateKey(k.params, k.seed)
	if err != nil {
		return nil, err
	}
	var opts crypto.SignerOpts = crypto.Hash(0)
	if len(context) > 0 {
		opts = &mldsa.Options{Context: string(context)}
	}
	return priv.Sign(rand.Reader, message, opts)
}

// certKeyFromDisk reads and unwraps a relay's machine key. It is read every
// time rather than held, so that a cert.json written by a renewal a moment
// ago is what the next handshake signs with, and there is nothing to
// invalidate.
func (s *Server) certKeyFromDisk(relay string) (*certKey, error) {
	wrapped, err := s.home.CertKey(relay)
	if err != nil {
		return nil, err
	}
	der, err := keyfile.Unwrap(wrapped, s.homeKey)
	if err != nil {
		return nil, fmt.Errorf("the machine key for %s: %v", relay, err)
	}
	defer zero(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("the machine key for %s: %v", relay, err)
	}
	priv, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the machine key for %s is %T, not ML-DSA", relay, parsed)
	}
	return &certKey{seed: priv.Bytes(), params: priv.PublicKey().Parameters()}, nil
}

func (s *Server) decapsulateLocked(key string, ciphertext []byte) ([]byte, error) {
	if s.homeKey == nil {
		return nil, errLocked
	}
	if key != KeyIdentity {
		return nil, fmt.Errorf("only the identity decapsulates, not %q", key)
	}
	dk, err := mlkem.NewDecapsulationKey768(s.ident.mlkemSeed)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ciphertext)
}

func (s *Server) exchangeLocked(key string, public []byte) ([]byte, error) {
	if s.homeKey == nil {
		return nil, errLocked
	}
	if key != KeyIdentity {
		return nil, fmt.Errorf("only the identity exchanges, not %q", key)
	}
	priv, err := ecdh.X25519().NewPrivateKey(s.ident.x25519Key)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// generateLocked makes a machine key for a relay and holds it under the
// pending name. It returns the public key, PKIX DER, and the wrapped form
// the client writes into cert.json once the relay has issued a certificate.
//
// The pending name is not the on-disk name deliberately: a renewal asks for
// a new key while the connection it renews over is authenticated with the
// old one, and if the new key answered to the old name a handshake between
// the two moments would present the old certificate with the new key.
func (s *Server) generateLocked(key string, params int) (pub, wrapped []byte, handle string, err error) {
	if s.homeKey == nil {
		return nil, nil, "", errLocked
	}
	relay, err := relayName(key, CertPrefix)
	if err != nil {
		return nil, nil, "", err
	}
	set, err := clientca.ParameterSet(params)
	if err != nil {
		return nil, nil, "", err
	}
	priv, err := mldsa.GenerateKey(set)
	if err != nil {
		return nil, nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", err
	}
	defer zero(der)
	wrapped, err = keyfile.Wrap(der, s.homeKey)
	if err != nil {
		return nil, nil, "", err
	}
	pub, err = x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		return nil, nil, "", err
	}
	handle = PendingPrefix + relay
	if old, ok := s.pending[handle]; ok {
		zero(old.seed)
	}
	s.pending[handle] = &certKey{seed: priv.Bytes(), params: set}
	return pub, wrapped, handle, nil
}

// relayName is the relay a key name refers to, checked as a name so that it
// can be a directory segment and nothing else.
func relayName(key, prefix string) (string, error) {
	name := strings.TrimPrefix(key, prefix)
	if name == key {
		return "", fmt.Errorf("key %q does not begin with %q", key, prefix)
	}
	if err := identity.ValidName(name); err != nil {
		return "", fmt.Errorf("key %q: %v", key, err)
	}
	return name, nil
}
