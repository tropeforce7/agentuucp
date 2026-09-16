package agent

import (
	"bytes"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

const passphrase = "correct horse battery staple"

// fakeHome is a Home in memory: an identity under a home key under the test
// passphrase, and machine keys a test adds as it goes. The store's
// implementation is tested with the store; this is the agent's contract.
type fakeHome struct {
	root    string
	id      *identity.Identity
	homeKey []byte
	encHome []byte
	identKy []byte

	mu    sync.Mutex
	certs map[string][]byte
}

func newFakeHome(t *testing.T) *fakeHome {
	t.Helper()
	id, err := identity.Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := testutil.Seed(t)
	homeKey := testutil.Bytes(r, keyfile.HomeKeySize)
	encHome, err := keyfile.Encrypt(homeKey, keyfile.TestPassphrase(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := id.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	identKey, err := keyfile.Wrap(secrets, homeKey)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHome{
		root: t.TempDir(), id: id, homeKey: homeKey, encHome: encHome, identKy: identKey,
		certs: map[string][]byte{},
	}
}

func (h *fakeHome) Root() string             { return h.root }
func (h *fakeHome) HomeKey() ([]byte, error) { return h.encHome, nil }
func (h *fakeHome) IdentityKey() (uint8, []byte, error) {
	return uint8(h.id.Suite().ID), h.identKy, nil
}
func (h *fakeHome) CertKey(relay string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w, ok := h.certs[relay]
	if !ok {
		return nil, fmt.Errorf("no machine key for %s", relay)
	}
	return w, nil
}

// addCert writes a machine key for a relay the way cert.json holds one, and
// returns the key.
func (h *fakeHome) addCert(t *testing.T, relay string, params mldsa.Parameters) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := keyfile.Wrap(der, h.homeKey)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.certs[relay] = wrapped
	h.mu.Unlock()
	return key
}

// runtimeDirFor points the agent at a short temporary directory. t.TempDir
// on macOS is long enough to push a socket path past the 104-byte limit,
// and the runtime directory is the thing under test here anyway.
func runtimeDirFor(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

// testClock is a clock a test moves and the agent's goroutines read.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// running is an agent serving a fake home over a real socket.
type running struct {
	home   *fakeHome
	server *Server
	client *Client
	clock  *testClock
}

func startAgent(t *testing.T) *running {
	t.Helper()
	runtimeDirFor(t)
	home := newFakeHome(t)
	clock := &testClock{t: time.Now()}
	s := NewServer(home, Options{Now: clock.Now})
	l, err := Listen(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		s.Stop()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
		l.Close()
	})
	c, err := NewClient(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	return &running{home: home, server: s, client: c, clock: clock}
}

func (r *running) unlock(t *testing.T, ttl time.Duration) {
	t.Helper()
	if err := r.client.Unlock([]byte(passphrase), ttl); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

func TestTheAgentSignsAndDecapsulatesWhatItHolds(t *testing.T) {
	a := startAgent(t)
	st, err := a.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Locked || len(st.Keys) != 0 {
		t.Fatalf("a fresh agent is %+v, want locked and empty", st)
	}
	a.unlock(t, DefaultTTL)
	st, err = a.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Locked || len(st.Keys) != 1 || st.Keys[0] != KeyIdentity {
		t.Fatalf("after unlock the agent is %+v", st)
	}
	if want := a.clock.Now().Add(DefaultTTL); !st.Until.Equal(want.Truncate(time.Second)) {
		t.Errorf("until is %s, want %s", st.Until, want)
	}

	r, seed := testutil.Seed(t)
	msg := testutil.Bytes(r, 1+r.IntN(500))
	sig, err := a.client.Sign(KeyIdentity, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !a.home.id.Public().Verify(msg, sig) {
		t.Errorf("the agent's signature does not verify under the identity's public key (seed %d)", seed)
	}
	if _, err := a.client.Sign(KeyIdentity, msg, []byte("ctx")); err == nil {
		t.Error("a context on an Ed25519 signature was accepted")
	}

	// The whole identity, composed over the socket, opens what was sealed
	// to the public half — the envelope's shape without the envelope.
	remote, err := a.client.Identity(a.home.id.Suite(), "ada", a.home.id.Public().Bundle())
	if err != nil {
		t.Fatal(err)
	}
	if remote.Fingerprint() != a.home.id.Fingerprint() {
		t.Fatal("the remote identity has a different fingerprint")
	}
	ct, err := hpke.Seal(a.home.id.Public().KEM, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"), msg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := hpke.Open(remote.KEM(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"), ct)
	if err != nil {
		t.Fatalf("the remote KEM did not open a message sealed to the identity: %v (seed %d)", err, seed)
	}
	if !bytes.Equal(back, msg) {
		t.Error("the plaintext came back changed")
	}
	sig, err = remote.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !a.home.id.Public().Verify(msg, sig) {
		t.Error("the remote identity's signature does not verify")
	}

	// A machine key on disk signs under its name, with and without a
	// context, and the signature verifies under its public key.
	key := a.home.addCert(t, "work", mldsa.MLDSA65())
	signer := a.client.CertSigner(CertPrefix+"work", key.PublicKey())
	sig, err = signer.Sign(nil, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(key.PublicKey(), msg, sig, nil); err != nil {
		t.Errorf("the machine key's signature does not verify: %v", err)
	}
	sig, err = signer.Sign(nil, msg, &mldsa.Options{Context: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(key.PublicKey(), msg, sig, &mldsa.Options{Context: "tls"}); err != nil {
		t.Errorf("the machine key's signature under a context does not verify: %v", err)
	}
	if err := mldsa.Verify(key.PublicKey(), msg, sig, nil); err == nil {
		t.Error("a signature made under a context verified without one: the context was dropped")
	}
	if _, err := a.client.Sign(CertPrefix+"nowhere", msg, nil); err == nil || !strings.Contains(err.Error(), "no machine key for nowhere") {
		t.Errorf("a key that is not there gave %v", err)
	}
	if _, err := a.client.Sign(CertPrefix+"../x", msg, nil); err == nil {
		t.Error("a relay name that is a path was accepted")
	}
	if _, err := a.client.Sign("nothing", msg, nil); err == nil {
		t.Error("an unknown key name was accepted")
	}

	// Lock, and it is locked; unlock again needs no restart.
	if err := a.client.Lock(); err != nil {
		t.Fatal(err)
	}
	if st, _ := a.client.Status(); !st.Locked {
		t.Error("not locked after lock")
	}
	a.unlock(t, 0)
	if st, _ := a.client.Status(); st.Locked || !st.Until.IsZero() {
		t.Errorf("after an unlock with no ttl the agent is %+v", st)
	}
}

// TestALockedAgentRefusesByName: the exact error text for every key-needing
// op; status and lock still answer; a client that finds no agent at all
// reports the same condition.
func TestALockedAgentRefusesByName(t *testing.T) {
	a := startAgent(t)
	for name, op := range map[string]func() error{
		"sign": func() error { _, err := a.client.Sign(KeyIdentity, []byte("m"), nil); return err },
		"decapsulate": func() error {
			_, err := a.client.Decapsulate(KeyIdentity, make([]byte, 1088))
			return err
		},
		"exchange": func() error { _, err := a.client.Exchange(KeyIdentity, make([]byte, 32)); return err },
		"generate": func() error { _, err := a.client.Generate(CertPrefix+"work", 65); return err },
	} {
		err := op()
		if !errors.Is(err, identity.ErrLocked) {
			t.Errorf("%s on a locked agent gave %v, want identity.ErrLocked", name, err)
		}
		if err == nil || !strings.HasSuffix(err.Error(), LockedMessage) {
			t.Errorf("%s on a locked agent says %q, want it to end with %q", name, err, LockedMessage)
		}
	}
	if _, err := a.client.Status(); err != nil {
		t.Errorf("status on a locked agent: %v", err)
	}
	if err := a.client.Lock(); err != nil {
		t.Errorf("lock on a locked agent: %v", err)
	}

	// No agent at all: the socket is gone.
	if err := a.client.Stop(); err != nil {
		t.Fatal(err)
	}
	<-a.server.Stopped()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(a.client.Socket()); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the socket was not removed after stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := a.client.Status(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("status with no agent gave %v, want ErrNotRunning", err)
	}
	_, err := a.client.Sign(KeyIdentity, []byte("m"), nil)
	if !errors.Is(err, identity.ErrLocked) || !errors.Is(err, ErrNotRunning) {
		t.Errorf("sign with no agent gave %v, want both ErrLocked and ErrNotRunning", err)
	}
}

func TestTheWrongPassphraseIsRefusedAtUnlock(t *testing.T) {
	a := startAgent(t)
	a.unlock(t, DefaultTTL)
	err := a.client.Unlock([]byte(passphrase+"x"), DefaultTTL)
	if err == nil || err.Error() != keyfile.ErrPassphrase.Error() {
		t.Fatalf("a wrong passphrase gave %v, want %q", err, keyfile.ErrPassphrase)
	}
	// Nothing is held after: not even what the good unlock before it held.
	st, err := a.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Locked || len(st.Keys) != 0 || !st.Until.IsZero() {
		t.Errorf("after a refused unlock the agent is %+v, want locked and empty", st)
	}
	a.server.mu.Lock()
	held := a.server.homeKey != nil || a.server.ident != nil
	a.server.mu.Unlock()
	if held {
		t.Error("the server still holds key material after a refused unlock")
	}
	if err := a.client.Unlock(nil, DefaultTTL); !errors.Is(err, keyfile.ErrEmptyPassphrase) && (err == nil || err.Error() != keyfile.ErrEmptyPassphrase.Error()) {
		t.Errorf("an empty passphrase gave %v", err)
	}
	if err := a.client.Unlock([]byte(passphrase), -time.Second); err == nil {
		t.Error("a negative ttl was accepted")
	}
}

// TestTTLLocksOnTheClock: unlocked at t, a request at t+ttl-1s succeeds, at
// t+ttl it is refused, with the timer goroutine not having run — the
// injected clock moved and the real one did not.
func TestTTLLocksOnTheClock(t *testing.T) {
	a := startAgent(t)
	start := a.clock.Now()
	const ttl = time.Hour
	a.unlock(t, ttl)
	a.clock.Set(start.Add(ttl - time.Second))
	if _, err := a.client.Sign(KeyIdentity, []byte("m"), nil); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}
	a.clock.Set(start.Add(ttl))
	if _, err := a.client.Sign(KeyIdentity, []byte("m"), nil); !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("at expiry: %v, want ErrLocked", err)
	}
	st, err := a.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Locked || !st.Until.IsZero() {
		t.Errorf("after expiry the agent is %+v", st)
	}
	// Status alone locks an expired agent too: the check is on every
	// request, not only the ones that need a key.
	a.clock.Set(start)
	a.unlock(t, ttl)
	a.clock.Set(start.Add(ttl))
	if st, _ := a.client.Status(); !st.Locked {
		t.Error("status did not notice the expiry")
	}
	a.server.mu.Lock()
	held := a.server.homeKey != nil
	a.server.mu.Unlock()
	if held {
		t.Error("the home key is still held after expiry")
	}
	// A new unlock replaces the old expiry.
	a.clock.Set(start)
	a.unlock(t, ttl)
	a.clock.Set(start.Add(ttl / 2))
	a.unlock(t, ttl)
	a.clock.Set(start.Add(ttl + ttl/2 - time.Second))
	if _, err := a.client.Sign(KeyIdentity, []byte("m"), nil); err != nil {
		t.Errorf("the second unlock did not replace the first's expiry: %v", err)
	}
}

// TestLockZeroes: the byte slices the agent held read as zero after lock;
// the test keeps its own references to prove it.
func TestLockZeroes(t *testing.T) {
	home := newFakeHome(t)
	s := NewServer(home, Options{})
	if err := s.Unlock([]byte(passphrase), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.generateLocked(CertPrefix+"work", 65); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	refs := [][]byte{s.homeKey, s.ident.signSeed, s.ident.mlkemSeed, s.ident.x25519Key}
	for _, k := range s.pending {
		refs = append(refs, k.seed)
	}
	s.mu.Unlock()
	if len(refs) != 5 {
		t.Fatalf("holding %d slices, want 5", len(refs))
	}
	for i, ref := range refs {
		if len(ref) == 0 || bytes.Equal(ref, make([]byte, len(ref))) {
			t.Fatalf("slice %d is empty or already zero before lock", i)
		}
	}
	s.Lock()
	for i, ref := range refs {
		if !bytes.Equal(ref, make([]byte, len(ref))) {
			t.Errorf("slice %d was not zeroed by lock", i)
		}
	}
	st := s.Status()
	if !st.Locked || len(st.Keys) != 0 {
		t.Errorf("after lock the agent is %+v", st)
	}
}

// TestAnotherUidIsRefused: the peer-credential check is a function of a
// uid; it refuses uid+1 and accepts uid. The syscall wrapper is exercised by
// every other test in the package.
func TestAnotherUidIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("an AF_UNIX socket on Windows carries no peer credentials; the runtime directory is the whole check there")
	}
	runtimeDirFor(t)
	home := newFakeHome(t)
	for _, tc := range []struct {
		name   string
		uid    int
		accept bool
	}{
		{"the agent's own uid", os.Getuid(), true},
		{"another uid", os.Getuid() + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(home, Options{UID: tc.uid})
			l, err := Listen(home.Root())
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- s.Serve(l) }()
			defer func() { s.Stop(); <-done; l.Close() }()
			c, err := NewClient(home.Root())
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Status()
			if tc.accept && err != nil {
				t.Fatalf("refused by an agent of my own uid: %v", err)
			}
			if !tc.accept {
				if err == nil {
					t.Fatal("accepted by an agent of another uid")
				}
				if !strings.Contains(err.Error(), "without answering") {
					t.Errorf("the refusal is %q, want the closed-without-a-reply message", err)
				}
			}
		})
	}
	// Zero is not a uid the option can name, so an agent run as root is
	// still root's: the default is the process's own.
	if s := NewServer(home, Options{}); s.uid != os.Getuid() {
		t.Errorf("the default uid is %d, want %d", s.uid, os.Getuid())
	}
}

// TestFramesAreBoundedBeforeTheyAreRead: a 4-byte length over the cap is
// refused without allocation, measured with HeapAlloc.
func TestFramesAreBoundedBeforeTheyAreRead(t *testing.T) {
	a := startAgent(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 8; i++ {
		conn, err := net.Dial("unix", a.client.Socket())
		if err != nil {
			t.Fatal(err)
		}
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], MaxFrame+1)
		if _, err := conn.Write(prefix[:]); err != nil {
			t.Fatal(err)
		}
		frame, err := readFrame(conn)
		if err != nil {
			t.Fatalf("no reply to an oversize frame: %v", err)
		}
		var resp response
		if err := json.Unmarshal(frame, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.OK || !strings.Contains(resp.Error, "over the 1048576 byte limit") {
			t.Errorf("an oversize frame gave %+v", resp)
		}
		conn.Close()
	}
	runtime.ReadMemStats(&after)
	// The claim is "not proportional to what was declared": eight refusals
	// of a megabyte each must not cost eight megabytes. TotalAlloc rather
	// than HeapAlloc, because a buffer allocated and dropped before the
	// refusal is garbage by the time the reply arrives, and HeapAlloc
	// would not see it; TotalAlloc counts every byte ever allocated.
	if grew := int64(after.TotalAlloc) - int64(before.TotalAlloc); grew > MaxFrame {
		t.Errorf("%d bytes were allocated refusing 8 oversize frames; the length was read before it was checked", grew)
	}
	// And the frame exactly at the cap is read, and refused for what it
	// is rather than its size.
	conn, err := net.Dial("unix", a.client.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := bytes.Repeat([]byte("x"), MaxFrame)
	if err := writeFrame(conn, body); err != nil {
		t.Fatal(err)
	}
	frame, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var resp response
	json.Unmarshal(frame, &resp)
	if resp.OK || !strings.Contains(resp.Error, "bad request") {
		t.Errorf("a frame at the cap gave %+v, want the bad request refusal", resp)
	}

	// Malformed requests, each refused with an error and the connection
	// closed, none crashing the agent.
	for name, raw := range map[string]string{
		"not json":       "{",
		"unknown op":     `{"op":"steal"}`,
		"unknown field":  `{"op":"status","extra":1}`,
		"trailing data":  `{"op":"status"}{"op":"status"}`,
		"a bare array":   `[]`,
		"an empty frame": ``,
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := net.Dial("unix", a.client.Socket())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
			conn.Write(prefix[:])
			conn.Write([]byte(raw))
			frame, err := readFrame(conn)
			if err != nil {
				t.Fatalf("no reply: %v", err)
			}
			var resp response
			json.Unmarshal(frame, &resp)
			if resp.OK || resp.Error == "" {
				t.Errorf("%s gave %+v", name, resp)
			}
			if _, err := io.ReadAll(conn); err != nil {
				t.Errorf("the connection was not closed cleanly: %v", err)
			}
		})
	}
	if _, err := a.client.Status(); err != nil {
		t.Errorf("the agent stopped answering after the malformed requests: %v", err)
	}
}

// TestGenerateSignsACSRAndReturnsAWrappedKey: generate, sign over a CSR
// under the handle, the wrapped key unwraps under the home key to the same
// public key.
func TestGenerateSignsACSRAndReturnsAWrappedKey(t *testing.T) {
	a := startAgent(t)
	a.unlock(t, DefaultTTL)
	g, err := a.client.Generate(CertPrefix+"work", 65)
	if err != nil {
		t.Fatal(err)
	}
	if g.Handle != PendingPrefix+"work" {
		t.Errorf("handle is %q", g.Handle)
	}
	if g.Public.Parameters() != mldsa.MLDSA65() {
		t.Errorf("generated %s, asked for ML-DSA-65", g.Public.Parameters())
	}
	csr, err := clientca.NewCSR(a.client.CertSigner(g.Handle, g.Public), "laptop", "a-token")
	if err != nil {
		t.Fatal(err)
	}
	req, err := clientca.ParseCSR(csr, mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("the CSR the agent signed does not parse: %v", err)
	}
	if !req.Key.Equal(g.Public) || req.Token != "a-token" || req.Label != "laptop" {
		t.Errorf("the CSR is for the wrong key or carries the wrong fields: %+v", req)
	}
	block, _ := pem.Decode(g.Wrapped)
	if block == nil || block.Type != keyfile.WrappedBlockType {
		t.Fatalf("the wrapped key is not a %s block", keyfile.WrappedBlockType)
	}
	der, err := keyfile.Unwrap(g.Wrapped, a.home.homeKey)
	if err != nil {
		t.Fatalf("the wrapped key does not unwrap under the home key: %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := parsed.(*mldsa.PrivateKey)
	if !ok || !priv.PublicKey().Equal(g.Public) {
		t.Error("the wrapped key is not the key the public half belongs to")
	}
	// The pending key is what status names, and the signer under the
	// on-disk name still finds nothing until the file is written.
	st, _ := a.client.Status()
	if len(st.Keys) != 2 || st.Keys[0] != KeyIdentity && st.Keys[1] != KeyIdentity {
		t.Errorf("status names %v", st.Keys)
	}
	if _, err := a.client.Sign(CertPrefix+"work", []byte("m"), nil); err == nil {
		t.Error("the on-disk name answered before cert.json was written")
	}
	// Written to disk, the on-disk name signs with it.
	a.home.mu.Lock()
	a.home.certs["work"] = g.Wrapped
	a.home.mu.Unlock()
	sig, err := a.client.Sign(CertPrefix+"work", []byte("m"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(g.Public, []byte("m"), sig, nil); err != nil {
		t.Errorf("the key written to disk does not sign as the generated one: %v", err)
	}
	if _, err := a.client.Generate(CertPrefix+"work", 50); err == nil {
		t.Error("an unknown parameter set was accepted")
	}
	if _, err := a.client.Generate("work", 65); err == nil {
		t.Error("a key name without the prefix was accepted")
	}
	// Lock drops the pending key.
	a.client.Lock()
	a.unlock(t, DefaultTTL)
	if _, err := a.client.Sign(g.Handle, []byte("m"), nil); err == nil {
		t.Error("the pending key survived a lock")
	}
}

// TestALazyKeyIsReadOnFirstUse: a cert.json written after unlock is signed
// with on the first sign that names it, and one replaced by a renewal is
// what the next sign uses.
func TestALazyKeyIsReadOnFirstUse(t *testing.T) {
	a := startAgent(t)
	a.unlock(t, DefaultTTL)
	if _, err := a.client.Sign(CertPrefix+"work", []byte("m"), nil); err == nil {
		t.Fatal("a key that is not on disk signed")
	}
	first := a.home.addCert(t, "work", mldsa.MLDSA65())
	sig, err := a.client.Sign(CertPrefix+"work", []byte("m"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(first.PublicKey(), []byte("m"), sig, nil); err != nil {
		t.Error("the key written after unlock was not the one that signed")
	}
	second := a.home.addCert(t, "work", mldsa.MLDSA65())
	sig, err = a.client.Sign(CertPrefix+"work", []byte("m"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(second.PublicKey(), []byte("m"), sig, nil); err != nil {
		t.Error("the replaced key was not the one that signed: the agent is holding a stale one")
	}
	// A key under another home key is refused by name, not signed with.
	other := newFakeHome(t)
	other.addCert(t, "work", mldsa.MLDSA65())
	a.home.mu.Lock()
	a.home.certs["work"] = other.certs["work"]
	a.home.mu.Unlock()
	if _, err := a.client.Sign(CertPrefix+"work", []byte("m"), nil); err == nil ||
		!strings.Contains(err.Error(), "the machine key for work") {
		t.Errorf("a key under another home key gave %v", err)
	}
}

func TestTwoAgentsForOneHomeCannotRun(t *testing.T) {
	runtimeDirFor(t)
	home := newFakeHome(t)
	first, err := Listen(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(home.Root()); !errors.Is(err, ErrAnotherAgent) {
		t.Fatalf("a second Listen gave %v, want ErrAnotherAgent", err)
	}
	// Another home is another agent.
	other := newFakeHome(t)
	second, err := Listen(other.Root())
	if err != nil {
		t.Fatalf("a second home could not get its own agent: %v", err)
	}
	second.Close()
	first.Close()
	// After the first is gone, the lock is free and a stale socket file is
	// replaced rather than refused.
	paths, _ := PathsFor(home.Root())
	if err := os.WriteFile(paths.Socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Listen(home.Root())
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	again.Close()
	info, err := os.Stat(paths.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("the runtime directory is mode %04o, want 0700", info.Mode().Perm())
	}
}

// TestTheAgentDeniesAttachment: on Linux, PR_GET_DUMPABLE reports the
// process undumpable after Harden; on macOS the test is that PT_DENY_ATTACH
// returned no error, since there is nothing else to read.
func TestTheAgentDeniesAttachment(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no hardening on this platform")
	}
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
	ok, err := Hardened()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Harden returned nil but the process is not hardened")
	}
}

// TestSocketPathIsPerHomeAndShort: two homes get two sockets, the same home
// spelled two ways gets one, and the path fits macOS's 104-byte limit from
// a runtime directory of ordinary length.
func TestSocketPathIsPerHomeAndShort(t *testing.T) {
	dir := runtimeDirFor(t)
	a, err := SocketPath("/home/ada/.auu")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SocketPath("/home/bob/.auu")
	if a == b {
		t.Error("two homes share a socket")
	}
	if c, _ := SocketPath("/home/ada/../ada/.auu/"); c != a {
		t.Errorf("the same home spelled differently got %s and %s", a, c)
	}
	if !strings.HasPrefix(a, dir+string(os.PathSeparator)+runtimeSubdir) {
		t.Errorf("socket %s is not under the runtime directory", a)
	}
	if !strings.HasSuffix(a, ".sock") || len(strings.TrimSuffix(filepath.Base(a), ".sock")) != idLen {
		t.Errorf("socket %s is not <id>.sock", a)
	}
	if _, err := SocketPath(""); err == nil {
		t.Error("an empty home got a socket")
	}
}

// TestStopIsAnsweredBeforeItIsActedOn: the reply to stop reaches the client
// before the agent stops, so 'auu agent stop' reads "ok" and not a closed
// socket. A net.Pipe write blocks until the other end reads, which is what
// makes the order observable: if stopped closed before the reply was
// written, it would be closed here before the reply is read.
func TestStopIsAnsweredBeforeItIsActedOn(t *testing.T) {
	home := newFakeHome(t)
	s := NewServer(home, Options{})
	client, server := net.Pipe()
	go s.Handle(server)
	body, err := json.Marshal(&request{Op: OpStop})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(client, body); err != nil {
		t.Fatal(err)
	}
	// The agent is now writing the reply and blocked on this end reading
	// it; it must not have stopped yet.
	select {
	case <-s.Stopped():
		t.Fatal("the agent stopped before its reply to stop was read")
	default:
	}
	frame, err := readFrame(client)
	if err != nil {
		t.Fatalf("no reply to stop: %v", err)
	}
	var resp response
	if err := json.Unmarshal(frame, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("stop was refused: %+v", resp)
	}
	select {
	case <-s.Stopped():
	case <-time.After(5 * time.Second):
		t.Fatal("the agent did not stop after answering stop")
	}
	client.Close()
}
