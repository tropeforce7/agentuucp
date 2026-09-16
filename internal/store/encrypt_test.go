package store

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

const testPassphrase = "correct horse battery staple"

func cheap(secret string) keyfile.Passphrase { return keyfile.TestPassphrase(secret) }

// plainHome is a home with an identity, one relay and a machine key there,
// exactly as auu init and auu register leave it.
func plainHome(t *testing.T) (*Store, *identity.Identity, *Relay, *mldsa.PrivateKey) {
	t.Helper()
	s := newStore(t)
	id, err := identity.Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	r, err := s.AddRelay("work", "https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t, key)
	rec := &CertRecord{
		Relay: r.URL, Serial: "01", Label: "laptop",
		Key:       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		Cert:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})),
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	if err := s.SaveCertFor(r, rec); err != nil {
		t.Fatal(err)
	}
	return s, id, r, key
}

// selfSigned is a certificate for a key, enough for TLS() to read the
// public half out of.
func selfSigned(t *testing.T, key *mldsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: bigOne(), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// snapshot is every file under a home, by relative path.
func snapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		out[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameFiles(t *testing.T, want, got map[string][]byte, what string) {
	t.Helper()
	for name, data := range want {
		if !bytes.Equal(got[name], data) {
			t.Errorf("%s: %s changed", what, name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: %s appeared", what, name)
		}
	}
}

// agentFor runs an in-process agent for a store, on a real socket in the
// runtime directory noAgent chose, unlocked with the test passphrase.
func agentFor(t *testing.T, s *Store) *agent.Server {
	t.Helper()
	srv := agent.NewServer(s, agent.Options{})
	l, err := agent.Listen(s.Root())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() { srv.Stop(); <-done; l.Close() })
	if err := srv.Unlock([]byte(testPassphrase), 0); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	return srv
}

// noAgent points the socket at an empty directory, so any attempt to reach
// an agent fails as not running until agentFor starts one there. Short,
// because t.TempDir on macOS can push a socket path past 104 bytes.
func noAgent(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
}

func TestAnEncryptedHomeRoundTrips(t *testing.T) {
	noAgent(t)
	s, id, r, key := plainHome(t)
	before := snapshot(t, s.Root())
	if enc, err := s.Encrypted(); err != nil || enc {
		t.Fatalf("a plain home reports encrypted=%v, %v", enc, err)
	}

	if err := s.EncryptHome(cheap(testPassphrase)); err != nil {
		t.Fatalf("EncryptHome: %v", err)
	}
	if err := s.EncryptHome(cheap(testPassphrase)); !errors.Is(err, ErrEncrypted) {
		t.Errorf("a second EncryptHome gave %v, want ErrEncrypted", err)
	}
	enc, err := s.Encrypted()
	if err != nil || !enc {
		t.Fatalf("after EncryptHome the home reports encrypted=%v, %v", enc, err)
	}
	after := snapshot(t, s.Root())
	for _, f := range []string{homeKeyFile, identityKeyFile} {
		if _, ok := after[f]; !ok {
			t.Errorf("%s was not written", f)
		}
	}
	if !keyfile.IsEncrypted(after[homeKeyFile]) || !keyfile.IsWrapped(after[identityKeyFile]) {
		t.Error("home.key and identity.key are not the formats they should be")
	}
	for _, secret := range []string{"sign_seed", "kem_seed"} {
		if bytes.Contains(after[identityFile], []byte(secret)) {
			t.Errorf("identity.json still carries %s", secret)
		}
	}
	certPath := filepath.Join(relaysDir, "work", certFile)
	if !bytes.Contains(after[certPath], []byte(keyfile.WrappedBlockType)) ||
		bytes.Contains(after[certPath], []byte("BEGIN PRIVATE KEY")) {
		t.Error("cert.json's key is not wrapped")
	}
	// Nothing else changed.
	for name, data := range before {
		if name == identityFile || name == certPath {
			continue
		}
		if !bytes.Equal(after[name], data) {
			t.Errorf("%s changed, and only the key files should", name)
		}
	}
	// A stray .new is not left behind.
	for name := range after {
		if strings.HasSuffix(name, newSuffix) {
			t.Errorf("%s was left behind", name)
		}
	}

	// Self reads no key: no agent is running and it answers.
	self, err := s.Self()
	if err != nil {
		t.Fatalf("Self on an encrypted home with no agent: %v", err)
	}
	if self.Fingerprint() != id.Fingerprint() || self.Name != "ada" {
		t.Error("Self is not the same identity")
	}
	// Identity is remote, has the same fingerprint, and connects to
	// nothing until used: with no agent it loads, and the first signature
	// is what says locked.
	remote, err := s.Identity()
	if err != nil {
		t.Fatalf("Identity on an encrypted home: %v", err)
	}
	if !remote.Remote() || remote.Fingerprint() != id.Fingerprint() || remote.Name != "ada" {
		t.Error("the remote identity is not the same identity, or is not remote")
	}
	if _, err := remote.Sign([]byte("m")); !errors.Is(err, identity.ErrLocked) {
		t.Errorf("signing with no agent gave %v, want ErrLocked", err)
	}
	if err := s.SaveIdentity(id); !errors.Is(err, ErrEncrypted) {
		t.Errorf("SaveIdentity on an encrypted home gave %v, want ErrEncrypted", err)
	}

	// With an agent, it signs and the machine key presents.
	agentFor(t, s)
	sig, err := remote.Sign([]byte("m"))
	if err != nil {
		t.Fatalf("signing through the agent: %v", err)
	}
	if !id.Public().Verify([]byte("m"), sig) {
		t.Error("the agent's signature does not verify under the identity")
	}
	rec, err := s.CertFor(r)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Encrypted() {
		t.Error("the record does not say its key is encrypted")
	}
	tlsCert, err := rec.TLS()
	if err != nil {
		t.Fatalf("TLS on a wrapped key: %v", err)
	}
	signer, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("the private key is %T, not a crypto.Signer", tlsCert.PrivateKey)
	}
	if !signer.Public().(*mldsa.PublicKey).Equal(key.PublicKey()) {
		t.Error("the remote signer's public key is not the certificate's")
	}
	sig, err = signer.Sign(nil, []byte("hello"), crypto.Hash(0))
	if err != nil {
		t.Fatalf("signing with the machine key through the agent: %v", err)
	}
	if err := mldsa.Verify(key.PublicKey(), []byte("hello"), sig, nil); err != nil {
		t.Error("the machine key's signature does not verify")
	}

	// And back: byte-identical to before.
	if err := s.DecryptHome([]byte(testPassphrase + "x")); err == nil || !errors.Is(err, keyfile.ErrPassphrase) {
		t.Errorf("a wrong passphrase gave %v", err)
	}
	if err := s.DecryptHome([]byte(testPassphrase)); err != nil {
		t.Fatalf("DecryptHome: %v", err)
	}
	sameFiles(t, before, snapshot(t, s.Root()), "after remove")
	if err := s.DecryptHome([]byte(testPassphrase)); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("a second DecryptHome gave %v, want ErrNotEncrypted", err)
	}
	local, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if local.Remote() {
		t.Error("the identity is still remote after remove")
	}
}

// TestAPlainHomeIsUntouched: a home never encrypted produces, after every
// operation in this file is exercised against another home, files identical
// to before — and its own reads change nothing either.
func TestAPlainHomeIsUntouched(t *testing.T) {
	noAgent(t)
	s, _, r, _ := plainHome(t)
	before := snapshot(t, s.Root())
	other, _, _, _ := plainHome(t)
	if err := other.EncryptHome(cheap(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	if err := other.ChangePassphrase([]byte(testPassphrase), cheap("another passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := other.DecryptHome([]byte("another passphrase")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Identity(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Self(); err != nil {
		t.Fatal(err)
	}
	if enc, err := s.Encrypted(); err != nil || enc {
		t.Fatalf("encrypted=%v, %v", enc, err)
	}
	rec, err := s.CertFor(r)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Encrypted() {
		t.Error("a plain key reports encrypted")
	}
	if _, err := rec.TLS(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HomeKey(); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("HomeKey on a plain home gave %v", err)
	}
	if err := s.ChangePassphrase([]byte("x"), cheap("y")); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("ChangePassphrase on a plain home gave %v", err)
	}
	sameFiles(t, before, snapshot(t, s.Root()), "the plain home")
}

// TestHalfConvertedHomesAreDiagnosed: each state a crash between renames
// can leave, written by hand, refused with its message; set or remove run
// again finishes.
func TestHalfConvertedHomesAreDiagnosed(t *testing.T) {
	noAgent(t)
	// The files of a fully encrypted home and of the plain one, to assemble
	// states from.
	s, id, r, _ := plainHome(t)
	plain := snapshot(t, s.Root())
	if err := s.EncryptHome(cheap(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	encrypted := snapshot(t, s.Root())
	certPath := filepath.Join(relaysDir, "work", certFile)

	write := func(t *testing.T, root string, files map[string][]byte) {
		t.Helper()
		for name, data := range files {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), dirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), data, fileMode); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name  string
		files map[string][]byte
		want  string
		// finish is what finishes the job: set or remove.
		finish func(*Store) error
	}{
		{
			// set crashed after home.key's rename.
			name:   "home.key with a plain identity",
			files:  map[string][]byte{identityFile: plain[identityFile], certPath: plain[certPath], homeKeyFile: encrypted[homeKeyFile]},
			want:   "home.key exists but identity.json holds the keys in the clear",
			finish: func(s *Store) error { return s.EncryptHome(cheap(testPassphrase)) },
		},
		{
			// set crashed after identity.key's rename.
			name: "home.key and identity.key with a plain identity",
			files: map[string][]byte{identityFile: plain[identityFile], certPath: plain[certPath],
				homeKeyFile: encrypted[homeKeyFile], identityKeyFile: encrypted[identityKeyFile]},
			want:   "home.key and identity.key exist but identity.json holds the keys in the clear",
			finish: func(s *Store) error { return s.EncryptHome(cheap(testPassphrase)) },
		},
		{
			// set crashed after identity.json's rename, before cert.json's;
			// or remove crashed after cert.json's, before identity.json's.
			name: "an encrypted identity with a plain machine key",
			files: map[string][]byte{identityFile: encrypted[identityFile], certPath: plain[certPath],
				homeKeyFile: encrypted[homeKeyFile], identityKeyFile: encrypted[identityKeyFile]},
			want:   "the identity is encrypted but the machine key for work is not",
			finish: func(s *Store) error { return s.EncryptHome(cheap(testPassphrase)) },
		},
		{
			// remove crashed after identity.json's rename, before the deletions.
			name: "a plain identity with identity.key and home.key still there",
			files: map[string][]byte{identityFile: plain[identityFile], certPath: plain[certPath],
				homeKeyFile: encrypted[homeKeyFile], identityKeyFile: encrypted[identityKeyFile]},
			want:   "identity.json holds the keys in the clear",
			finish: func(s *Store) error { return s.DecryptHome([]byte(testPassphrase)) },
		},
		{
			// remove crashed after identity.key was deleted, before home.key.
			name:   "a plain identity with home.key still there",
			files:  map[string][]byte{identityFile: plain[identityFile], certPath: plain[certPath], homeKeyFile: encrypted[homeKeyFile]},
			want:   "home.key exists but identity.json holds the keys in the clear",
			finish: func(s *Store) error { return s.DecryptHome([]byte(testPassphrase)) },
		},
		{
			// Not a crash: identity.key with no home.key.
			name: "an encrypted identity with no home.key",
			files: map[string][]byte{identityFile: encrypted[identityFile], certPath: encrypted[certPath],
				identityKeyFile: encrypted[identityKeyFile]},
			want: "there is no home.key",
		},
		{
			name: "an encrypted identity with no identity.key",
			files: map[string][]byte{identityFile: encrypted[identityFile], certPath: encrypted[certPath],
				homeKeyFile: encrypted[homeKeyFile]},
			want: "there is no identity.key",
		},
		{
			// Not a crash: a cert.json copied from an encrypted home.
			name:  "a wrapped machine key in a plain home",
			files: map[string][]byte{identityFile: plain[identityFile], certPath: encrypted[certPath]},
			want:  "the machine key for work in this home is encrypted but the identity is not",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			if _, err := s.AddRelay("work", r.URL); err != nil {
				t.Fatal(err)
			}
			write(t, s.Root(), tc.files)
			_, err := s.Identity()
			if err == nil {
				t.Fatalf("%s was not refused", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s gave %q, want it to mention %q", tc.name, err, tc.want)
			}
			if _, err := s.Encrypted(); err == nil {
				t.Error("Encrypted did not refuse")
			}
			if tc.finish == nil {
				return
			}
			if err := tc.finish(s); err != nil {
				t.Fatalf("finishing: %v", err)
			}
			loaded, err := s.Identity()
			if err != nil {
				t.Fatalf("after finishing: %v", err)
			}
			if loaded.Fingerprint() != id.Fingerprint() {
				t.Error("finishing produced a different identity")
			}
			enc, err := s.Encrypted()
			if err != nil {
				t.Fatal(err)
			}
			if enc != loaded.Remote() {
				t.Errorf("encrypted=%v but remote=%v", enc, loaded.Remote())
			}
			if enc {
				// Everything encrypted: the machine key too.
				rec, _ := s.CertFor(r)
				if !rec.Encrypted() {
					t.Error("the machine key was not finished")
				}
			} else {
				got := snapshot(t, s.Root())
				for _, f := range []string{identityFile, certPath} {
					if !bytes.Equal(got[f], plain[f]) {
						t.Errorf("after finishing a remove, %s is not the plain file", f)
					}
				}
				for _, f := range []string{homeKeyFile, identityKeyFile} {
					if _, left := got[f]; left {
						t.Errorf("after finishing a remove, %s is still there", f)
					}
				}
			}
		})
	}
}

// TestPassphraseChangeRewritesOnlyHomeKey: every other file's bytes are
// unchanged; the old passphrase no longer opens it; the new one does.
func TestPassphraseChangeRewritesOnlyHomeKey(t *testing.T) {
	noAgent(t)
	s, _, _, _ := plainHome(t)
	if err := s.EncryptHome(cheap(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.Root())
	if err := s.ChangePassphrase([]byte("wrong"), cheap("a new passphrase")); !errors.Is(err, keyfile.ErrPassphrase) {
		t.Errorf("a wrong old passphrase gave %v", err)
	}
	if err := s.ChangePassphrase([]byte(testPassphrase), cheap("a new passphrase")); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, s.Root())
	for name, data := range before {
		if name == homeKeyFile {
			if bytes.Equal(after[name], data) {
				t.Error("home.key was not rewritten")
			}
			continue
		}
		if !bytes.Equal(after[name], data) {
			t.Errorf("%s changed on a passphrase change", name)
		}
	}
	encrypted, _ := s.HomeKey()
	if _, err := keyfile.Decrypt(encrypted, []byte(testPassphrase)); !errors.Is(err, keyfile.ErrPassphrase) {
		t.Error("the old passphrase still opens home.key")
	}
	homeKey, err := keyfile.Decrypt(encrypted, []byte("a new passphrase"))
	if err != nil {
		t.Fatal("the new passphrase does not open home.key")
	}
	// And it is the same home key: identity.key still unwraps.
	if _, err := keyfile.Unwrap(after[identityKeyFile], homeKey); err != nil {
		t.Error("the home key changed on a passphrase change")
	}
}

// TestTheAgentsViewOfTheHome: the three reads the agent makes.
func TestTheAgentsViewOfTheHome(t *testing.T) {
	noAgent(t)
	s, id, _, _ := plainHome(t)
	if _, _, err := s.IdentityKey(); err == nil {
		t.Error("IdentityKey on a plain home answered")
	}
	if _, err := s.CertKey("work"); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Errorf("CertKey on a plain home gave %v", err)
	}
	if err := s.EncryptHome(cheap(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	suite, wrapped, err := s.IdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	if suite != uint8(id.Suite().ID) || !keyfile.IsWrapped(wrapped) {
		t.Error("IdentityKey is not the suite and the wrapped block")
	}
	wrapped, err = s.CertKey("work")
	if err != nil {
		t.Fatal(err)
	}
	if !keyfile.IsWrapped(wrapped) {
		t.Error("CertKey is not the wrapped block")
	}
	for _, bad := range []string{"../work", "nowhere", "self", ""} {
		if _, err := s.CertKey(bad); err == nil {
			t.Errorf("CertKey(%q) answered", bad)
		}
	}
	var rec CertRecord
	data, _ := os.ReadFile(s.relayPath(&Relay{Name: "work"}, certFile))
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Key != string(wrapped) {
		t.Error("CertKey is not what cert.json holds")
	}
}

func bigOne() *big.Int { return big.NewInt(1) }
