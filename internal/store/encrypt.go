package store

import (
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// A home under a passphrase.
//
// Two files change and one appears. home.key is a keyfile block whose
// plaintext is a random home key. identity.key is the identity's two seeds,
// wrapped under the home key. identity.json keeps the name, the suite and
// the public bundle and drops the seeds. Every relays/<name>/cert.json keeps
// its shape, with its key field a wrapped block instead of a plain one.
// Nothing else in the home changes, and a home that has never been
// encrypted is byte for byte what it always was.
//
// The store never decrypts anything itself except in the two commands that
// convert a home. Everything else is the agent's: Identity on an encrypted
// home is an identity whose private operations go over the socket, and
// CertFor's record signs the same way.

const (
	homeKeyFile     = "home.key"
	identityKeyFile = "identity.key"
	newSuffix       = ".new"
)

// ErrEncrypted is a home that is already under a passphrase, for the
// command that would put it under one.
var ErrEncrypted = errors.New("this home is already encrypted")

// ErrNotEncrypted is a home that is not under a passphrase, for the
// commands that need it to be.
var ErrNotEncrypted = errors.New("this home is not encrypted")

// ErrInterrupted is a home a crash left between the renames of a
// passphrase change. The error that wraps it names the state; running the
// interrupted command again finishes it.
var ErrInterrupted = errors.New("a passphrase change was interrupted")

// homeState is what the files say about a home: plain, encrypted, or a
// crash between two renames.
type homeState struct {
	// identity is which form identity.json has: "plain", "locked", "" for
	// no identity at all.
	identity    string
	homeKey     bool
	identityKey bool
	// plainCerts and wrappedCerts are the relays whose cert.json holds a
	// key of each kind.
	plainCerts, wrappedCerts []string
}

func (h *homeState) plain() bool {
	return h.identity == "plain" && !h.homeKey && !h.identityKey && len(h.wrappedCerts) == 0
}

func (h *homeState) encrypted() bool {
	return h.identity == "locked" && h.homeKey && h.identityKey && len(h.plainCerts) == 0
}

// identityLost is what to do about an identity file nothing can read.
const identityLost = "if you have a backup of this home, restore it; if not, this identity is lost " +
	"and 'auu init --force' makes a new one"

// sniffIdentity says which form identity.json takes without parsing keys:
// seeds present is plain, a bundle and no seeds is locked, anything else is
// refused by name, as a damaged file.
func sniffIdentity(path string, data []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", damaged(path, "is not valid JSON", err, identityLost)
	}
	_, hasSign := fields["sign_seed"]
	_, hasKEM := fields["kem_seed"]
	_, hasBundle := fields["bundle"]
	switch {
	case hasSign && hasKEM && !hasBundle:
		return "plain", nil
	case !hasSign && !hasKEM && hasBundle:
		return "locked", nil
	case hasSign != hasKEM:
		return "", damaged(path, "holds one seed and not the other", nil, identityLost)
	case hasBundle:
		return "", damaged(path, "holds both the seeds and a bundle, which is neither a plain identity "+
			"nor an encrypted one", nil, identityLost)
	default:
		return "", damaged(path, "holds neither seeds nor a bundle", nil, identityLost)
	}
}

// state reads the files. It is cheap: five stats and one small JSON parse.
func (s *Store) state() (*homeState, error) {
	h := &homeState{}
	data, err := os.ReadFile(s.path(identityFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if h.identity, err = sniffIdentity(s.path(identityFile), data); err != nil {
			return nil, err
		}
	}
	h.homeKey = exists(s.path(homeKeyFile))
	h.identityKey = exists(s.path(identityKeyFile))
	relays, err := s.Relays()
	if err != nil {
		return nil, err
	}
	for _, r := range relays {
		raw, err := readPrivate(s.relayPath(r, certFile))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var c CertRecord
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, certDamaged(s.relayPath(r, certFile), r.Name, err)
		}
		if keyfile.IsWrapped([]byte(c.Key)) {
			h.wrappedCerts = append(h.wrappedCerts, r.Name)
		} else {
			h.plainCerts = append(h.plainCerts, r.Name)
		}
	}
	return h, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Encrypted says whether the home is under a passphrase. A half-converted
// home is an error, by name.
func (s *Store) Encrypted() (bool, error) {
	h, err := s.state()
	if err != nil {
		return false, err
	}
	return h.encrypted(), s.diagnose(h)
}

// diagnose refuses the states a crash between renames can leave, each by
// name, with the advice to run the interrupted command again.
func (s *Store) diagnose(h *homeState) error {
	if h.plain() || h.encrypted() || h.identity == "" && !h.homeKey && !h.identityKey {
		return nil
	}
	const again = "run 'auu passphrase set' or 'auu passphrase remove' again, whichever was interrupted, to finish it"
	var state string
	switch {
	case h.identity == "plain" && len(h.wrappedCerts) > 0:
		// Not a crash: neither command can leave this. A file was copied
		// from an encrypted home.
		return &damagedFile{msg: fmt.Sprintf("the machine key for %s in this home is encrypted but the identity is not; "+
			"it was copied from an encrypted home, and the key cannot be used here: "+
			"run 'auu register --relay %s --token TOKEN' to get this machine its own",
			strings.Join(h.wrappedCerts, " and "), h.wrappedCerts[0])}
	case h.identity == "plain" && (h.homeKey || h.identityKey):
		state = fmt.Sprintf("%s %s but identity.json holds the keys in the clear",
			strings.Join(present(h), " and "), exist(present(h)))
	case h.identity == "locked" && !h.homeKey:
		state = "identity.json holds no keys and there is no home.key to unlock them with"
	case h.identity == "locked" && !h.identityKey:
		state = "identity.json holds no keys and there is no identity.key"
	case h.identity == "locked" && len(h.plainCerts) > 0:
		state = fmt.Sprintf("the identity is encrypted but the machine key for %s is not",
			strings.Join(h.plainCerts, " and "))
	case h.identity == "":
		state = fmt.Sprintf("%s %s but there is no identity", strings.Join(present(h), " and "), exist(present(h)))
	default:
		state = "this home is part encrypted and part not"
	}
	// Damaged as well as interrupted: the home needs a person, and the
	// caller that asks which it was still finds ErrInterrupted beneath.
	return &damagedFile{msg: fmt.Sprintf("%s: %v; %s", state, ErrInterrupted, again), inner: ErrInterrupted}
}

func exist(names []string) string {
	if len(names) == 1 {
		return "exists"
	}
	return "exist"
}

func present(h *homeState) []string {
	var out []string
	if h.homeKey {
		out = append(out, homeKeyFile)
	}
	if h.identityKey {
		out = append(out, identityKeyFile)
	}
	return out
}

// The agent's view of the home. The agent reads these and nothing else.

// HomeKey is home.key.
func (s *Store) HomeKey() ([]byte, error) {
	data, err := readPrivate(s.path(homeKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEncrypted
	}
	return data, err
}

// IdentityKey is identity.key and the suite it is under.
func (s *Store) IdentityKey() (uint8, []byte, error) {
	locked, err := s.locked()
	if err != nil {
		return 0, nil, err
	}
	data, err := readPrivate(s.path(identityKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, fmt.Errorf("no %s", identityKeyFile)
	}
	if err != nil {
		return 0, nil, err
	}
	return uint8(locked.Suite.ID), data, nil
}

// CertKey is the wrapped machine key in a relay's cert.json.
func (s *Store) CertKey(relay string) ([]byte, error) {
	if err := ValidRelayName(relay); err != nil {
		return nil, err
	}
	r, err := s.readRelay(relay)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this home has no relay named %s", relay)
	}
	if err != nil {
		return nil, err
	}
	rec, err := s.CertFor(r)
	if errors.Is(err, ErrNoCert) {
		return nil, fmt.Errorf("no machine key for %s: %s", relay, err)
	}
	if err != nil {
		return nil, err
	}
	if !keyfile.IsWrapped([]byte(rec.Key)) {
		return nil, fmt.Errorf("the machine key for %s is not encrypted", relay)
	}
	return []byte(rec.Key), nil
}

// locked reads identity.json's encrypted form.
func (s *Store) locked() (*identity.Locked, error) {
	data, err := os.ReadFile(s.path(identityFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, err
	}
	var l identity.Locked
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("identity file is corrupt: %w", err)
	}
	return &l, nil
}

// remoteIdentity is the identity over the agent, for an encrypted home.
// Nothing is connected here; the first private operation is.
func (s *Store) remoteIdentity() (*identity.Identity, error) {
	l, err := s.locked()
	if err != nil {
		return nil, err
	}
	c, err := agent.NewClient(s.root)
	if err != nil {
		return nil, err
	}
	return c.Identity(l.Suite, l.Name, l.Bundle)
}

// Converting a home, both ways, and changing the passphrase.

// staged is a set of files written beside their targets, to be renamed in
// order or removed on failure.
type staged struct {
	tmps  []string
	dests []string
}

func (st *staged) write(dest string, data []byte) error {
	tmp := dest + newSuffix
	if err := writeFileAtomic(tmp, data, fileMode); err != nil {
		return err
	}
	st.tmps = append(st.tmps, tmp)
	st.dests = append(st.dests, dest)
	return nil
}

func (st *staged) discard() {
	for _, tmp := range st.tmps {
		os.Remove(tmp)
	}
}

// commit renames every staged file into place, in the order they were
// staged, and syncs the directories touched.
func (st *staged) commit() error {
	dirs := map[string]bool{}
	for i, tmp := range st.tmps {
		if err := os.Rename(tmp, st.dests[i]); err != nil {
			return err
		}
		dirs[filepath.Dir(st.dests[i])] = true
	}
	st.tmps = nil
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		if err := syncDir(d); err != nil {
			return err
		}
	}
	return nil
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		// No directory fsync there; NTFS journals the metadata itself.
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	// Directories cannot be synced on every filesystem; the rename is
	// what matters and has happened.
	f.Sync()
	return nil
}

// EncryptHome puts a plain home under a passphrase, or finishes an
// interrupted conversion.
//
// A plain home gets a fresh home key under pass: home.key, identity.key,
// the public identity.json and every cert.json are written beside their
// targets and renamed in that order, so a crash leaves a state diagnose
// names and running this again finishes. A home whose identity is already
// encrypted but has plain machine keys — a crash after the identity's
// renames — is finished under its existing home key, which pass must open.
func (s *Store) EncryptHome(pass keyfile.Passphrase) error {
	if len(pass.Secret) == 0 {
		return keyfile.ErrEmptyPassphrase
	}
	h, err := s.state()
	if err != nil {
		return err
	}
	if h.encrypted() {
		return ErrEncrypted
	}
	if h.identity == "" {
		return ErrNoIdentity
	}
	if h.identity == "plain" && len(h.wrappedCerts) > 0 {
		return s.diagnose(h)
	}
	var homeKey []byte
	st := &staged{}
	defer st.discard()
	if h.identity == "locked" {
		// Finishing. The identity is under a home key already; open it.
		encrypted, err := s.HomeKey()
		if err != nil {
			return err
		}
		if homeKey, err = keyfile.Decrypt(encrypted, pass.Secret); err != nil {
			return err
		}
		if !h.identityKey {
			return s.diagnose(h)
		}
	} else {
		id, err := s.plainIdentity()
		if err != nil {
			return err
		}
		homeKey = make([]byte, keyfile.HomeKeySize)
		if _, err := rand.Read(homeKey); err != nil {
			return err
		}
		encrypted, err := keyfile.Encrypt(homeKey, pass)
		if err != nil {
			return err
		}
		secrets, err := id.Secrets()
		if err != nil {
			return err
		}
		wrapped, err := keyfile.Wrap(secrets, homeKey)
		if err != nil {
			return err
		}
		public, err := json.MarshalIndent(identity.NewLocked(id), "", "  ")
		if err != nil {
			return err
		}
		if err := st.write(s.path(homeKeyFile), encrypted); err != nil {
			return err
		}
		if err := st.write(s.path(identityKeyFile), wrapped); err != nil {
			return err
		}
		if err := st.write(s.path(identityFile), append(public, '\n')); err != nil {
			return err
		}
	}
	for _, name := range h.plainCerts {
		r, err := s.readRelay(name)
		if err != nil {
			return err
		}
		rec, err := s.CertFor(r)
		if err != nil {
			return err
		}
		block, _ := pem.Decode([]byte(rec.Key))
		if block == nil || block.Type != "PRIVATE KEY" {
			return fmt.Errorf("%s: the key is not a PKCS#8 PEM block", s.relayPath(r, certFile))
		}
		wrapped, err := keyfile.Wrap(block.Bytes, homeKey)
		if err != nil {
			return err
		}
		rec.Key = string(wrapped)
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		if err := st.write(s.relayPath(r, certFile), append(data, '\n')); err != nil {
			return err
		}
	}
	return st.commit()
}

// DecryptHome takes a home out from under its passphrase, writing every key
// back in the clear, or finishes an interrupted removal. Machine keys are
// unwrapped first, then the identity, and home.key is deleted last, so a
// crash leaves a state diagnose names and running this again finishes.
func (s *Store) DecryptHome(secret []byte) error {
	if len(secret) == 0 {
		return keyfile.ErrEmptyPassphrase
	}
	h, err := s.state()
	if err != nil {
		return err
	}
	if h.plain() {
		return ErrNotEncrypted
	}
	if h.identity == "" {
		return ErrNoIdentity
	}
	if h.identity == "plain" && len(h.wrappedCerts) > 0 {
		return s.diagnose(h)
	}
	var homeKey []byte
	if h.homeKey {
		encrypted, err := s.HomeKey()
		if err != nil {
			return err
		}
		if homeKey, err = keyfile.Decrypt(encrypted, secret); err != nil {
			return err
		}
	} else if h.identity == "locked" || len(h.wrappedCerts) > 0 {
		return s.diagnose(h)
	}
	st := &staged{}
	defer st.discard()
	for _, name := range h.wrappedCerts {
		r, err := s.readRelay(name)
		if err != nil {
			return err
		}
		rec, err := s.CertFor(r)
		if err != nil {
			return err
		}
		der, err := keyfile.Unwrap([]byte(rec.Key), homeKey)
		if err != nil {
			return fmt.Errorf("%s: %w", s.relayPath(r, certFile), err)
		}
		rec.Key = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		if err := st.write(s.relayPath(r, certFile), append(data, '\n')); err != nil {
			return err
		}
	}
	if h.identity == "locked" {
		l, err := s.locked()
		if err != nil {
			return err
		}
		wrapped, err := readPrivate(s.path(identityKeyFile))
		if err != nil {
			return err
		}
		der, err := keyfile.Unwrap(wrapped, homeKey)
		if err != nil {
			return fmt.Errorf("%s: %w", identityKeyFile, err)
		}
		id, err := identity.FromSecrets(l.Suite, l.Name, der)
		if err != nil {
			return err
		}
		if id.Fingerprint() != mustFingerprint(l) {
			return errors.New("identity.key does not hold the keys identity.json's bundle belongs to")
		}
		data, err := json.MarshalIndent(id, "", "  ")
		if err != nil {
			return err
		}
		if err := st.write(s.path(identityFile), append(data, '\n')); err != nil {
			return err
		}
	}
	if err := st.commit(); err != nil {
		return err
	}
	for _, f := range []string{identityKeyFile, homeKeyFile} {
		if err := os.Remove(s.path(f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDir(s.root)
}

func mustFingerprint(l *identity.Locked) string {
	pub, err := l.Public()
	if err != nil {
		return ""
	}
	return pub.Fingerprint()
}

// ChangePassphrase rewrites home.key under a new passphrase. Nothing else
// on disk changes: every key is under the home key, and the home key is
// what this re-seals.
func (s *Store) ChangePassphrase(old []byte, pass keyfile.Passphrase) error {
	if len(pass.Secret) == 0 {
		return keyfile.ErrEmptyPassphrase
	}
	encrypted, err := s.HomeKey()
	if err != nil {
		return err
	}
	homeKey, err := keyfile.Decrypt(encrypted, old)
	if err != nil {
		return err
	}
	fresh, err := keyfile.Encrypt(homeKey, pass)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(homeKeyFile), fresh, fileMode)
}

// plainIdentity reads identity.json's plain form, which holds the keys, so
// its mode is checked first; the encrypted form holds only the public half
// and is not.
func (s *Store) plainIdentity() (*identity.Identity, error) {
	data, err := readPrivate(s.path(identityFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, err
	}
	var id identity.Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("identity file is corrupt: %w", err)
	}
	return &id, nil
}
