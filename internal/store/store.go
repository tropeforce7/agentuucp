// Package store manages a user's local auu state: identity, configuration, the
// authorized peer list, and the spool of received and sent mail.
//
// The peer list is the trust anchor of the whole system. It is exchanged out of
// band, the way ssh public keys are, and nothing on the network can add to it.
package store

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600

	identityFile = "identity.json"
	configFile   = "config.json"
	peersFile    = "authorized_peers"
	cursorFile   = "cursor"

	inboxDir      = "inbox"
	sentDir       = "sent"
	quarantineDir = "quarantine"
	serveDir      = "serve"

	// minPrefix is the shortest fingerprint prefix accepted for lookups.
	minPrefix = 8
)

// ErrNoIdentity means auu init has not been run.
var ErrNoIdentity = errors.New("no identity: run 'auu init --name YOUR-NAME' first")

// ErrAmbiguous means a lookup matched more than one peer.
type ErrAmbiguous struct {
	Query      string
	Candidates []string
	// What the candidates are: "peers" or "messages". The same error serves
	// both lookups, and an id that matches two messages is not two peers.
	What string
}

func (e *ErrAmbiguous) Error() string {
	return fmt.Sprintf("%q matches %d %s: %s", e.Query, len(e.Candidates), e.What, strings.Join(e.Candidates, ", "))
}

// Config is the user's local settings. What it does not hold is anything
// about one relay: that lives under relays/, one directory per relay, because
// a home may know several.
type Config struct {
	Name string `json:"name"`
	// DefaultRelay is the relay a command acts on when --relay and AUU_RELAY
	// say nothing. It is the name, not the URL.
	DefaultRelay string `json:"default_relay,omitempty"`
	// StreamThreshold is the estimated size above which a message is sent as
	// a stream rather than an envelope. Zero means the default.
	StreamThreshold int64 `json:"stream_threshold,omitempty"`
	// ChunkSize is the plaintext bytes per stream chunk. Zero means the
	// default.
	ChunkSize int `json:"chunk_size,omitempty"`
	// Editor composes a message when none is given at a terminal. Empty
	// means VISUAL, then EDITOR, then vi; AUU_EDITOR in the environment
	// beats all of them.
	Editor string `json:"editor,omitempty"`
	// VouchAnswer lets auu inbox and auu wait answer a peer who asks
	// whether you hold a key, with your vouch, when the key is on your
	// list. Off unless typed for: an answer tells the peer who asked that
	// the key is on your list, and signing it originates as you.
	VouchAnswer bool `json:"vouch_answer,omitempty"`
}

// Store is a handle on the auu home directory.
type Store struct {
	root string
	// self is the owner's public bundle, loaded on first use. Several
	// questions the peer list answers — who is this, may they write to me,
	// what are they called — have the same answer for the owner, and the
	// peer list is not where it lives.
	self *identity.Public
}

// ErrSelfPeer is refused by AddPeer: an owner does not need to be on their
// own list to write to themselves, and a list entry for yourself is a thing
// people then wonder about.
var ErrSelfPeer = errors.New("that is your own key: messages to yourself need no peer entry, use --to self")

// Self is the owner's public bundle, with their name. In an encrypted home
// it is read from identity.json's public form and touches no key and no
// agent, which is what lets every command that needs only the public half
// run with the identity locked.
func (s *Store) Self() (*identity.Public, error) {
	if s.self != nil {
		return s.self, nil
	}
	data, err := os.ReadFile(s.path(identityFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, err
	}
	form, err := sniffIdentity(s.path(identityFile), data)
	if err != nil {
		return nil, err
	}
	if form == "locked" {
		l, err := s.locked()
		if err != nil {
			return nil, err
		}
		pub, err := l.Public()
		if err != nil {
			return nil, err
		}
		s.self = pub
		return s.self, nil
	}
	id, err := s.plainIdentity()
	if err != nil {
		return nil, err
	}
	s.self = id.Public()
	return s.self, nil
}

// isSelfAlias reports whether a query names the owner by convention rather
// than by key. There is one word for it, and it is reserved as a name so it
// can never be anyone else.
func isSelfAlias(query string) bool { return query == "self" }

// DefaultRoot is $AUU_HOME, or ~/.auu.
func DefaultRoot() (string, error) {
	if root := os.Getenv("AUU_HOME"); root != "" {
		return root, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".auu"), nil
}

// Open returns a store rooted at path, creating the directory tree if needed.
func Open(root string) (*Store, error) {
	s := &Store{root: root}
	for _, dir := range []string{root,
		filepath.Join(root, inboxDir),
		filepath.Join(root, sentDir),
		filepath.Join(root, quarantineDir),
		filepath.Join(root, relaysDir),
	} {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return nil, err
		}
	}
	if err := privateHome(root); err != nil {
		return nil, err
	}
	warnWritable(filepath.Join(root, peersFile), "who you trust", false)
	for _, dir := range []string{inboxDir, sentDir, quarantineDir} {
		warnWritable(filepath.Join(root, dir), "your mail", true)
	}
	if err := s.refuseHomeFromBefore(); err != nil {
		return nil, err
	}
	return s, nil
}

// looseRelayFiles are the files a home kept in its root before it could
// know more than one relay, when it held the one relay's URL in config.json
// and its anchor, certificate and cursor beside it. Each now lives under
// relays/NAME/, and one in the root is a home from before.
var looseRelayFiles = []string{anchorFile, certFile, cursorFile}

// refuseHomeFromBefore refuses, at Open, a home from before it could know
// more than one relay: a config.json of the old shape, which Config refuses
// by the key, or a relay's file loose in the root. Nothing on this machine
// is from before, so the home is not moved to the new shape, which is a
// path nobody tests; the sentence names the file and says what to do.
func (s *Store) refuseHomeFromBefore() error {
	if _, err := s.Config(); err != nil {
		return err
	}
	for _, file := range looseRelayFiles {
		if _, err := os.Stat(s.path(file)); err == nil {
			return s.fromBefore(s.path(file), "is a relay's file in the home's root")
		}
	}
	return nil
}

// fromBefore is the sentence for a file a home held before it could know
// more than one relay. It names every file such a home kept, since a home
// that has one may have the others and each would be refused in turn;
// deleting them costs the relay's record, which 'auu relay add' makes
// again, and nothing else.
func (s *Store) fromBefore(path, fact string) error {
	return damaged(path, fact+", which is how a home from before v0.11.0 kept its one relay", nil,
		"this auu reads none of it; delete config.json and any of trust_anchor.pem, cert.json and cursor "+
			"in the home's root, then add the relay again with 'auu relay add', "+
			"or delete the home and run 'auu init' again")
}

// OpenDefault opens the store at DefaultRoot.
func OpenDefault() (*Store, error) {
	root, err := DefaultRoot()
	if err != nil {
		return nil, err
	}
	return Open(root)
}

func (s *Store) Root() string            { return s.root }
func (s *Store) path(p ...string) string { return filepath.Join(append([]string{s.root}, p...)...) }

// writeFileAtomic writes through a temporary file in the same directory, so a
// crash or a concurrent reader never sees a half-written peer list.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// HasIdentity reports whether an identity has been created.
func (s *Store) HasIdentity() bool {
	_, err := os.Stat(s.path(identityFile))
	return err == nil
}

// SaveIdentity writes the identity, secrets included, mode 0600. It refuses
// an encrypted home: a plain identity.json beside a home.key is the state a
// crash leaves, and writing one on purpose would be the same thing.
func (s *Store) SaveIdentity(id *identity.Identity) error {
	if exists(s.path(homeKeyFile)) || exists(s.path(identityKeyFile)) {
		return fmt.Errorf("%w; run 'auu passphrase remove' first", ErrEncrypted)
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(identityFile), append(data, '\n'), fileMode)
}

// Identity loads the user's identity.
//
// In a plain home it is the keys, from identity.json. In an encrypted home
// it is a remote identity: the public half from identity.json, and every
// private operation performed by the agent on first use. Opening it
// connects to nothing. A home that is neither — a crash between the renames
// of a passphrase change — is refused by name.
func (s *Store) Identity() (*identity.Identity, error) {
	h, err := s.state()
	if err != nil {
		return nil, err
	}
	if h.identity == "" {
		if err := s.diagnose(h); err != nil {
			return nil, err
		}
		return nil, ErrNoIdentity
	}
	if err := s.diagnose(h); err != nil {
		return nil, err
	}
	if h.encrypted() {
		return s.remoteIdentity()
	}
	return s.plainIdentity()
}

// SaveConfig writes the local configuration.
func (s *Store) SaveConfig(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(configFile), append(data, '\n'), fileMode)
}

// configKeys is every key config.json may hold: the keys Config writes,
// read from its tags, so the two cannot drift.
var configKeys = jsonKeys(Config{})

// configKeysFromBefore are the keys config.json held before a home could
// know more than one relay: the one relay's URL and what was pinned for
// it. Config carries no field for them, so nothing reads them; a file
// that has one is refused by the key, as a home from before.
var configKeysFromBefore = []string{"relay", "trust_anchor_spki", "server_int_spki", "server_int_not_before"}

// jsonKeys is the JSON key of every field of a struct, from its tags.
func jsonKeys(v any) map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// Config loads the local configuration. A missing file is not an error. A
// file this program wrote is read to its shape: a key Config does not
// write is refused by name, and one of the keys from before a home could
// know more than one relay is refused as that, with the fix.
func (s *Store) Config() (Config, error) {
	var c Config
	data, err := os.ReadFile(s.path(configFile))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return Config{}, s.configDamaged(err)
	}
	for _, key := range sortedKeys(keys) {
		if configKeys[key] {
			continue
		}
		if slices.Contains(configKeysFromBefore, key) {
			return Config{}, s.fromBefore(s.path(configFile), fmt.Sprintf("has a key %q", key))
		}
		return Config{}, damaged(s.path(configFile), fmt.Sprintf("has a key this auu does not know, %q", key), nil,
			"remove it, or delete the file and set the default relay again with 'auu relay default NAME'; "+
				"it holds only that, the stream settings, your editor and whether vouch questions are answered")
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, s.configDamaged(err)
	}
	return c, nil
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// configDamaged is a config.json nothing can read, met by Config, which
// Open calls first. Deleting it costs the default relay and the settings,
// and nothing that cannot be set again.
func (s *Store) configDamaged(cause error) error {
	return damaged(s.path(configFile), "is not valid JSON", cause,
		"delete it and set the default relay again with 'auu relay default NAME'; "+
			"it holds only that, the stream settings, your editor and whether vouch questions are answered")
}

// NameFree reports whether a peer may be added under the name it carries:
// nothing else on the list folds to it, and no room has it. It is what AddPeer refuses on,
// asked separately by a command that must know before it does something
// it cannot undo — a knock is posted before the peer is added, and a
// refusal after the post would leave the knock sent and the peer out.
func (s *Store) NameFree(pub *identity.Public) error {
	peers, err := s.Peers()
	if err != nil {
		return err
	}
	if err := nameFree(peers, pub); err != nil {
		return err
	}
	return s.roomNameTaken(pub.Name)
}

// nameFree is NameFree over a list already read. A peer already on the
// list under its own fingerprint is not in its own way.
func nameFree(peers []*identity.Public, pub *identity.Public) error {
	for _, existing := range peers {
		if existing.Fingerprint() == pub.Fingerprint() {
			continue
		}
		if existing.Name != "" && pub.Name != "" && strings.EqualFold(existing.Name, pub.Name) {
			return fmt.Errorf("peer name %q is already used by %s; choose a different name",
				pub.Name, existing.Short())
		}
	}
	return nil
}

// Peers returns the authorized peer list in file order.
func (s *Store) Peers() ([]*identity.Public, error) {
	data, err := os.ReadFile(s.path(peersFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var peers []*identity.Public
	for n, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		pub, err := identity.ParseExportLine(trimmed)
		if err != nil {
			// A line of the wrong length in a file of lines is, as often
			// as not, a line an editor or a mail client wrapped: the rest
			// of it is the next line. The question is asked here, since
			// the parser sees one line at a time and the break is between
			// them. A person has to fix the file, so it is damaged.
			wrapped := ""
			if errors.Is(err, identity.ErrLineLength) {
				wrapped = " (was the line wrapped?)"
			}
			return nil, &damagedFile{msg: fmt.Sprintf("%s line %d: %v%s", s.path(peersFile), n+1, err, wrapped)}
		}
		peers = append(peers, pub)
	}
	return peers, nil
}

// VouchedPrefix begins the comment line written above an entry added on
// a peer's word: "# vouched for by NAME (SHORT-ID) on DATE". The reader
// skips it as it skips every comment, and RemovePeer takes it with the
// entry below it. It is the one place the file records where an entry
// came from.
const VouchedPrefix = "# vouched for by "

// AddPeer appends a peer. Re-adding the same key is a no-op; presenting a
// different key for a fingerprint that is already known is refused, since a
// fingerprint commits to its key material and a mismatch means something is
// wrong rather than updated.
func (s *Store) AddPeer(pub *identity.Public) (added bool, err error) {
	return s.addPeer(pub, "")
}

// AddPeerNoted is AddPeer with one comment line written directly above the
// entry, in the same write: where the entry came from. The note is one line
// beginning with VouchedPrefix, since that is the only comment this program
// writes and the only one RemovePeer takes with its entry.
func (s *Store) AddPeerNoted(pub *identity.Public, note string) (added bool, err error) {
	if !strings.HasPrefix(note, VouchedPrefix) || strings.ContainsAny(note, "\r\n") {
		return false, fmt.Errorf("store: a peer's note is one line beginning %q", VouchedPrefix)
	}
	return s.addPeer(pub, note)
}

// CheckPeer says what AddPeer would refuse pub for, without writing
// anything: the person's own key, a name the export line's rule refuses, a
// peer list it cannot read, a name another peer's folds equal to, or a
// room's. A key already held is not refused, as AddPeer takes it as added
// already. A command that must do something the person cannot take back
// before the peer is written asks this first, so the one refusal that is
// the person's to fix comes before it, and the peer is written last.
func (s *Store) CheckPeer(pub *identity.Public) error {
	_, err := s.checkPeer(pub)
	return err
}

func (s *Store) addPeer(pub *identity.Public, note string) (added bool, err error) {
	held, err := s.checkPeer(pub)
	if err != nil || held {
		return false, err
	}
	line := pub.ExportLine()
	existing, err := os.ReadFile(s.path(peersFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	buf := string(existing)
	if buf != "" && !strings.HasSuffix(buf, "\n") {
		buf += "\n"
	}
	if note != "" {
		buf += note + "\n"
	}
	buf += line + "\n"
	if err := writeFileAtomic(s.path(peersFile), []byte(buf), fileMode); err != nil {
		return false, err
	}
	return true, nil
}

// checkPeer is AddPeer's every refusal, in its order, and whether the key
// is held already.
func (s *Store) checkPeer(pub *identity.Public) (held bool, err error) {
	if self, err := s.Self(); err == nil && self.Fingerprint() == pub.Fingerprint() {
		return false, ErrSelfPeer
	}
	// The name is written into the file as part of an export line, and a
	// line the reader cannot parse makes the whole file unreadable: every
	// peer then reads as a stranger and every message is quarantined
	// until somebody edits it by hand. So a name this rule refuses never
	// reaches the file, whichever command asked for it.
	if pub.Name != "" {
		if err := identity.ValidName(pub.Name); err != nil {
			return false, err
		}
	}
	peers, err := s.Peers()
	if err != nil {
		return false, err
	}
	for _, existing := range peers {
		if existing.Fingerprint() == pub.Fingerprint() {
			return true, nil
		}
		if existing.Name != "" && pub.Name != "" && strings.EqualFold(existing.Name, pub.Name) {
			return false, fmt.Errorf("peer name %q is already used by %s; choose a different name",
				pub.Name, existing.Short())
		}
	}
	// One name means one thing: a peer may not take a room's (D56).
	if err := s.roomNameTaken(pub.Name); err != nil {
		return false, err
	}
	return false, nil
}

// RemovePeer drops a peer by fingerprint. It reports whether anything went.
//
// It edits the file line by line and leaves every other line as it was
// written: every other entry, a blank line, and a comment, whether this
// program wrote it or a person did. The one line it takes besides the
// entry is the vouched-for comment directly above it, which is about that
// entry and nothing else. It used to rewrite the file from the parsed
// entries, which dropped every comment in it whenever any peer was removed.
func (s *Store) RemovePeer(fp string) (bool, error) {
	// The whole file is held to the reader's rule first, so a file that
	// cannot be read is refused by the reader's sentence and not edited.
	if _, err := s.Peers(); err != nil {
		return false, err
	}
	data, err := os.ReadFile(s.path(peersFile))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	lines := strings.SplitAfter(string(data), "\n")
	var kept []string
	found := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if pub, err := identity.ParseExportLine(trimmed); err == nil && pub.Fingerprint() == fp {
				found = true
				if n := len(kept); n > 0 && strings.HasPrefix(strings.TrimSpace(kept[n-1]), VouchedPrefix) {
					kept = kept[:n-1]
				}
				continue
			}
		}
		kept = append(kept, line)
	}
	if !found {
		return false, nil
	}
	return true, writeFileAtomic(s.path(peersFile), []byte(strings.Join(kept, "")), fileMode)
}

// Resolve finds a peer by exact fingerprint, exact name, unique fingerprint
// prefix, or unique case-insensitive name prefix, in that order.
func (s *Store) Resolve(query string) (*identity.Public, error) {
	if query == "" {
		return nil, errors.New("empty peer name")
	}
	// The owner first, by the word or by exact fingerprint, and before the
	// peer list is consulted at all: a note to yourself needs no peers.
	if self, err := s.Self(); err == nil && (isSelfAlias(query) || query == self.Fingerprint()) {
		return self, nil
	}
	peers, err := s.Peers()
	if err != nil {
		return nil, err
	}
	if len(peers) == 0 {
		return nil, errors.New("no peers yet: add one with 'auu peers add'")
	}
	for _, p := range peers {
		if p.Fingerprint() == query {
			return p, nil
		}
	}
	var byName []*identity.Public
	for _, p := range peers {
		if p.Name == query {
			byName = append(byName, p)
		}
	}
	if len(byName) == 1 {
		return byName[0], nil
	}
	if len(byName) > 1 {
		return nil, ambiguous(query, byName)
	}

	lower := strings.ToLower(query)
	if len(query) >= minPrefix {
		var byFP []*identity.Public
		for _, p := range peers {
			if strings.HasPrefix(p.Fingerprint(), lower) {
				byFP = append(byFP, p)
			}
		}
		if len(byFP) == 1 {
			return byFP[0], nil
		}
		if len(byFP) > 1 {
			return nil, ambiguous(query, byFP)
		}
	}

	var byPrefix []*identity.Public
	for _, p := range peers {
		if p.Name != "" && strings.HasPrefix(strings.ToLower(p.Name), lower) {
			byPrefix = append(byPrefix, p)
		}
	}
	if len(byPrefix) == 1 {
		return byPrefix[0], nil
	}
	if len(byPrefix) > 1 {
		return nil, ambiguous(query, byPrefix)
	}
	return nil, fmt.Errorf("no peer matches %q", query)
}

func ambiguous(query string, candidates []*identity.Public) error {
	e := &ErrAmbiguous{Query: query, What: "peers"}
	for _, c := range candidates {
		label := c.Short()
		if c.Name != "" {
			label = c.Name + " (" + c.Short() + ")"
		}
		e.Candidates = append(e.Candidates, label)
	}
	return e
}

// PeerName returns the local name for a fingerprint, or an empty string when
// the sender is not a known peer.
func (s *Store) PeerName(fp string) string {
	if self, err := s.Self(); err == nil && self.Fingerprint() == fp {
		return self.Name
	}
	peers, err := s.Peers()
	if err != nil {
		return ""
	}
	for _, p := range peers {
		if p.Fingerprint() == fp {
			return p.Name
		}
	}
	return ""
}

// IsAuthorized reports whether a fingerprint is on the peer list.
func (s *Store) IsAuthorized(fp string) bool {
	if self, err := s.Self(); err == nil && self.Fingerprint() == fp {
		return true
	}
	peers, err := s.Peers()
	if err != nil {
		return false
	}
	for _, p := range peers {
		if p.Fingerprint() == fp {
			return true
		}
	}
	return false
}

// readCursor reads one relay's cursor. A missing file is zero: nothing has
// been fetched from that relay yet.
// readCursor reads one relay's cursor. The relay is named in the advice for
// a cursor that will not parse, because the cursor is also the record that
// this identity has a mailbox on that relay: deleted, the relay would be
// passed by as one nobody has joined, and 'auu inbox --relay NAME' is what
// selects it regardless.
func readCursor(path, relay string) (int64, error) {
	data, err := regular.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(data))
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n < 0 {
		// Whatever is in the file, shown but bounded: it is going into a
		// sentence a person reads.
		if len(text) > 40 {
			text = text[:40] + "…"
		}
		return 0, damaged(path, fmt.Sprintf("is not a message id (%q)", text), nil,
			fmt.Sprintf("run 'auu cursor reset --relay %s', which writes it again; the next fetch starts from the beginning and delivers nothing twice", relay))
	}
	return n, nil
}

func writeCursor(path string, n int64) error {
	return writeFileAtomic(path, []byte(strconv.FormatInt(n, 10)+"\n"), fileMode)
}

// recordAdvice is what to do about a record in a box that will not read.
const recordAdvice = "fix it, or move it out of the box; the rest of the box reads without it"

// Stored is one message as kept on disk.
type Stored struct {
	RelayID int64 `json:"relay_id"`
	// Relay is the name of the relay this message arrived through, which is
	// what a reply goes back the way of. Every record names one, so the
	// key is always written, and Load refuses a record without it.
	Relay    string    `json:"relay"`
	Received time.Time `json:"received"`
	// Arrived is this machine's clock when the record was first saved, and
	// what the inbox, a thread's latest and serve's opener are ordered by:
	// Received is the relay's word, and a relay that put its clock ahead
	// could pin its message atop the inbox within the skew. Save sets it
	// when it is zero and never after, so a record moved, marked or
	// rewritten keeps it; a record an earlier release wrote has none, and
	// Load reads it as Received, or as the file's time when Received
	// cannot be written back or is more than relayapi.MaxSkew ahead of
	// this machine's clock (arrivedBefore, G9).
	Arrived    time.Time       `json:"arrived"`
	Read       bool            `json:"read"`
	Inner      *envelope.Inner `json:"inner"`
	SenderName string          `json:"sender_name"`
	// Streamed says the attachments are files in a directory beside this
	// record rather than bytes inside it.
	Streamed bool `json:"streamed,omitempty"`
	// PayloadOnRelay says only the manifest has been fetched: the body is
	// still on the relay, waiting for somebody to decide about the sender.
	PayloadOnRelay bool `json:"payload_on_relay,omitempty"`
	// PayloadGone says the payload PayloadOnRelay left there is no longer
	// on the relay: a cursor reset found the relay holding nothing that
	// is this message, so its relay id names nothing of it any more and
	// nothing asks the relay for it under that id. PayloadOnRelay stays,
	// since the body is still not here.
	PayloadGone bool `json:"payload_gone,omitempty"`
	// RelaySize is the size the relay listed the message at. With RelayID
	// and Received it names the relay's copy, which is what a cursor past
	// everything the relay holds is checked against before anything is
	// downloaded again. Zero, a record written before it was kept, matches
	// nothing, and the check falls to the re-fetch.
	RelaySize int64 `json:"relay_size,omitempty"`
	// OnRelay says the message is still queued on the relay it came
	// through: this machine fetched it from a channel set to keep, and it
	// stays there until somebody removes it with 'auu rm'. False, the
	// zero the key is left out for, is a message acknowledged away.
	OnRelay bool `json:"on_relay,omitempty"`
	// AckOwed says, beside OnRelay, that the relay holds this message only
	// because its acknowledgement has not yet been made: it was fetched
	// whole from a channel that does not keep, and the record was saved
	// before the acknowledgement, saying what the relay still held, so
	// that an acknowledgement refused or cut off leaves a record that is
	// counted as on the relay and is acknowledged at the next fetch
	// without a byte downloaded again (G32, R47). The acknowledgement's
	// success, or the relay saying the row is gone, clears both in one
	// save. It means nothing without OnRelay: a record that a cursor reset
	// or a keep setting let go from the relay is not acknowledged. False,
	// the zero the key is left out for, is every other record, among them
	// mail kept on the relay on purpose.
	AckOwed bool `json:"ack_owed,omitempty"`
	// Channel is the channel the message was sent to, or filed under on
	// receipt; empty is default.
	Channel string `json:"channel,omitempty"`
	// Via is the relays a received message came through before the one it
	// arrived at, nearest the sender first, joined by "!". Empty — the
	// value the key is left out for — is mail posted to that relay
	// directly, which is every message on a relay that peers with nobody.
	//
	// It is the recipient's own record of where their mail has been, since
	// a relay cannot judge that for them, and it is what a reply is sent
	// back along: reversed, it is the path from here to whoever wrote.
	Via string `json:"via,omitempty"`
	// Path is the address a sent message went by: the relays between this
	// machine's relay and the recipient's, nearest first, joined by "!".
	// Empty — the value the key is left out for — is a recipient on the
	// relay it was posted to, which is every message sent before relays
	// could forward.
	//
	// It is the sender's copy of where their mail went, and it is what
	// makes RelayID legible: with a path that id is a row in the first
	// hop's queue rather than a message in a mailbox, and it is the number
	// an undeliverable coming back will name.
	Path string `json:"path,omitempty"`
	// Newer names the critical section this build does not know that a
	// stream carries, which is why it waits on the relay rather than being
	// here (D42): PayloadOnRelay is true beside it, nothing of the body is
	// here, and a build that knows the section fetches it whole. Empty, the
	// value the key is left out for, is every other message.
	Newer string `json:"newer,omitempty"`
	// DroppedSections counts the sections this build does not read on a
	// message, none of them critical and unknown, that were over
	// wire.MaxKeptBytes and so not kept with the message (D31); the ones
	// at or under it are kept in Inner.Sections as they came. Zero, the
	// value the key is left out for, is a message that lost none.
	DroppedSections int `json:"dropped_sections,omitempty"`
	// Copies is a sent message to several: one entry per recipient, in the
	// order the recipients section names them, saying where each copy went
	// and whether the relay has it. The record's Inner is the first copy's,
	// since the copies differ only in their to and their signature. Empty,
	// the value the key is left out for, is every other record.
	Copies []SentCopy `json:"copies,omitempty"`
}

// SentCopy is one copy of a sent message to several.
type SentCopy struct {
	Fingerprint string `json:"fingerprint"`
	// Name is the recipient's name on this machine when it was sent.
	Name string `json:"name,omitempty"`
	// Path is the relays the copy went by, joined by "!", empty for a
	// recipient on the relay it was posted to.
	Path string `json:"path,omitempty"`
	// RelayID is the relay's id for the copy once it has it: a message in
	// the recipient's mailbox, or a row in the first hop's queue for a
	// copy by a path. Zero is a copy not yet placed.
	RelayID int64 `json:"relay_id,omitempty"`
	// RefusedCode and Refused are the relay's code and sentence the last
	// time it refused the copy, as the outbox keeps them; empty once it is
	// placed.
	RefusedCode string `json:"refused_code,omitempty"`
	Refused     string `json:"refused,omitempty"`
	// Dropped says the sender gave the copy up with auu outbox drop, so it
	// will never be placed; a copy the relay has cannot be dropped.
	Dropped bool `json:"dropped,omitempty"`
}

// Box names a spool directory.
type Box string

const (
	Inbox      Box = inboxDir
	Sent       Box = sentDir
	Quarantine Box = quarantineDir
)

// StillOnRelay reports whether the relay is taken to hold something of this
// message under its relay id: the message itself, kept there, or a
// quarantined stream's payload that was left there and is not gone.
func (m *Stored) StillOnRelay() bool {
	return m.OnRelay || (m.PayloadOnRelay && !m.PayloadGone)
}

func (s *Store) msgPath(box Box, id string) string {
	return s.path(string(box), id+".json")
}

// Save writes a message into a spool directory.
func (s *Store) Save(box Box, m *Stored) error {
	if m.Inner == nil || m.Inner.ID == "" {
		return errors.New("message has no id")
	}
	if message.ValidID(m.Inner.ID) != nil {
		return fmt.Errorf("refusing to store message with malformed id %q", m.Inner.ID)
	}
	if m.Arrived.IsZero() {
		m.Arrived = time.Now().UTC()
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.msgPath(box, m.Inner.ID), append(data, '\n'), fileMode)
}

// errNoMessage is Load's error for an id the box does not hold, which
// Holding tells from every other.
var errNoMessage = errors.New("no message")

// Holding is Load for a caller that asks whether a box holds a message at
// all, by its whole id: nil and no error when it does not, and Load's error
// for a record that is there and will not read.
func (s *Store) Holding(box Box, id string) (*Stored, error) {
	m, err := s.Load(box, id)
	if errors.Is(err, errNoMessage) {
		return nil, nil
	}
	return m, err
}

// UpdateSent is how a sent record is written (G45, R61): the record is
// read, given to change, and what change returns is saved, all under the
// home's sent lock, so that two processes placing two of a message's
// copies at once do not each save over the other's change. Replacing the
// file atomically is no protection, since each writer replaces the whole
// record with the one it read. change is given nil when the box does not
// hold the record, and returns nil to save nothing; it runs under the
// lock, so it does nothing but change the record.
func (s *Store) UpdateSent(id string, change func(m *Stored) *Stored) error {
	lock, _, err := lockfile.Take(context.Background(), s.SentLockPath(), sentLockWait, nil)
	if err != nil {
		return err
	}
	defer lock.Release()
	m, err := s.Holding(Sent, id)
	if err != nil {
		return err
	}
	next := change(m)
	if next == nil {
		return nil
	}
	return s.Save(Sent, next)
}

// Load reads one message from a spool directory.
func (s *Store) Load(box Box, id string) (*Stored, error) {
	// Guards the filesystem: an id arrives inside a signed but otherwise
	// untrusted record, and it becomes a file name.
	if message.ValidID(id) != nil {
		return nil, fmt.Errorf("malformed message id %q", id)
	}
	path := s.msgPath(box, id)
	f, err := regular.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w %s", errNoMessage, id)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	// Read strictly (R24, R24a): a key this program does not write, a key
	// twice or one in another case is refused by name rather than dropped.
	// Every key v0.15.0, v0.16.0 and v0.17.0 wrote, the message inside and
	// each copy included, is still on Stored, so a record any of them wrote
	// reads as it did.
	var m Stored
	if err := wire.Decode(data, &m); err != nil {
		return nil, damaged(path, "will not read", err, recordAdvice)
	}
	if m.Inner == nil {
		return nil, errors.New("the record holds no message")
	}
	// A record from v0.15.0 to v0.17.0 has no arrival of its own; the
	// relay's received stands in for it, which is the order it was listed
	// in when it was written. Those releases kept whatever received a
	// relay sent, and one outside what this program can write back would
	// put a time in serve's ledger its save refuses, at every start, and
	// one ahead of this machine's clock would list the message newest for
	// good (G9); for that record the file's own time stands in, held to
	// the same two, and this machine's clock otherwise.
	if m.Arrived.IsZero() {
		m.Arrived = s.arrivedBefore(f, path, m.Received)
	}
	if m.RelayID < 0 {
		return nil, fmt.Errorf("the record's relay id %d is negative", m.RelayID)
	}
	if m.RelaySize < 0 {
		return nil, fmt.Errorf("the record's relay size %d is negative", m.RelaySize)
	}
	// Every record names the relay it came through. One that names none
	// is from before a home could know more than one, and nothing on this
	// machine is from before; one that names something that is not a
	// relay name was not written by this program.
	if m.Relay == "" {
		return nil, errors.New("the record names no relay, which is how a record from before v0.11.0 was written; delete the file")
	}
	if err := ValidRelayName(m.Relay); err != nil {
		return nil, fmt.Errorf("the record's relay: %v", err)
	}
	// The record was written after Open ran every rule; a record that
	// says otherwise was not written by this program, or was written by
	// one from before a rule, and every print that slices its id, its
	// sender or a digest, or shows its words, expects what the rule holds.
	if err := message.ValidID(m.Inner.ID); err != nil {
		return nil, fmt.Errorf("the record's message id: %v", err)
	}
	// Save names the file by the message's id, so a record under another
	// id's name was put there by something else, and a later save or
	// remove of what it says it is would touch another file (C-4).
	if m.Inner.ID != id {
		return nil, damaged(path, "holds the message "+m.Inner.ID+", not the one its name says", nil, recordAdvice)
	}
	if !identity.ValidFingerprint(m.Inner.From) || !identity.ValidFingerprint(m.Inner.To) {
		return nil, errors.New("the record's from or to is not a fingerprint")
	}
	if err := m.Inner.Body.ValidShape(); err != nil {
		return nil, fmt.Errorf("the record's message: %v", err)
	}
	// What a message kept of its sections was held to wire.Check by Open,
	// and each it did not know to wire.MaxKeptBytes by the fetch, a known
	// section's size being its own rule's: a record that says otherwise was
	// not written by this program. The check asks whether the name is known
	// on any path, not on a message, since a release before this one kept
	// a section known only on requests and answers whole, and a record any
	// release from v0.15.0 wrote is read by every later one (R13); the fetch
	// holds the cap on the message path from now on.
	if err := wire.Check(m.Inner.Sections); err != nil {
		return nil, fmt.Errorf("the record's sections: %v", err)
	}
	for _, sec := range m.Inner.Sections {
		if !wire.Known(sec.Name, wire.AnyPath) && len(sec.Data) > wire.MaxKeptBytes {
			return nil, fmt.Errorf("the record's section %q is %d bytes, over the %d kept", sec.Name, len(sec.Data), wire.MaxKeptBytes)
		}
	}
	// The list of everybody a message to several went to was held to its
	// rule by Open, for the reader the record's to names, and by the sealer
	// for each copy, a sent record keeping the first copy's: a record whose
	// list says otherwise was not written by this program.
	if _, err := recipients.CheckSections(m.Inner.Sections, m.Inner.Body.Type, m.Inner.To); err != nil {
		return nil, fmt.Errorf("in the record, %v", err)
	}
	if err := validCopies(box, &m); err != nil {
		return nil, fmt.Errorf("the record's copies: %v", err)
	}
	if m.DroppedSections < 0 {
		return nil, fmt.Errorf("the record's dropped section count %d is negative", m.DroppedSections)
	}
	if m.Newer != "" {
		if err := wire.ValidName(m.Newer); err != nil {
			return nil, fmt.Errorf("the record's newer section: %v", err)
		}
		if !m.PayloadOnRelay {
			return nil, errors.New("the record waits for a newer auu but says its payload is not on the relay")
		}
	}
	return &m, nil
}

// validCopies holds a sent record's copies to what the sender wrote: only
// in sent/, only on a message the recipients section says went to several,
// one copy for each recipient it names and no other, each path an address,
// each relay id a number the relay could have given, and each kept refusal
// a line of at most relayapi.MaxSaid with a code that is a name, since
// every one of them is shown.
func validCopies(box Box, m *Stored) error {
	if len(m.Copies) == 0 {
		return nil
	}
	if box != Sent {
		return errors.New("only a sent message has copies")
	}
	list, err := recipients.CheckSections(m.Inner.Sections, m.Inner.Body.Type, m.Inner.To)
	if err != nil {
		return err
	}
	if len(list.To) != len(m.Copies) {
		return fmt.Errorf("%d copies for a message to %d", len(m.Copies), len(list.To))
	}
	named := make(map[string]bool, len(list.To))
	for _, fp := range list.To {
		named[fp] = true
	}
	for i, c := range m.Copies {
		if !identity.ValidFingerprint(c.Fingerprint) || !named[c.Fingerprint] {
			return fmt.Errorf("copy %d is not for a recipient the message names", i+1)
		}
		delete(named, c.Fingerprint)
		if c.Name != "" && identity.ValidName(c.Name) != nil {
			return fmt.Errorf("copy %d's name is not a name", i+1)
		}
		if c.Path != "" && CheckAddress(strings.Split(c.Path, "!"), nil, relayapi.MaxHops) != nil {
			return fmt.Errorf("copy %d's path is not an address", i+1)
		}
		if c.RelayID < 0 {
			return fmt.Errorf("copy %d's relay id %d is negative", i+1, c.RelayID)
		}
		if c.Dropped && c.RelayID != 0 {
			return fmt.Errorf("copy %d is given up and placed both", i+1)
		}
		if c.RefusedCode != "" && wire.ValidName(c.RefusedCode) != nil {
			return fmt.Errorf("copy %d's refusal code is not a name", i+1)
		}
		if len(c.Refused) > relayapi.MaxSaid || message.ValidOneLine("refused", c.Refused) != nil {
			return fmt.Errorf("copy %d's refusal is not one line of at most %d bytes", i+1, relayapi.MaxSaid)
		}
	}
	return nil
}

// warnedOnce is the paths already warned about in this process — a spool
// file a box could not read (warnUnreadable), a record whose arrival
// Load could not take from its received (arrivedBefore, keyed by the
// path with "#arrived" after it) and a directory under relays/ that is
// not a relay (warnSkippedRelay) — so a command that lists a box or the
// relays more than once says each once. Keyed by the full path, so the
// uses cannot collide.
var warnedOnce sync.Map

// warnUnreadable says, once per file per command, that a record in a box
// could not be read and is left out of the listing.
func (s *Store) warnUnreadable(box Box, name string, err error) {
	path := s.path(string(box), name)
	if _, already := warnedOnce.LoadOrStore(path, true); already {
		return
	}
	if errors.Is(err, ErrDamaged) {
		// The sentence names the file and what to do already.
		fmt.Fprintf(os.Stderr, "warning: %v; it is not listed\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %s could not be read (%v) and is not listed\n", path, err)
}

// arrivedBefore is the arrival Load gives a record an earlier release
// wrote: its received when that can be written back and is not ahead of
// this machine's clock by more than relayapi.MaxSkew (G9), otherwise the
// time the record's file was last written held to the same two rules,
// otherwise now, said once per file per command with which it took. The
// arrival is UTC, as Save writes one. A received in the year 9000 lent as
// the arrival would list the message newest for good, and a read would
// write it back as its own.
func (s *Store) arrivedBefore(f *os.File, path string, received time.Time) time.Time {
	var modTime *time.Time
	if fi, err := f.Stat(); err == nil {
		t := fi.ModTime()
		modTime = &t
	}
	arrived, which := legacyArrival(received, modTime, time.Now())
	if which == "" {
		return arrived
	}
	if _, already := warnedOnce.LoadOrStore(path+"#arrived", true); !already {
		fmt.Fprintf(os.Stderr, "warning: %s holds a received time this program cannot write back or that is ahead of this machine's clock; "+
			"it is ordered as arriving at %s, %s\n", path, arrived.Format(time.RFC3339), which)
	}
	return arrived
}

// legacyArrival is arrivedBefore's choice, given the clock: received when it
// fits, otherwise the file's time when there is one and it fits, otherwise
// now, each UTC. A time fits when relayapi.Writable holds it and it is not
// after now plus relayapi.MaxSkew. which is empty when received was lent,
// and otherwise names what was taken, for the warning.
func legacyArrival(received time.Time, modTime *time.Time, now time.Time) (arrived time.Time, which string) {
	fits := func(t time.Time) bool {
		return relayapi.Writable(t) && !t.After(now.Add(relayapi.MaxSkew))
	}
	if fits(received) {
		return received.UTC(), ""
	}
	if modTime != nil && fits(*modTime) {
		return modTime.UTC(), "the file's time"
	}
	return now.UTC(), "this machine's clock"
}

// List returns every message in a spool directory, oldest first.
func (s *Store) List(box Box) ([]*Stored, error) {
	return s.list(box, true)
}

// ListQuietly is List for a look at a box that is not the box's own
// listing: the fetch's look for streams that wait for a newer auu, and the
// count of them. A record that will not read is left out without a word,
// since the warning says it "is not listed", which is the box's own listing
// to say, once, when a person asks for it.
func (s *Store) ListQuietly(box Box) ([]*Stored, error) {
	return s.list(box, false)
}

func (s *Store) list(box Box, warn bool) ([]*Stored, error) {
	entries, err := os.ReadDir(s.path(string(box)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Stored
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		m, err := s.Load(box, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			// A stray file must not break the whole listing, and must not
			// vanish from it in silence either: a record that will not
			// read is a message a person thinks they have. Said once per
			// file per command, since a listing is read more than once
			// in one. The container suite's M09 found a flipped record
			// simply absent.
			if warn {
				s.warnUnreadable(box, e.Name(), err)
			}
			continue
		}
		out = append(out, m)
	}
	slices.SortFunc(out, ArrivalOrder)
	return out, nil
}

// LeftOn counts the messages this machine has left on one relay on
// purpose, which is what the relay still counts behind this machine's
// cursor: mail fetched from a channel set to keep, in the inbox or the
// quarantine; a quarantined stream whose payload was recorded from its
// manifest and deliberately not fetched, so that a stranger cannot make
// anybody download two gigabytes; and a message removed here alone with
// 'auu rm --local-only', which has no record left to say so and is
// remembered in the relay's own left-behind file. A fetch that finds the
// relay counting more than these has a cursor past mail.
func (s *Store) LeftOn(relay string) (int64, error) {
	var n int64
	for _, box := range []Box{Inbox, Quarantine} {
		msgs, err := s.List(box)
		if err != nil {
			return 0, err
		}
		for _, m := range msgs {
			if m.Relay == relay && m.StillOnRelay() {
				n++
			}
		}
	}
	left, err := s.LeftBehind(relay)
	if err != nil {
		return 0, err
	}
	return n + int64(len(left)), nil
}

// Move relocates a message between boxes, taking its attachment directory with
// it when it has one. A streamed message's files live beside its record, so
// moving the record alone would strand them.
//
// The files are placed first, the record published second and the old
// record retired last (G31, R46): a record in the new box is never there
// before its files are, so a move that fails part way leaves the message
// whole where it was. A failure saving the new record puts the files back;
// a failure removing the old record after the save is said, and the new
// box, which Find searches first, answers with the record whose files are
// beside it. A record or files in the new box left by an earlier attempt
// are taken over: the old box's files, while they are there, are the ones
// that were verified, and once they have gone they are the new box's.
//
// It holds the spool lock, which a stream's delivery holds to swap its
// files in, so a move and a delivery of the one message never act on its
// files at once.
func (s *Store) Move(from, to Box, id string) error {
	m, err := s.Load(from, id)
	if err != nil {
		return err
	}
	lock, _, err := lockfile.Take(context.Background(), s.SpoolLockPath(), spoolLockWait, nil)
	if err != nil {
		return err
	}
	defer lock.Release()
	placed := false
	src, dst := s.AttachmentDir(from, id), s.AttachmentDir(to, id)
	if m.Streamed {
		if _, err := os.Lstat(src); err == nil {
			if err := os.RemoveAll(dst); err != nil {
				return err
			}
			if err := os.Rename(src, dst); err != nil {
				return err
			}
			placed = true
		}
	}
	if err := s.Save(to, m); err != nil {
		if placed {
			if rerr := os.Rename(dst, src); rerr != nil {
				return fmt.Errorf("%w; and its files could not be put back from %s: %v", err, dst, rerr)
			}
		}
		return err
	}
	if err := os.Remove(s.msgPath(from, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("message %s is in %s, but its old record in %s could not be removed: %w", id, to, from, err)
	}
	return nil
}

// Remove deletes a stored message and its attachment directory, if it has
// one. A message that is not there is not an error: the caller asked for
// it to be gone, and it is.
func (s *Store) Remove(box Box, id string) error {
	// The rule at the call, as Load and Save have it: the store's exported
	// edge is a boundary of its own, whatever its callers checked.
	if err := message.ValidID(id); err != nil {
		return fmt.Errorf("message id %q is %w", id, err)
	}
	// A sent record goes under the lock it is changed under, so that a
	// change read before the removal is not saved after it.
	if box == Sent {
		lock, _, err := lockfile.Take(context.Background(), s.SentLockPath(), sentLockWait, nil)
		if err != nil {
			return err
		}
		defer lock.Release()
	}
	if err := os.RemoveAll(s.AttachmentDir(box, id)); err != nil {
		return err
	}
	err := os.Remove(s.msgPath(box, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PeekByID reads what a record Load refuses still says of the relay's
// copy, without loading it: the way out for such a record, which List does
// not show and Find cannot name. The boxes are searched for the id's file
// and the first found is read; the box is returned, with the relay name and
// the relay's number the raw record carried, each held to its own rule
// (ValidRelayName; a positive int64) and empty or zero when it did not
// carry one that passes, and the sender when it is a fingerprint. Nothing
// else in the record is read and nothing is changed. ErrNotExist when no
// box holds the id.
//
// It is the first of the two steps of removing such a record, and
// Remove(box, id) the second: a caller that leaves the relay's copy
// accounted for saves that account between them, so that a save which
// fails leaves the record, and the removal can be asked again (G33, R48).
func (s *Store) PeekByID(id string) (box Box, relay string, relayID int64, from string, err error) {
	if err := message.ValidID(id); err != nil {
		return "", "", 0, "", fmt.Errorf("message id %q is %w", id, err)
	}
	for _, box := range []Box{Inbox, Quarantine, Sent} {
		path := s.msgPath(box, id)
		data, err := regular.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", "", 0, "", err
		}
		var raw struct {
			Relay   string `json:"relay"`
			RelayID int64  `json:"relay_id"`
			Inner   struct {
				From string `json:"from"`
			} `json:"inner"`
		}
		if json.Unmarshal(data, &raw) == nil {
			if ValidRelayName(raw.Relay) == nil && raw.RelayID > 0 {
				relay, relayID = raw.Relay, raw.RelayID
			}
			// The sender, under its own rule, for the left-behind entry:
			// what is not a fingerprint is not known.
			if identity.ValidFingerprint(raw.Inner.From) {
				from = raw.Inner.From
			}
		}
		return box, relay, relayID, from, nil
	}
	return "", "", 0, "", os.ErrNotExist
}

// RemoveByID is PeekByID and then Remove: a record Load refuses, removed
// by its id alone with its attachments, and what it said of the relay's
// copy returned. A caller that must leave that copy accounted for calls
// the two itself and saves the account between them.
func (s *Store) RemoveByID(id string) (box Box, relay string, relayID int64, from string, err error) {
	box, relay, relayID, from, err = s.PeekByID(id)
	if err != nil {
		return "", "", 0, "", err
	}
	if err := s.Remove(box, id); err != nil {
		return "", "", 0, "", err
	}
	return box, relay, relayID, from, nil
}

// AttachmentDir is where a streamed message's files live: beside its record,
// named for the message.
func (s *Store) AttachmentDir(box Box, id string) string {
	return filepath.Join(s.root, string(box), id+".d")
}

// spoolLockWait is how long a move waits for the spool lock: a swap holds
// it for two renames and a record's save.
const spoolLockWait = 30 * time.Second

// SpoolLockPath is the lock a streamed message's files are swapped under,
// one for the home: the swap and the record's save are short, and two
// fetches through two relays can deliver the one message at once.
func (s *Store) SpoolLockPath() string { return s.path("spool.lock") }

// sentLockWait is how long a writer of a sent record waits for another:
// the other holds it for one record's read and save.
const sentLockWait = 30 * time.Second

// SentLockPath is the lock every writer of a sent record holds (UpdateSent),
// one for the home, as the spool lock is: a send, its resume and a drop
// are separate processes, and each changes the record of one message.
func (s *Store) SentLockPath() string { return s.path("sent.lock") }

// ServeDir is where 'auu serve' keeps its state: its lock, its ledger, and a
// directory apiece for each channel, thread and worktree. It is the store's
// to name, as the relays' directory is, and serve's to fill; nothing is
// created here.
func (s *Store) ServeDir() string { return s.path(serveDir) }

// Find looks a message up in the inbox, then sent, then quarantine, accepting a
// unique id prefix of at least 4 characters.
// ErrNoMatch is Find's answer when no readable record has the id or the
// prefix; it wraps the id, and a caller that would remove a record by its
// id without reading it asks for this and nothing else.
var ErrNoMatch = errors.New("no message matches")

func (s *Store) Find(idOrPrefix string) (Box, *Stored, error) {
	if len(idOrPrefix) < 4 {
		return "", nil, errors.New("message id prefix must be at least 4 characters")
	}
	lower := strings.ToLower(idOrPrefix)
	var (
		hits  []*Stored
		boxes []Box
	)
	for _, box := range []Box{Inbox, Sent, Quarantine} {
		msgs, err := s.List(box)
		if err != nil {
			return "", nil, err
		}
		for _, m := range msgs {
			if m.Inner.ID == lower {
				return box, m, nil
			}
			if strings.HasPrefix(m.Inner.ID, lower) {
				hits = append(hits, m)
				boxes = append(boxes, box)
			}
		}
	}
	// A message to yourself is in sent/ and in inbox/ under one id. That is
	// one message in two places, not two messages, and the boxes are walked
	// inbox first so the copy that was received is the one found. Only
	// different ids are an ambiguity.
	var distinct []string // full ids, in the order first seen
	for _, m := range hits {
		known := false
		for _, d := range distinct {
			if d == m.Inner.ID {
				known = true
				break
			}
		}
		if !known {
			distinct = append(distinct, m.Inner.ID)
		}
	}
	switch len(distinct) {
	case 0:
		return "", nil, fmt.Errorf("%w %q", ErrNoMatch, idOrPrefix)
	case 1:
		return boxes[0], hits[0], nil
	default:
		short := make([]string, len(distinct))
		for i, d := range distinct {
			short[i] = d[:12]
		}
		return "", nil, &ErrAmbiguous{Query: idOrPrefix, Candidates: short, What: "messages"}
	}
}

// FindThread finds the latest message on a thread, in the inbox or in sent,
// by thread id or a unique prefix of one. Quarantine is not searched: a
// stranger's thread is not one to reply on.
//
// "Latest" is LaterThan's, ArrivalOrder: by when the message arrived on
// this machine, then by the id the relay gave it, and by the relay's
// received and the sender's own timestamp only to break a tie. The order
// is this machine's own and never depends on which file was listed first.
func (s *Store) FindThread(idOrPrefix string) (Box, *Stored, error) {
	if len(idOrPrefix) < 4 {
		return "", nil, errors.New("thread id prefix must be at least 4 characters")
	}
	lower := strings.ToLower(idOrPrefix)
	var (
		latest    *Stored
		latestBox Box
		threads   []string
	)
	for _, box := range []Box{Inbox, Sent} {
		msgs, err := s.List(box)
		if err != nil {
			return "", nil, err
		}
		for _, m := range msgs {
			tid := m.Inner.Body.Thread
			if !strings.HasPrefix(tid, lower) {
				continue
			}
			known := false
			for _, t := range threads {
				if t == tid {
					known = true
					break
				}
			}
			if !known {
				threads = append(threads, tid)
			}
			if latest == nil || LaterThan(m, latest) {
				latest, latestBox = m, box
			}
		}
	}
	switch len(threads) {
	case 0:
		return "", nil, fmt.Errorf("no thread matches %q", idOrPrefix)
	case 1:
		return latestBox, latest, nil
	default:
		short := make([]string, len(threads))
		for i, t := range threads {
			short[i] = t[:12]
		}
		return "", nil, &ErrAmbiguous{Query: idOrPrefix, Candidates: short, What: "threads"}
	}
}

// FirstOnThread is the message a thread was opened with, by its full id: the
// earliest of the messages on the thread that are here, preferring one that
// is a reply to nothing, since that is what opens a thread. A thread is not
// named after the message that started it — it is given an id of its own —
// so this is a walk and not a lookup.
//
// It is how the thread's subject is known, the subject being the opener's.
// A thread whose first message has been removed here answers with the
// earliest of what is left that answers nothing, and failing that with the
// earliest of all, which is the best that can be said; a thread with
// nothing on it is not found.
//
// Quarantine is not searched, for the same reason FindThread does not search
// it: a message from somebody who is not a peer is not part of anyone's
// thread, and letting one in would let a stranger who learned a thread id
// choose what a trusted message says it is about.
func (s *Store) FirstOnThread(thread string) (Box, *Stored, error) {
	var (
		first    *Stored
		firstBox Box
	)
	for _, box := range []Box{Inbox, Sent} {
		msgs, err := s.List(box)
		if err != nil {
			return "", nil, err
		}
		for _, m := range msgs {
			if m.Inner.Body.Thread != thread {
				continue
			}
			if first == nil || opensBefore(m, first) {
				first, firstBox = m, box
			}
		}
	}
	if first == nil {
		return "", nil, fmt.Errorf("no message on thread %q", thread)
	}
	return firstBox, first, nil
}

// opensBefore orders two messages on a thread by how likely each is to be
// the one it was opened with: a message that answers nothing comes before
// one that answers something, whatever the clocks say, and otherwise the
// earlier of the two by LaterThan's ordering.
func opensBefore(a, b *Stored) bool {
	if opensA, opensB := a.Inner.Body.InReplyTo == "", b.Inner.Body.InReplyTo == ""; opensA != opensB {
		return opensA
	}
	return LaterThan(b, a)
}

// ArrivalOrder is the one order of messages on this machine: the inbox's,
// a thread's, and the order serve takes its pending messages in. It is by
// when each arrived here, then by the relay's id, then by the relay's
// received, then by the sender's own timestamp, and last by the message
// id, so that two records are never equal unless they are one. A
// thread's order is the receiver's, not the sender's clock and not the
// relay's: the timestamp inside a message is whatever its sender wrote,
// and when it came first a peer who stamped a message in the year 9999
// was "latest" on that thread for as long as the message was kept, so
// every reply by thread went to them; and a relay's received is its own
// word, which a relay with its clock ahead could use to pin its message
// atop the inbox. Arrival here is this machine's own, and the relay's
// received and the sender's stamp only break a tie.
func ArrivalOrder(a, b *Stored) int {
	if c := a.Arrived.Compare(b.Arrived); c != 0 {
		return c
	}
	if c := cmp.Compare(a.RelayID, b.RelayID); c != 0 {
		return c
	}
	if c := a.Received.Compare(b.Received); c != 0 {
		return c
	}
	if c := a.Inner.Time.Compare(b.Inner.Time); c != 0 {
		return c
	}
	return strings.Compare(a.Inner.ID, b.Inner.ID)
}

// LaterThan says whether a comes after b in ArrivalOrder: the later of two
// messages on a thread.
func LaterThan(a, b *Stored) bool { return ArrivalOrder(a, b) > 0 }

// MarkRead flags a message as read in place.
func (s *Store) MarkRead(box Box, id string) error {
	m, err := s.Load(box, id)
	if err != nil {
		return err
	}
	if m.Read {
		return nil
	}
	m.Read = true
	return s.Save(box, m)
}
