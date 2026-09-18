package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// One home, several relays.
//
// Everything a relay is to this machine — the URL, the pinned anchor, this
// machine's certificate there, how far its mailbox has been drained — lives in
// one directory named for the relay. The identity, the peer list and the
// spools are shared: a person is one person wherever their mail arrives, and
// that is what "one home" means.

const (
	relaysDir = "relays"
	relayFile = "relay.json"
)

// ErrNoDefaultRelay means no relay has been chosen to act on when none is
// named. A home gets a default the moment its first relay is added, so this
// is what a person sees after removing the one they had.
var ErrNoDefaultRelay = errors.New("no default relay")

// ErrNoSuchRelay means nothing in this home matches.
var ErrNoSuchRelay = errors.New("no such relay")

// Relay is one relay this home knows: what it is called here, where it is,
// and what this machine has learned about its certificates.
type Relay struct {
	Name  string    `json:"name"`
	URL   string    `json:"url"`
	Added time.Time `json:"added"`

	// TrustAnchorSPKI is the hash of the trust anchor this machine pinned
	// for this relay, and what its trust_anchor.pem is checked against.
	// Empty when the relay has a publicly trusted certificate.
	TrustAnchorSPKI string `json:"trust_anchor_spki,omitempty"`

	// ServerIntSPKI and ServerIntNotBefore are this relay's server signing
	// intermediate as this machine last saw it. A newer one is a rotation,
	// because only the operator's offline authority can issue one; an older
	// one is a retired authority being replayed, and is refused. The ratchet
	// is per relay: what one relay's authority did says nothing about
	// another's.
	ServerIntSPKI      string    `json:"server_int_spki,omitempty"`
	ServerIntNotBefore time.Time `json:"server_int_not_before,omitempty"`
}

// ValidRelayName checks a name a person typed. It is an identity name: the
// same characters, the same reserved word, so one rule covers every name in
// the home and no name can ever be a path segment of its own devising.
func ValidRelayName(name string) error {
	if err := identity.ValidName(name); err != nil {
		return fmt.Errorf("relay name %q: letters, digits, '.', '_' and '-' only, "+
			"beginning with a letter or digit, and never \"self\"", name)
	}
	return nil
}

func (s *Store) relayDir(name string) string { return s.path(relaysDir, name) }

// RelayDir is where everything about one relay lives.
func (s *Store) RelayDir(r *Relay) string { return s.relayDir(r.Name) }

func (s *Store) relayPath(r *Relay, file string) string {
	return filepath.Join(s.relayDir(r.Name), file)
}

// Relays returns every relay this home knows, by name.
func (s *Store) Relays() ([]*Relay, error) {
	entries, err := os.ReadDir(s.path(relaysDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Relay
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		r, err := s.readRelay(e.Name())
		if errors.Is(err, os.ErrNotExist) {
			// A directory with no record in it is a half-finished 'relay
			// add' and not a relay. Adding it again finishes the job.
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) readRelay(name string) (*Relay, error) {
	path := filepath.Join(s.relayDir(name), relayFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Relay
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, damaged(path, "is not valid JSON", err, fmt.Sprintf(
			"enrol again with a token, or remove the relay with 'auu relay rm %s' and add it again", name))
	}
	// The directory is the name. A record that says otherwise would send
	// every read for one relay at another relay's files.
	r.Name = name
	return &r, nil
}

// SaveRelay writes a relay's record.
func (s *Store) SaveRelay(r *Relay) error {
	if err := ValidRelayName(r.Name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.relayDir(r.Name), dirMode); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.relayPath(r, relayFile), append(data, '\n'), fileMode)
}

// Relay finds one relay by exact name, by URL, or by a unique name prefix, in
// that order — the way a peer is found, for the same reason: a person types
// what they remember.
func (s *Store) Relay(query string) (*Relay, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("empty relay name")
	}
	relays, err := s.Relays()
	if err != nil {
		return nil, err
	}
	if len(relays) == 0 {
		return nil, fmt.Errorf("%w: this home has no relays yet", ErrNoSuchRelay)
	}
	for _, r := range relays {
		if r.Name == query {
			return r, nil
		}
	}
	if looksLikeURL(query) {
		for _, r := range relays {
			if sameRelayURL(r.URL, query) {
				return r, nil
			}
		}
		return nil, fmt.Errorf("%w at %s; add it first", ErrNoSuchRelay, query)
	}
	lower := strings.ToLower(query)
	var byPrefix []*Relay
	for _, r := range relays {
		if strings.HasPrefix(strings.ToLower(r.Name), lower) {
			byPrefix = append(byPrefix, r)
		}
	}
	switch len(byPrefix) {
	case 1:
		return byPrefix[0], nil
	case 0:
		return nil, fmt.Errorf("%w named %q; this home has %s",
			ErrNoSuchRelay, query, relayNames(relays))
	default:
		e := &ErrAmbiguous{Query: query, What: "relays"}
		for _, r := range byPrefix {
			e.Candidates = append(e.Candidates, r.Name)
		}
		return nil, e
	}
}

// relayNames lists what a home has, for an error that would otherwise leave
// somebody guessing.
func relayNames(relays []*Relay) string {
	if len(relays) == 0 {
		return "none"
	}
	names := make([]string, 0, len(relays))
	for _, r := range relays {
		names = append(names, r.Name)
	}
	return strings.Join(names, ", ")
}

// RelayNames is relayNames over what the home holds, for a command that has
// to say what the choices are.
func (s *Store) RelayNames() string {
	relays, err := s.Relays()
	if err != nil {
		return "none"
	}
	return relayNames(relays)
}

func looksLikeURL(s string) bool { return strings.Contains(s, "://") }

// sameRelayURL compares two relay URLs the way a person would. The port is
// part of the address — token.NormaliseRelay keeps it, and so does every
// token audience — but a port a person left off because it is the scheme's
// own is the same address, and typing it should not fail to match.
func sameRelayURL(a, b string) bool {
	if token.NormaliseRelay(a) == token.NormaliseRelay(b) {
		return true
	}
	return withoutDefaultPort(a) == withoutDefaultPort(b)
}

func withoutDefaultPort(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return token.NormaliseRelay(raw)
	}
	host := u.Host
	switch {
	case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return u.Scheme + "://" + host
}

// AddRelay records a relay. An empty name is the URL's host, which is what a
// person calls it anyway.
func (s *Store) AddRelay(name, rawURL string) (*Relay, error) {
	normalised := token.NormaliseRelay(rawURL)
	if err := token.ValidateRelay(normalised); err != nil {
		return nil, fmt.Errorf("relay URL %s %v", rawURL, err)
	}
	relays, err := s.Relays()
	if err != nil {
		return nil, err
	}
	for _, r := range relays {
		if sameRelayURL(r.URL, normalised) {
			return nil, fmt.Errorf("%s is already here, as %q", r.URL, r.Name)
		}
	}
	if name == "" {
		name, err = defaultRelayName(normalised, relays)
		if err != nil {
			return nil, err
		}
	}
	if err := ValidRelayName(name); err != nil {
		return nil, err
	}
	for _, r := range relays {
		if strings.EqualFold(r.Name, name) {
			return nil, fmt.Errorf("this home already has a relay called %q, at %s; "+
				"choose another name", r.Name, r.URL)
		}
	}
	r := &Relay{Name: name, URL: normalised, Added: time.Now().UTC().Truncate(time.Second)}
	if err := s.SaveRelay(r); err != nil {
		return nil, err
	}
	// The first relay is the default, so a home with one relay never has to
	// think about which one it means.
	if len(relays) == 0 {
		if err := s.SetDefaultRelay(r.Name); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// defaultRelayName is the name a relay gets when nobody chose one: the URL's
// host. Two relays on one host — which is what a test, and a person running
// two on one machine, both have — get the port, and then a number, so adding
// a relay never fails over a name nobody asked for.
//
// The host is made a valid name first. It used to be tried as it was, and
// a host the rule refuses — an IPv6 literal, which begins with a colon; a
// hostname over the sixty-four bytes a name may be — was refused with
// every suffix too, so the loop never returned: 'auu relay add
// https://[::1]:8443', an enrolment token naming such a relay, and Open of
// a legacy home that did spun for ever. Now the base keeps the characters
// the rule allows, so every candidate is valid and the loop ends on the
// first name not taken; and it has a ceiling all the same, after which it
// returns an error rather than a name, so no later change to the rule can
// bring the hang back.
func defaultRelayName(normalised string, existing []*Relay) (string, error) {
	base := "relay"
	var port string
	if u, err := url.Parse(normalised); err == nil && u.Hostname() != "" {
		base = relayNameBase(u.Hostname())
		port = u.Port()
	}
	taken := func(name string) bool {
		for _, r := range existing {
			if strings.EqualFold(r.Name, name) {
				return true
			}
		}
		return ValidRelayName(name) != nil
	}
	if !taken(base) {
		return base, nil
	}
	if port != "" && !taken(base+"-"+port) {
		return base + "-" + port, nil
	}
	const ceiling = 1000
	for n := 2; n <= ceiling; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if !taken(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no free name for a relay at %s under %s-%d; name it with --name", normalised, base, ceiling)
}

// relayNameBase is a host as a valid relay name: the characters the rule
// allows, kept in order, beginning at the first letter or digit, cut to
// leave room for a numbered suffix, and "relay" when nothing is left or
// what is left is the reserved word. An IPv6 literal such as ::1 becomes
// 1, and 2001:db8::1 becomes 2001db81.
func relayNameBase(host string) string {
	var b strings.Builder
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
			b.WriteByte(c)
		case b.Len() > 0 && (c == '.' || c == '_' || c == '-'):
			b.WriteByte(c)
		}
	}
	base := b.String()
	// Room for "-" and up to four digits under MaxNameBytes.
	if room := identity.MaxNameBytes - 5; len(base) > room {
		base = base[:room]
	}
	if base == "" || ValidRelayName(base) != nil {
		return "relay"
	}
	return base
}

// RenameRelay moves a relay's directory, which is its name.
func (s *Store) RenameRelay(oldName, newName string) error {
	r, err := s.Relay(oldName)
	if err != nil {
		return err
	}
	if err := ValidRelayName(newName); err != nil {
		return err
	}
	if strings.EqualFold(r.Name, newName) && r.Name != newName {
		// Only the spelling changes; a rename through a temporary name would
		// be needed on a case-insensitive filesystem, and it is not worth it.
		return fmt.Errorf("%q and %q differ only in case", r.Name, newName)
	}
	if r.Name == newName {
		return nil
	}
	if _, err := s.Relay(newName); err == nil {
		return fmt.Errorf("this home already has a relay called %q", newName)
	}
	if err := os.Rename(s.relayDir(r.Name), s.relayDir(newName)); err != nil {
		return err
	}
	old := r.Name
	r.Name = newName
	if err := s.SaveRelay(r); err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if cfg.DefaultRelay == old {
		cfg.DefaultRelay = newName
		if err := s.SaveConfig(cfg); err != nil {
			return err
		}
	}
	return nil
}

// RemoveRelay forgets a relay: its record, its pinned anchor, this machine's
// certificate there, and its cursor. Mail already in the spool stays, because
// it is mail.
func (s *Store) RemoveRelay(name string) error {
	r, err := s.Relay(name)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(s.relayDir(r.Name)); err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if cfg.DefaultRelay == r.Name {
		// Deliberately not replaced with whatever is left: which relay a
		// person means is theirs to say, and guessing it here would send
		// mail somewhere they did not choose.
		cfg.DefaultRelay = ""
		return s.SaveConfig(cfg)
	}
	return nil
}

// DefaultRelay is the relay a command acts on when none is named.
func (s *Store) DefaultRelay() (*Relay, error) {
	cfg, err := s.Config()
	if err != nil {
		return nil, err
	}
	if cfg.DefaultRelay == "" {
		return nil, ErrNoDefaultRelay
	}
	r, err := s.readRelay(cfg.DefaultRelay)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoDefaultRelay
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SetDefaultRelay records which relay commands act on by default.
func (s *Store) SetDefaultRelay(name string) error {
	r, err := s.Relay(name)
	if err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.DefaultRelay = r.Name
	return s.SaveConfig(cfg)
}

// Registered reports whether this identity is registered on a relay, as far
// as this home knows: registering writes the cursor, so the file existing is
// the record that there is a mailbox there to drain.
func (s *Store) Registered(r *Relay) bool {
	_, err := os.Stat(s.relayPath(r, cursorFile))
	return err == nil
}

// MarkRegistered records that this identity has a mailbox on a relay, by
// starting its cursor. A cursor already there is left alone: it says how far
// the mailbox has been drained, and registering again does not undrain it.
func (s *Store) MarkRegistered(r *Relay) error {
	if s.Registered(r) {
		return nil
	}
	return s.SetCursorFor(r, 0)
}

// ForgetIdentityAt drops everything in a relay's directory that belonged to
// the identity rather than to the relay: this machine's certificate and the
// key with it, how far that identity's mailbox there had been drained, and
// when its allow list was last pushed.
//
// The relay's record and its pinned anchor stay. They are facts about the
// relay, and a new identity meets the same relay with the same authority; the
// certificate, the cursor and the push are facts about an identity that has
// gone.
func (s *Store) ForgetIdentityAt(r *Relay) error {
	if err := s.RemoveCertFor(r); err != nil {
		return err
	}
	if err := s.ClearAllowPushed(r); err != nil {
		return err
	}
	err := os.Remove(s.relayPath(r, cursorFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// CursorFor is the highest message id already fetched from one relay.
func (s *Store) CursorFor(r *Relay) (int64, error) {
	return readCursor(s.relayPath(r, cursorFile), r.Name)
}

// CursorSkipsMail is a relay's mailbox holding messages this home's cursor
// is already past: the relay lists nothing after the cursor and counts
// something in all. The cursor was set ahead by hand, or the home was
// copied from a machine that had drained further, and either way it is a
// person's to put right, by removing the file the sentence names. The relay
// said how many; nothing here has been touched.
//
// The advice names the relay because a cursor is also the record that this
// identity has a mailbox there: with it gone, a plain 'auu inbox' in a home
// that knows other relays would pass this one by as one nobody has joined.
// Naming it selects it regardless, and the fetch writes the cursor again.
func (s *Store) CursorSkipsMail(r *Relay, waiting int64) error {
	waits := "messages are"
	if waiting == 1 {
		waits = "message is"
	}
	return &damagedFile{msg: fmt.Sprintf(
		"%d %s waiting on %s before this machine's cursor; delete %s and run 'auu inbox --relay %s' to fetch from the beginning",
		waiting, waits, r.Name, s.relayPath(r, cursorFile), r.Name)}
}

// SetCursorFor records how far one relay's mailbox has been drained.
func (s *Store) SetCursorFor(r *Relay, n int64) error {
	if err := os.MkdirAll(s.relayDir(r.Name), dirMode); err != nil {
		return err
	}
	return writeCursor(s.relayPath(r, cursorFile), n)
}
