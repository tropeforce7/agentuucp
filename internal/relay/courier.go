package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A relay forwards mail to a neighbouring relay by being a user of it.
//
// It has an identity of its own — the courier — enrolled on the neighbour
// with a token that neighbour's administrator issued, which is the whole of
// "the administrators trust each other" and is two commands each side
// already has. So a relay knows a neighbour twice, and each half is an
// existing thing:
//
// To dial one, a relay entry in the courier home: an ordinary auu home the
// relay's user owns, made with 'auu init' and filled with 'auu enrol TOKEN
// --name bar'. The name the operator gives the relay there is the name
// senders write in a path. The home carries the neighbour's URL, its pinned
// anchor and this courier's certificate there, under every rule those files
// already have.
//
// To accept from one, an export line in the couriers file, in the
// administrators file's format and re-read the same way. The line's name is
// this relay's name for that neighbour, and what it will write into the
// return path a reply travels back along.
//
// The operator uses one name for a neighbour in both places. Nothing can
// enforce it — a relay cannot learn a neighbour's identity from its health
// answer — so a mismatch is not silent instead: the start says which names
// appear in one and not the other, and a reply along a name this relay has
// no entry for is refused at its first hop with the name in the sentence,
// where the person replying reads it.
//
// One-way peering is allowed by construction. A relay may accept from a
// neighbour it never dials, or dial one that does not accept from it; the
// first is a relay that receives but cannot reply, the second a relay that
// sends but hears nothing back. Both are configurations an operator may
// want, and neither is a refusal.

// CourierConfig is what a relay needs to be a courier of its neighbours and
// to accept their mail. A nil CourierConfig on Config is a relay that
// forwards nothing and accepts nothing forwarded.
type CourierConfig struct {
	// Home is the auu home this relay dials its neighbours from, owned by
	// the relay's user. Empty means this relay dials nobody: it may still
	// accept forwarded mail, which is one-way peering.
	Home string
	// AuthorizedFile holds the export lines of the neighbours this relay
	// accepts forwarded mail from, each with this relay's name for it.
	// Empty means this relay accepts from nobody and may still dial, which
	// is the other direction of one-way peering.
	AuthorizedFile string
	// PublicURL is this relay's own URL, so that a neighbour in the home
	// which is really this relay can be refused at the start rather than
	// found by an envelope going round in a circle.
	PublicURL string
}

// does reports whether this block asks for anything at all. A block with
// neither key is refused rather than ignored: an operator who wrote one
// meant something by it.
func (c CourierConfig) does() bool { return c.Home != "" || c.AuthorizedFile != "" }

// Courier is a relay's side of every peering it has: the identity it posts
// to neighbours as, the neighbours it can dial, and the neighbours it
// accepts from.
type Courier struct {
	// id is the courier identity, out of the home. It is the second signing
	// key a relay holds, after the certificate authority's.
	id *identity.Identity
	// home is the auu home id came out of, which also holds each
	// neighbour's URL, anchor and this courier's certificate there.
	home *store.Store
	// neighbours is every relay in the home, by the name the operator gave
	// it, which is the name a sender writes in a path.
	neighbours map[string]*store.Relay
	// couriers is the live view of the couriers file.
	couriers *courierSet
}

// NewCourier reads a relay's courier configuration and refuses at the start
// everything that cannot work, by name.
//
// It is called before the listener opens, so every refusal here is a relay
// that does not start rather than a fault found at the first forwarded
// message. The home is opened, which creates the directories an auu home
// has, so this is not run to validate a settings file: Validate in
// cmd/auu-relay checks what it can without touching the home, and this runs
// once at the start.
func NewCourier(cfg CourierConfig, log *slog.Logger) (*Courier, error) {
	if !cfg.does() {
		return nil, errors.New("courier is configured with neither home nor authorized_file, " +
			"so it would forward nothing and accept nothing: set courier.home to dial " +
			"neighbours, courier.authorized_file to accept from them, or remove the block")
	}
	c := &Courier{neighbours: map[string]*store.Relay{}}
	if cfg.Home != "" {
		if err := c.openHome(cfg, log); err != nil {
			return nil, err
		}
	}
	// The set is loaded here, once, so that a typo in the file is a relay
	// that does not start rather than one that silently accepts from
	// nobody, and so the first forwarded message is judged by what the
	// start logged.
	var loaded *Couriers
	if cfg.AuthorizedFile != "" {
		var err error
		if loaded, err = LoadCouriers(cfg.AuthorizedFile); err != nil {
			return nil, err
		}
		if c.id != nil {
			if name, ok := loaded.Names[c.id.Public().Fingerprint()]; ok {
				return nil, fmt.Errorf("%s admits this relay's own courier identity as %q: "+
					"a relay that accepted mail from itself would carry its own envelopes back "+
					"to itself; remove that line", cfg.AuthorizedFile, name)
			}
		}
	}
	var own string
	if c.id != nil {
		own = c.id.Public().Fingerprint()
	}
	c.couriers = newCourierSet(cfg.AuthorizedFile, loaded, own, log)
	c.sayWhatIsOneWay(cfg, log)
	// An operator reading a start wants to see that peering is on and how
	// far it reaches, as they see the administrators counted; without it
	// the only count is the one a reload prints, which is to say only after
	// somebody has edited the file.
	log.Info("couriers loaded",
		"neighbours", len(c.neighbours), "accepted", c.couriers.count(),
		"home", cfg.Home, "file", cfg.AuthorizedFile)
	return c, nil
}

// openHome opens the courier home, takes the identity out of it and reads
// the neighbours it knows.
func (c *Courier) openHome(cfg CourierConfig, log *slog.Logger) error {
	home, err := store.Open(cfg.Home)
	if err != nil {
		return fmt.Errorf("courier.home %s: %w", cfg.Home, err)
	}
	id, err := home.Identity()
	switch {
	case errors.Is(err, store.ErrNoIdentity):
		return fmt.Errorf("courier.home %s holds no identity: make one with 'auu init' as the user "+
			"this relay runs as, with AUU_HOME=%s and no passphrase set on it, then join each "+
			"neighbour with 'auu enrol --name NAME TOKEN'", cfg.Home, cfg.Home)
	case err != nil:
		return fmt.Errorf("courier.home %s: %w", cfg.Home, err)
	}
	// A relay cannot be asked for a passphrase and runs no agent, so an
	// identity it can only use through one is an identity it cannot use.
	// This is the one place the relay wants a key in its own process.
	if id.Remote() {
		return fmt.Errorf("courier.home %s holds an encrypted identity, which needs a passphrase "+
			"and an agent to unlock: a relay can be asked for neither. Take the passphrase off "+
			"with 'AUU_HOME=%s auu passphrase remove', which keeps the identity the neighbours "+
			"admitted, and protect the file with the host as the relay's bundle is protected",
			cfg.Home, cfg.Home)
	}
	relays, err := home.Relays()
	if err != nil {
		return fmt.Errorf("courier.home %s: %w", cfg.Home, err)
	}
	for _, r := range relays {
		// The name is keyed folded because both halves of a peering fold
		// internally — the home refuses two relays whose names differ only
		// in case, and so does the couriers file, since each name is a
		// directory and two filesystems spell Bar and bar as one — so a
		// file saying Bar against a home saying bar is one neighbour, not
		// a pair of one-way ones.
		// A neighbour that is really this relay would take an envelope out
		// and hand it straight back, which the carried table would refuse
		// and nobody would be told about; it is a misconfiguration with a
		// name, so it is refused at the start.
		if cfg.PublicURL != "" && isThisRelay(r.URL, cfg.PublicURL) {
			return fmt.Errorf("courier.home %s has a relay %q at %s, which is this relay's own "+
				"public_url: a relay cannot be its own neighbour; remove it with "+
				"'auu relay rm %s'", cfg.Home, r.Name, r.URL, r.Name)
		}
		c.neighbours[strings.ToLower(r.Name)] = r
	}
	c.home, c.id = home, id
	c.sayWhatCannotBeRead(cfg, log)
	return nil
}

// sayWhatCannotBeRead warns about a neighbour whose certificate in the
// courier home cannot be read, at the start, naming the home.
//
// It is a warning and not a refusal: the file can be repaired while the
// relay runs, and a relay that will not start because one of its neighbours'
// certificates is damaged is worse for everybody it serves than one that
// says so and forwards to the others. Nor is it silence, which would leave
// the fault to be found at the first message for that neighbour, in a
// worker's log line, by an operator who had no reason to look.
//
// The sentence is the relay's own because internal/dial's is a user's: that
// one says to run 'auu register --relay NAME --token TOKEN', which is right
// here too but says nothing about which home to run it in, and the courier's
// home is not the operator's own.
func (c *Courier) sayWhatCannotBeRead(cfg CourierConfig, log *slog.Logger) {
	for _, r := range sortedNeighbours(c.neighbours) {
		name := r.Name
		// The anchor first, because the dialling needs both and a damaged
		// one fails in the same way and for the same operator.
		if _, err := c.home.AnchorFor(r); err != nil && !errors.Is(err, store.ErrNoAnchor) {
			log.Warn("courier: this relay's pinned anchor for a neighbour cannot be read, "+
				"so it will not be able to reach it; repair it in the courier home",
				"name", r.Name, "home", cfg.Home, "err", err,
				"repair", fmt.Sprintf("AUU_HOME=%s auu enrol --name %s TOKEN", cfg.Home, r.Name))
		}
		rec, err := c.home.CertFor(r)
		if err == nil {
			// The record being readable is not the certificate being
			// usable: the PEM inside it is what a handshake needs, and it
			// is TLS that says so, which is the same call the dialling
			// makes. Checking only the record would pass a file that
			// cannot be used and leave the fault for the first message.
			_, err = rec.TLS()
		}
		switch {
		case err == nil, errors.Is(err, store.ErrNoCert):
			// None is a state: a neighbour may not require client
			// certificates, and one this relay has not enrolled on yet has
			// none to offer. The neighbour says which at the first post.
		default:
			log.Warn("courier: this relay's certificate for a neighbour cannot be read, "+
				"so it will not be able to post there; repair it in the courier home",
				"name", name, "home", cfg.Home, "err", err,
				"repair", fmt.Sprintf("AUU_HOME=%s auu register --relay %s --token TOKEN", cfg.Home, name))
		}
	}
}

// sayWhatIsOneWay logs the names that appear on one side of the peering and
// not the other, once at the start.
//
// Neither is a refusal: a relay may accept from a neighbour it never dials
// and dial one that never accepts from it. But a name in only one of the two
// places is also what a typo looks like, and the consequence — a reply
// refused at its first hop, or mail this relay forwards that comes back to
// nobody — is read by a user rather than by the operator who made it. So the
// start says it plainly, and the operator decides which it is.
func (c *Courier) sayWhatIsOneWay(cfg CourierConfig, log *slog.Logger) {
	if cfg.Home == "" || cfg.AuthorizedFile == "" {
		// One-way by configuration, which the operator wrote on purpose.
		// Saying it here as well would be noise at every start.
		return
	}
	accepted := map[string]bool{}
	for _, name := range c.couriers.acceptedNames() {
		accepted[strings.ToLower(name)] = true
		if _, ok := c.neighbours[strings.ToLower(name)]; !ok {
			log.Info("courier: this relay accepts mail from a neighbour it cannot dial; "+
				"a reply along that name will be refused at its first hop",
				"name", name, "file", cfg.AuthorizedFile, "home", cfg.Home)
		}
	}
	for _, r := range sortedNeighbours(c.neighbours) {
		name := r.Name
		if !accepted[strings.ToLower(name)] {
			log.Info("courier: this relay dials a neighbour it accepts no mail from; "+
				"that neighbour's replies and its undeliverables will be refused here",
				"name", name, "home", cfg.Home, "file", cfg.AuthorizedFile)
		}
	}
}

// sortedNeighbours is a neighbour map's relays in order of the name the
// operator gave each one, so that a start logs them the same way twice and
// logs the spelling that is in the home rather than the folded key they are
// held under.
func sortedNeighbours(m map[string]*store.Relay) []*store.Relay {
	out := make([]*store.Relay, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// isThisRelay reports whether a neighbour in the courier home is this relay.
//
// It asks the home's own question, store.SameRelayURL, so that a spelling
// the home would refuse to add twice cannot be admitted here as a
// neighbour — the port a person leaves off because it is the scheme's own
// is the case that matters, and a comparison of this relay's own devising
// missed it. The two URLs are lowered first, which the home does not do: a
// relay URL is a scheme and a host and nothing else, token.ValidateRelay
// admitting no path and no query, and both of those are case-insensitive,
// so folding here can only catch more. That it catches more than the home
// does is the right way round for this check, since what it is for is
// refusing a relay that would carry its own mail back to itself.
func isThisRelay(neighbour, mine string) bool {
	return store.SameRelayURL(strings.ToLower(neighbour), strings.ToLower(mine))
}

// Neighbour is the relay a name in a path refers to, out of the courier
// home. The name has been held to store.ValidRelayName before it reaches
// here, by whoever read it off the wire.
func (c *Courier) Neighbour(name string) (*store.Relay, bool) {
	if c == nil {
		return nil, false
	}
	r, ok := c.neighbours[strings.ToLower(name)]
	if !ok {
		return nil, false
	}
	// A copy, because the dialling writes into this struct: the trust
	// anchor's ratchet records what it last saw through SeenIntermediateFor,
	// which sets the fields on the caller's own Relay. One shared pointer
	// handed to every caller would be an unsynchronised write the first time
	// a neighbour's authority rotated, and the callers are the workers of
	// the commit after this one.
	cp := *r
	return &cp, true
}

// Accepts reports whether a fingerprint is a neighbour this relay takes
// forwarded mail from, and this relay's name for it — the name it writes
// into the return path.
func (c *Courier) Accepts(fp string) (string, bool) {
	if c == nil {
		return "", false
	}
	return c.couriers.lookup(fp)
}

// Identity is the courier's own identity, what this relay posts to its
// neighbours as.
func (c *Courier) Identity() *identity.Identity {
	if c == nil {
		return nil
	}
	return c.id
}

// errSelfCourier is why a reload was refused: the file has come to admit
// this relay's own courier. It is a sentinel so the warning carries an
// error as every other warning here does, and never a formatted string.
var errSelfCourier = errors.New("the file admits this relay's own courier identity")

// Couriers is a couriers file as it was read.
type Couriers struct {
	// Names is this relay's name for each neighbour, by fingerprint.
	//
	// The keys themselves are deliberately not kept. A courier is a
	// registered identity of the relay it posts to, so what verifies its
	// request is the bundle in its mailbox, on the one path every
	// authenticated request takes; this file answers whether a fingerprint
	// is a neighbour and what this relay calls it, and nothing else. A map
	// of keys nothing reads would be a second place to look for the answer
	// to "who is this", which is how two answers to one question start.
	Names map[string]string

	// Size and ModTime are the file as it was before the read, so a write
	// that lands during it is seen as a change on the next look rather
	// than missed.
	Size    int64
	ModTime time.Time
}

// LoadCouriers reads the export lines of the neighbours a relay accepts
// forwarded mail from.
//
// It is the administrators file's loader, with the administrators file's
// reasoning: whoever can write this file decides which relays may put mail
// into this one's mailboxes, so the file must not be writable by group or
// others. Two things are its own. A name must pass store.ValidRelayName and
// not merely identity.ValidName, because a name here is a path element a
// sender writes and a directory name in a courier home, and one rule for a
// name is the rule. And the lines are capped at relayapi.MaxCouriers, which
// the route that lists them back to a user is held to as well.
func LoadCouriers(path string) (*Couriers, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("couriers file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("couriers file %s is a directory", path)
	}
	// Whoever can write this file can have this relay accept mail from a
	// relay of their own, which its senders' allow lists would then admit
	// as a courier. The check is Unix's, for the reason the administrators
	// file's is: on Windows a FileMode is made from the read-only
	// attribute and says nothing about who may write.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm&0o022 != 0 {
		return nil, fmt.Errorf("couriers file %s is mode %04o: it must not be writable by group "+
			"or others, since whoever can write it decides which relays may forward mail here", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("couriers file: %w", err)
	}
	keys, err := identity.ParseExportLines(path, data)
	if err != nil {
		return nil, err
	}
	if len(keys) > relayapi.MaxCouriers {
		return nil, fmt.Errorf("couriers file %s holds %d neighbours; at most %d",
			path, len(keys), relayapi.MaxCouriers)
	}
	c := &Couriers{
		Names:   map[string]string{},
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	byName := map[string]*identity.Public{}
	for _, pub := range keys {
		// The export line's own rule is identity.ValidName; a neighbour's
		// name is also a path element and a directory, so it is held to
		// the stricter rule here, at the one place the file is read.
		if err := store.ValidRelayName(pub.Name); err != nil {
			return nil, fmt.Errorf("couriers file %s: %w", path, err)
		}
		fp := pub.Fingerprint()
		if was, dup := c.Names[fp]; dup {
			return nil, fmt.Errorf("couriers file %s lists one neighbour twice, as %q and %q: "+
				"a fingerprint is one relay and takes one name", path, was, pub.Name)
		}
		// Two neighbours under one name would make a path element
		// ambiguous and a return path a guess, so it is refused rather
		// than resolved in favour of either. Folded, since the name is a
		// directory in the courier home and two filesystems spell those
		// as one.
		if was, dup := byName[strings.ToLower(pub.Name)]; dup {
			return nil, fmt.Errorf("couriers file %s lists two neighbours as %q (%s and %s): "+
				"a name is one relay, and a path could not say which",
				path, pub.Name, was.Short(), pub.Short())
		}
		c.Names[fp] = pub.Name
		byName[strings.ToLower(pub.Name)] = pub
	}
	return c, nil
}

// courierSet is the live view of the couriers file: the administrators
// file's set, with a name beside each key.
type courierSet struct {
	path string
	log  *slog.Logger
	// own is this relay's own courier fingerprint, so that a line
	// admitting it cannot arrive by an edit after the start refused it.
	own string

	mu       sync.Mutex
	names    map[string]string
	size     int64
	modTime  time.Time
	complain bool
}

// newCourierSet starts from the set the caller loaded, so the first
// forwarded message is judged by what the start logged.
func newCourierSet(path string, loaded *Couriers, own string, log *slog.Logger) *courierSet {
	c := &courierSet{
		path: path, log: log, own: own,
		names:    map[string]string{},
		complain: true,
	}
	if path == "" || loaded == nil {
		return c
	}
	c.names, c.size, c.modTime = loaded.Names, loaded.Size, loaded.ModTime
	return c
}

// enabled reports whether this relay accepts forwarded mail at all.
func (c *courierSet) enabled() bool { return c != nil && c.path != "" }

// lookup answers whether a fingerprint is a neighbour, and this relay's name
// for it, re-reading the file first if it has changed.
func (c *courierSet) lookup(fp string) (string, bool) {
	if !c.enabled() {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
	name, ok := c.names[fp]
	return name, ok
}

// count reports how many neighbours this relay accepts from.
func (c *courierSet) count() int {
	if !c.enabled() {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
	return len(c.names)
}

// acceptedNames is every name this relay has for a neighbour it accepts
// from, in order.
func (c *courierSet) acceptedNames() []string {
	if !c.enabled() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
	out := make([]string, 0, len(c.names))
	for _, name := range c.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (c *courierSet) refreshLocked() {
	info, err := os.Stat(c.path)
	if err != nil {
		c.warn("couriers file could not be read; keeping the neighbours loaded earlier", err)
		return
	}
	if info.Size() == c.size && info.ModTime().Equal(c.modTime) {
		return
	}
	loaded, err := LoadCouriers(c.path)
	if err != nil {
		c.warn("couriers file could not be reloaded; keeping the neighbours loaded earlier", err)
		return
	}
	// The start refuses a file that admits this relay's own courier, and an
	// edit is the other way the same line can arrive. Refusing the reload
	// rather than the line keeps the set one thing an operator can reason
	// about — what is loaded is a file that was whole — and the relay goes
	// on with the neighbours it had until the line is taken out.
	if c.own != "" {
		if name, bad := loaded.Names[c.own]; bad {
			c.warn(fmt.Sprintf("couriers file now admits this relay's own courier as %q, which would "+
				"carry this relay's own envelopes back to it; keeping the neighbours loaded earlier "+
				"until that line is removed", name), errSelfCourier)
			return
		}
	}
	c.names, c.size, c.modTime = loaded.Names, loaded.Size, loaded.ModTime
	c.complain = true
	// An operator who adds or removes a neighbour wants to see the relay
	// take it, and one who did not wants to know that somebody did.
	c.log.Info("couriers reloaded", "count", len(c.names), "path", c.path)
}

// warn logs once per run of failures, so a file that has been deleted does
// not produce a line on every forwarded message.
func (c *courierSet) warn(msg string, err error) {
	if !c.complain {
		return
	}
	c.complain = false
	c.log.Warn(msg, "path", c.path, "err", err, "couriers", len(c.names))
}
