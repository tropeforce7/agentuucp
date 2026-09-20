// Package identity holds an auu user's long-term keys: an Ed25519 signing key
// that defines the user's address, and an HPKE key used to receive encrypted
// mail.
//
// The KEM is MLKEM768-X25519, better known as X-Wing: ML-KEM-768 combined with
// X25519, so an attacker must break both to recover a message. It comes from
// the standard library's crypto/hpke, which tracks draft-ietf-hpke-pq.
package identity

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// KEMPublicKeySize is the serialised length of an X-Wing public key:
	// the ML-KEM-768 encapsulation key followed by the X25519 point.
	KEMPublicKeySize = 1216
	// KEMPrivateKeySize is the serialised length of an X-Wing private key.
	KEMPrivateKeySize = 32

	// BundleSize is the length of a public bundle in the original suite:
	// sign_pub || kem_pub, with no leading suite byte. A bundle of another
	// suite is a different length and says which it is; see suite.go.
	BundleSize = ed25519.PublicKeySize + KEMPublicKeySize // 32 + 1216 = 1248

	fingerprintDomain = "ccx-id-v1"

	// Export line prefixes. ccx2 is the form, the one there is: one token
	// with no spaces, so a line can be pasted unquoted and selected with a
	// double-click. ccx1, the original space-separated form, is not read:
	// nothing on the wire is from before, and a line of that form is
	// refused in a sentence that says the identity must be exported again
	// by the current auu, which is the one thing its owner can do.
	exportPrefix      = "ccx2"
	olderExportPrefix = "ccx1"
	exportSep         = "."

	// MaxNameBytes bounds a name, the one free-text field an export line
	// carries.
	MaxNameBytes = 64
)

// KEMSuite is the KEM the default identity suite receives mail with. It is
// kept as a function for the callers that want the KEM alone; anything that
// needs to know what an identity is made of should ask its Suite.
func KEMSuite() hpke.KEM { return DefaultSuite().KEM() }

// DefaultSuite is what Generate builds and what an identity file with no
// suite recorded is assumed to be.
func DefaultSuite() *Suite {
	s, ok := SuiteByID(SuiteEd25519XWing)
	if !ok {
		panic("identity: the default suite is not registered")
	}
	return s
}

// Identity is a full key pair. Keep it secret; it is stored mode 0600.
//
// A remote identity, from FromRemote, has no seeds: its private operations
// are performed by the agent, and everything above the Sign and KEM seam
// works the same either way.
type Identity struct {
	Name string

	suite    *Suite
	signSeed []byte
	kemSeed  []byte
	sign     Signer
	kem      hpke.PrivateKey
	pub      *Public
	remote   bool
}

// Suite is the set of algorithms this identity is built from.
func (id *Identity) Suite() *Suite { return id.suite }

// Public is a peer's public bundle, optionally carrying the display name that
// travelled with it.
type Public struct {
	Name string
	KEM  hpke.PublicKey

	// suite says what the signing half is. signPub is opaque bytes rather
	// than a named key type, so that adding a suite does not change this
	// struct or anything that reads it.
	suite   *Suite
	signPub []byte
	bundle  []byte
	fp      string
}

// Suite is the set of algorithms this identity is built from.
func (p *Public) Suite() *Suite { return p.suite }

// Generate creates a new identity from fresh random keys.
func Generate(name string) (*Identity, error) {
	if name != "" {
		if err := ValidName(name); err != nil {
			return nil, err
		}
	}
	return GenerateSuite(DefaultSuite(), name)
}

// GenerateSuite creates a new identity under a particular suite. Generate is
// the one to call; this exists so that a suite can be exercised before it
// becomes the default.
func GenerateSuite(suite *Suite, name string) (*Identity, error) {
	if name != "" {
		if err := ValidName(name); err != nil {
			return nil, err
		}
	}
	signSeed := make([]byte, suite.SignSeedSize)
	if _, err := rand.Read(signSeed); err != nil {
		return nil, err
	}
	kem, err := suite.KEM().GenerateKey()
	if err != nil {
		return nil, err
	}
	kemSeed, err := kem.Bytes()
	if err != nil {
		return nil, err
	}
	return FromSeedsSuite(suite, name, signSeed, kemSeed)
}

// FromSeeds rebuilds an identity deterministically from its two stored
// secrets, under the default suite. An identity file written before suites
// existed records no suite and is this one.
func FromSeeds(name string, signSeed, kemSeed []byte) (*Identity, error) {
	return FromSeedsSuite(DefaultSuite(), name, signSeed, kemSeed)
}

// FromSeedsSuite rebuilds an identity from its two stored secrets: the
// signing seed and the serialised HPKE private key.
func FromSeedsSuite(suite *Suite, name string, signSeed, kemSeed []byte) (*Identity, error) {
	if suite == nil {
		return nil, errors.New("identity: no suite")
	}
	if len(signSeed) != suite.SignSeedSize {
		return nil, fmt.Errorf("identity: signing seed must be %d bytes", suite.SignSeedSize)
	}
	kem, err := suite.KEM().NewPrivateKey(kemSeed)
	if err != nil {
		return nil, fmt.Errorf("identity: bad kem key: %w", err)
	}
	sign, err := suite.NewSigner(signSeed)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		Name:     name,
		suite:    suite,
		signSeed: append([]byte{}, signSeed...),
		kemSeed:  append([]byte{}, kemSeed...),
		sign:     sign,
		kem:      kem,
	}
	id.pub = newPublic(suite, name, sign.Public(), kem.PublicKey())
	return id, nil
}

func (id *Identity) Public() *Public      { return id.pub }
func (id *Identity) KEM() hpke.PrivateKey { return id.kem }
func (id *Identity) Fingerprint() string  { return id.pub.Fingerprint() }

// Sign signs msg with the identity's signing key. It fails only for a remote
// identity whose agent is locked or gone; see ErrLocked.
func (id *Identity) Sign(msg []byte) ([]byte, error) { return id.sign.Sign(msg) }

// Remote says whether this identity's secrets live in the agent rather than
// in this process.
func (id *Identity) Remote() bool { return id.remote }

type identityJSON struct {
	Name string `json:"name"`
	// Suite is omitted for the original one, so an identity file written by
	// this build is byte-identical to one written before suites existed and
	// a downgrade still reads it. A file with no suite is the default.
	Suite    SuiteID `json:"suite,omitempty"`
	SignSeed string  `json:"sign_seed"`
	KEMSeed  string  `json:"kem_seed"`
}

func (id *Identity) MarshalJSON() ([]byte, error) {
	if id.remote {
		// The seeds are not here to write, and a file with empty ones
		// would be an identity nobody could ever load.
		return nil, errors.New("identity: a remote identity has no secrets to write")
	}
	out := identityJSON{
		Name:     id.Name,
		SignSeed: base64.StdEncoding.EncodeToString(id.signSeed),
		KEMSeed:  base64.StdEncoding.EncodeToString(id.kemSeed),
	}
	if id.suite.ID != SuiteEd25519XWing {
		out.Suite = id.suite.ID
	}
	return json.Marshal(out)
}

func (id *Identity) UnmarshalJSON(b []byte) error {
	var j identityJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	signSeed, err := base64.StdEncoding.DecodeString(j.SignSeed)
	if err != nil {
		return fmt.Errorf("identity: bad sign_seed: %w", err)
	}
	kemSeed, err := base64.StdEncoding.DecodeString(j.KEMSeed)
	if err != nil {
		return fmt.Errorf("identity: bad kem_seed: %w", err)
	}
	suiteID := j.Suite
	if suiteID == 0 {
		suiteID = SuiteEd25519XWing
	}
	suite, ok := SuiteByID(suiteID)
	if !ok {
		// A key file from a newer release. Say so, rather than failing on a
		// seed length and sending somebody after the wrong problem.
		return fmt.Errorf("identity: this key uses suite %d, which this build does not know; "+
			"upgrade auu", suiteID)
	}
	restored, err := FromSeedsSuite(suite, j.Name, signSeed, kemSeed)
	if err != nil {
		return err
	}
	*id = *restored
	return nil
}

// newPublic assembles a bundle and the fingerprint over it.
//
// The bundle of the original suite is the bare concatenation, exactly as it
// always was, so every existing fingerprint, export line and stored bundle is
// unchanged. Every other suite prefixes its identifier, which is what makes a
// bundle self-describing from the day a second one exists.
func newPublic(suite *Suite, name string, signPub []byte, kem hpke.PublicKey) *Public {
	bundle := make([]byte, 0, suite.wireSize())
	if suite.tagged() {
		bundle = append(bundle, byte(suite.ID))
	}
	bundle = append(bundle, signPub...)
	bundle = append(bundle, kem.Bytes()...)

	// The domain is versioned, so a future change to how a fingerprint is
	// computed can be told from this one. The suite is inside the bundle
	// rather than beside it here: two suites cannot produce the same bundle,
	// so they cannot produce the same fingerprint.
	sum := sha256.Sum256(append([]byte(fingerprintDomain), bundle...))
	return &Public{
		Name:    name,
		KEM:     kem,
		suite:   suite,
		signPub: append([]byte{}, signPub...),
		bundle:  bundle,
		fp:      hex.EncodeToString(sum[:]),
	}
}

// ParseBundle decodes a raw public bundle, of whichever suite it is. The name
// is not carried in a bundle, so it comes back empty.
func ParseBundle(b []byte) (*Public, error) {
	suite, err := suiteForWire(b)
	if err != nil {
		return nil, err
	}
	body := b
	if suite.tagged() {
		body = b[1:]
	}
	signPub := body[:suite.SignPublicSize]
	kem, err := suite.KEM().NewPublicKey(body[suite.SignPublicSize:])
	if err != nil {
		return nil, fmt.Errorf("identity: bad kem key: %w", err)
	}
	return newPublic(suite, "", signPub, kem), nil
}

func (p *Public) Bundle() []byte      { return append([]byte{}, p.bundle...) }
func (p *Public) Fingerprint() string { return p.fp }

// SignPublic is the signing half of the bundle, as it appears there.
func (p *Public) SignPublic() []byte { return append([]byte{}, p.signPub...) }

// Short returns the first 16 hex characters of the fingerprint. Display only:
// never use it to look a peer up.
func (p *Public) Short() string { return p.fp[:16] }

// Verify reports whether sig is a valid signature by this peer over msg,
// under whichever suite this identity is.
func (p *Public) Verify(msg, sig []byte) bool {
	if len(sig) != p.suite.SignatureSize {
		return false
	}
	return p.suite.Verify(p.signPub, msg, sig)
}

// ExportLine renders the single line a user pastes to a peer, in the spirit of
// an ssh authorized_keys entry.
// ExportLine is the one-token form of a public bundle, the thing a person
// hands to a colleague: "ccx2.<base64url bundle>.<name>", with the name and
// its separator omitted when there is no name.
func (p *Public) ExportLine() string {
	line := exportPrefix + exportSep + base64.RawURLEncoding.EncodeToString(p.bundle)
	if p.Name != "" {
		line += exportSep + p.Name
	}
	return line
}

// ValidName reports whether a name may travel in an export line and be typed
// after --to: one to MaxNameBytes ASCII letters, digits, dots, underscores or
// hyphens, beginning with a letter or digit. The rule is what makes an export
// line a single shell word, and it is also what keeps a name from carrying a
// newline into authorized_peers or an escape sequence into a terminal.
func ValidName(name string) error {
	if name == "" {
		return errors.New("identity: name is empty")
	}
	if len(name) > MaxNameBytes {
		return fmt.Errorf("identity: name is %d bytes; at most %d", len(name), MaxNameBytes)
	}
	if strings.EqualFold(name, "self") {
		return errors.New("identity: the name \"self\" is reserved; it means you")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return fmt.Errorf("identity: name %q: letters, digits, '.', '_' and '-' only, "+
				"beginning with a letter or digit", name)
		}
	}
	return nil
}

// Printable is a name as it may be written to a terminal: one that passes
// ValidName unchanged, and anything else with every byte outside the
// printable set escaped the way strconv.Quote escapes it, without the
// quotes. A relay applies ValidName at registration now, but one from
// before that may still hold a name with an escape sequence or a newline
// in it, and every place a name from the network reaches a terminal goes
// through here so that it cannot reach the terminal as a command.
func Printable(name string) string {
	if ValidName(name) == nil {
		return name
	}
	q := strconv.Quote(name)
	return q[1 : len(q)-1]
}

// PrintableText is a sentence from the network as it may be written to a
// terminal: every printable character, the space and the tab kept as they
// are, quotes and backslashes among them, and everything else — a control
// character, a format character such as a bidi override, a line break, a
// byte that is not UTF-8 — escaped the way strconv.Quote would escape it.
// Printable is for a name, which has a rule and rarely needs escaping;
// this is for text that has none, such as the sentence a relay sends with
// a refusal, which every user of every relay reads on standard error.
func PrintableText(s string) string { return printable(s, false) }

// PrintableLines is PrintableText with the line break kept as well, for a
// message's text, which is prose of many lines: what a terminal shows and
// a line break are kept, and everything else is escaped. The rule at
// Validate, and again at Load, refuses a text with anything else in it;
// this is the last line under the rule, not the rule.
func PrintableLines(s string) string { return printable(s, true) }

func printable(s string, keepNewline bool) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == ' ' || r == '\t' || (keepNewline && r == '\n') || strconv.IsPrint(r):
			b.WriteString(s[i : i+size])
		default:
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}

// ErrLineLength is an export line whose encoded part is not the length of
// any key: too short, which is what a line wrapped by an editor or a mail
// client looks like, or too long. A reader of a file of lines uses it to
// ask the wrapping question, since the file's lines reach it one at a time
// and the break is between them.
var ErrLineLength = errors.New("identity: key line is not the length of a key")

// ParseExportLines parses a file of export lines, one key per line, blank
// lines and lines beginning with # skipped, in file order. A line that does
// not parse is refused as "NAME line N: …", name being what the caller
// calls the file. It is the one loop a relay's administrator file and a kit's
// admin lines go through, so the numbering and the sentence are one piece
// of code.
func ParseExportLines(name string, data []byte) ([]*Public, error) {
	var keys []*Public
	for n, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		pub, err := ParseExportLine(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, n+1, err)
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

// ParseExportLine parses one export line in either form. Blank lines and
// comments are the caller's business; this rejects them.
func ParseExportLine(line string) (*Public, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, errors.New("identity: not a key line")
	}

	var (
		enc     *base64.Encoding
		encoded string
		name    string
	)
	switch {
	case strings.HasPrefix(trimmed, exportPrefix+exportSep):
		enc = base64.RawURLEncoding
		encoded, name, _ = strings.Cut(trimmed[len(exportPrefix)+len(exportSep):], exportSep)
	case trimmed == olderExportPrefix || strings.HasPrefix(trimmed, olderExportPrefix+" "):
		return nil, fmt.Errorf("identity: this is a %s export line, an older form; "+
			"ask its owner to run 'auu id export' with the current auu and paste that line", olderExportPrefix)
	default:
		kind := trimmed
		if i := strings.IndexAny(trimmed, " ."); i >= 0 {
			kind = trimmed[:i]
		}
		return nil, fmt.Errorf("identity: unknown key type %q", kind)
	}

	// Length before decode: DecodeString allocates the whole output first, so
	// the length the line claims is checked against the valid sizes before
	// anything is allocated from it. Every registered suite's size is
	// accepted here; which one it actually is, ParseBundle decides.
	if !encodedLengthIsASuite(enc, len(encoded)) {
		// A line with a break in it arrives here as the wrong length, and
		// the break is the more likely explanation than a key of another
		// size; say so when the input shows one.
		wrapped := ""
		if strings.Contains(trimmed, "\n") {
			wrapped = " (was the line wrapped?)"
		}
		return nil, fmt.Errorf("%w: %d encoded bytes, %s encoded%s",
			ErrLineLength, len(encoded), knownSizes(), wrapped)
	}
	raw, err := enc.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("identity: bad base64 in key line: %w", err)
	}
	pub, err := ParseBundle(raw)
	if err != nil {
		return nil, err
	}
	if name != "" {
		if err := ValidName(name); err != nil {
			return nil, err
		}
		pub.Name = name
	}
	return pub, nil
}

// ValidFingerprint reports whether s is a well formed fingerprint: 64 lowercase
// hex characters. Use it before letting a value near the database or filesystem.
func ValidFingerprint(s string) bool { return lowerHex(s, 64) }

// ShortIDLen is how much of a fingerprint a short id is: the 16 characters
// that listings print, which is what a person most often has to hand.
const ShortIDLen = 16

// ValidShortID reports whether s is a well formed short id: the first
// ShortIDLen characters of a fingerprint, lowercase hex.
func ValidShortID(s string) bool { return lowerHex(s, ShortIDLen) }

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encodedLengthIsASuite reports whether n encoded bytes could be a bundle of
// some registered suite.
func encodedLengthIsASuite(enc *base64.Encoding, n int) bool {
	for size := range byWireLen {
		if enc.EncodedLen(size) == n {
			return true
		}
	}
	return false
}
