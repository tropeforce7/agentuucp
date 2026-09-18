// Package token implements auu enrolment tokens: short, signed, self-describing
// grants that let one person create one mailbox on one relay before a stated
// date.
//
// A token is signed by the issuing administrator's own identity key, so the
// issuer is bound into it cryptographically and removing an administrator from
// a relay's authorized file invalidates everything they ever issued. Nothing
// here talks to a relay: a relay additionally requires that a token be
// registered with it, which is what makes revocation and single use possible.
package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

const (
	// Prefix names the token format that is written. The version lives here,
	// like ccx2 on an export line, so an old verifier refuses a new token
	// outright rather than misreading it.
	//
	// ccxt2 added the trust anchor a machine pins when it redeems the token.
	// A field could not simply be added, because the payload is decoded
	// strictly on purpose.
	Prefix = "ccxt2"
	// LegacyPrefix is still read. A ccxt1 token pins no anchor, which is
	// what a relay with a publicly trusted certificate wants anyway.
	LegacyPrefix = "ccxt1"

	// signDomain separates token signatures from the other five things an
	// identity key signs: requests (ccx-http-v1), messages (ccx-sig-v1),
	// stream manifests (ccx-stream-sig-v1), channel directories
	// (ccx-channels-v1) and allow lists (ccx-allow-v1). A signature made
	// for one purpose must not verify for another.
	signDomain = "ccx-token-v1"

	// UseRegister creates one mailbox.
	UseRegister = "register"
	// UseCert issues one client certificate to a machine of an identity
	// that already has a mailbox. It must name that identity in Subject:
	// a certificate token is a permission to add a machine to one account,
	// never a permission at large.
	UseCert = "cert"

	// MaxPayloadBytes bounds the signed JSON. A token is pasted into chat
	// windows and shells; it has no business being long.
	MaxPayloadBytes = 1024
	// MaxNoteBytes bounds the note.
	MaxNoteBytes = 200
	// MaxUses bounds how many mailboxes one token may create.
	MaxUses = 1000

	idBytes = 16
)

// Failures a caller can tell apart. A relay turns each into its own message.
var (
	ErrForm        = errors.New("token: malformed")
	ErrSignature   = errors.New("token: signature does not verify")
	ErrIssuer      = errors.New("token: key does not match the claimed issuer")
	ErrUse         = errors.New("token: unsupported use")
	ErrExpired     = errors.New("token: expired")
	ErrNotYetValid = errors.New("token: not yet valid")
)

// Claims is the signed content of a token.
//
// Every field is always present on the wire. There is no omitempty: the
// signature covers the exact bytes, and a field that sometimes vanishes is a
// field two implementations will eventually disagree about.
type Claims struct {
	ID      string `json:"id"`
	Issuer  string `json:"issuer"`
	Relay   string `json:"relay"`
	Use     string `json:"use"`
	Subject string `json:"subject"`
	Note    string `json:"note"`
	// Anchor is the SHA-256 of the trust anchor's SubjectPublicKeyInfo, 64
	// lowercase hex characters, or empty for a relay whose certificate a
	// machine can verify without pinning anything.
	//
	// It is the whole of how transport trust bootstraps: a machine fetches
	// the anchor from the relay over a connection nothing has verified, and
	// believes it only if it hashes to this. The assumption is one that was
	// already being made — whoever handed you this token could have handed
	// you the wrong relay URL — so putting the hash here makes an existing
	// assumption checkable rather than adding one.
	Anchor    string `json:"anchor"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Uses      int    `json:"uses"`
}

// NotBeforeTime and NotAfterTime are the window as times.
func (c Claims) NotBeforeTime() time.Time { return time.Unix(c.NotBefore, 0) }
func (c Claims) NotAfterTime() time.Time  { return time.Unix(c.NotAfter, 0) }

// Issue signs claims with the issuer's identity and returns the token string.
//
// It fills in the id, the issuer, and not_before, and defaults uses to one.
// Everything else is the caller's, and every rule is checked before signing:
// an invalid token should not exist, rather than be rejected later by a relay
// the holder has already been told to trust.
func Issue(id *identity.Identity, c Claims) (string, error) {
	if id == nil {
		return "", errors.New("token: no issuing identity")
	}
	c.Issuer = id.Fingerprint()
	if c.ID == "" {
		raw := make([]byte, idBytes)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		c.ID = hex.EncodeToString(raw)
	}
	if c.NotBefore == 0 {
		c.NotBefore = time.Now().Unix()
	}
	if c.Uses == 0 {
		c.Uses = 1
	}
	if c.Use == "" {
		c.Use = UseRegister
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if len(payload) > MaxPayloadBytes {
		return "", fmt.Errorf("%w: payload is %d bytes, over the %d byte limit",
			ErrForm, len(payload), MaxPayloadBytes)
	}
	sig, err := id.Sign(signingBytes(payload))
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		Prefix,
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(sig),
	}, "."), nil
}

// signingBytes is the exact input to the signature.
func signingBytes(payload []byte) []byte {
	out := make([]byte, 0, len(signDomain)+len(payload))
	out = append(out, signDomain...)
	return append(out, payload...)
}

// Unverified is a token that has been split and read, but not checked.
type Unverified struct {
	// Claims is what the token says about itself. It is not to be believed:
	// anyone can write anything here and sign it with any key. It exists so a
	// caller can find the issuer's key, and so a person can be shown what they
	// have been sent before anyone acts on it.
	Claims Claims

	payload []byte
	sig     []byte
}

// Parse splits a token string and reads its payload without checking anything.
// Nothing it returns may be trusted; see Verify.
func Parse(s string) (*Unverified, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected three dot-separated parts, got %d", ErrForm, len(parts))
	}
	if parts[0] != Prefix && parts[0] != LegacyPrefix {
		return nil, fmt.Errorf("%w: unknown token type %q, expected %q", ErrForm, parts[0], Prefix)
	}
	// Length before decode, both times. Decoding allocates the whole output
	// first, so a length taken from the peer must be refused against the cap
	// before anything is allocated from it.
	if maxEncoded := base64.RawURLEncoding.EncodedLen(MaxPayloadBytes); len(parts[1]) > maxEncoded {
		return nil, fmt.Errorf("%w: payload is %d encoded bytes, over the %d byte limit",
			ErrForm, len(parts[1]), maxEncoded)
	}
	// The signature is whatever the issuer's identity suite produces, so the
	// length is checked against every suite rather than against one. Still
	// before decoding: a length no suite could have signed cannot verify, so
	// refusing it here costs an attacker the allocation.
	if !signatureLengthKnown(len(parts[2])) {
		return nil, fmt.Errorf("%w: signature is %d encoded bytes, want %s",
			ErrForm, len(parts[2]), encodedSignatureLengths())
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64 in the payload", ErrForm)
	}
	if len(payload) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload is %d bytes, over the %d byte limit",
			ErrForm, len(payload), MaxPayloadBytes)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64 in the signature", ErrForm)
	}
	u := &Unverified{payload: payload, sig: sig}
	if err := decode(payload, &u.Claims); err != nil {
		return nil, err
	}
	return u, nil
}

// IssuerFingerprint is the identity the token claims signed it. Use it to look
// a key up; it proves nothing on its own.
func (u *Unverified) IssuerFingerprint() string { return u.Claims.Issuer }

// Verify checks the signature with the issuer's key, then reads the payload
// again and returns the claims that key vouched for.
//
// The order matters. The claims are decoded from the raw bytes only after the
// signature over those same bytes has verified, so nothing a caller acts on
// has ever come from an unverified token. The issuer's fingerprint is checked
// against the claim first, so a caller who looked the key up somewhere other
// than the token cannot be talked into verifying with the wrong one.
func (u *Unverified) Verify(issuer *identity.Public, now time.Time, skew time.Duration) (*Claims, error) {
	if issuer == nil {
		return nil, ErrIssuer
	}
	if issuer.Fingerprint() != u.Claims.Issuer {
		return nil, ErrIssuer
	}
	if !issuer.Verify(signingBytes(u.payload), u.sig) {
		return nil, ErrSignature
	}

	var c Claims
	if err := decode(u.payload, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	// Belt and braces: the signature covers these bytes, so this cannot differ
	// from the check above unless the decode is not deterministic.
	if c.Issuer != issuer.Fingerprint() {
		return nil, ErrIssuer
	}
	if !ValidUse(c.Use) {
		return nil, fmt.Errorf("%w: %q", ErrUse, c.Use)
	}
	if now.Add(skew).Unix() < c.NotBefore {
		return nil, ErrNotYetValid
	}
	if now.Add(-skew).Unix() > c.NotAfter {
		return nil, ErrExpired
	}
	return &c, nil
}

// decode reads a payload strictly. An unknown field is an error: a token is
// not a place for extensions one side understands and the other ignores.
func decode(payload []byte, c *Claims) error {
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("%w: %v", ErrForm, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after the payload object", ErrForm)
	}
	return nil
}

// ValidID reports whether s has the shape of a token id: 32 lowercase hex
// characters, the encoding of the idBytes Issue draws. The relay checks a
// path segment with it before the value goes near a query, and the client
// checks a listing's ids with it before a command slices them.
func ValidID(s string) bool { return len(s) == 2*idBytes && isLowerHex(s) }

// Validate applies every rule in the format to a set of claims.
func (c Claims) Validate() error {
	if !ValidID(c.ID) {
		return fmt.Errorf("%w: id must be %d lowercase hex characters", ErrForm, 2*idBytes)
	}
	if !identity.ValidFingerprint(c.Issuer) {
		return fmt.Errorf("%w: issuer is not a fingerprint", ErrForm)
	}
	if err := ValidateRelay(c.Relay); err != nil {
		return fmt.Errorf("%w: relay %v", ErrForm, err)
	}
	if !ValidUse(c.Use) {
		return fmt.Errorf("%w: %q", ErrUse, c.Use)
	}
	if c.Subject != "" && !identity.ValidFingerprint(c.Subject) {
		return fmt.Errorf("%w: subject is not a fingerprint", ErrForm)
	}
	// A certificate token adds a machine to an existing identity, so it
	// only means anything bound to one. Refused here rather than at the
	// relay, so an unbound one never exists to be handed to somebody.
	if c.Use == UseCert && c.Subject == "" {
		return fmt.Errorf("%w: a certificate token must be bound to a fingerprint", ErrForm)
	}
	if err := ValidateNote(c.Note); err != nil {
		return fmt.Errorf("%w: note %v", ErrForm, err)
	}
	if c.Anchor != "" && !isAnchor(c.Anchor) {
		return fmt.Errorf("%w: anchor must be 64 lowercase hex characters", ErrForm)
	}
	if c.NotBefore <= 0 {
		return fmt.Errorf("%w: not_before is missing", ErrForm)
	}
	if c.NotAfter <= 0 {
		return fmt.Errorf("%w: not_after is required", ErrForm)
	}
	if c.NotAfter <= c.NotBefore {
		return fmt.Errorf("%w: not_after is not after not_before", ErrForm)
	}
	if c.Uses < 1 || c.Uses > MaxUses {
		return fmt.Errorf("%w: uses must be between 1 and %d, got %d", ErrForm, MaxUses, c.Uses)
	}
	return nil
}

// ValidateRelay checks the audience URL. It is exported because a relay checks
// its own public_url against the same rules.
func ValidateRelay(raw string) error {
	if raw == "" {
		return errors.New("is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("has no host")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("must not have a path")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("must be a bare scheme and host")
	}
	return nil
}

// ValidateNote checks the human-readable purpose. A token that does not say
// what it is for is a shared secret with extra steps, so the note is required.
//
// It is exported because the relay checks it again on registration: this text
// reaches administrators' terminals and the operator's log, and it arrives
// from whoever signed the token.
func ValidateNote(note string) error {
	if note == "" {
		return errors.New("is required: say who the token is for")
	}
	if len(note) > MaxNoteBytes {
		return fmt.Errorf("is %d bytes, over the %d byte limit", len(note), MaxNoteBytes)
	}
	if !utf8.ValidString(note) {
		return errors.New("is not valid UTF-8")
	}
	for _, r := range note {
		if r < 0x20 || r == 0x7f {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// NormaliseRelay trims a relay URL to the bare scheme and host used as a token
// audience, so that a trailing slash never causes a mismatch.
func NormaliseRelay(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSuffix(strings.TrimSpace(raw), "/")
	}
	return u.Scheme + "://" + u.Host
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Describe renders claims for a person about to act on them.
//
// It is shared by auu and auu-admin so that a holder and an issuer read the
// same words about the same token. verified says whether the signature was
// checked; issuerName is a local label for the issuer, when the reader has
// one. An unverified description says so plainly rather than looking the same
// as a checked one.
func Describe(c Claims, issuerName string, verified bool, now time.Time) string {
	// Never sliced: Parse decodes claims without Validate, and a pasted
	// token with a two-character issuer once panicked here. A caller that
	// wants the shape checked runs Validate first and says so; this
	// renders whatever it is given.
	issuer := short(c.Issuer)
	if issuerName != "" {
		issuer = fmt.Sprintf("%s <%s>", issuerName, short(c.Issuer))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "token:   %s\n", c.ID)
	fmt.Fprintf(&b, "use:     %s\n", DescribeUse(c.Use))
	fmt.Fprintf(&b, "issuer:  %s\n", issuer)
	// The token's own words for its relay and its note, escaped: a token
	// is a string somebody else made, and an unverified one is described
	// before any key has said anything about it.
	fmt.Fprintf(&b, "relay:   %s\n", identity.PrintableText(c.Relay))
	fmt.Fprintf(&b, "for:     %s\n", identity.PrintableText(c.Note))
	if c.Subject != "" {
		fmt.Fprintf(&b, "bound to: %s\n", short(c.Subject))
	}
	fmt.Fprintf(&b, "expires: %s (%s)\n",
		c.NotAfterTime().Local().Format("2006-01-02 15:04 MST"), Until(c.NotAfterTime(), now))
	if c.Uses > 1 {
		fmt.Fprintf(&b, "uses:    %d\n", c.Uses)
	}
	if verified {
		fmt.Fprintf(&b, "signature: checked against the issuer's key\n")
	} else {
		fmt.Fprintf(&b, "signature: NOT checked; the issuer is not in your peer list. "+
			"The relay will check it.\n")
	}
	return b.String()
}

// Until renders how long is left, or how long ago it ran out. A token that
// ran out inside the clock skew a relay allows is still good there, and a
// person deciding whether to hurry is told so, to the second; past the skew
// it is expired and that is all. The container suite's X01 found a token
// described as expired and then accepted.
//
// Times are compared as times, and no difference is negated: time.Sub
// saturates at the Duration limits for a gap over about 292 years, and
// the negation of the minimum is the minimum, so an expiry that far in
// the past once read as inside the skew with a negative age.
func Until(t, now time.Time) string {
	switch {
	case t.Before(now.Add(-relayapi.MaxSkew)):
		ago := now.Sub(t)
		if ago == math.MaxInt64 {
			return "expired long ago"
		}
		return "expired " + roughly(ago) + " ago"
	case t.Before(now):
		return fmt.Sprintf("expired %s ago; a relay accepts it for %s past that",
			now.Sub(t).Truncate(time.Second), roughly(relayapi.MaxSkew))
	default:
		return "in " + roughly(t.Sub(now))
	}
}

// short is the first sixteen characters of an id, or the whole of one
// shorter than that, which a token nobody validated may carry.
func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func roughly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/(24*time.Hour)), "day")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// ValidUse reports whether a use is one this build knows.
func ValidUse(use string) bool {
	return use == UseRegister || use == UseCert
}

// DescribeUse says in words what a token is for, for a person deciding
// whether to redeem one.
func DescribeUse(use string) string {
	switch use {
	case UseRegister:
		return "register (create a mailbox on this relay)"
	case UseCert:
		return "cert (add another machine to an existing identity)"
	default:
		return use
	}
}

// signatureLengthKnown reports whether n encoded bytes is the length of a
// signature by some registered identity suite.
func signatureLengthKnown(n int) bool {
	for _, size := range identity.SignatureSizes() {
		if base64.RawURLEncoding.EncodedLen(size) == n {
			return true
		}
	}
	return false
}

// encodedSignatureLengths names the acceptable lengths, for the refusal.
func encodedSignatureLengths() string {
	var b strings.Builder
	for i, size := range identity.SignatureSizes() {
		if i > 0 {
			b.WriteString(" or ")
		}
		fmt.Fprintf(&b, "%d", base64.RawURLEncoding.EncodedLen(size))
	}
	return b.String()
}

// isAnchor reports whether s is a trust anchor hash: 64 lowercase hex
// characters, the same shape as a fingerprint and checked the same way.
func isAnchor(s string) bool {
	return len(s) == 64 && isLowerHex(s)
}
