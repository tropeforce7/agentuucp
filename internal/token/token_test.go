package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

func admin(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate("admin")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func base(now time.Time) Claims {
	return Claims{
		Relay:     "https://relay.example.com",
		Use:       UseRegister,
		Note:      "Bob, for the protocol review",
		NotBefore: now.Unix(),
		NotAfter:  now.Add(7 * 24 * time.Hour).Unix(),
		Uses:      1,
	}
}

func TestRoundTrip(t *testing.T) {
	id := admin(t)
	now := time.Now()
	s, err := Issue(id, base(now))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, Prefix+".") {
		t.Fatalf("token %q does not carry the version prefix", s)
	}
	// A token gets pasted into URLs, shells and chat windows.
	if strings.ContainsAny(s, "+/= \n") {
		t.Fatalf("token %q contains a character that will not survive being pasted", s)
	}

	u, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	if u.IssuerFingerprint() != id.Fingerprint() {
		t.Fatal("parsed token does not name its issuer")
	}
	c, err := u.Verify(id.Public(), now, relayapi.MaxSkew)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != id.Fingerprint() || c.Note != "Bob, for the protocol review" || c.Uses != 1 {
		t.Fatalf("claims did not survive: %+v", c)
	}
	if len(c.ID) != 32 {
		t.Fatalf("id %q is not 16 bytes of hex", c.ID)
	}
}

func TestIssueFillsAndDefaults(t *testing.T) {
	id := admin(t)
	c := base(time.Now())
	c.NotBefore = 0
	c.Uses = 0
	c.Use = ""
	s, err := Issue(id, c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	got := u.Claims
	if got.NotBefore == 0 {
		t.Fatal("not_before was not filled in")
	}
	if got.Uses != 1 {
		t.Fatalf("uses defaulted to %d, want 1", got.Uses)
	}
	if got.Use != UseRegister {
		t.Fatalf("use defaulted to %q", got.Use)
	}
	if got.Issuer != id.Fingerprint() {
		t.Fatal("issuer was not taken from the signing identity")
	}
}

// The issuer field is filled from the key, so a caller cannot mint a token in
// somebody else's name even by asking for it.
func TestIssuerCannotBeClaimed(t *testing.T) {
	id, other := admin(t), admin(t)
	c := base(time.Now())
	c.Issuer = other.Fingerprint()
	s, err := Issue(id, c)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := Parse(s)
	if u.Claims.Issuer != id.Fingerprint() {
		t.Fatal("Issue honoured a claimed issuer instead of the signing key")
	}
	if _, err := u.Verify(other.Public(), time.Now(), relayapi.MaxSkew); !errors.Is(err, ErrIssuer) {
		t.Fatalf("verifying with the wrong key gave %v, want ErrIssuer", err)
	}
}

func TestAlteredPayloadFails(t *testing.T) {
	id := admin(t)
	now := time.Now()
	s, err := Issue(id, base(now))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(s, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the note, keeping the length so only the content changes.
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	c.Note = strings.Repeat("x", len(c.Note))
	altered, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	forged := Prefix + "." + base64.RawURLEncoding.EncodeToString(altered) + "." + parts[2]

	u, err := Parse(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Verify(id.Public(), now, relayapi.MaxSkew); !errors.Is(err, ErrSignature) {
		t.Fatalf("an altered payload gave %v, want ErrSignature", err)
	}
}

// The same identity key signs requests, messages and tokens. A signature made
// for one of those must never verify as another.
func TestRequestSignatureIsNotATokenSignature(t *testing.T) {
	id := admin(t)
	now := time.Now()
	s, err := Issue(id, base(now))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(s, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	// A signature over the very same payload bytes, but without the token
	// domain: exactly what an attacker who could get an administrator to sign
	// arbitrary data would hold.
	bare := mustSign(t, id, payload)
	forged := Prefix + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bare)
	u, err := Parse(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Verify(id.Public(), now, relayapi.MaxSkew); !errors.Is(err, ErrSignature) {
		t.Fatal("a signature without the token domain string verified as a token")
	}

	// And the reverse: a token signature does not verify as a request.
	tokenSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signing := relayapi.SigningString("POST", "/v1/register", now.Unix(), "nonce", payload)
	if id.Public().Verify(signing, tokenSig) {
		t.Fatal("a token signature verified as a request signature")
	}
}

func TestTimeWindow(t *testing.T) {
	id := admin(t)
	now := time.Now()
	c := base(now)
	c.NotBefore = now.Add(time.Hour).Unix()
	c.NotAfter = now.Add(2 * time.Hour).Unix()
	s, err := Issue(id, c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}

	// Well before the window.
	if _, err := u.Verify(id.Public(), now, relayapi.MaxSkew); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("before not_before gave %v, want ErrNotYetValid", err)
	}
	// Inside the skew allowance of the start.
	if _, err := u.Verify(id.Public(), now.Add(time.Hour-relayapi.MaxSkew), relayapi.MaxSkew); err != nil {
		t.Fatalf("the skew allowance was not applied at the start: %v", err)
	}
	// Inside the window.
	if _, err := u.Verify(id.Public(), now.Add(90*time.Minute), relayapi.MaxSkew); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
	// Inside the skew allowance of the end.
	if _, err := u.Verify(id.Public(), now.Add(2*time.Hour+relayapi.MaxSkew), relayapi.MaxSkew); err != nil {
		t.Fatalf("the skew allowance was not applied at the end: %v", err)
	}
	// Past it.
	if _, err := u.Verify(id.Public(), now.Add(3*time.Hour), relayapi.MaxSkew); !errors.Is(err, ErrExpired) {
		t.Fatalf("after not_after gave %v, want ErrExpired", err)
	}
}

func TestClaimRules(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		mutex func(*Claims)
		want  error
	}{
		{"no relay", func(c *Claims) { c.Relay = "" }, ErrForm},
		{"relay with a path", func(c *Claims) { c.Relay = "https://relay.example.com/v1" }, ErrForm},
		{"relay with a query", func(c *Claims) { c.Relay = "https://relay.example.com?x=1" }, ErrForm},
		{"relay is not a URL", func(c *Claims) { c.Relay = "relay.example.com" }, ErrForm},
		{"unknown use", func(c *Claims) { c.Use = "admin" }, ErrUse},
		{"no note", func(c *Claims) { c.Note = "" }, ErrForm},
		{"note too long", func(c *Claims) { c.Note = strings.Repeat("x", MaxNoteBytes+1) }, ErrForm},
		{"note with a newline", func(c *Claims) { c.Note = "line\nbreak" }, ErrForm},
		{"note with an escape", func(c *Claims) { c.Note = "colour\x1b[31m" }, ErrForm},
		{"bad subject", func(c *Claims) { c.Subject = "not-a-fingerprint" }, ErrForm},
		{"no not_after", func(c *Claims) { c.NotAfter = 0 }, ErrForm},
		{"not_after before not_before", func(c *Claims) { c.NotAfter = c.NotBefore - 1 }, ErrForm},
		{"zero uses is filled, negative is not", func(c *Claims) { c.Uses = -1 }, ErrForm},
		{"too many uses", func(c *Claims) { c.Uses = MaxUses + 1 }, ErrForm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := admin(t)
			c := base(now)
			tc.mutex(&c)
			if _, err := Issue(id, c); !errors.Is(err, tc.want) {
				t.Fatalf("Issue gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSubjectAndNoteSurvive(t *testing.T) {
	id, bob := admin(t), admin(t)
	c := base(time.Now())
	c.Subject = bob.Fingerprint()
	s, err := Issue(id, c)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := Parse(s)
	got, err := u.Verify(id.Public(), time.Now(), relayapi.MaxSkew)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != bob.Fingerprint() {
		t.Fatalf("subject %q, want %q", got.Subject, bob.Fingerprint())
	}
}

func TestParseRejectsBadForms(t *testing.T) {
	id := admin(t)
	good, err := Issue(id, base(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")

	cases := map[string]string{
		"empty":            "",
		"one part":         Prefix,
		"two parts":        Prefix + "." + parts[1],
		"four parts":       good + ".extra",
		"wrong prefix":     "ccxt9." + parts[1] + "." + parts[2],
		"no prefix":        parts[1] + "." + parts[2] + ".x",
		"bad payload b64":  Prefix + ".!!!." + parts[2],
		"bad sig b64":      Prefix + "." + parts[1] + ".!!!",
		"padded base64":    Prefix + "." + parts[1] + "==." + parts[2],
		"payload not json": "ccxt1." + base64.RawURLEncoding.EncodeToString([]byte("hello")) + "." + parts[2],
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(s); !errors.Is(err, ErrForm) {
				t.Fatalf("Parse(%q) gave %v, want ErrForm", s, err)
			}
		})
	}
}

func TestUnknownFieldIsRejected(t *testing.T) {
	id := admin(t)
	good, err := Issue(id, base(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	raw["admin"] = true
	extended, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := Prefix + "." + base64.RawURLEncoding.EncodeToString(extended) + "." + parts[2]
	if _, err := Parse(s); !errors.Is(err, ErrForm) {
		t.Fatalf("a token carrying an unknown field parsed: %v", err)
	}
}

func TestOversizePayloadIsRejected(t *testing.T) {
	// Issue refuses to make one.
	id := admin(t)
	c := base(time.Now())
	c.Note = strings.Repeat("x", MaxNoteBytes)
	if _, err := Issue(id, c); err != nil {
		t.Fatalf("a token at the note limit was refused: %v", err)
	}

	// And Parse refuses to read one, whatever it claims.
	big, err := json.Marshal(map[string]string{"note": strings.Repeat("x", MaxPayloadBytes)})
	if err != nil {
		t.Fatal(err)
	}
	s := Prefix + "." + base64.RawURLEncoding.EncodeToString(big) + ".AAAA"
	if _, err := Parse(s); !errors.Is(err, ErrForm) {
		t.Fatalf("an oversize payload parsed: %v", err)
	}
}

func TestNormaliseRelay(t *testing.T) {
	for in, want := range map[string]string{
		"https://relay.example.com":      "https://relay.example.com",
		"https://relay.example.com/":     "https://relay.example.com",
		" https://relay.example.com/ ":   "https://relay.example.com",
		"http://127.0.0.1:8080":          "http://127.0.0.1:8080",
		"https://relay.example.com:443/": "https://relay.example.com:443",
	} {
		if got := NormaliseRelay(in); got != want {
			t.Errorf("NormaliseRelay(%q) = %q, want %q", in, got, want)
		}
	}
}

// Both sides of both edges. MaxUses+1 was tested and MaxUses was not, which is
// exactly the gap a >= written for > would slip through.
func TestUsesAndNoteBoundaries(t *testing.T) {
	id := admin(t)
	now := time.Now()

	for _, c := range []struct {
		uses   int
		accept bool
	}{
		{-1, false}, {0, true}, // zero means unset and becomes one
		{1, true}, {2, true},
		{MaxUses - 1, true}, {MaxUses, true}, {MaxUses + 1, false},
	} {
		claims := base(now)
		claims.Uses = c.uses
		_, err := Issue(id, claims)
		if c.accept != (err == nil) {
			t.Errorf("uses %d: err=%v, want accepted=%v", c.uses, err, c.accept)
		}
	}

	for _, c := range []struct {
		n      int
		accept bool
	}{
		{0, false}, {1, true}, {2, true},
		{MaxNoteBytes - 1, true}, {MaxNoteBytes, true}, {MaxNoteBytes + 1, false},
	} {
		claims := base(now)
		claims.Note = strings.Repeat("n", c.n)
		_, err := Issue(id, claims)
		if c.accept != (err == nil) {
			t.Errorf("a note of %d bytes: err=%v, want accepted=%v", c.n, err, c.accept)
		}
	}
}

// The window is a pair of signed timestamps from the wire.
func TestClaimTimeExtremes(t *testing.T) {
	id := admin(t)
	for _, c := range []struct {
		name                string
		notBefore, notAfter int64
		accept              bool
	}{
		{"MinInt64 not_before", math.MinInt64, 1, false},
		{"zero not_before", 0, 1, false},
		{"negative not_before", -1, 1, false},
		{"zero not_after", 1, 0, false},
		{"equal", 100, 100, false},
		{"one second apart", 100, 101, true},
		{"MaxInt64 not_after", 100, math.MaxInt64, true},
		{"MaxInt64 both", math.MaxInt64, math.MaxInt64, false},
		{"MinInt64 not_after", 100, math.MinInt64, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			claims := base(time.Now())
			claims.NotBefore, claims.NotAfter = c.notBefore, c.notAfter
			_, err := Issue(id, claims)
			if c.accept != (err == nil) {
				t.Fatalf("err=%v, want accepted=%v", err, c.accept)
			}
		})
	}

	// A far-future expiry must not make the human-readable form panic.
	c := base(time.Now())
	c.NotAfter = math.MaxInt64
	raw, err := Issue(id, c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s := Describe(u.Claims, "", false, time.Now()); s == "" {
		t.Fatal("Describe produced nothing for a MaxInt64 expiry")
	}
	if s := Until(u.Claims.NotAfterTime(), time.Now()); s == "" {
		t.Fatal("Until produced nothing for a MaxInt64 expiry")
	}
}

func TestCertTokenMustBeBoundToAFingerprint(t *testing.T) {
	// A certificate token adds a machine to one identity. Unbound, it would
	// be a permission at large, so one must not exist to be handed out.
	id := admin(t)
	unbound := Claims{
		Relay: "https://relay.example.com", Use: UseCert,
		Note: "laptop", NotAfter: time.Now().Add(time.Hour).Unix(),
	}
	if _, err := Issue(id, unbound); !errors.Is(err, ErrForm) {
		t.Fatalf("Issue of an unbound cert token: %v, want ErrForm", err)
	} else if !strings.Contains(err.Error(), "must be bound to a fingerprint") {
		t.Errorf("error %q does not say what is missing", err)
	}

	// Bound, it is fine.
	bound := unbound
	bound.Subject = strings.Repeat("a", 64)
	raw, err := Issue(id, bound)
	if err != nil {
		t.Fatalf("Issue of a bound cert token: %v", err)
	}
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := u.Verify(id.Public(), time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Use != UseCert {
		t.Errorf("use = %q, want %q", claims.Use, UseCert)
	}
	if claims.Subject != bound.Subject {
		t.Errorf("subject = %q, want %q", claims.Subject, bound.Subject)
	}
}

func TestVerifyRefusesAnUnknownUse(t *testing.T) {
	// A relay must not act on a use it does not understand, whatever the
	// signature says.
	id := admin(t)
	for _, use := range []string{"admin", "REGISTER", "cert ", "", "renew"} {
		c := Claims{
			ID: strings.Repeat("a", 32), Issuer: id.Fingerprint(),
			Relay: "https://relay.example.com", Use: use, Note: "x",
			NotBefore: time.Now().Add(-time.Minute).Unix(),
			NotAfter:  time.Now().Add(time.Hour).Unix(), Uses: 1,
		}
		if err := c.Validate(); !errors.Is(err, ErrUse) && !errors.Is(err, ErrForm) {
			t.Errorf("use %q: Validate = %v, want a refusal", use, err)
		}
		if ValidUse(use) {
			t.Errorf("ValidUse(%q) = true", use)
		}
	}
	if !ValidUse(UseRegister) || !ValidUse(UseCert) {
		t.Error("a defined use was refused")
	}
}

func TestDescribeNamesTheUse(t *testing.T) {
	// Somebody handed a token runs 'auu token show' before redeeming it.
	// What it will do to their machine is the first thing they need.
	id := admin(t)
	c := Claims{
		ID: strings.Repeat("a", 32), Issuer: id.Fingerprint(),
		Relay: "https://relay.example.com", Use: UseCert, Subject: strings.Repeat("b", 64),
		Note: "laptop", NotBefore: time.Now().Unix(),
		NotAfter: time.Now().Add(time.Hour).Unix(), Uses: 1,
	}
	got := Describe(c, "", true, time.Now())
	if !strings.Contains(got, "add another machine") {
		t.Errorf("Describe does not say what a cert token does:\n%s", got)
	}
	c.Use = UseRegister
	if got := Describe(c, "", true, time.Now()); !strings.Contains(got, "create a mailbox") {
		t.Errorf("Describe does not say what a register token does:\n%s", got)
	}
}

func TestTheAnchorTravelsInTheToken(t *testing.T) {
	// A machine cannot check a relay's certificate before it has enrolled,
	// so the token it was handed carries what to check against. That the
	// token is signed by an administrator is what makes it worth checking.
	id := admin(t)
	anchor := strings.Repeat("ab", 32)
	raw, err := Issue(id, Claims{
		Relay: "https://relay.example.com", Use: UseRegister, Note: "bunty",
		Anchor: anchor, NotAfter: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, Prefix+".") {
		t.Fatalf("a token with an anchor was written as %q", raw[:8])
	}
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := u.Verify(id.Public(), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Anchor != anchor {
		t.Errorf("anchor = %q, want %q", claims.Anchor, anchor)
	}
	// It is covered by the signature, which is the point of it being here
	// rather than beside the token. Altered in the decoded payload, keeping
	// its length, so only the anchor changes.
	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var altered Claims
	if err := json.Unmarshal(payload, &altered); err != nil {
		t.Fatal(err)
	}
	altered.Anchor = strings.Repeat("cd", 32)
	forgedPayload, err := json.Marshal(altered)
	if err != nil {
		t.Fatal(err)
	}
	forged := Prefix + "." + base64.RawURLEncoding.EncodeToString(forgedPayload) + "." + parts[2]
	u2, err := Parse(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u2.Verify(id.Public(), time.Now(), time.Minute); !errors.Is(err, ErrSignature) {
		t.Errorf("a token with a swapped anchor gave %v, want ErrSignature", err)
	}
}

func TestAnAnchorMustBeAHashOrAbsent(t *testing.T) {
	// One step either side of the length, the wrong case, and empty, which
	// is how a relay with a publicly trusted certificate says "nothing to
	// pin".
	base := Claims{
		ID: strings.Repeat("a", 32), Issuer: strings.Repeat("b", 64),
		Relay: "https://relay.example.com", Use: UseRegister, Note: "x",
		NotBefore: time.Now().Unix(), NotAfter: time.Now().Add(time.Hour).Unix(), Uses: 1,
	}
	for _, tc := range []struct {
		name   string
		anchor string
		ok     bool
	}{
		{"absent", "", true},
		{"a hash", strings.Repeat("0", 64), true},
		{"one short", strings.Repeat("0", 63), false},
		{"one long", strings.Repeat("0", 65), false},
		{"uppercase", strings.Repeat("A", 64), false},
		{"not hex", strings.Repeat("g", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Anchor = tc.anchor
			err := c.Validate()
			if tc.ok && err != nil {
				t.Errorf("anchor %q was refused: %v", tc.anchor, err)
			}
			if !tc.ok {
				if err == nil {
					t.Errorf("anchor %q was accepted", tc.anchor)
				} else if !strings.Contains(err.Error(), "64 lowercase hex") {
					t.Errorf("error %q does not say what an anchor is", err)
				}
			}
		})
	}
}

func TestALegacyTokenStillParsesAndPinsNothing(t *testing.T) {
	// ccxt1 tokens were handed out before anchors existed. One still works
	// and simply pins nothing, which is what a relay with a public
	// certificate wants.
	id := admin(t)
	c := Claims{
		ID: strings.Repeat("c", 32), Issuer: id.Fingerprint(),
		Relay: "https://relay.example.com", Use: UseRegister, Note: "old",
		NotBefore: time.Now().Add(-time.Minute).Unix(),
		NotAfter:  time.Now().Add(time.Hour).Unix(), Uses: 1,
	}
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	old := LegacyPrefix + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mustSign(t, id, signingBytes(payload)))

	u, err := Parse(old)
	if err != nil {
		t.Fatalf("a ccxt1 token no longer parses: %v", err)
	}
	claims, err := u.Verify(id.Public(), time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("a ccxt1 token no longer verifies: %v", err)
	}
	if claims.Anchor != "" {
		t.Errorf("a ccxt1 token produced anchor %q", claims.Anchor)
	}
}

// A token that ran out inside the clock skew a relay allows is still good
// there, and the description says so, to the second, for a person deciding
// whether to hurry; past the skew it is expired and that is all. The two
// edges are where Verify's are, one second apart. The container suite's X01
// found a token described as expired and then enrolled with.
func TestDescribeSaysHowLongAnExpiredTokenStillWorks(t *testing.T) {
	id := admin(t)
	expiry := time.Now().Truncate(time.Second)
	raw, err := Issue(id, Claims{
		Relay: "https://relay.example.com", Use: UseRegister, Note: "soon",
		NotBefore: expiry.Add(-time.Hour).Unix(), NotAfter: expiry.Unix(), Uses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		now      time.Time
		want     string // what the "expires:" line ends with
		accepted bool   // what the relay would do at that moment
	}{
		{"a second before", expiry.Add(-time.Second), "(in less than a minute)", true},
		{"thirty seconds after", expiry.Add(30 * time.Second), "(expired 30s ago; a relay accepts it for 5 minutes past that)", true},
		{"the skew exactly", expiry.Add(relayapi.MaxSkew), "(expired 5m0s ago; a relay accepts it for 5 minutes past that)", true},
		{"a second past the skew", expiry.Add(relayapi.MaxSkew + time.Second), "(expired 5 minutes ago)", false},
		{"an hour after", expiry.Add(time.Hour), "(expired 1 hour ago)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Describe(u.Claims, "", true, tc.now)
			line := ""
			for _, l := range strings.Split(got, "\n") {
				if strings.HasPrefix(l, "expires:") {
					line = l
				}
			}
			if !strings.HasSuffix(line, tc.want) {
				t.Fatalf("expires line %q does not end with %q", line, tc.want)
			}
			_, err := u.Verify(id.Public(), tc.now, relayapi.MaxSkew)
			if accepted := err == nil; accepted != tc.accepted {
				t.Fatalf("the relay would accept it: %v (%v), and the description says %v", accepted, err, tc.accepted)
			}
		})
	}
}

// The integer review at af0d96e (reviews/trace/): three renderings of a
// peer's number, kept as regressions.

// unverifiedToken builds a token string that Parse accepts without any
// signature or claim check: a real prefix, the given claims as the payload,
// and 64 bytes of zero where an Ed25519 signature would be.
func unverifiedToken(t *testing.T, c Claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	return strings.Join([]string{
		Prefix,
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(sig),
	}, ".")
}

// TestDescribeNeverSlicesAShortIssuer: Parse decodes claims and checks
// nothing, and Describe sliced Issuer[:16], so a pasted token with a
// short issuer panicked enrol and token show. Now Describe renders
// whatever it is given, the whole of a short id, and the callers that
// want the shape checked run Validate first.
func TestDescribeNeverSlicesAShortIssuer(t *testing.T) {
	for _, issuer := range []string{"", "a", "ab", strings.Repeat("a", 15), strings.Repeat("a", 16), strings.Repeat("a", 64)} {
		raw := unverifiedToken(t, Claims{
			Issuer: issuer, Relay: "https://relay.example.com", Use: UseRegister,
			NotBefore: 1, NotAfter: 2, Uses: 1,
		})
		u, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse refused the token: %v; expected it to parse, since Parse checks no claim", err)
		}
		got := Describe(u.Claims, "", false, time.Now())
		want := issuer
		if len(want) > 16 {
			want = want[:16]
		}
		if !strings.Contains(got, "issuer:  "+want+"\n") {
			t.Errorf("issuer of %d characters described as:\n%s", len(issuer), got)
		}
		if named := Describe(u.Claims, "boss", false, time.Now()); !strings.Contains(named, "issuer:  boss <"+want+">\n") {
			t.Errorf("issuer of %d characters with a name described as:\n%s", len(issuer), named)
		}
	}
}

func TestDescribeNeverSlicesAShortSubject(t *testing.T) {
	raw := unverifiedToken(t, Claims{
		Issuer: strings.Repeat("a", 64), Subject: "ab",
		Relay: "https://relay.example.com", Use: UseRegister,
		NotBefore: 1, NotAfter: 2, Uses: 1,
	})
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := Describe(u.Claims, "", false, time.Now()); !strings.Contains(got, "bound to: ab\n") {
		t.Fatalf("a two-character subject described as:\n%s", got)
	}
}

// TestUntilNeverNegatesASaturatedDifference: Until negated the difference
// between the expiry and now, and time.Sub saturates at the Duration
// minimum for a gap over about 292 years, whose negation is itself, so a
// token expired that long ago read as inside the relay's skew with a
// negative age. Now Until compares times and negates nothing.
func TestUntilNeverNegatesASaturatedDifference(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	saturates := now.Add(-time.Duration(math.MaxInt64)).Add(-time.Second)
	justFits := now.Add(-time.Duration(math.MaxInt64)).Add(time.Second)
	if got := Until(justFits, now); !strings.HasPrefix(got, "expired ") || strings.Contains(got, "-") || strings.Contains(got, "a relay accepts") {
		t.Fatalf("Until for an expiry a second inside the Duration range said %q; expected an expired-long-ago sentence", got)
	}
	for _, c := range []struct {
		name string
		t    time.Time
	}{
		{"one second past where Sub saturates", saturates},
		{"not_after -10000000000 (the year 1653)", time.Unix(-10_000_000_000, 0)},
		{"not_after 1734", time.Date(1734, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"not_after MinInt64", time.Unix(math.MinInt64, 0)},
	} {
		got := Until(c.t, now)
		if strings.Contains(got, "-") || strings.Contains(got, "a relay accepts") || !strings.HasPrefix(got, "expired ") {
			t.Errorf("%s: Until said %q; expected it to say the token expired, not a negative age, and not that a relay still accepts it", c.name, got)
		}
	}
	if got := Until(time.Unix(math.MinInt64, 0), now); got != "expired long ago" {
		t.Errorf("a saturated gap: %q, want \"expired long ago\"", got)
	}
	// The edges of the skew, and the future, are as they were.
	if got := Until(now.Add(-time.Minute), now); got != "expired 1m0s ago; a relay accepts it for 5 minutes past that" {
		t.Errorf("a minute ago: %q", got)
	}
	if got := Until(now.Add(-relayapi.MaxSkew-time.Second), now); got != "expired 5 minutes ago" {
		t.Errorf("a second past the skew: %q", got)
	}
	if got := Until(now.Add(3*time.Hour), now); got != "in 3 hours" {
		t.Errorf("three hours ahead: %q", got)
	}
	if got := Until(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), now); !strings.HasPrefix(got, "in ") || strings.Contains(got, "-") {
		t.Errorf("the far future: %q", got)
	}
}

// TestDescribeOfAnExpiryFromTheFarPastSaysExpired is the same value
// through the door a person uses: a pasted token whose not_after is far in
// the past reaches Describe without Validate.
func TestDescribeOfAnExpiryFromTheFarPastSaysExpired(t *testing.T) {
	raw := unverifiedToken(t, Claims{
		Issuer: strings.Repeat("a", 64), Relay: "https://relay.example.com", Use: UseRegister,
		NotBefore: 1, NotAfter: math.MinInt64, Uses: 1,
	})
	u, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := Describe(u.Claims, "", false, time.Now())
	if strings.Contains(got, "a relay accepts") || !strings.Contains(got, "expired long ago") {
		t.Fatalf("Describe of a token with not_after MinInt64:\n%s", got)
	}
}
