package vouch

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

func gen(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// now is the clock every test holds a vouch to, fixed so that an issue
// time's distance from it is exact.
var now = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

// base is a vouch by v for x that passes every rule, for a test to spoil
// one way.
func base(v, x *identity.Identity) *Document {
	return &Document{
		V:       Version,
		Voucher: v.Fingerprint(),
		Subject: x.Fingerprint(),
		Bundle:  x.Public().Bundle(),
		Name:    "xavier",
		Issued:  now.Add(-time.Hour),
	}
}

func mustSign(t *testing.T, id *identity.Identity, msg []byte) []byte {
	t.Helper()
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

// signRaw signs a document's bytes as they stand under the vouch domain,
// for a test that must present bytes Sign would refuse to make.
func signRaw(t *testing.T, id *identity.Identity, d *Document) ([]byte, []byte) {
	t.Helper()
	doc, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return doc, mustSign(t, id, signingBytes(doc))
}

func TestRoundTrip(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	d := base(v, x)
	doc, sig, err := Sign(v, d, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(v.Public(), doc, sig, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Voucher != v.Fingerprint() || got.Subject != x.Fingerprint() || string(got.Bundle) != string(x.Public().Bundle()) ||
		got.Name != "xavier" || !got.Issued.Equal(d.Issued) {
		t.Fatalf("the vouch did not survive: %+v", got)
	}
	// The JSON names are the design's, and every field is written.
	for _, want := range []string{`"v":1`, `"voucher":"`, `"subject":"`, `"bundle":"`, `"name":"xavier"`, `"issued":"2026-09-29T09:00:00Z"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("document lacks %s:\n%s", want, doc)
		}
	}
}

// The zero value marshals every key, so absence and zero cannot be one
// thing on the wire.
func TestTheZeroValueWritesEveryKey(t *testing.T) {
	out, err := json.Marshal(Document{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"v":`, `"voucher":`, `"subject":`, `"bundle":`, `"name":`, `"issued":`} {
		if !strings.Contains(string(out), key) {
			t.Errorf("the zero value leaves out %s: %s", key, out)
		}
	}
}

// The round trip over random names of every length the rule admits and
// random issue times, with the seed logged; and a bit flipped in each
// region — the document, the signature — breaks it with the specific
// error, as does the right document under the wrong key.
func TestSignVerifyRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	v, x, other := gen(t, "v"), gen(t, "x"), gen(t, "other")
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	name := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			limit := len(alphabet)
			if i == 0 {
				limit = 62
			}
			b[i] = alphabet[r.IntN(limit)]
		}
		if strings.EqualFold(string(b), "self") {
			b[0] = 'x'
		}
		return string(b)
	}
	lengths := []int{1, 2, identity.MaxNameBytes - 1, identity.MaxNameBytes}
	for i := 0; i < 100; i++ {
		n := lengths[i%len(lengths)]
		if i >= 2*len(lengths) {
			n = 1 + r.IntN(identity.MaxNameBytes)
		}
		d := &Document{
			Subject: x.Fingerprint(),
			Bundle:  x.Public().Bundle(),
			Name:    name(n),
			// Any time up to the edge of the skew ahead of now.
			Issued: time.Unix(r.Int64N(now.Unix()+int64(relayapi.MaxSkew/time.Second)), r.Int64N(1_000_000_000)).UTC(),
		}
		doc, sig, err := Sign(v, d, now)
		if err != nil {
			t.Fatalf("seed %d: iteration %d, name %q issued %s: %v", seed, i, d.Name, d.Issued, err)
		}
		got, err := Verify(v.Public(), doc, sig, now)
		if err != nil {
			t.Fatalf("seed %d: iteration %d: %v", seed, i, err)
		}
		if got.Name != d.Name || !got.Issued.Equal(d.Issued) || got.Subject != d.Subject {
			t.Fatalf("seed %d: iteration %d: the vouch did not survive: %+v", seed, i, got)
		}
		flipped := testutil.FlipBit(doc, r.IntN(len(doc)*8))
		if _, err := Verify(v.Public(), flipped, sig, now); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d: a flipped document bit: %v, want ErrSignature", seed, i, err)
		}
		flipped = testutil.FlipBit(sig, r.IntN(len(sig)*8))
		if _, err := Verify(v.Public(), doc, flipped, now); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d: a flipped signature bit: %v, want ErrSignature", seed, i, err)
		}
		if _, err := Verify(other.Public(), doc, sig, now); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d: the wrong key: %v, want ErrSignature", seed, i, err)
		}
	}
}

// Sign takes the voucher from the key and refuses a vouch that breaks a
// rule, so that an invalid one never exists to be sent.
func TestSignFillsTheVoucherAndRefusesAnInvalidVouch(t *testing.T) {
	v, x, other := gen(t, "v"), gen(t, "x"), gen(t, "other")
	d := base(v, x)
	d.Voucher = other.Fingerprint()
	d.V = 0
	doc, _, err := Sign(v, d, now)
	if err != nil {
		t.Fatal(err)
	}
	if d.Voucher != v.Fingerprint() || d.V != Version || !strings.Contains(string(doc), `"voucher":"`+v.Fingerprint()+`"`) {
		t.Fatalf("Sign left voucher %q v %d", d.Voucher, d.V)
	}
	cases := []struct {
		label string
		spoil func(d *Document)
		want  string
	}{
		{"self-vouch", func(d *Document) { d.Subject, d.Bundle = v.Fingerprint(), v.Public().Bundle() }, "a voucher does not vouch for themselves"},
		{"bundle not the subject", func(d *Document) { d.Bundle = other.Public().Bundle() }, "bundle is not the subject's key"},
		{"empty name", func(d *Document) { d.Name = "" }, "name is empty"},
		{"name over the cap", func(d *Document) { d.Name = strings.Repeat("a", identity.MaxNameBytes+1) }, "name is 65 bytes; at most 64"},
		{"name with a control character", func(d *Document) { d.Name = "x\x1bv" },
			`name "x\x1bv": letters, digits, '.', '_' and '-' only, beginning with a letter or digit`},
		{"issued zero", func(d *Document) { d.Issued = time.Time{} }, "issued is missing"},
		{"issued in 2099", func(d *Document) { d.Issued = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) },
			"issued 2099-01-01T00:00:00Z is more than 5m0s ahead of this machine's clock"},
	}
	for _, c := range cases {
		d := base(v, x)
		c.spoil(d)
		if _, _, err := Sign(v, d, now); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v; want %q", c.label, err, c.want)
		}
	}
	if _, _, err := Sign(nil, base(v, x), now); err == nil {
		t.Fatal("Sign with no identity signed")
	}
}

// Validate's own rules at every edge.
func TestAVouchIsCheckedAtEveryEdge(t *testing.T) {
	v, x, other := gen(t, "v"), gen(t, "x"), gen(t, "other")
	long := strings.Repeat("a", identity.MaxNameBytes)
	cases := []struct {
		label string
		spoil func(d *Document)
		want  string
	}{
		{"as built", func(d *Document) {}, ""},
		{"v 2", func(d *Document) { d.V = 2 }, "v is 2; this build reads 1"},
		{"v 0", func(d *Document) { d.V = 0 }, "v is 0; this build reads 1"},
		{"voucher not a fingerprint", func(d *Document) { d.Voucher = "v" }, "voucher is not a fingerprint"},
		{"voucher upper case", func(d *Document) { d.Voucher = strings.ToUpper(d.Voucher) }, "voucher is not a fingerprint"},
		{"subject not a fingerprint", func(d *Document) { d.Subject = d.Subject[1:] }, "subject is not a fingerprint"},
		{"voucher is the subject", func(d *Document) { d.Voucher = d.Subject }, "a voucher does not vouch for themselves"},
		{"no bundle", func(d *Document) { d.Bundle = nil }, "bundle: bundle is 0 bytes, which is no known suite (want 1248)"},
		{"a bundle one byte short", func(d *Document) { d.Bundle = d.Bundle[1:] }, "bundle: bundle is 1247 bytes, which is no known suite (want 1248)"},
		{"somebody else's bundle", func(d *Document) { d.Bundle = other.Public().Bundle() }, "bundle is not the subject's key"},
		{"name empty", func(d *Document) { d.Name = "" }, "name is empty"},
		{"name at the cap", func(d *Document) { d.Name = long }, ""},
		{"name one over the cap", func(d *Document) { d.Name = long + "a" }, "name is 65 bytes; at most 64"},
		{"name with a format character", func(d *Document) { d.Name = "x\u202e" },
			`name "x\u202e": letters, digits, '.', '_' and '-' only, beginning with a letter or digit`},
		{"name self", func(d *Document) { d.Name = "Self" }, `the name "self" is reserved; it means you`},
		{"issued missing", func(d *Document) { d.Issued = time.Time{} }, "issued is missing"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			d := base(v, x)
			c.spoil(d)
			err := d.Validate()
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && err == nil:
				t.Fatalf("accepted; want %q", c.want)
			case c.want != "" && err.Error() != c.want:
				t.Fatalf("got %q, want %q", err, c.want)
			}
		})
	}
}

// The one rule with a clock: an issue time more than relayapi.MaxSkew
// ahead of now is refused at Verify as at Sign, one second either side of
// the edge, and a year ahead; one from long ago is a statement at a time
// and taken.
func TestAVouchFromTheFutureIsRefused(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	for _, c := range []struct {
		label  string
		issued time.Time
		ok     bool
	}{
		{"a year ago", now.AddDate(-1, 0, 0), true},
		{"now", now, true},
		{"a second inside the skew", now.Add(relayapi.MaxSkew - time.Second), true},
		{"at the skew", now.Add(relayapi.MaxSkew), true},
		{"a second past the skew", now.Add(relayapi.MaxSkew + time.Second), false},
		{"in 2099", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), false},
	} {
		t.Run(c.label, func(t *testing.T) {
			d := base(v, x)
			d.Issued = c.issued
			d.V = Version
			doc, sig := signRaw(t, v, d)
			_, err := Verify(v.Public(), doc, sig, now)
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "ahead of this machine's clock")) {
				t.Fatalf("got %v; want the refusal of a future issue time", err)
			}
		})
	}
}

// Verify's order: the length, the signature, the form and rules, the
// voucher, the clock. A document that does not verify is never decoded.
func TestAVerifiedVouchIsTheSignersAlone(t *testing.T) {
	v, x, other := gen(t, "v"), gen(t, "x"), gen(t, "other")
	doc, sig, err := Sign(v, base(v, x), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		label    string
		pub      *identity.Public
		doc, sig []byte
		want     error
	}{
		{"the wrong key", other.Public(), doc, sig, ErrSignature},
		{"one bit of the signature", v.Public(), doc, testutil.FlipBit(sig, len(sig)*4), ErrSignature},
		{"the document truncated by one byte", v.Public(), doc[:len(doc)-1], sig, ErrSignature},
		{"the document extended by one byte", v.Public(), append(append([]byte{}, doc...), ' '), sig, ErrSignature},
		{"the signature truncated by one byte", v.Public(), doc, sig[:len(sig)-1], ErrSignature},
		{"the signature extended by one byte", v.Public(), doc, append(append([]byte{}, sig...), 0), ErrSignature},
		{"no signature", v.Public(), doc, nil, ErrSignature},
		{"bytes that are not a document", v.Public(), []byte("not a document"), nil, ErrSignature},
		{"a signature without the domain", v.Public(), doc, mustSign(t, v, doc), ErrSignature},
		{"no key", nil, doc, sig, ErrOwner},
	} {
		if _, err := Verify(c.pub, c.doc, c.sig, now); !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", c.label, err, c.want)
		}
	}
	t.Run("one byte of the name changed", func(t *testing.T) {
		i := strings.Index(string(doc), `"name":"xavier"`) + len(`"name":"`)
		changed := append([]byte{}, doc...)
		changed[i] = 'j'
		if _, err := Verify(v.Public(), changed, sig, now); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("a voucher that is not the signer", func(t *testing.T) {
		d := base(v, x)
		d.Voucher = other.Fingerprint()
		forged, forgedSig := signRaw(t, v, d)
		if _, err := Verify(v.Public(), forged, forgedSig, now); !errors.Is(err, ErrOwner) {
			t.Fatalf("got %v, want ErrOwner", err)
		}
		if _, err := Verify(other.Public(), forged, forgedSig, now); !errors.Is(err, ErrSignature) {
			t.Fatalf("under the named voucher's key: %v, want ErrSignature", err)
		}
	})
	t.Run("an unknown field", func(t *testing.T) {
		with := strings.Replace(string(doc), `"v":1,`, `"v":1,"trust":100,`, 1)
		if with == string(doc) {
			t.Fatal("the document has no v to insert after")
		}
		_, err := Verify(v.Public(), []byte(with), mustSign(t, v, signingBytes([]byte(with))), now)
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), `unknown field "trust"`) {
			t.Fatalf("got %v, want ErrForm naming the field", err)
		}
	})
	t.Run("trailing data", func(t *testing.T) {
		with := append(append([]byte{}, doc...), []byte(`{}`)...)
		if _, err := Verify(v.Public(), with, mustSign(t, v, signingBytes(with)), now); !errors.Is(err, ErrForm) {
			t.Fatalf("got %v, want ErrForm", err)
		}
	})
	t.Run("a rule broken under a good signature", func(t *testing.T) {
		d := base(v, x)
		d.Bundle = other.Public().Bundle()
		bad, badSig := signRaw(t, v, d)
		if _, err := Verify(v.Public(), bad, badSig, now); err == nil || err.Error() != "bundle is not the subject's key" {
			t.Fatalf("got %v", err)
		}
	})
}

// A document over relayapi.MaxVouchBytes is refused by the length before
// the signature is checked, on Verify and on Parse; at the cap it is
// taken. Over the cap and under the wrong key, the length is the refusal,
// which is the which-check-fired shape.
func TestAVouchIsHeldToItsBytesBeforeTheSignature(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	doc, sig, err := Sign(v, base(v, x), now)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(n int) []byte {
		out := append([]byte{}, doc[:len(doc)-1]...)
		out = append(out, strings.Repeat(" ", n-len(doc))...)
		return append(out, '}')
	}
	atCap := pad(relayapi.MaxVouchBytes)
	if _, err := Verify(v.Public(), atCap, mustSign(t, v, signingBytes(atCap)), now); err != nil {
		t.Fatalf("a document at the cap, %d bytes: %v", len(atCap), err)
	}
	over := pad(relayapi.MaxVouchBytes + 1)
	_, err = Verify(v.Public(), over, sig, now)
	if !errors.Is(err, ErrForm) || err.Error() != "vouch is malformed: the vouch is 2049 bytes; at most 2048, so send it compact" {
		t.Fatalf("a document one over the cap: %v", err)
	}
	if _, err := Verify(v.Public(), over, mustSign(t, v, signingBytes(over)), now); !errors.Is(err, ErrForm) {
		t.Fatalf("a signed document one over the cap: %v", err)
	}
	if _, err := Verify(gen(t, "stranger").Public(), over, sig, now); !errors.Is(err, ErrForm) {
		t.Fatalf("over the cap under the wrong key: %v; want the length's refusal", err)
	}
	if _, err := Parse(over); !errors.Is(err, ErrForm) {
		t.Fatalf("Parse one over the cap: %v", err)
	}
	if _, err := Parse(atCap); err != nil {
		t.Fatalf("Parse at the cap: %v", err)
	}
}

// Parse is as strict about the form and the rules without a signature.
func TestParseIsStrictWithoutASignature(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	doc, _, err := Sign(v, base(v, x), now)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := Parse(doc); err != nil || d.Name != "xavier" {
		t.Fatalf("Parse of a good document: %+v, %v", d, err)
	}
	if _, err := Parse([]byte(`{"v":1,"trust":100}`)); !errors.Is(err, ErrForm) {
		t.Fatalf("an unknown field: %v, want ErrForm", err)
	}
	if _, err := Parse(append(append([]byte{}, doc...), '{', '}')); !errors.Is(err, ErrForm) {
		t.Fatalf("trailing data: %v, want ErrForm", err)
	}
	if _, err := Parse([]byte(`not json`)); !errors.Is(err, ErrForm) {
		t.Fatalf("not JSON: %v, want ErrForm", err)
	}
}

// The same identity key now signs eight things. A vouch signature must not
// verify as any of the other seven, nor any of them as a vouch; the three
// documents beside it, the card, the allow list and the directory, are
// each checked in both directions by name.
func TestVouchSignatureDomainIsSeparate(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	doc, sig, err := Sign(v, base(v, x), now)
	if err != nil {
		t.Fatal(err)
	}
	pub := v.Public()
	others := map[string][]byte{
		"token":      append([]byte("ccx-token-v1"), doc...),
		"envelope":   append([]byte("ccx-sig-v1"+pub.Fingerprint()), doc...),
		"stream":     append([]byte("ccx-stream-sig-v1"+pub.Fingerprint()), doc...),
		"directory":  append([]byte("ccx-channels-v1"), doc...),
		"allow list": append([]byte("ccx-allow-v1"), doc...),
		"card":       append([]byte("ccx-card-v1"), doc...),
		"request":    relayapi.SigningString("POST", "/v1/mailbox/x", 0, "n", doc),
	}
	for name, input := range others {
		if pub.Verify(input, sig) {
			t.Errorf("a vouch signature verified as a %s signature", name)
		}
		if _, err := Verify(pub, doc, mustSign(t, v, input), now); !errors.Is(err, ErrSignature) {
			t.Errorf("a %s signature verified as a vouch signature: %v", name, err)
		}
	}
	// The domain is a wire constant, pinned from outside its definition.
	if string(signingBytes(nil)) != "ccx-vouch-v1" {
		t.Fatalf("the vouch domain is %q, want ccx-vouch-v1", signingBytes(nil))
	}
}
