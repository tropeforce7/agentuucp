package card

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

func owner(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate("owner")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// base is a card that passes every rule, for a test to spoil one way.
func base(id *identity.Identity) *Document {
	return &Document{
		V:      Version,
		Owner:  id.Fingerprint(),
		Issued: time.Date(2026, 9, 22, 10, 4, 0, 0, time.UTC),
		Name:   "bob",
		Listed: true,
		Knocks: true,
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

func TestRoundTrip(t *testing.T) {
	id := owner(t)
	d := base(id)
	doc, sig, err := Sign(id, d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(id.Public(), doc, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != id.Fingerprint() || !got.Issued.Equal(d.Issued) || got.Name != "bob" || !got.Listed || !got.Knocks {
		t.Fatalf("the card did not survive: %+v", got)
	}
	// The JSON names are the design's, and the two words are always
	// written, false included, so a card says what it means.
	for _, want := range []string{`"v":1`, `"owner":"`, `"issued":"2026-09-22T10:04:00Z"`, `"name":"bob"`, `"listed":true`, `"knocks":true`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("document lacks %s:\n%s", want, doc)
		}
	}
	d = base(id)
	d.Listed, d.Knocks = false, false
	doc, _, err = Sign(id, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"listed":false`, `"knocks":false`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("a card that says no lacks %s:\n%s", want, doc)
		}
	}
}

// The round trip over random names of every length the rule admits and
// random issue times, with the seed logged; and a bit flipped in each
// region — the document, the signature — breaks it with the specific
// error, as does the right document under the wrong key.
func TestSignVerifyRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	id, other := owner(t), owner(t)
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	name := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			// The first byte is a letter or a digit: the rule's shape.
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
	for i := 0; i < 200; i++ {
		n := lengths[i%len(lengths)]
		if i >= 2*len(lengths) {
			n = 1 + r.IntN(identity.MaxNameBytes)
		}
		d := &Document{
			Issued: time.Unix(r.Int64N(4_000_000_000), r.Int64N(1_000_000_000)).UTC(),
			Name:   name(n),
			Listed: r.IntN(2) == 0,
			Knocks: r.IntN(2) == 0,
		}
		doc, sig, err := Sign(id, d)
		if err != nil {
			t.Fatalf("seed %d: iteration %d, name of %d bytes %q: %v", seed, i, n, d.Name, err)
		}
		got, err := Verify(id.Public(), doc, sig)
		if err != nil {
			t.Fatalf("seed %d: iteration %d: %v", seed, i, err)
		}
		if got.Name != d.Name || got.Listed != d.Listed || got.Knocks != d.Knocks || !got.Issued.Equal(d.Issued) {
			t.Fatalf("seed %d: iteration %d: the card did not survive: %+v", seed, i, got)
		}
		// One bit of the document: the signature refuses it before the
		// decoder sees it, whatever the flip did to the JSON.
		flipped := testutil.FlipBit(doc, r.IntN(len(doc)*8))
		if _, err := Verify(id.Public(), flipped, sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d: a flipped document bit: %v, want ErrSignature", seed, i, err)
		}
		flipped = testutil.FlipBit(sig, r.IntN(len(sig)*8))
		if _, err := Verify(id.Public(), doc, flipped); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d: a flipped signature bit: %v, want ErrSignature", seed, i, err)
		}
		if _, err := Verify(other.Public(), doc, sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("seed %d: iteration %d: the wrong key: %v, want ErrSignature", seed, i, err)
		}
	}
}

// Sign takes the owner from the key and refuses a card that breaks a
// rule, so that an invalid one never exists to be pushed.
func TestSignFillsTheOwnerAndRefusesAnInvalidCard(t *testing.T) {
	id, other := owner(t), owner(t)
	d := base(id)
	d.Owner = other.Fingerprint()
	d.V = 0
	doc, _, err := Sign(id, d)
	if err != nil {
		t.Fatal(err)
	}
	if d.Owner != id.Fingerprint() || d.V != Version {
		t.Fatalf("Sign left owner %q v %d", d.Owner, d.V)
	}
	if !strings.Contains(string(doc), `"owner":"`+id.Fingerprint()+`"`) {
		t.Fatal("the document does not name the signing key as its owner")
	}

	d = base(id)
	d.Issued = time.Time{}
	if _, _, err := Sign(id, d); err == nil || err.Error() != "issued is missing" {
		t.Fatalf("Sign of a card with no issued: %v", err)
	}
	d = base(id)
	d.Name = ""
	if _, _, err := Sign(id, d); err == nil || err.Error() != "name is empty" {
		t.Fatalf("Sign of a card with no name: %v", err)
	}
	if _, _, err := Sign(nil, base(id)); err == nil {
		t.Fatal("Sign with no identity signed")
	}
}

// Validate's own rules: the version, the owner, issued, and the name at
// every edge of the export line's rule — empty, the cap, one over it, a
// control character, a format character, "self", a bad first byte.
func TestACardIsCheckedAtEveryEdge(t *testing.T) {
	id := owner(t)
	long := strings.Repeat("a", identity.MaxNameBytes)
	cases := []struct {
		label string
		spoil func(d *Document)
		want  string
	}{
		{"as built", func(d *Document) {}, ""},
		{"neither listed nor knocks", func(d *Document) { d.Listed, d.Knocks = false, false }, ""},
		{"v 2", func(d *Document) { d.V = 2 }, "v is 2; this build reads 1"},
		{"v 0", func(d *Document) { d.V = 0 }, "v is 0; this build reads 1"},
		{"owner not a fingerprint", func(d *Document) { d.Owner = "alice" }, "owner is not a fingerprint"},
		{"owner upper case", func(d *Document) { d.Owner = strings.ToUpper(d.Owner) }, "owner is not a fingerprint"},
		{"owner one short", func(d *Document) { d.Owner = d.Owner[1:] }, "owner is not a fingerprint"},
		{"issued missing", func(d *Document) { d.Issued = time.Time{} }, "issued is missing"},
		{"name empty", func(d *Document) { d.Name = "" }, "name is empty"},
		{"name at the cap", func(d *Document) { d.Name = long }, ""},
		{"name one over the cap", func(d *Document) { d.Name = long + "a" },
			"name is 65 bytes; at most 64"},
		{"name with a control character", func(d *Document) { d.Name = "bo\x1bb" },
			`name "bo\x1bb": letters, digits, '.', '_' and '-' only, beginning with a letter or digit`},
		{"name with a format character", func(d *Document) { d.Name = "bob\u202e" },
			`name "bob\u202e": letters, digits, '.', '_' and '-' only, beginning with a letter or digit`},
		{"name with a space", func(d *Document) { d.Name = "bob smith" },
			`name "bob smith": letters, digits, '.', '_' and '-' only, beginning with a letter or digit`},
		{"name beginning with a dot", func(d *Document) { d.Name = ".bob" },
			`name ".bob": letters, digits, '.', '_' and '-' only, beginning with a letter or digit`},
		{"name self", func(d *Document) { d.Name = "Self" }, `the name "self" is reserved; it means you`},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			d := base(id)
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

// Verify's order: the signature, then the form, then the rules, then the
// owner. A document that does not verify is never decoded.
func TestAVerifiedCardIsTheSignersAlone(t *testing.T) {
	id, other := owner(t), owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the wrong key", func(t *testing.T) {
		if _, err := Verify(other.Public(), doc, sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("one byte of the document changed", func(t *testing.T) {
		// One letter of the name, so the document still decodes and
		// still validates: only the signature can refuse it.
		i := strings.Index(string(doc), `"name":"bob"`) + len(`"name":"`)
		changed := append([]byte{}, doc...)
		changed[i] = 'r'
		if _, err := Verify(id.Public(), changed, sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("one bit of the signature changed", func(t *testing.T) {
		changed := testutil.FlipBit(sig, len(sig)*4)
		if _, err := Verify(id.Public(), doc, changed); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("the document truncated by one byte", func(t *testing.T) {
		if _, err := Verify(id.Public(), doc[:len(doc)-1], sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("the document extended by one byte", func(t *testing.T) {
		if _, err := Verify(id.Public(), append(append([]byte{}, doc...), ' '), sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("the signature truncated by one byte", func(t *testing.T) {
		if _, err := Verify(id.Public(), doc, sig[:len(sig)-1]); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("the signature extended by one byte", func(t *testing.T) {
		if _, err := Verify(id.Public(), doc, append(append([]byte{}, sig...), 0)); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("no signature", func(t *testing.T) {
		if _, err := Verify(id.Public(), doc, nil); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("bytes that are not a document, under no signature", func(t *testing.T) {
		// The signature is what refuses it, never the decoder: the
		// decoder does not run on bytes nobody vouched for.
		if _, err := Verify(id.Public(), []byte("not a document"), nil); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("a signature without the domain", func(t *testing.T) {
		if _, err := Verify(id.Public(), doc, mustSign(t, id, doc)); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("owner not the signer", func(t *testing.T) {
		d := base(id)
		d.Owner = other.Fingerprint()
		forged, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		forgedSig := mustSign(t, id, signingBytes(forged))
		if _, err := Verify(id.Public(), forged, forgedSig); !errors.Is(err, ErrOwner) {
			t.Fatalf("got %v, want ErrOwner", err)
		}
		if _, err := Verify(other.Public(), forged, forgedSig); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("an unknown field", func(t *testing.T) {
		with := strings.Replace(string(doc), `"v":1,`, `"v":1,"colour":"blue",`, 1)
		if with == string(doc) {
			t.Fatal("the document has no v to insert after")
		}
		withSig := mustSign(t, id, signingBytes([]byte(with)))
		_, err := Verify(id.Public(), []byte(with), withSig)
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), `unknown field "colour"`) {
			t.Fatalf("got %v, want ErrForm naming the field", err)
		}
	})
	t.Run("trailing data", func(t *testing.T) {
		with := append(append([]byte{}, doc...), []byte(`{}`)...)
		withSig := mustSign(t, id, signingBytes(with))
		if _, err := Verify(id.Public(), with, withSig); !errors.Is(err, ErrForm) {
			t.Fatalf("got %v, want ErrForm", err)
		}
	})
	t.Run("a rule broken under a good signature", func(t *testing.T) {
		d := base(id)
		d.Name = ""
		bad, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(id.Public(), bad, mustSign(t, id, signingBytes(bad)))
		if err == nil || err.Error() != "name is empty" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no key", func(t *testing.T) {
		if _, err := Verify(nil, doc, sig); !errors.Is(err, ErrOwner) {
			t.Fatalf("got %v, want ErrOwner", err)
		}
	})
}

// A document over relayapi.MaxCardBytes is refused by the length before
// the signature is checked, on Verify and on Parse: a padded document is
// what a reader must not spend a signature check on, and the refusal
// names the bytes and the cap. At the cap it is taken.
func TestACardIsHeldToItsBytesBeforeTheSignature(t *testing.T) {
	id := owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	// Padded with spaces inside the object, which a decoder ignores and
	// the signature covers when signed by hand.
	pad := func(n int) []byte {
		out := append([]byte{}, doc[:len(doc)-1]...)
		out = append(out, strings.Repeat(" ", n-len(doc))...)
		return append(out, '}')
	}
	atCap := pad(relayapi.MaxCardBytes)
	if _, err := Verify(id.Public(), atCap, mustSign(t, id, signingBytes(atCap))); err != nil {
		t.Fatalf("a document at the cap, %d bytes: %v", len(atCap), err)
	}
	over := pad(relayapi.MaxCardBytes + 1)
	// Signed by nobody, since the length refuses it before the signature
	// is looked at; the signature is a valid one over other bytes.
	_, err = Verify(id.Public(), over, sig)
	if !errors.Is(err, ErrForm) || err.Error() != "card is malformed: the card is 513 bytes; at most 512, so send it compact" {
		t.Fatalf("a document one over the cap: %v", err)
	}
	// And under a good signature all the same.
	if _, err := Verify(id.Public(), over, mustSign(t, id, signingBytes(over))); !errors.Is(err, ErrForm) {
		t.Fatalf("a signed document one over the cap: %v", err)
	}
	if _, err := Parse(over); !errors.Is(err, ErrForm) {
		t.Fatalf("Parse of a document one over the cap: %v", err)
	}
	if _, err := Parse(atCap); err != nil {
		t.Fatalf("Parse of a document at the cap: %v", err)
	}
	// The order: over the cap and under the wrong key, the length is the
	// refusal, not the signature.
	if _, err := Verify(owner(t).Public(), over, sig); !errors.Is(err, ErrForm) {
		t.Fatalf("over the cap under the wrong key: %v; want the length's refusal", err)
	}
}

// Parse is Verify without the signature, for the one document that has
// none: it is as strict about the form and the rules.
func TestParseIsStrictWithoutASignature(t *testing.T) {
	id := owner(t)
	doc, _, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(doc)
	if err != nil || d.Name != "bob" {
		t.Fatalf("Parse of a good document: %+v, %v", d, err)
	}
	if _, err := Parse([]byte(`{"v":1,"colour":"blue"}`)); !errors.Is(err, ErrForm) {
		t.Fatalf("an unknown field: %v, want ErrForm", err)
	}
	if _, err := Parse(append(append([]byte{}, doc...), '{', '}')); !errors.Is(err, ErrForm) {
		t.Fatalf("trailing data: %v, want ErrForm", err)
	}
	if _, err := Parse([]byte(`{"v":1,"owner":"nobody","issued":"2026-09-22T10:04:00Z","name":"bob","listed":true,"knocks":true}`)); err == nil ||
		err.Error() != "owner is not a fingerprint" {
		t.Fatalf("a rule broken: %v", err)
	}
	if _, err := Parse([]byte(`not json`)); !errors.Is(err, ErrForm) {
		t.Fatalf("not JSON: %v, want ErrForm", err)
	}
}

// The same identity key now signs seven things. A card signature must not
// verify as any of the other six, nor any of them as a card; the allow
// list and the directory, the two documents beside it, are each checked
// in both directions by name.
func TestCardSignatureDomainIsSeparate(t *testing.T) {
	id := owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()
	others := map[string][]byte{
		"token":      append([]byte("ccx-token-v1"), doc...),
		"envelope":   append([]byte("ccx-sig-v1"+pub.Fingerprint()), doc...),
		"stream":     append([]byte("ccx-stream-sig-v1"+pub.Fingerprint()), doc...),
		"directory":  append([]byte("ccx-channels-v1"), doc...),
		"allow list": append([]byte("ccx-allow-v1"), doc...),
		"request":    relayapi.SigningString("PUT", "/v1/mailbox/x/card", 0, "n", doc),
	}
	for name, input := range others {
		if pub.Verify(input, sig) {
			t.Errorf("a card signature verified as a %s signature", name)
		}
		if _, err := Verify(pub, doc, mustSign(t, id, input)); !errors.Is(err, ErrSignature) {
			t.Errorf("a %s signature verified as a card signature: %v", name, err)
		}
	}
	// The domain is a wire constant, pinned here from outside its
	// definition, so a rename in the package is a failing test.
	if string(signingBytes(nil)) != "ccx-card-v1" {
		t.Fatalf("the card domain is %q, want ccx-card-v1", signingBytes(nil))
	}
}

// TestACardCarriesNoSections: a grant document is strict, and stays so under mixed versions
// (D39). The door for what an older build does not understand is on
// message content and the API alone; here a sections field is an unknown
// field like any other, refused under a good signature, so it is never
// opened by habit. A change to a card is a new format version instead.
func TestACardCarriesNoSections(t *testing.T) {
	id := owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(id.Public(), doc, sig); err != nil {
		t.Fatalf("the document whole: %v; want it taken", err)
	}
	for _, sections := range []string{`[]`, `[{"name":"later","critical":false,"data":0}]`} {
		with := append([]byte(`{"sections":`+sections+`,`), doc[1:]...)
		_, err := Verify(id.Public(), with, mustSign(t, id, signingBytes(with)))
		if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), `unknown field "sections"`) {
			t.Errorf("sections %s: %v; want ErrForm naming the field", sections, err)
		}
	}
}

// TestACardRefusesEveryTrailingByte: a strict decode refused trailing data except the two bytes
// json.Decoder.More does not see, a closing brace and a closing bracket
// (ruling 56). The document is taken whole; with each of those after it,
// and with a plain stray byte, it is refused in this reader's own words.
func TestACardRefusesEveryTrailingByte(t *testing.T) {
	id := owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(id.Public(), doc, sig); err != nil {
		t.Fatalf("the document whole: %v", err)
	}
	for _, tail := range []string{"}", "]", "x"} {
		with := append(append([]byte{}, doc...), tail...)
		_, err := Verify(id.Public(), with, mustSign(t, id, signingBytes(with)))
		if tail == "x" {
			if !errors.Is(err, ErrForm) {
				t.Errorf("%q after the document: %v; want ErrForm", tail, err)
			}
			continue
		}
		if !errors.Is(err, ErrForm) || err.Error() != "card is malformed: trailing data after the document" {
			t.Errorf("%q after the document: %v; want the trailing-data sentence", tail, err)
		}
	}
}
