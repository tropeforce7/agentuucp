package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

func owner(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate("owner")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// fp is a well formed fingerprint that is nobody's, distinct per n, with
// letters in it so that a case test has something to change.
func fp(n int) string {
	return strings.Repeat("ab", 30) + fmt.Sprintf("%04x", n+1)
}

// base is a list that passes every rule, for a test to spoil one way.
func base(id *identity.Identity) *Document {
	return &Document{
		V:       Version,
		Owner:   id.Fingerprint(),
		Issued:  time.Date(2026, 9, 17, 10, 4, 0, 0, time.UTC),
		Senders: []string{fp(1), fp(2)},
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
	if got.Owner != id.Fingerprint() || !got.Issued.Equal(d.Issued) || len(got.Senders) != 2 {
		t.Fatalf("the list did not survive: %+v", got)
	}
	if !got.Admits(fp(1)) || !got.Admits(fp(2)) || got.Admits(fp(3)) {
		t.Fatalf("membership did not survive: %v", got.Senders)
	}
	// The JSON names are the design's.
	for _, want := range []string{`"v":1`, `"owner":"`, `"issued":"2026-09-17T10:04:00Z"`, `"senders":["`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("document lacks %s:\n%s", want, doc)
		}
	}
	if strings.Contains(string(doc), "null") {
		t.Errorf("something is written as null:\n%s", doc)
	}
}

// Sign takes the owner from the key, sorts the senders so two machines with
// one peer list sign the same bytes, writes a list of nobody as [] rather
// than null, and refuses a list that breaks a rule, so that an invalid one
// never exists to be pushed.
func TestSignFillsTheOwnerSortsAndRefusesAnInvalidList(t *testing.T) {
	id, other := owner(t), owner(t)
	d := base(id)
	d.Owner = other.Fingerprint()
	d.V = 0
	d.Senders = []string{fp(2), fp(1)}
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
	if !strings.Contains(string(doc), `"senders":["`+fp(1)+`","`+fp(2)+`"]`) {
		t.Fatalf("the senders are not sorted in the document:\n%s", doc)
	}

	d = base(id)
	d.Senders = nil
	doc, _, err = Sign(id, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), `"senders":[]`) {
		t.Fatalf("a list of nobody is not written as []:\n%s", doc)
	}

	d = base(id)
	d.Issued = time.Time{}
	if _, _, err := Sign(id, d); err == nil || err.Error() != "issued is missing" {
		t.Fatalf("Sign of a list with no issued: %v", err)
	}
	d = base(id)
	d.Senders[1] = "bob"
	if _, _, err := Sign(id, d); err == nil || err.Error() != `sender "bob": is not a fingerprint` {
		t.Fatalf("Sign of a list with a bad sender: %v", err)
	}
	if _, _, err := Sign(nil, base(id)); err == nil {
		t.Fatal("Sign with no identity signed")
	}
}

// Validate's own rules: the version, the owner, issued, the cap at 1000
// and 1001, every sender a fingerprint, none twice, and never the owner.
func TestAListIsCheckedAtEveryEdge(t *testing.T) {
	id := owner(t)
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fp(i)
		}
		return out
	}
	cases := []struct {
		label string
		spoil func(d *Document)
		want  string
	}{
		{"as built", func(d *Document) {}, ""},
		{"v 2", func(d *Document) { d.V = 2 }, "v is 2; this build reads 1"},
		{"v 0", func(d *Document) { d.V = 0 }, "v is 0; this build reads 1"},
		{"owner not a fingerprint", func(d *Document) { d.Owner = "alice" }, "owner is not a fingerprint"},
		{"owner upper case", func(d *Document) { d.Owner = strings.ToUpper(d.Owner) }, "owner is not a fingerprint"},
		{"issued missing", func(d *Document) { d.Issued = time.Time{} }, "issued is missing"},
		{"no senders", func(d *Document) { d.Senders = nil }, ""},
		{"1000 senders", func(d *Document) { d.Senders = many(relayapi.MaxAllowlist) }, ""},
		{"1001 senders", func(d *Document) { d.Senders = many(relayapi.MaxAllowlist + 1) },
			"the allow list has 1001 senders; at most 1000"},
		{"a sender that is not a fingerprint", func(d *Document) { d.Senders[0] = "not-a-fingerprint" },
			`sender "not-a-fingerprint": is not a fingerprint`},
		{"a sender in upper case", func(d *Document) { d.Senders[0] = strings.ToUpper(fp(1)) },
			`sender "` + strings.ToUpper(fp(1)) + `": is not a fingerprint`},
		{"a sender of 63 characters", func(d *Document) { d.Senders[0] = fp(1)[1:] },
			`sender "` + fp(1)[1:] + `": is not a fingerprint`},
		{"a duplicate", func(d *Document) { d.Senders = append(d.Senders, fp(1)) },
			`sender "` + fp(1) + `": listed twice`},
		{"the owner listed", func(d *Document) { d.Senders = append(d.Senders, d.Owner) },
			`sender "` + id.Fingerprint() + `": is the owner, who is always admitted`},
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

// A list of nobody admits everyone; a list of somebody admits them alone.
func TestAnEmptyListAdmitsEveryone(t *testing.T) {
	d := &Document{Senders: nil}
	if !d.Admits(fp(1)) {
		t.Fatal("a list of nobody refused a sender")
	}
	d.Senders = []string{}
	if !d.Admits(fp(1)) {
		t.Fatal("a list written as [] refused a sender")
	}
	d.Senders = []string{fp(1)}
	if !d.Admits(fp(1)) || d.Admits(fp(2)) {
		t.Fatal("a list of one did not admit exactly that one")
	}
}

// Verify's order: the signature, then the form, then the rules, then the
// owner. A document that does not verify is never decoded.
func TestAVerifiedListIsTheSignersAlone(t *testing.T) {
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
		// One hex digit of a sender, so the document still decodes and
		// still validates: only the signature can refuse it.
		i := strings.Index(string(doc), fp(1))
		changed := append([]byte{}, doc...)
		changed[i] = 'f'
		if _, err := Verify(id.Public(), changed, sig); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("one byte of the signature changed", func(t *testing.T) {
		changed := append([]byte{}, sig...)
		changed[len(changed)/2] ^= 0x01
		if _, err := Verify(id.Public(), doc, changed); !errors.Is(err, ErrSignature) {
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
		d.Senders = append(d.Senders, d.Owner)
		bad, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(id.Public(), bad, mustSign(t, id, signingBytes(bad)))
		if err == nil || err.Error() != `sender "`+id.Fingerprint()+`": is the owner, who is always admitted` {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no key", func(t *testing.T) {
		if _, err := Verify(nil, doc, sig); !errors.Is(err, ErrOwner) {
			t.Fatalf("got %v, want ErrOwner", err)
		}
	})
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
	if err != nil || len(d.Senders) != 2 {
		t.Fatalf("Parse of a good document: %+v, %v", d, err)
	}
	if _, err := Parse([]byte(`{"v":1,"colour":"blue"}`)); !errors.Is(err, ErrForm) {
		t.Fatalf("an unknown field: %v, want ErrForm", err)
	}
	if _, err := Parse(append(append([]byte{}, doc...), '{', '}')); !errors.Is(err, ErrForm) {
		t.Fatalf("trailing data: %v, want ErrForm", err)
	}
	if _, err := Parse([]byte(`{"v":1,"owner":"nobody","issued":"2026-09-17T10:04:00Z","senders":[]}`)); err == nil ||
		err.Error() != "owner is not a fingerprint" {
		t.Fatalf("a rule broken: %v", err)
	}
	if _, err := Parse([]byte(`not json`)); !errors.Is(err, ErrForm) {
		t.Fatalf("not JSON: %v, want ErrForm", err)
	}
}

// The same identity key now signs six things. An allow list signature must
// not verify as any of the other five, nor any of them as an allow list.
func TestAllowlistSignatureDomainIsSeparate(t *testing.T) {
	id := owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()
	others := map[string][]byte{
		"token":     append([]byte("ccx-token-v1"), doc...),
		"envelope":  append([]byte("ccx-sig-v1"+pub.Fingerprint()), doc...),
		"stream":    append([]byte("ccx-stream-sig-v1"+pub.Fingerprint()), doc...),
		"directory": append([]byte("ccx-channels-v1"), doc...),
		"request":   relayapi.SigningString("PUT", "/v1/mailbox/x/allow", 0, "n", doc),
	}
	for name, input := range others {
		if pub.Verify(input, sig) {
			t.Errorf("an allow list signature verified as a %s signature", name)
		}
		if _, err := Verify(pub, doc, mustSign(t, id, input)); !errors.Is(err, ErrSignature) {
			t.Errorf("a %s signature verified as an allow list signature: %v", name, err)
		}
	}
}
