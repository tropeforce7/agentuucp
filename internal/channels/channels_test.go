package channels

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

func at(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// base is a directory that passes every rule, for a test to spoil one way.
func base(id *identity.Identity) *Directory {
	return &Directory{
		V:      Version,
		Owner:  id.Fingerprint(),
		Issued: time.Date(2026, 9, 13, 1, 19, 29, 0, time.UTC),
		Channels: []Channel{
			{Name: Default, Description: "Anything that fits nowhere else"},
			{Name: "bug reports", Description: "One bug per message; attach the log",
				NotBefore: at("2026-10-01T00:00:00Z"), NotAfter: at("2026-12-31T23:59:59Z")},
		},
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
	if got.Owner != id.Fingerprint() || !got.Issued.Equal(d.Issued) || len(got.Channels) != 2 {
		t.Fatalf("the directory did not survive: %+v", got)
	}
	bugs := got.Find("bug reports")
	if bugs == nil || !bugs.NotBefore.Equal(*d.Channels[1].NotBefore) || !bugs.NotAfter.Equal(*d.Channels[1].NotAfter) {
		t.Fatalf("the period did not survive: %+v", bugs)
	}
	if got.Find("nothing") != nil {
		t.Fatal("Find found a channel that is not there")
	}
	// The JSON names are the design's, and a bound that is absent is absent
	// rather than null: an old reader of the document must not see a field
	// it cannot make sense of.
	for _, want := range []string{`"v":1`, `"owner":"`, `"issued":"2026-09-13T01:19:29Z"`, `"channels":[`,
		`"name":"default"`, `"description":"Anything`, `"not_before":"2026-10-01T00:00:00Z"`, `"not_after":"2026-12-31T23:59:59Z"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("document lacks %s:\n%s", want, doc)
		}
	}
	if strings.Contains(string(doc), "null") {
		t.Errorf("an absent bound is written as null:\n%s", doc)
	}
}

// Sign takes the owner from the key, as an enrolment token takes its issuer,
// and it refuses to sign a directory that breaks a rule, so that an invalid
// one never exists to be pushed.
func TestSignFillsTheOwnerAndRefusesAnInvalidDirectory(t *testing.T) {
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
		t.Fatalf("Sign of a directory with no issued: %v", err)
	}
	d = base(id)
	d.Channels[1].Name = "bug/reports"
	if _, _, err := Sign(id, d); err == nil || err.Error() != `channel "bug/reports": name contains "/"` {
		t.Fatalf("Sign of a directory with a bad name: %v", err)
	}
}

// Every rule for a name, one step either side of every edge.
func TestANameIsCheckedAtEveryEdge(t *testing.T) {
	cases := []struct {
		label, name, want string
	}{
		{"64 ASCII bytes", strings.Repeat("a", 64), ""},
		{"65 ASCII bytes", strings.Repeat("a", 65), "name is 65 bytes; at most 64"},
		{"64 bytes of two-byte runes", strings.Repeat("é", 32), ""},
		{"65 bytes of two-byte runes and one", strings.Repeat("é", 32) + "a", "name is 65 bytes; at most 64"},
		{"one byte", "a", ""},
		{"empty", "", "name is empty"},
		{"invalid UTF-8", "bug\xffs", "name is not valid UTF-8"},
		{"U+0007, a control", "bug\aS", "name contains U+0007, a control character"},
		{"U+000A, a line break", "bug\nreports", "name contains U+000A, a control character"},
		{"U+202E, a bidi override", "bug\u202Ereports", "name contains U+202E, a format character"},
		{"U+2060, a word joiner", "bug\u2060reports", "name contains U+2060, a format character"},
		{"U+00AD, a soft hyphen", "bug\u00ADreports", "name contains U+00AD, a format character"},
		{"U+2028, a line separator", "bug\u2028reports", "name contains U+2028, a line separator"},
		{"U+2029, a paragraph separator", "bug\u2029reports", "name contains U+2029, a paragraph separator"},
		{"U+E000, private use", "bug\uE000reports", "name contains U+E000, a private-use character"},
		{"U+F8FF, private use", "bug\uF8FFreports", "name contains U+F8FF, a private-use character"},
		{"leading space", " bugs", "name begins with white space"},
		{"trailing space", "bugs ", "name ends with white space"},
		{"leading no-break space", "\u00A0bugs", "name begins with white space"},
		{"trailing ideographic space", "bugs\u3000", "name ends with white space"},
		{"an inner space", "bug reports", ""},
		{"an inner tab", "bug\treports", "name contains U+0009, a control character"},
		{"a slash", "bug/reports", `name contains "/"`},
		{"a leading slash", "/bugs", `name contains "/"`},
		{"dot", ".", `name is "."`},
		{"dot dot", "..", `name is ".."`},
		{"dot dot dot", "...", "name ends with a dot, which Windows strips"},
		{"a trailing dot", "bugs.", "name ends with a dot, which Windows strips"},
		{"a dot inside", "bug.reports", ""},
		{"a less-than", "bug<reports", `name contains "<", which Windows forbids in a file name`},
		{"a greater-than", "bug>reports", `name contains ">", which Windows forbids in a file name`},
		{"a double quote", `bug"reports`, `name contains "\"", which Windows forbids in a file name`},
		{"a pipe", "bug|reports", `name contains "|", which Windows forbids in a file name`},
		{"a question mark", "bugs?", `name contains "?", which Windows forbids in a file name`},
		{"an asterisk", "bug*", `name contains "*", which Windows forbids in a file name`},
		{"a device stem with a trailing space", "con .reports", "name begins with CON , a device name on Windows"},
		{"a leading dot", ".bugs", ""},
		{"a backslash", `bug\reports`, `name contains "\"`},
		{"a colon", "C:reports", `name contains ":"`},
		{"a device name", "con.reports", "name begins with CON, a device name on Windows"},
		{"a device name alone", "lpt1", "name begins with LPT1, a device name on Windows"},
		{"a device name inside", "console", ""},
		{"the console input device", "conin$", "name begins with CONIN$, a device name on Windows"},
		{"the console output device with an extension", "CONOUT$.log", "name begins with CONOUT$, a device name on Windows"},
		{"the console input device's stem alone", "conin", ""},
		{"non-Latin", "エラー報告", ""},
		{"an emoji", "🐛", ""},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			err := ValidName(c.name)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("%q refused: %v", c.name, err)
			case c.want != "" && err == nil:
				t.Fatalf("%q accepted; want %q", c.name, c.want)
			case c.want != "" && err.Error() != c.want:
				t.Fatalf("%q: got %q, want %q", c.name, err, c.want)
			}
		})
	}
}

// Every rule for a description, one step either side of the edge. The one
// rule a name has and a description does not is white space at the ends.
func TestADescriptionIsCheckedAtEveryEdge(t *testing.T) {
	cases := []struct {
		label, desc, want string
	}{
		{"empty", "", ""},
		{"1024 bytes", strings.Repeat("d", 1024), ""},
		{"1025 bytes", strings.Repeat("d", 1025), "description is 1025 bytes; at most 1024"},
		{"1024 bytes of three-byte runes and one", strings.Repeat("報", 341) + "a", ""},
		{"1025 bytes of three-byte runes and two", strings.Repeat("報", 341) + "ab", "description is 1025 bytes; at most 1024"},
		{"a newline", "one bug\nper message", "description contains U+000A, a control character"},
		{"a carriage return", "one bug\r\nper message", "description contains U+000D, a control character"},
		{"invalid UTF-8", "one \xc3 bug", "description is not valid UTF-8"},
		{"U+202E", "one \u202E bug", "description contains U+202E, a format character"},
		{"U+2028", "one \u2028 bug", "description contains U+2028, a line separator"},
		{"U+2029", "one \u2029 bug", "description contains U+2029, a paragraph separator"},
		{"private use", "one \uE000 bug", "description contains U+E000, a private-use character"},
		{"white space at the ends is kept", "  one bug per message  ", ""},
		{"a slash", "bugs/errors welcome", ""},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			err := ValidDescription(c.desc)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("%q refused: %v", c.desc, err)
			case c.want != "" && err == nil:
				t.Fatalf("%q accepted; want %q", c.desc, c.want)
			case c.want != "" && err.Error() != c.want:
				t.Fatalf("%q: got %q, want %q", c.desc, err, c.want)
			}
		})
	}
}

// Validate's own rules: the version, the owner, issued, the count, names
// unique byte for byte, and a period that runs forwards. The error names the
// channel and the rule.
func TestADirectoryIsCheckedAtEveryEdge(t *testing.T) {
	id := owner(t)
	many := func(n int) []Channel {
		chs := make([]Channel, n)
		for i := range chs {
			chs[i] = Channel{Name: fmt.Sprintf("channel %d", i)}
		}
		return chs
	}
	cases := []struct {
		label string
		spoil func(d *Directory)
		want  string
	}{
		{"as built", func(d *Directory) {}, ""},
		{"v 2", func(d *Directory) { d.V = 2 }, "v is 2; this build reads 1"},
		{"v 0", func(d *Directory) { d.V = 0 }, "v is 0; this build reads 1"},
		{"owner not a fingerprint", func(d *Directory) { d.Owner = "alice" }, "owner is not a fingerprint"},
		{"owner upper case", func(d *Directory) { d.Owner = strings.ToUpper(d.Owner) }, "owner is not a fingerprint"},
		{"issued missing", func(d *Directory) { d.Issued = time.Time{} }, "issued is missing"},
		{"no channels", func(d *Directory) { d.Channels = nil }, ""},
		{"64 channels", func(d *Directory) { d.Channels = many(64) }, ""},
		{"65 channels", func(d *Directory) { d.Channels = many(65) }, "the directory has 65 channels; at most 64"},
		{"a bad name", func(d *Directory) { d.Channels[1].Name = " bug reports" }, `channel " bug reports": name begins with white space`},
		{"a name at 65 bytes", func(d *Directory) { d.Channels[1].Name = strings.Repeat("b", 65) },
			`channel "` + strings.Repeat("b", 65) + `": name is 65 bytes; at most 64`},
		{"a control character, escaped in the sentence", func(d *Directory) { d.Channels[1].Name = "bug\x1b[2J" },
			`channel "bug\x1b[2J": name contains U+001B, a control character`},
		{"a duplicate", func(d *Directory) { d.Channels = append(d.Channels, Channel{Name: "bug reports"}) },
			`channel "bug reports": listed twice`},
		{"a duplicate default", func(d *Directory) { d.Channels = append(d.Channels, Channel{Name: Default}) },
			`channel "default": listed twice`},
		{"a case-differing pair", func(d *Directory) { d.Channels = append(d.Channels, Channel{Name: "Bug reports"}) }, ""},
		{"a description at 1025 bytes", func(d *Directory) { d.Channels[1].Description = strings.Repeat("d", 1025) },
			`channel "bug reports": description is 1025 bytes; at most 1024`},
		{"a description with a newline", func(d *Directory) { d.Channels[0].Description = "one\ntwo" },
			`channel "default": description contains U+000A, a control character`},
		{"not_before after not_after", func(d *Directory) {
			d.Channels[1].NotBefore, d.Channels[1].NotAfter = at("2026-12-31T23:59:59Z"), at("2026-10-01T00:00:00Z")
		}, `channel "bug reports": not_before 2026-12-31T23:59:59Z is after not_after 2026-10-01T00:00:00Z`},
		{"not_before one second after not_after", func(d *Directory) {
			d.Channels[1].NotBefore, d.Channels[1].NotAfter = at("2026-10-01T00:00:01Z"), at("2026-10-01T00:00:00Z")
		}, `channel "bug reports": not_before 2026-10-01T00:00:01Z is after not_after 2026-10-01T00:00:00Z`},
		{"not_before equal to not_after", func(d *Directory) {
			d.Channels[1].NotBefore, d.Channels[1].NotAfter = at("2026-10-01T00:00:00Z"), at("2026-10-01T00:00:00Z")
		}, ""},
		{"a bound in another zone is shown in UTC", func(d *Directory) {
			d.Channels[1].NotBefore, d.Channels[1].NotAfter = at("2026-10-01T10:00:00+10:00"), at("2026-09-30T23:00:00Z")
		}, `channel "bug reports": not_before 2026-10-01T00:00:00Z is after not_after 2026-09-30T23:00:00Z`},
		{"only not_before", func(d *Directory) { d.Channels[1].NotAfter = nil }, ""},
		{"only not_after", func(d *Directory) { d.Channels[1].NotBefore = nil }, ""},
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
func TestAVerifiedDirectoryIsTheSignersAlone(t *testing.T) {
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
		// The description's first letter, so the document still decodes and
		// still validates: only the signature can refuse it.
		i := strings.Index(string(doc), "Anything")
		changed := append([]byte{}, doc...)
		changed[i] = 'a'
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
	t.Run("a signature without the domain", func(t *testing.T) {
		if _, err := Verify(id.Public(), doc, mustSign(t, id, doc)); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
	t.Run("owner not the signer", func(t *testing.T) {
		// Signed by the right key, over a document that names another
		// owner: what a relay would see if a client wrote the field itself.
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
		// And the same document verified with the key it names, which did
		// not sign it.
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
		d.Channels[1].Description = strings.Repeat("d", 1031)
		bad, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(id.Public(), bad, mustSign(t, id, signingBytes(bad)))
		if err == nil || err.Error() != `channel "bug reports": description is 1031 bytes; at most 1024` {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no key", func(t *testing.T) {
		if _, err := Verify(nil, doc, sig); !errors.Is(err, ErrOwner) {
			t.Fatalf("got %v, want ErrOwner", err)
		}
	})
}

// The same identity key now signs six things. A directory signature must
// not verify as any of the other five, nor any of them as a directory.
func TestDirectorySignatureDomainIsSeparate(t *testing.T) {
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
		"allow list": append([]byte("ccx-allow-v1"), doc...),
		"request":    relayapi.SigningString("PUT", "/v1/mailbox/x/channels", 0, "n", doc),
	}
	for name, input := range others {
		if pub.Verify(input, sig) {
			t.Errorf("a directory signature verified as a %s signature", name)
		}
		if _, err := Verify(pub, doc, mustSign(t, id, input)); !errors.Is(err, ErrSignature) {
			t.Errorf("a %s signature verified as a directory signature: %v", name, err)
		}
	}
}

// Both edges inclusive, one second either side, and each bound absent.
func TestOpenAtIsInclusiveAtBothEdges(t *testing.T) {
	open, closed := at("2026-10-01T00:00:00Z"), at("2026-12-31T23:59:59Z")
	cases := []struct {
		label string
		ch    Channel
		now   string
		open  bool
		why   string
	}{
		{"one second before not_before", Channel{NotBefore: open, NotAfter: closed}, "2026-09-30T23:59:59Z", false, "opens 2026-10-01T00:00:00Z"},
		{"at not_before", Channel{NotBefore: open, NotAfter: closed}, "2026-10-01T00:00:00Z", true, ""},
		{"between", Channel{NotBefore: open, NotAfter: closed}, "2026-11-15T12:00:00Z", true, ""},
		{"at not_after", Channel{NotBefore: open, NotAfter: closed}, "2026-12-31T23:59:59Z", true, ""},
		{"one second after not_after", Channel{NotBefore: open, NotAfter: closed}, "2027-01-01T00:00:00Z", false, "closed 2026-12-31T23:59:59Z"},
		{"no not_before, before the other bound", Channel{NotAfter: closed}, "2020-01-01T00:00:00Z", true, ""},
		{"no not_before, after not_after", Channel{NotAfter: closed}, "2027-01-01T00:00:00Z", false, "closed 2026-12-31T23:59:59Z"},
		{"no not_after, before not_before", Channel{NotBefore: open}, "2026-09-30T23:59:59Z", false, "opens 2026-10-01T00:00:00Z"},
		{"no not_after, long after not_before", Channel{NotBefore: open}, "2099-01-01T00:00:00Z", true, ""},
		{"no bounds", Channel{}, "2026-09-13T01:19:29Z", true, ""},
		{"a bound in another zone is said in UTC", Channel{NotBefore: at("2026-10-01T10:00:00+10:00")}, "2026-09-30T23:59:59Z", false, "opens 2026-10-01T00:00:00Z"},
		{"now in another zone, at not_before", Channel{NotBefore: open}, "2026-10-01T10:00:00+10:00", true, ""},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			open, why := c.ch.OpenAt(*at(c.now))
			if open != c.open || why != c.why {
				t.Fatalf("OpenAt(%s) = %v, %q; want %v, %q", c.now, open, why, c.open, c.why)
			}
		})
	}
}

// A document over relayapi.MaxDirectoryBytes is refused by the length
// before the signature is checked, on Verify and on the decode every
// reader goes through: a padded document is what a reader must not spend
// a signature check on, and the refusal names the bytes and the cap. At
// the cap it is taken.
func TestADirectoryIsHeldToItsBytesBeforeTheSignature(t *testing.T) {
	id := owner(t)
	doc, sig, err := Sign(id, base(id))
	if err != nil {
		t.Fatal(err)
	}
	// Padded with spaces inside the object, which a decoder ignores and
	// the signature covers when signed by hand: the bytes are whatever
	// the signer's encoder produced, and this is what a wider one does.
	pad := func(n int) []byte {
		out := append([]byte{}, doc[:len(doc)-1]...)
		out = append(out, strings.Repeat(" ", n-len(doc))...)
		return append(out, '}')
	}
	atCap := pad(relayapi.MaxDirectoryBytes)
	d, err := Verify(id.Public(), atCap, mustSign(t, id, signingBytes(atCap)))
	if err != nil {
		t.Fatalf("a document at the cap, %d bytes: %v", len(atCap), err)
	}
	if len(d.Channels) != len(base(id).Channels) {
		t.Fatalf("a document at the cap came back as %+v", d)
	}
	over := pad(relayapi.MaxDirectoryBytes + 1)
	// Signed by nobody, since the length refuses it before the signature
	// is looked at; the signature is a valid one over other bytes.
	_, err = Verify(id.Public(), over, sig)
	if !errors.Is(err, ErrForm) ||
		err.Error() != fmt.Sprintf("directory is malformed: the directory is %d bytes; at most %d, so send it compact",
			relayapi.MaxDirectoryBytes+1, relayapi.MaxDirectoryBytes) {
		t.Fatalf("a document one over the cap: %v", err)
	}
	// And under a good signature all the same: the length is the refusal.
	if _, err := Verify(id.Public(), over, mustSign(t, id, signingBytes(over))); !errors.Is(err, ErrForm) {
		t.Fatalf("a signed document one over the cap: %v", err)
	}
	// And under the wrong key, where the signature would otherwise refuse.
	if _, err := Verify(owner(t).Public(), over, sig); !errors.Is(err, ErrForm) {
		t.Fatalf("over the cap under the wrong key: %v; want the length's refusal", err)
	}
	// The decode every reader goes through runs the rule too, so a path
	// that reads a document's bytes without a signature has run it.
	if _, err := decode(over); !errors.Is(err, ErrForm) {
		t.Fatalf("decode of a document one over the cap: %v", err)
	}
	if _, err := decode(atCap); err != nil {
		t.Fatalf("decode of a document at the cap: %v", err)
	}
	// And this client never signs one over: Sign runs it after marshalling.
	if err := CheckLength(over); err == nil {
		t.Fatal("CheckLength took a document one over the cap")
	}
}

// TestADirectoryCarriesNoSections: a grant document is strict, and stays so under mixed versions
// (D39). The door for what an older build does not understand is on
// message content and the API alone; here a sections field is an unknown
// field like any other, refused under a good signature, so it is never
// opened by habit. A change to a channel directory is a new format version instead.
func TestADirectoryCarriesNoSections(t *testing.T) {
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

// TestADirectoryRefusesEveryTrailingByte: a strict decode refused trailing data except the two bytes
// json.Decoder.More does not see, a closing brace and a closing bracket
// (ruling 56). The document is taken whole; with each of those after it,
// and with a plain stray byte, it is refused in this reader's own words.
func TestADirectoryRefusesEveryTrailingByte(t *testing.T) {
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
		if !errors.Is(err, ErrForm) || err.Error() != "directory is malformed: trailing data after the document" {
			t.Errorf("%q after the document: %v; want the trailing-data sentence", tail, err)
		}
	}
}
