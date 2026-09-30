package message

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// carried signs a real vouch by one new identity for another, for the
// bodies below to carry.
func carried(t *testing.T) Carried {
	t.Helper()
	v, err := identity.Generate("v")
	if err != nil {
		t.Fatal(err)
	}
	x, err := identity.Generate("x")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	doc, sig, err := vouch.Sign(v, &vouch.Document{Subject: x.Fingerprint(), Bundle: x.Public().Bundle(),
		Name: "x", Issued: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	return Carried{Document: doc, Signature: sig}
}

const aFingerprint = "4c1d000000000000000000000000000000000000000000000000000000000000"

// Each of the three vouch fields belongs to one type and is refused by
// name on every other, at Validate on both ends and at ValidShape, which
// Load runs on a record read back; and each of the two new types is held
// to its own rule: a vouch message carries its vouch and answers nothing,
// a vouch question names a fingerprint and answers nothing, and a knock
// carries at most MaxKnockVouches vouches, each of a vouch's shape.
func TestTheVouchFieldsAreHeldToTheirTypes(t *testing.T) {
	c := carried(t)
	a, err := NewAttachment("a.txt", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	vouchBody := func() Body {
		cc := c
		return Body{Type: TypeVouch, Thread: knockThread, Subject: "vouch for x", Vouch: &cc}
	}
	askBody := func() Body {
		return Body{Type: TypeVouchAsk, Thread: knockThread, Subject: "do you trust 4c1d…", About: aFingerprint}
	}
	knockWith := func(n int) Body {
		b := goodKnock()
		for i := 0; i < n; i++ {
			b.Vouches = append(b.Vouches, c)
		}
		return b
	}
	plain := func(typ string) Body { return Body{Type: typ, Thread: knockThread, Text: "hello"} }

	for _, tc := range []struct {
		name string
		body Body
		want string
	}{
		{"a vouch message", vouchBody(), ""},
		{"a vouch question", askBody(), ""},
		{"a knock with no vouch", knockWith(0), ""},
		{"a knock with four vouches", knockWith(4), ""},
		{"a knock with five vouches", knockWith(5), "message: a knock carries 5 vouches; at most 4"},

		{"a vouch message with no vouch", func() Body { b := vouchBody(); b.Vouch = nil; return b }(), "message: a vouch message carries the vouch"},
		{"a vouch message answering", func() Body { b := vouchBody(); b.InReplyTo = knockThread; return b }(), "message: a vouch message opens a thread and answers nothing"},
		{"a vouch message with a file", func() Body { b := vouchBody(); b.Attachments = []Attachment{a}; return b }(), "message: a vouch message carries no attachment"},
		{"a vouch whose document does not parse", func() Body {
			b := vouchBody()
			b.Vouch.Document = []byte(`{"v":1}`)
			return b
		}(), "message: the vouch it carries: voucher is not a fingerprint"},
		{"a vouch whose document is not JSON", func() Body {
			b := vouchBody()
			b.Vouch.Document = []byte("not a vouch")
			return b
		}(), "message: the vouch it carries: vouch is malformed"},
		{"a vouch with no signature", func() Body { b := vouchBody(); b.Vouch.Signature = nil; return b }(), "message: the vouch it carries has no signature"},

		{"a question about nothing", func() Body { b := askBody(); b.About = ""; return b }(), "message: a vouch question's about is not a fingerprint"},
		{"a question about a short id", func() Body { b := askBody(); b.About = aFingerprint[:16]; return b }(), "message: a vouch question's about is not a fingerprint"},
		{"a question answering", func() Body { b := askBody(); b.InReplyTo = knockThread; return b }(), "message: a vouch question opens a thread and answers nothing"},
		{"a question with a file", func() Body { b := askBody(); b.Attachments = []Attachment{a}; return b }(), "message: a vouch question carries no attachment"},

		{"a knock whose vouch does not parse", func() Body {
			b := knockWith(2)
			b.Vouches[1] = Carried{Document: []byte("{}"), Signature: []byte{1}}
			return b
		}(), "message: vouch 2: v is 0; this build reads 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for path, err := range map[string]error{"Validate": tc.body.Validate(), "ValidShape": tc.body.ValidShape()} {
				switch {
				case tc.want == "" && err != nil:
					t.Errorf("%s refused it: %v", path, err)
				case tc.want != "" && (err == nil || !strings.HasPrefix(err.Error(), tc.want)):
					t.Errorf("%s: %v; want %q", path, err, tc.want)
				}
			}
		})
	}

	// Each field on each type it does not belong to, refused by name.
	for _, typ := range []string{TypeAsk, TypeReply, TypeNote, TypeAck, TypeKnock, TypeVouch, TypeVouchAsk} {
		for _, f := range []struct {
			field string
			owner string
			set   func(b *Body)
			want  string
		}{
			{"vouch", TypeVouch, func(b *Body) { cc := c; b.Vouch = &cc }, "message: vouch is a vouch message's alone"},
			{"about", TypeVouchAsk, func(b *Body) { b.About = aFingerprint }, "message: about is a vouch question's alone"},
			{"vouches", TypeKnock, func(b *Body) { b.Vouches = []Carried{c} }, "message: vouches are a knock's alone"},
		} {
			if typ == f.owner {
				continue
			}
			var b Body
			switch typ {
			case TypeKnock:
				b = goodKnock()
			case TypeVouch:
				b = vouchBody()
			case TypeVouchAsk:
				b = askBody()
			default:
				b = plain(typ)
			}
			f.set(&b)
			for path, err := range map[string]error{"Validate": b.Validate(), "ValidShape": b.ValidShape()} {
				if err == nil || err.Error() != f.want {
					t.Errorf("%s on a %s, at %s: %v; want %q", f.field, typ, path, err, f.want)
				}
			}
		}
	}
}

// A count field is a loop bound: the vouches a knock carries are counted
// before any of them is parsed, so a knock that names ten thousand is
// refused by the count with no document parsed and nothing allocated in
// proportion to the documents. A JSON array states no length, so the
// length a sender can claim is the bytes it sends, which the relay's
// knock cap bounds before the envelope is opened; this is the check that
// runs after that.
func TestAKnocksVouchesAreCountedBeforeTheyAreRead(t *testing.T) {
	c := carried(t)
	b := goodKnock()
	b.Vouches = make([]Carried, 10000)
	for i := range b.Vouches {
		b.Vouches[i] = c
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := b.Validate()
	runtime.ReadMemStats(&after)
	if err == nil || err.Error() != "message: a knock carries 10000 vouches; at most 4" {
		t.Fatalf("got %v", err)
	}
	// One vouch parsed costs a few kilobytes; ten thousand would be tens
	// of megabytes. The refusal parses none.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<10 {
		t.Errorf("refusing the count allocated %d bytes; the documents were read before the count", grew)
	}
}

// The new fields are the other rule of the wire's: fields a sender may
// leave out, absent unless their type carries them. The zero value
// marshals none of them, and a Carried marshals both of its keys.
func TestTheVouchFieldsAreLeftOutWhenEmpty(t *testing.T) {
	out, err := json.Marshal(Body{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"vouch"`, `"about"`, `"vouches"`} {
		if strings.Contains(string(out), key) {
			t.Errorf("the zero body writes %s: %s", key, out)
		}
	}
	out, err = json.Marshal(Carried{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"document":null,"signature":null}` {
		t.Errorf("the zero Carried marshals as %s", out)
	}
}
