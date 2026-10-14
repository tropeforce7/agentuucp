package channels

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitDirectoryV: a directory's v is 1 or 2, and Validate refuses
// every other value naming both, the type's extremes among them, as
// ErrVersion, which is what Verify returns for such a document under a
// good signature. A version 1 directory with a rule on a channel is
// refused naming the channel and the field, so no version 1 reader meets
// a rule under a version it reads; a version 2 directory with none is
// taken, since a reader takes what a writer would not write
// (TestSignWritesTheOldestVersionThatSaysWhatItMeans).
func TestLimitDirectoryV(t *testing.T) {
	id := owner(t)
	for _, v := range []int{0, 3, -1, math.MinInt, math.MaxInt} {
		d := base(id)
		d.V = v
		err := d.Validate()
		if want := fmt.Sprintf("v is %d; this build reads 1 and 2", v); err == nil || err.Error() != want || !errors.Is(err, ErrVersion) {
			t.Errorf("v %d: %v; want ErrVersion saying %q", v, err, want)
		}
		doc, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(id.Public(), doc, mustSign(t, id, signingBytes(doc))); !errors.Is(err, ErrVersion) || errors.Is(err, ErrForm) {
			t.Errorf("v %d under a good signature: %v; want ErrVersion alone", v, err)
		}
	}
	for _, v := range []int{Version1, Version2} {
		d := base(id)
		d.V = v
		if err := d.Validate(); err != nil {
			t.Errorf("v %d: %v", v, err)
		}
	}
	// A version this build does not read is ErrVersion whatever fields it
	// carries: v is read before the strict decode, which would otherwise
	// refuse the newer version's field first and call the document
	// malformed. The same field under v 1 and v 2 is the strict decode's
	// ErrForm, as it was.
	doc, err := json.Marshal(base(id))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		v       string
		version bool
	}{{"3", true}, {"-1", true}, {"0", true}, {"9223372036854775807", true}, {"1", false}, {"2", false}} {
		with := strings.Replace(string(doc), `"v":1,`, `"v":`+c.v+`,"colour":"blue",`, 1)
		if with == string(doc) {
			t.Fatal("the document has no v to replace")
		}
		_, err := Verify(id.Public(), []byte(with), mustSign(t, id, signingBytes([]byte(with))))
		switch {
		case c.version && (!errors.Is(err, ErrVersion) || errors.Is(err, ErrForm) ||
			err.Error() != fmt.Sprintf("v is %s; this build reads 1 and 2", c.v)):
			t.Errorf("v %s with a field this build does not know: %v; want ErrVersion alone naming 1 and 2", c.v, err)
		case !c.version && (!errors.Is(err, ErrForm) || errors.Is(err, ErrVersion) || !strings.Contains(err.Error(), `unknown field "colour"`)):
			t.Errorf("v %s with a field this build does not know: %v; want ErrForm naming the field", c.v, err)
		}
	}
	// A v that is not a whole number, and a document with none, are not a
	// version at all: the first is the strict decode's ErrForm, as it was,
	// and the second is v 0, refused by Validate as ErrVersion.
	for _, c := range []struct {
		v, field string
		form     bool
	}{{`"2"`, `"v":"2",`, true}, {"2.5", `"v":2.5,`, true}, {"1e0", `"v":1e0,`, true}, {"null", `"v":null,`, false}, {"absent", ``, false}} {
		with := strings.Replace(string(doc), `"v":1,`, c.field, 1)
		_, err := Verify(id.Public(), []byte(with), mustSign(t, id, signingBytes([]byte(with))))
		if c.form && (!errors.Is(err, ErrForm) || errors.Is(err, ErrVersion)) {
			t.Errorf("v %s: %v; want ErrForm", c.v, err)
		}
		if !c.form && (!errors.Is(err, ErrVersion) || err.Error() != "v is 0; this build reads 1 and 2") {
			t.Errorf("v %s: %v; want ErrVersion as v 0", c.v, err)
		}
	}
	for _, rule := range []struct {
		field string
		set   func(*Channel)
	}{
		{"max_bytes", func(ch *Channel) { ch.MaxBytes = 1 }},
		{"no_streams", func(ch *Channel) { ch.NoStreams = true }},
		{"no_forwards", func(ch *Channel) { ch.NoForwards = true }},
	} {
		d := base(id)
		rule.set(&d.Channels[1])
		want := fmt.Sprintf(`channel "bug reports": %s needs v 2; this directory is v 1`, rule.field)
		if err := d.Validate(); err == nil || err.Error() != want || errors.Is(err, ErrVersion) {
			t.Errorf("v 1 with %s: %v; want %q", rule.field, err, want)
		}
		d.V = Version2
		if err := d.Validate(); err != nil {
			t.Errorf("v 2 with %s: %v", rule.field, err)
		}
	}
}

// TestLimitChannelMaxBytes: a channel's max_bytes is 0, the relay's own
// cap, or 1 to relayapi.MaxStreamSize, the protocol's ceiling, at
// Validate: 0, 1 and the ceiling taken, one over it, -1, MinInt64 and
// MaxInt64 refused naming the channel, the value and the range.
func TestLimitChannelMaxBytes(t *testing.T) {
	id := owner(t)
	for _, c := range []struct {
		n  int64
		ok bool
	}{
		{0, true}, {1, true}, {relayapi.MaxStreamSize, true},
		{relayapi.MaxStreamSize + 1, false}, {-1, false}, {math.MinInt64, false}, {math.MaxInt64, false},
	} {
		d := ruled(id)
		d.Channels[1].MaxBytes = c.n
		err := d.Validate()
		want := fmt.Sprintf(`channel "bug reports": max_bytes is %d; 0 for the relay's own, or 1 to %d`, c.n, relayapi.MaxStreamSize)
		switch {
		case c.ok && err != nil:
			t.Errorf("max_bytes %d: %v; want it taken", c.n, err)
		case !c.ok && (err == nil || err.Error() != want):
			t.Errorf("max_bytes %d: %v; want %q", c.n, err, want)
		}
	}
}

// TestLimitADirectoryDocumentIsCapped: the document's bytes at every edge
// a reader meets — the empty document, which the signature refuses since
// there is nothing for the length to refuse, and the cap, one over it and
// far past it, which the length refuses first and by name.
func TestLimitADirectoryDocumentIsCapped(t *testing.T) {
	id := owner(t)
	for _, n := range []int{relayapi.MaxDirectoryBytes + 1, relayapi.MaxDirectoryBytes * 2, relayapi.MaxDocumentBytes} {
		doc := []byte("{" + strings.Repeat(" ", n-2) + "}")
		_, err := Verify(id.Public(), doc, mustSign(t, id, signingBytes(doc)))
		if !errors.Is(err, ErrForm) ||
			!strings.Contains(err.Error(), fmt.Sprintf("the directory is %d bytes; at most %d", n, relayapi.MaxDirectoryBytes)) {
			t.Errorf("%d bytes: %v; want the length's refusal", n, err)
		}
	}
	if _, err := Verify(id.Public(), nil, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("an empty document: %v; want the signature's refusal", err)
	}
}
