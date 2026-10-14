package channels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestSignWritesTheOldestVersionThatSaysWhatItMeans: a writer uses the
// oldest format that says what the document means. A directory with no
// rule signs as version 1 whatever the caller set, and marshals byte for
// byte as a version 1 directory did before the rules were added; one with
// any rule on any channel signs as version 2 whatever the caller set; and
// the version signed is written back, as the owner is.
func TestSignWritesTheOldestVersionThatSaysWhatItMeans(t *testing.T) {
	id := owner(t)

	// The channel as it was before version 2, for the bytes a version 1
	// directory has always had.
	type channelV1 struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		NotBefore   *time.Time `json:"not_before,omitempty"`
		NotAfter    *time.Time `json:"not_after,omitempty"`
	}
	type directoryV1 struct {
		V        int         `json:"v"`
		Owner    string      `json:"owner"`
		Issued   time.Time   `json:"issued,omitzero"`
		Channels []channelV1 `json:"channels"`
	}
	for _, callerV := range []int{0, Version1, Version2, 3, -1, math.MaxInt} {
		d := base(id)
		d.V = callerV
		doc, sig, err := Sign(id, d)
		if err != nil {
			t.Fatalf("no rule, the caller's v %d: %v", callerV, err)
		}
		if d.V != Version1 {
			t.Errorf("no rule, the caller's v %d: written back as %d; want 1", callerV, d.V)
		}
		old := directoryV1{V: 1, Owner: id.Fingerprint(), Issued: d.Issued}
		for _, ch := range d.Channels {
			old.Channels = append(old.Channels, channelV1{ch.Name, ch.Description, ch.NotBefore, ch.NotAfter})
		}
		want, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(doc, want) {
			t.Errorf("no rule, the caller's v %d: signed\n%s\nwant the version 1 bytes\n%s", callerV, doc, want)
		}
		if got, err := Verify(id.Public(), doc, sig); err != nil || got.V != Version1 {
			t.Errorf("no rule, the caller's v %d: verified as %+v, %v", callerV, got, err)
		}
	}

	for _, rule := range []struct {
		name, field string
		set         func(*Channel)
	}{
		{"max_bytes", `"max_bytes":1`, func(ch *Channel) { ch.MaxBytes = 1 }},
		{"no_streams", `"no_streams":true`, func(ch *Channel) { ch.NoStreams = true }},
		{"no_forwards", `"no_forwards":true`, func(ch *Channel) { ch.NoForwards = true }},
	} {
		for which := range base(id).Channels {
			for _, callerV := range []int{0, Version1, Version2, 3} {
				d := base(id)
				d.V = callerV
				rule.set(&d.Channels[which])
				doc, sig, err := Sign(id, d)
				if err != nil {
					t.Fatalf("%s on channel %d, the caller's v %d: %v", rule.name, which, callerV, err)
				}
				if d.V != Version2 {
					t.Errorf("%s on channel %d, the caller's v %d: written back as %d; want 2", rule.name, which, callerV, d.V)
				}
				if !strings.HasPrefix(string(doc), `{"v":2,`) || strings.Count(string(doc), rule.field) != 1 {
					t.Errorf("%s on channel %d: signed\n%s\nwant v 2 and %s once", rule.name, which, doc, rule.field)
				}
				if got, err := Verify(id.Public(), doc, sig); err != nil || got.V != Version2 {
					t.Errorf("%s on channel %d: verified as %+v, %v", rule.name, which, got, err)
				}
			}
		}
	}
}

// TestAChannelTakesWhatItsRuleSays: Takes at the bound and one over, a
// stream and an envelope, forwarded and direct, with and without
// no_streams and no_forwards, each refusal with its sentence, and the
// order when more than one rule refuses: streams, then forwards, then the
// size.
func TestAChannelTakesWhatItsRuleSays(t *testing.T) {
	const n = 65536
	over := fmt.Sprintf("takes at most %d bytes on the wire; this message is %d", n, n+1)
	const noStreams, noForwards = "takes no streams", "takes no mail by way of another relay"
	cases := []struct {
		label             string
		ch                Channel
		size              int64
		stream, forwarded bool
		why               string
	}{
		{"no rule, the largest size", Channel{}, math.MaxInt64, true, true, ""},
		{"max_bytes 0 is the relay's own", Channel{MaxBytes: 0}, relayapi.MaxStreamSize, false, false, ""},
		{"an envelope at the bound", Channel{MaxBytes: n}, n, false, false, ""},
		{"an envelope one over", Channel{MaxBytes: n}, n + 1, false, false, over},
		{"a stream at the bound", Channel{MaxBytes: n}, n, true, false, ""},
		{"a stream one over", Channel{MaxBytes: n}, n + 1, true, false, over},
		{"a delivery at the bound", Channel{MaxBytes: n}, n, false, true, ""},
		{"a delivery one over", Channel{MaxBytes: n}, n + 1, false, true, over},
		{"max_bytes 1, one byte", Channel{MaxBytes: 1}, 1, false, false, ""},
		{"max_bytes 1, two bytes", Channel{MaxBytes: 1}, 2, false, false, "takes at most 1 bytes on the wire; this message is 2"},
		{"no_streams, a stream", Channel{NoStreams: true}, 1, true, false, noStreams},
		{"no_streams, an envelope", Channel{NoStreams: true}, math.MaxInt64, false, false, ""},
		{"no_streams, a delivery of an envelope", Channel{NoStreams: true}, 1, false, true, ""},
		{"no_forwards, a delivery", Channel{NoForwards: true}, 1, false, true, noForwards},
		{"no_forwards, a direct post", Channel{NoForwards: true}, 1, false, false, ""},
		{"no_forwards, a direct stream", Channel{NoForwards: true}, 1, true, false, ""},
		{"every rule, a forwarded stream over the size", Channel{MaxBytes: n, NoStreams: true, NoForwards: true}, n + 1, true, true, noStreams},
		{"every rule, a delivery over the size", Channel{MaxBytes: n, NoStreams: true, NoForwards: true}, n + 1, false, true, noForwards},
		{"every rule, a direct envelope over the size", Channel{MaxBytes: n, NoStreams: true, NoForwards: true}, n + 1, false, false, over},
		{"every rule, a direct envelope at the size", Channel{MaxBytes: n, NoStreams: true, NoForwards: true}, n, false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			ok, why := c.ch.Takes(c.size, c.stream, c.forwarded)
			if ok != (c.why == "") || why != c.why {
				t.Fatalf("Takes(%d, %v, %v) = %v, %q; want %v, %q", c.size, c.stream, c.forwarded, ok, why, c.why == "", c.why)
			}
		})
	}
}

// fullDirectory is a directory at every maximum, the one MaxDirectoryBytes'
// comment measures: MaxChannels channels, each name MaxChannelNameBytes of
// "&" but one byte to tell them apart, each description
// MaxChannelDescriptionBytes of "<", both bounds set, every time carried
// to the nanosecond in loc, and every rule at its widest, max_bytes at the
// protocol's ceiling and no_streams and no_forwards true.
func fullDirectory(loc *time.Location) *Directory {
	const tell = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
	at := time.Date(2026, 9, 20, 0, 0, 0, 123456789, loc)
	d := &Directory{Issued: at}
	for i := 0; i < relayapi.MaxChannels; i++ {
		nb, na := at, at.Add(time.Hour)
		d.Channels = append(d.Channels, Channel{
			Name:        strings.Repeat("&", relayapi.MaxChannelNameBytes-1) + tell[i:i+1],
			Description: strings.Repeat("<", relayapi.MaxChannelDescriptionBytes),
			NotBefore:   &nb, NotAfter: &na,
			MaxBytes: relayapi.MaxStreamSize, NoStreams: true, NoForwards: true,
		})
	}
	return d
}

// TestTheDirectoryCapsCommentIsTheMeasurement pins the claim: the figures
// in MaxDirectoryBytes' comment and MaxDocumentBytes' are what this
// client marshals for a directory at every maximum, rules included, so a
// field added or widened without remeasuring fails here. Each figure is
// asserted against the encoder, and the widest is held under the cap.
func TestTheDirectoryCapsCommentIsTheMeasurement(t *testing.T) {
	id := owner(t)
	plus10 := time.FixedZone("+10:00", 10*60*60)
	sign := func(d *Directory) (doc, sig []byte) {
		t.Helper()
		doc, sig, err := Sign(id, d)
		if err != nil {
			t.Fatal(err)
		}
		if d.V != Version2 {
			t.Fatalf("the full directory signed as v %d; want 2", d.V)
		}
		return doc, sig
	}
	utc, _ := sign(fullDirectory(time.UTC))
	full := fullDirectory(plus10)
	compact, sig := sign(full)
	tabbed, err := json.MarshalIndent(full, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	spaced, err := json.MarshalIndent(full, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(relayapi.ChannelsRequest{Document: compact, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	padded, err := json.Marshal(relayapi.ChannelsRequest{Document: bytes.Repeat([]byte(" "), relayapi.MaxDirectoryBytes), Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		what      string
		got, want int
	}{
		{"compact, times on UTC", len(utc), 429_705},
		{"compact, times at +10:00", len(compact), 430_350},
		{"the same, tab-indented", len(tabbed), 432_989},
		{"the same, four spaces", len(spaced), 437_804},
		{"the request carrying the compact one", len(request), 573_918},
		{"the request carrying one padded to the cap", len(padded), 699_170},
	} {
		if m.got != m.want {
			t.Errorf("%s: %d bytes; the comment says %d: remeasure", m.what, m.got, m.want)
		}
	}
	if len(spaced) >= relayapi.MaxDirectoryBytes || len(padded) >= relayapi.MaxDocumentBytes {
		t.Errorf("the widest directory is %d bytes against %d, and a padded request %d against %d",
			len(spaced), relayapi.MaxDirectoryBytes, len(padded), relayapi.MaxDocumentBytes)
	}
	if _, err := Verify(id.Public(), compact, sig); err != nil {
		t.Fatalf("the full directory does not verify: %v", err)
	}
}
