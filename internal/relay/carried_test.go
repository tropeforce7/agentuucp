package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// postBytes sends a body exactly as given, signed over those bytes, so that
// one that is not JSON at all reaches the route rather than the test's own
// encoder.
func (h *harness) postBytes(id *identity.Identity, path string, body []byte) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest("POST", h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := relayapi.SignRequest(id, req, body); err != nil {
		h.t.Fatal(err)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// The outer envelope has two definitions, the recipient's in envelope and
// the relay's in relayapi, so that the relay need not import the package
// that opens what it carries. They are one shape: the same fields under the
// same tags in the same order, and one value marshals to the same bytes
// through either. A field added to one and not the other is a fifth field
// the relays on a path would refuse, so this is what says which parted.
func TestTheCarriedEnvelopeIsTheEnvelope(t *testing.T) {
	type field struct{ name, tag, kind string }
	shape := func(rt reflect.Type) []field {
		var out []field
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			out = append(out, field{f.Name, f.Tag.Get("json"), f.Type.String()})
		}
		return out
	}
	env, carried := shape(reflect.TypeFor[envelope.Envelope]()), shape(reflect.TypeFor[relayapi.Carried]())
	for i := 0; i < len(env) || i < len(carried); i++ {
		switch {
		case i >= len(env):
			t.Errorf("relayapi.Carried has field %+v, which envelope.Envelope does not", carried[i])
		case i >= len(carried):
			t.Errorf("envelope.Envelope has field %+v, which relayapi.Carried does not", env[i])
		case env[i] != carried[i]:
			t.Errorf("field %d parted: envelope.Envelope has %+v, relayapi.Carried %+v", i, env[i], carried[i])
		}
	}
	for _, ch := range []string{"", "work"} {
		a, err := json.Marshal(envelope.Envelope{V: 2, To: "to", CT: []byte("ct"), Ch: ch})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(relayapi.Carried{V: 2, To: "to", CT: []byte("ct"), Ch: ch})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("one envelope with ch %q marshals two ways: envelope.Envelope %s, relayapi.Carried %s", ch, a, b)
		}
	}
}

// outer is an outer envelope written by hand, as a sender of another
// version would write it: the relay is given these bytes and must store
// them as they are.
func outer(v, to, ct string) []byte {
	return []byte(`{"v":` + v + `,"to":"` + to + `","ct":"` + ct + `"}`)
}

// refusedEnvelopes is what no route takes, each with the sentence every
// route gives. The version is the two ends' business, but a version below 1
// is no version, and the four fields are frozen.
func refusedEnvelopes(to string) []struct{ name, raw, want string } {
	ct := base64.StdEncoding.EncodeToString([]byte("sealed"))
	return []struct{ name, raw, want string }{
		{"v at MinInt64", string(outer(strconv.FormatInt(math.MinInt64, 10), to, ct)),
			"envelope v is -9223372036854775808; a relay carries any version from 1"},
		{"v at -1", string(outer("-1", to, ct)), "envelope v is -1; a relay carries any version from 1"},
		{"v at 0", string(outer("0", to, ct)), "envelope v is 0; a relay carries any version from 1"},
		{"v left out", `{"to":"` + to + `","ct":"` + ct + `"}`, "envelope v is 0; a relay carries any version from 1"},
		{"v over an int64", string(outer("9223372036854775808", to, ct)),
			"malformed envelope: json: cannot unmarshal number 9223372036854775808 into Go struct field Carried.v of type int"},
		{"v not a whole number", string(outer("1.5", to, ct)),
			"malformed envelope: json: cannot unmarshal number 1.5 into Go struct field Carried.v of type int"},
		{"a fifth field", `{"v":1,"to":"` + to + `","ct":"` + ct + `","sections":[]}`,
			`malformed envelope: json: unknown field "sections"`},
		{"a field in another case", `{"V":1,"to":"` + to + `","ct":"` + ct + `"}`,
			`malformed envelope: key "V" matches the field "v" only by case, in an object at depth 1`},
		{"a field twice", `{"v":1,"v":2,"to":"` + to + `","ct":"` + ct + `"}`,
			`malformed envelope: key "v" appears twice in an object at depth 1`},
		{"trailing data", string(outer("1", to, ct)) + `}`, "malformed envelope: trailing data after the value"},
		{"no ciphertext", string(outer("1", to, "")), "envelope carries no ciphertext"},
		{"to not a fingerprint", string(outer("1", "bob", ct)), "envelope to is not a fingerprint"},
	}
}

// TestThePostAndKnockRoutesCarryAnyVersion: a relay stores an envelope of
// any version from 1, and the bytes it stores are the bytes it was given;
// below 1, a fifth field, a field read two ways, trailing data and an empty
// ciphertext are each refused with the one sentence every route gives, and
// nothing is stored. The post route took an empty ciphertext until this
// commit: an envelope with nothing sealed in it is one nobody can open,
// which the recipient's client could only have acknowledged away.
func TestThePostAndKnockRoutesCarryAnyVersion(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("bob's card: %d %s", status, body)
	}
	fp := bob.Fingerprint()
	for _, route := range []struct {
		name, path, kind string
		taken            int
	}{
		{"post", "/v1/mailbox/" + fp, relayapi.KindEnvelope, http.StatusOK},
		{"knock", "/v1/mailbox/" + fp + "/knock", relayapi.KindKnock, http.StatusOK},
	} {
		latest := func() []byte {
			rows := h.stored(t, fp)
			for i := len(rows) - 1; i >= 0; i-- {
				if rows[i].Kind == route.kind {
					return rows[i].Envelope
				}
			}
			return nil
		}
		for i, v := range []string{"1", "2", "7", strconv.FormatInt(math.MaxInt64, 10)} {
			raw := outer(v, fp, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s %d", route.name, i))))
			status, body := h.postBytes(alice, route.path, raw)
			if status != route.taken {
				t.Fatalf("%s, v %s: %d %s; want it carried", route.name, v, status, body)
			}
			if got := latest(); !bytes.Equal(got, raw) {
				t.Errorf("%s, v %s: stored %s; want the bytes posted, %s", route.name, v, got, raw)
			}
		}
		for _, tc := range refusedEnvelopes(fp) {
			before := len(h.stored(t, fp))
			status, body := h.postBytes(alice, route.path, []byte(tc.raw))
			if status != http.StatusBadRequest || errorText(t, body) != tc.want {
				t.Errorf("%s, %s: %d %s; want 400 %q", route.name, tc.name, status, body, tc.want)
			}
			if after := len(h.stored(t, fp)); after != before {
				t.Errorf("%s, %s: %d rows stored for a refused envelope", route.name, tc.name, after-before)
			}
		}
	}
}

// TestTheForwardRouteCarriesAnyVersion: the route that used to refuse every
// version but its own ("this relay carries 1") queues any from 1 for the
// next hop, and refuses below it with the sentence every route gives.
func TestTheForwardRouteCarriesAnyVersion(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	fp := h.fpOf(t, "bob")
	for i, v := range []string{"1", "2", "7", strconv.FormatInt(math.MaxInt64, 10)} {
		raw := outer(v, fp, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("hop %d", i))))
		status, body := h.postSigned(t, user, "/v1/forward", []byte(fmt.Sprintf(`{"envelope":%s,"path":["bar"],"via":[]}`, raw)))
		if status != http.StatusCreated {
			t.Fatalf("v %s: %d %s; want it queued", v, status, body)
		}
	}
	if n := h.outboundRows(t); n != 4 {
		t.Fatalf("%d rows queued; want the four versions", n)
	}
	for _, tc := range refusedEnvelopes(fp) {
		if tc.name == "trailing data" {
			// The envelope is a value inside a request that has parsed, so
			// nothing can follow it there: the request itself would not be
			// JSON. The post and knock routes, whose body is the envelope,
			// are where trailing data is refused.
			continue
		}
		want := tc.want
		if tc.name == "a field twice" {
			// The request's own strict decode walks every key at every
			// depth, the envelope's among them, so on this route a key
			// given twice is refused as the request, before the envelope
			// is read as one.
			want = `malformed forward request: key "v" appears twice in an object at depth 2`
		}
		status, body := h.postSigned(t, user, "/v1/forward", []byte(fmt.Sprintf(`{"envelope":%s,"path":["bar"],"via":[]}`, tc.raw)))
		if status != http.StatusBadRequest || errorText(t, body) != want {
			t.Errorf("%s: %d %s; want 400 %q", tc.name, status, body, want)
		}
	}
	if n := h.outboundRows(t); n != 4 {
		t.Errorf("%d rows queued after the refusals; want the four versions alone", n)
	}
}

// TestAVersionTwoEnvelopeCrossesTwoRelays: posted at A, carried by A to B and
// by B to C, and delivered at C with the bytes A was given, which is the
// whole of what a relay may do with a version it does not know (D38).
func TestAVersionTwoEnvelopeCrossesTwoRelays(t *testing.T) {
	c := newChain(t)
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")
	env := sealedFor(bob.Fingerprint(), "a version two envelope")
	env.V = 2
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	status, _, body := c.a.forward(alice, request(env, []string{"bar", "baz"}, nil))
	if status != http.StatusCreated {
		t.Fatalf("alice posting a v 2 envelope: %d %s", status, body)
	}
	c.handOn(t, c.a, "bar")
	c.handOn(t, c.b, "baz")
	rows := c.c.stored(t, bob.Fingerprint())
	if len(rows) != 1 {
		t.Fatalf("bob's mailbox at C holds %d rows; want the one envelope", len(rows))
	}
	if !bytes.Equal(rows[0].Envelope, raw) {
		t.Errorf("C stored %s; want the bytes alice posted at A, %s", rows[0].Envelope, raw)
	}
	if rows[0].Via == "" {
		t.Error("the row at C names no relay it came through")
	}
}

// TestLimitCarriedV: the relay's own range for the outer version, held by
// parseCarried on every route. It is 1 and up, with no ceiling, since a
// version is the two ends' business; envelope.Open holds the recipient's
// narrower range on its own row.
func TestLimitCarriedV(t *testing.T) {
	to := ids(t, "bob")[0].Fingerprint()
	ct := base64.StdEncoding.EncodeToString([]byte("sealed"))
	for _, v := range []int64{1, 2, math.MaxInt64 - 1, math.MaxInt64} {
		env, err := parseCarried(outer(strconv.FormatInt(v, 10), to, ct))
		if err != nil || int64(env.V) != v {
			t.Errorf("v %d: %+v, %v; want it carried", v, env, err)
		}
	}
	for _, v := range []int64{0, -1, math.MinInt64 + 1, math.MinInt64} {
		want := "envelope v is " + strconv.FormatInt(v, 10) + "; a relay carries any version from 1"
		if _, err := parseCarried(outer(strconv.FormatInt(v, 10), to, ct)); err == nil || err.Error() != want {
			t.Errorf("v %d: %v; want %q", v, err, want)
		}
	}
	for _, text := range []string{"9223372036854775808", "-9223372036854775809", "1e3", "1.0", `"1"`, "+1", "-0"} {
		_, err := parseCarried(outer(text, to, ct))
		if text == "-0" {
			// JSON's -0 is the integer zero, which is no version.
			if err == nil || err.Error() != "envelope v is 0; a relay carries any version from 1" {
				t.Errorf("v %s: %v; want it read as 0 and refused", text, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("v %s: carried; want it refused", text)
		}
	}
}

// R4: what a listing page says in its sections comes out of the page's own
// budget, so a full page and its sections together are never over what an
// older client holds. pageBudget is max_bytes less the sections as this
// build encodes them, never below one, and no budget stays none.
func TestAListingPagesBudgetCountsItsSections(t *testing.T) {
	sections := []wire.Section{{Name: "later", Data: json.RawMessage(`"` + strings.Repeat("a", 100) + `"`)}}
	encoded, err := json.Marshal(sections)
	if err != nil {
		t.Fatal(err)
	}
	n := int64(len(encoded))
	for _, tc := range []struct {
		maxBytes, want int64
		sections       []wire.Section
	}{
		{1000, 1000, nil},
		{1000, 1000 - n, sections},
		{n + 1, 1, sections},
		{n, 1, sections},
		{0, 0, sections},
	} {
		if got := pageBudget(tc.maxBytes, tc.sections); got != tc.want {
			t.Errorf("pageBudget(%d, %d sections) = %d, want %d", tc.maxBytes, len(tc.sections), got, tc.want)
		}
	}

	// Through a listing: two envelopes that fit max_bytes exactly fit one
	// page, and with the sections said beside them the second is the
	// next page's.
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	for _, text := range []string{"one", "two"} {
		if status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sealed(t, alice, bob.Public(), text), nil); status != http.StatusOK {
			t.Fatalf("post: %d %s", status, body)
		}
	}
	rows := h.stored(t, bob.Fingerprint())
	if len(rows) != 2 {
		t.Fatalf("stored %d", len(rows))
	}
	h.server.cfg.MaxBytes = rows[0].Size + rows[1].Size
	page, _, err := h.server.look(bob.Fingerprint(), 0, 10, false, nil)
	if err != nil || len(page.Messages) != 2 || len(page.Sections.Sections) != 0 {
		t.Fatalf("without sections: %d messages, %v", len(page.Messages), err)
	}
	listingSections = sections
	t.Cleanup(func() { listingSections = nil })
	page, _, err = h.server.look(bob.Fingerprint(), 0, 10, false, nil)
	if err != nil || len(page.Messages) != 1 || len(page.Sections.Sections) != 1 {
		t.Fatalf("with sections: %d messages and %d sections, %v; want the second message left for the next page",
			len(page.Messages), len(page.Sections.Sections), err)
	}
}

// R9: a page follows max_bytes and never passes relayapi.MaxPageBytes, so
// that every page but one whose lone first row is over it fits a client's
// MaxListingHold, whatever the relay's max_bytes. On a relay at the
// ceiling, a mailbox of legal envelopes of about 7 MiB each, more than
// MaxPageBytes in all, is listed a page at a time: each page's envelopes
// total at most MaxPageBytes and the next row would have passed it, and
// the answer, rows and fields, is under MaxListingHold. A lone first row
// over MaxPageBytes is still listed, alone.
func TestAListingPageIsCutAtMaxPageBytes(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: relayapi.MaxBytesCeiling})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	env := sealed(t, alice, bob.Public(), strings.Repeat("m", 5<<20))
	const count = 12
	for range count {
		if _, err := h.store.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", env, Quotas{}, Forwarded{}); err != nil {
			t.Fatal(err)
		}
	}
	if total := int64(count * len(env)); total <= relayapi.MaxPageBytes {
		t.Fatalf("the mailbox holds %d bytes; the test needs more than MaxPageBytes, %d", total, relayapi.MaxPageBytes)
	}
	var after int64
	listed := 0
	for listed < count {
		status, body := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?after="+strconv.FormatInt(after, 10)+"&limit=200", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("listing after %d: %d %s", after, status, body)
		}
		if int64(len(body)) >= relayapi.MaxListingHold {
			t.Fatalf("a page of %d bytes; want it under MaxListingHold, %d", len(body), relayapi.MaxListingHold)
		}
		var page relayapi.ListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Messages) == 0 {
			t.Fatalf("an empty page after %d with %d of %d listed", after, listed, count)
		}
		var inline int64
		for _, m := range page.Messages {
			inline += int64(len(m.Envelope))
		}
		if inline > relayapi.MaxPageBytes {
			t.Fatalf("a page of %d envelopes, %d bytes; want at most MaxPageBytes, %d", len(page.Messages), inline, relayapi.MaxPageBytes)
		}
		listed += len(page.Messages)
		if listed < count && inline+int64(len(env)) <= relayapi.MaxPageBytes {
			t.Fatalf("a page of %d bytes ended with room for the next row of %d under MaxPageBytes", inline, len(env))
		}
		after = page.Messages[len(page.Messages)-1].ID
	}
	if listed != count {
		t.Fatalf("listed %d rows; want %d", listed, count)
	}

	// A lone first row over MaxPageBytes, as one posted under a large
	// max_bytes is, is listed alone; the row after it is the next page's.
	big := sealed(t, alice, carol.Public(), strings.Repeat("b", 49<<20))
	if int64(len(big)) <= relayapi.MaxPageBytes {
		t.Fatalf("the big envelope is %d bytes; the test needs it over MaxPageBytes", len(big))
	}
	small := sealed(t, alice, carol.Public(), "small")
	for _, raw := range [][]byte{big, small} {
		if _, err := h.store.Put(carol.Fingerprint(), "default", relayapi.KindEnvelope, "", raw, Quotas{}, Forwarded{}); err != nil {
			t.Fatal(err)
		}
	}
	page, _, err := h.server.look(carol.Fingerprint(), 0, 200, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Messages) != 1 || len(page.Messages[0].Envelope) != len(big) {
		t.Fatalf("a lone first row over MaxPageBytes: %d rows; want it listed alone", len(page.Messages))
	}
}
