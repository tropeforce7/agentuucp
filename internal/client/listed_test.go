package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// listedEntry is one entry as a relay would serve it, signed by owner
// unless the test spoils it.
func listedEntry(t *testing.T, owner *identity.Identity, listed bool) relayapi.ListedEntry {
	t.Helper()
	doc, sig, err := card.Sign(owner, &card.Document{Issued: time.Now(), Name: owner.Name, Listed: listed})
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.ListedEntry{Bundle: owner.Public().Bundle(), Document: doc, Signature: sig}
}

// byFingerprint sorts identities as the relay lists them.
func byFingerprint(ids []*identity.Identity) []*identity.Identity {
	out := append([]*identity.Identity{}, ids...)
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint() < out[j].Fingerprint() })
	return out
}

// listingRelay is a fake relay whose listing is served page by page from
// the entries given, in the order given, honouring after and limit as
// the real one does unless the test says otherwise.
func listingRelay(t *testing.T, entries []relayapi.ListedEntry, total int64) *httptest.Server {
	t.Helper()
	fps := make([]string, len(entries))
	for i, e := range entries {
		pub, err := identity.ParseBundle(e.Bundle)
		if err != nil {
			fps[i] = ""
			continue
		}
		fps[i] = pub.Fingerprint()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/listed" {
			http.NotFound(w, r)
			return
		}
		after := r.URL.Query().Get("after")
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		page := []relayapi.ListedEntry{}
		for i, e := range entries {
			if fps[i] > after || (fps[i] == "" && after == "") {
				page = append(page, e)
				if len(page) == limit {
					break
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.ListedResponse{Entries: page, Listed: total})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Every entry is verified here and never trusted before: a bundle whose
// fingerprint is not the document's owner, a signature under another key,
// a document that says listed false, a bundle that will not parse, a
// signature blanked, each dropped and counted and the rest kept; the
// count the relay gave is reported. So a row edited in the database
// removes a name and never adds one.
func TestAListingEntryThatDoesNotVerifyIsDroppedAndCounted(t *testing.T) {
	alice, bob, carol, dave, erin, frank, mallory := testIdentity(t, "alice"), testIdentity(t, "bob"), testIdentity(t, "carol"),
		testIdentity(t, "dave"), testIdentity(t, "erin"), testIdentity(t, "frank"), testIdentity(t, "mallory")
	good := listedEntry(t, alice, true)
	// bob's card under mallory's bundle: the owner is bob, the bundle's
	// fingerprint is mallory's.
	wrongBundle := listedEntry(t, bob, true)
	wrongBundle.Bundle = mallory.Public().Bundle()
	// carol's document signed by mallory.
	wrongKey := listedEntry(t, carol, true)
	forged, _ := mallory.Sign(append([]byte("ccx-card-v1"), wrongKey.Document...))
	wrongKey.Signature = forged
	unlisted := listedEntry(t, dave, false)
	badBundle := listedEntry(t, erin, true)
	badBundle.Bundle = []byte("not a bundle")
	blank := listedEntry(t, frank, true)
	blank.Signature = nil
	// The relay serves in the order of the fingerprints of the bundles it
	// holds, which for the wrong-bundle entry is mallory's; the bundle
	// that will not parse is dropped before the order is looked at, and
	// goes first.
	entries := []relayapi.ListedEntry{badBundle, good, wrongBundle, wrongKey, unlisted, blank}
	sort.SliceStable(entries[1:], func(i, j int) bool {
		a, _ := identity.ParseBundle(entries[1+i].Bundle)
		b, _ := identity.ParseBundle(entries[1+j].Bundle)
		return a.Fingerprint() < b.Fingerprint()
	})
	srv := listingRelay(t, entries, 6)
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Listed(context.Background())
	if err != nil {
		t.Fatalf("the listing: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Public.Fingerprint() != alice.Fingerprint() || got.Entries[0].Card.Name != "alice" {
		t.Fatalf("kept %d entries, want alice alone: %+v", len(got.Entries), got.Entries)
	}
	if got.Dropped != 5 || got.Total != 6 {
		t.Fatalf("dropped %d, total %d; want 5 and 6", got.Dropped, got.Total)
	}
}

// The order is the relay's promise and a client refuses an answer that
// breaks it, by name: an entry whose fingerprint is not above the one
// before it, since a listing that could repeat or go backwards could go
// on for ever. A page with more entries than the limit asked for is a
// relay that ignored the parameter, refused by name; a page without
// entries at all is refused by name, [] being what an empty page says.
func TestAListingOutOfOrderOrOverTheLimitIsRefusedByName(t *testing.T) {
	alice, bob := testIdentity(t, "alice"), testIdentity(t, "bob")
	people := byFingerprint([]*identity.Identity{alice, bob})
	first, second := listedEntry(t, people[0], true), listedEntry(t, people[1], true)
	try := func(t *testing.T, answer any) error {
		t.Helper()
		srv := fakeRelay(t, map[string]any{"/v1/listed": answer})
		c, err := New(srv.URL, alice, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Listed(context.Background())
		return err
	}
	refused := func(t *testing.T, answer any, field, want string) {
		t.Helper()
		err := try(t, answer)
		if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), ", "+field+" is not "+want) {
			t.Fatalf("%v; want ErrMalformedAnswer naming %s", err, field)
		}
	}
	// In order: taken.
	if err := try(t, relayapi.ListedResponse{Entries: []relayapi.ListedEntry{first, second}, Listed: 2}); err != nil {
		t.Fatalf("a page in order: %v", err)
	}
	// Backwards, and repeated.
	refused(t, relayapi.ListedResponse{Entries: []relayapi.ListedEntry{second, first}, Listed: 2},
		"an entry's fingerprint", "above the one before it, in the order the relay promised")
	refused(t, relayapi.ListedResponse{Entries: []relayapi.ListedEntry{first, first}, Listed: 2},
		"an entry's fingerprint", "above the one before it, in the order the relay promised")
	// More than the page asked for: one over, and every one of them
	// verifying, since it is the count that is refused.
	many := make([]relayapi.ListedEntry, 0, relayapi.MaxListedLimit+1)
	for i := 0; i < relayapi.MaxListedLimit+1; i++ {
		many = append(many, listedEntry(t, testIdentity(t, "p"+strconv.Itoa(i)), true))
	}
	refused(t, relayapi.ListedResponse{Entries: many, Listed: int64(len(many))}, "entries", "at most the 100 asked for")
	// No entries field.
	refused(t, map[string]any{"listed": 0}, "entries", "present: a page carries its entries, [] past the end")
	// A count below zero.
	refused(t, map[string]any{"entries": []any{}, "listed": -1}, "listed", "a count (zero or more)")
	// And the tag: the zero value names entries as null, which is the
	// absence the check refuses, and listed as 0, a value.
	if zero, _ := json.Marshal(relayapi.ListedResponse{}); !strings.Contains(string(zero), `"entries":null`) || !strings.Contains(string(zero), `"listed":0`) {
		t.Fatalf("the zero answer: %s", zero)
	}
}

// The page loop: a listing longer than one page is fetched page by page
// from the last fingerprint seen, and a page shorter than the limit is
// the last; the relay's count is reported as given. And the whole is
// bounded: a relay that serves full page after full page of distinct
// fingerprints is refused by name once the listing passes what this
// client will hold, rather than fetched without end.
func TestAListingIsFetchedPageByPageAndBounded(t *testing.T) {
	var ids []*identity.Identity
	for i := 0; i < relayapi.MaxListedLimit+5; i++ {
		ids = append(ids, testIdentity(t, "p"+strconv.Itoa(i)))
	}
	ids = byFingerprint(ids)
	entries := make([]relayapi.ListedEntry, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, listedEntry(t, id, true))
	}
	srv := listingRelay(t, entries, int64(len(entries)))
	c, err := New(srv.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Listed(context.Background())
	if err != nil {
		t.Fatalf("two pages: %v", err)
	}
	if len(got.Entries) != len(ids) || got.Dropped != 0 || got.Total != int64(len(ids)) {
		t.Fatalf("got %d entries, dropped %d, total %d; want %d, 0, %d", len(got.Entries), got.Dropped, got.Total, len(ids), len(ids))
	}
	for i, e := range got.Entries {
		if e.Public.Fingerprint() != ids[i].Fingerprint() {
			t.Fatalf("entry %d is not the %dth by fingerprint", i, i)
		}
	}

	// A relay that repeats: the same fingerprint served twice on one page
	// is out of order, and refused at once. The order rule is what bounds
	// a relay that repeats or goes backwards.
	base := listedEntry(t, ids[0], true)
	repeating := fakeRelay(t, map[string]any{"/v1/listed": relayapi.ListedResponse{Entries: []relayapi.ListedEntry{base, base}, Listed: 2}})
	c, err = New(repeating.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Listed(context.Background()); !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "an entry's fingerprint is not above the one before it") {
		t.Fatalf("a relay that repeats: %v; want the order refusal", err)
	}

	// A relay that climbs without end: full page after full page of
	// distinct identities, each entry verifying, which only the ceiling
	// can stop. One page past the ceiling is served, and the listing is
	// refused by name once what is kept passes it; a relay with that
	// many listed identities is not one this client is for.
	if maxListedEntries%relayapi.MaxListedLimit != 0 {
		t.Fatalf("the ceiling %d is not a whole number of pages of %d", maxListedEntries, relayapi.MaxListedLimit)
	}
	pool := make([]*identity.Identity, 0, maxListedEntries+relayapi.MaxListedLimit)
	for i := 0; i < cap(pool); i++ {
		pool = append(pool, testIdentity(t, "q"+strconv.Itoa(i)))
	}
	pool = byFingerprint(pool)
	climbing := make([]relayapi.ListedEntry, 0, len(pool))
	for _, id := range pool {
		climbing = append(climbing, listedEntry(t, id, true))
	}
	srv2 := listingRelay(t, climbing, int64(len(climbing)))
	c, err = New(srv2.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Listed(context.Background())
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "has more than 10000 entries, which is more than this client will read") {
		t.Fatalf("a relay that climbs past the ceiling: %v; want the refusal naming the ceiling", err)
	}
	// And exactly the ceiling is taken whole.
	srv3 := listingRelay(t, climbing[:maxListedEntries], int64(maxListedEntries))
	c, err = New(srv3.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = c.Listed(context.Background())
	if err != nil || len(got.Entries) != maxListedEntries {
		t.Fatalf("a listing at the ceiling: %v, %d entries; want it taken whole", err, len(got.Entries))
	}

	// Entries that do not verify count too: the same climb with every
	// signature blanked is dropped entry by entry, and refused at the
	// ceiling all the same rather than fetched to the end of the relay's
	// patience. Against the rule as it was, only kept entries counted,
	// and a relay of unverifiable entries kept the client fetching.
	blanked := make([]relayapi.ListedEntry, 0, len(climbing))
	for _, e := range climbing {
		blanked = append(blanked, relayapi.ListedEntry{Bundle: e.Bundle, Document: e.Document})
	}
	srv4 := listingRelay(t, blanked, int64(len(blanked)))
	c, err = New(srv4.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Listed(context.Background()); !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "has more than 10000 entries") {
		t.Fatalf("a relay climbing past the ceiling with unverifiable entries: %v; want the refusal naming the ceiling", err)
	}

	// A full page of bundles that will not parse advances nothing: the
	// next page would be the same one, so it is refused by name at once
	// rather than asked for again without end.
	junk := make([]relayapi.ListedEntry, 0, relayapi.MaxListedLimit)
	for i := 0; i < relayapi.MaxListedLimit; i++ {
		junk = append(junk, relayapi.ListedEntry{Bundle: []byte("not a bundle"), Document: []byte("{}"), Signature: []byte("s")})
	}
	var asked atomic.Int64
	jsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.ListedResponse{Entries: junk, Listed: 1 << 30})
	}))
	t.Cleanup(jsrv.Close)
	c, err = New(jsrv.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Listed(context.Background())
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "a full page is not one that can be paged past") {
		t.Fatalf("a full page that advances nothing: %v; want the refusal by name", err)
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("the page was asked for %d times, want once", n)
	}
}

// TestLimitAListingPageIsHeldToItsBytes: a page of the card listing is
// read under relayapi.MaxListedBytes, the most this client holds of one,
// sized to MaxListedLimit entries as this client marshals them and
// measured here — a full page of one-suite bundles and cards at the
// name's cap is written in the constant's comment — and a page one byte
// over the hold is refused by name.
func TestLimitAListingPageIsHeldToItsBytes(t *testing.T) {
	var ids []*identity.Identity
	for i := 0; i < relayapi.MaxListedLimit; i++ {
		ids = append(ids, testIdentity(t, strings.Repeat("a", identity.MaxNameBytes-4)+strconv.Itoa(1000+i)))
	}
	ids = byFingerprint(ids)
	entries := make([]relayapi.ListedEntry, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, listedEntry(t, id, true))
	}
	full := relayapi.ListedResponse{Entries: entries, Listed: int64(len(entries))}
	wire, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a full page of %d entries is %d bytes on the wire; the hold is %d", len(entries), len(wire), relayapi.MaxListedBytes)
	if len(wire) > relayapi.MaxListedBytes || len(wire) < 200_000 {
		t.Fatalf("a full page is %d bytes; want under the hold %d and above 200,000, near the 210,286 the constant's comment records", len(wire), relayapi.MaxListedBytes)
	}
	// The worst page: every card padded to relayapi.MaxCardBytes, which is
	// the most a relay will take at the push, signed as padded. Under the
	// hold by the constant's own arithmetic, and taken whole.
	worst := make([]relayapi.ListedEntry, 0, len(ids))
	for _, id := range ids {
		compact, _, err := card.Sign(id, &card.Document{Issued: time.Now(), Name: id.Name, Listed: true})
		if err != nil {
			t.Fatal(err)
		}
		padded := append([]byte{}, compact[:len(compact)-1]...)
		padded = append(padded, strings.Repeat(" ", relayapi.MaxCardBytes-len(compact))...)
		padded = append(padded, '}')
		sig, err := id.Sign(append([]byte("ccx-card-v1"), padded...))
		if err != nil {
			t.Fatal(err)
		}
		worst = append(worst, relayapi.ListedEntry{Bundle: id.Public().Bundle(), Document: padded, Signature: sig})
	}
	worstWire, _ := json.Marshal(relayapi.ListedResponse{Entries: worst, Listed: int64(len(worst))})
	t.Logf("the worst page, every card at %d bytes, is %d bytes on the wire", relayapi.MaxCardBytes, len(worstWire))
	if len(worstWire) > relayapi.MaxListedBytes {
		t.Fatalf("the worst page is %d bytes, over the hold %d: the hold's arithmetic is wrong", len(worstWire), relayapi.MaxListedBytes)
	}
	wsrv := listingRelay(t, worst, int64(len(worst)))
	wc, err := New(wsrv.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := wc.Listed(context.Background()); err != nil || len(got.Entries) != len(worst) || got.Dropped != 0 {
		t.Fatalf("the worst page: %v; want every padded card taken", err)
	}
	// A card one byte over the cap in the listing is dropped by the
	// reader's own length check, before its signature is verified.
	oversize := append([]byte{}, worst[0].Document[:len(worst[0].Document)-1]...)
	oversize = append(oversize, ' ', '}')
	osig, _ := ids[0].Sign(append([]byte("ccx-card-v1"), oversize...))
	over := append([]relayapi.ListedEntry{}, worst...)
	over[0] = relayapi.ListedEntry{Bundle: worst[0].Bundle, Document: oversize, Signature: osig}
	osrv := listingRelay(t, over, int64(len(over)))
	oc, err := New(osrv.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := oc.Listed(context.Background()); err != nil || len(got.Entries) != len(worst)-1 || got.Dropped != 1 {
		t.Fatalf("a card over its cap in the listing: %v, %d kept, %d dropped; want it dropped", err, len(got.Entries), got.Dropped)
	}
	// Served exactly: taken, the full page and then the empty one after
	// it.
	srv := listingRelay(t, entries, int64(len(entries)))
	c, err := New(srv.URL, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Listed(context.Background())
	if err != nil || len(got.Entries) != len(entries) {
		t.Fatalf("a full page: %v; want it taken whole", err)
	}
	// Padded to the hold: taken; one over: refused by name. The padded
	// page is the first; the page after it is empty.
	empty, _ := json.Marshal(relayapi.ListedResponse{Entries: []relayapi.ListedEntry{}, Listed: int64(len(entries))})
	for _, tc := range []struct {
		n    int
		want string
	}{{relayapi.MaxListedBytes, ""}, {relayapi.MaxListedBytes + 1, "the body is not under 262144 bytes, the most this route holds"}} {
		padded := padJSON(wire, tc.n)
		psrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("after") != "" {
				w.Write(empty)
				return
			}
			w.Write(padded)
		}))
		c, err := New(psrv.URL, ids[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Listed(context.Background())
		psrv.Close()
		if tc.want == "" && err != nil {
			t.Fatalf("a page at the hold, %d bytes: %v; want it taken", len(padded), err)
		}
		if tc.want != "" && (!errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), tc.want)) {
			t.Fatalf("a page one over the hold, %d bytes: %v; want the refusal naming the hold", len(padded), err)
		}
	}
}

// padJSON grows a JSON object to exactly n bytes with spaces before its
// closing brace, which a decoder ignores.
func padJSON(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := append([]byte{}, b[:len(b)-1]...)
	out = append(out, strings.Repeat(" ", n-len(b))...)
	return append(out, '}')
}
