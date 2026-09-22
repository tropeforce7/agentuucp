package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The card listing: every identity on the relay whose card says the relay
// may list them, each entry verified here and never trusted before. The
// relay serves stored bytes and verifies nothing on the way out; the
// reader is the party that must not trust the relay, so it verifies each
// entry with the bundle beside it and drops what fails, counting it. A
// row edited in the relay's database therefore removes a name from what a
// reader sees and never adds one.

// ListedPeer is one entry the reader verified: the identity's public
// bundle, whose fingerprint is the card's owner, and the card the owner
// signed, whose name is a name from the wire — a suggestion at a prompt
// and never a local label until a person accepts it.
type ListedPeer struct {
	Public *identity.Public
	Card   *card.Document
}

// ListedResult is the whole listing, every page fetched: the entries that
// verified, in fingerprint order; how many the relay served that did not
// and were dropped; and how many listed cards the relay said it holds in
// all, its own count, which the reader reports and does not lean on.
type ListedResult struct {
	Entries []ListedPeer
	Dropped int
	Total   int64
}

// maxListedEntries bounds the whole listing, counting every entry the
// relay serves, kept or dropped: a relay that serves full page after full
// page of distinct fingerprints would otherwise have the client fetch and
// hold without end, and one that serves full pages of entries that do not
// verify would have it fetch and verify without end. A relay with more
// listed identities than this is not one this client is for, and the
// refusal says so by name. It is a bound the program chose over a loop,
// which the limit ledger has no kind for; its test stands without a row.
const maxListedEntries = 10000

// Listed fetches the card listing page by page and verifies every entry.
//
// Each page is asked for at relayapi.MaxListedLimit entries from the last
// fingerprint seen, exclusive, and read under relayapi.MaxListedBytes; a
// page with more entries than asked for is a relay that ignored the
// parameter, refused by name, and an entry whose fingerprint is not above
// the last one seen breaks the order the relay promised, and the answer
// is refused whole by name, since a listing that could repeat or go
// backwards could also go on for ever. A page shorter than the limit is
// the last; a full page from which no entry's bundle parsed would be
// asked for again from the same place, and is refused by name instead.
// Every entry served counts toward maxListedEntries, kept or dropped. An
// entry is kept only when its bundle parses, its signature verifies under
// the bundle's key with the bundle's fingerprint as the document's owner,
// the document is under the card's cap, and it says listed; anything
// else is dropped and counted, never an error, since the relay's rows
// are the relay's and a reader refuses what it cannot verify.
func (c *Client) Listed(ctx context.Context) (*ListedResult, error) {
	out := &ListedResult{Entries: []ListedPeer{}}
	after := ""
	seen := 0
	for {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(relayapi.MaxListedLimit))
		if after != "" {
			q.Set("after", after)
		}
		var resp relayapi.ListedResponse
		if err := c.doWithin(ctx, "GET", "/v1/listed?"+q.Encode(), nil, &resp, nil, relayapi.MaxListedBytes); err != nil {
			return nil, err
		}
		if err := c.checkListed(&resp); err != nil {
			return nil, err
		}
		out.Total = resp.Listed
		if seen += len(resp.Entries); seen > maxListedEntries {
			return nil, fmt.Errorf("%w: the card listing from the relay at %s has more than %d entries, which is more than this client will read",
				ErrMalformedAnswer, c.base, maxListedEntries)
		}
		from := after
		for i := range resp.Entries {
			e := &resp.Entries[i]
			pub, err := identity.ParseBundle(e.Bundle)
			if err != nil {
				out.Dropped++
				continue
			}
			fp := pub.Fingerprint()
			// The order first: it is the relay's promise about the page,
			// not about the entry, and an answer that breaks it is refused
			// whole before the entry is looked at.
			if fp <= after {
				return nil, c.malformed("the card listing", "an entry's fingerprint", "above the one before it, in the order the relay promised")
			}
			after = fp
			d, err := card.Verify(pub, e.Document, e.Signature)
			if err != nil || !d.Listed {
				out.Dropped++
				continue
			}
			out.Entries = append(out.Entries, ListedPeer{Public: pub, Card: d})
		}
		if len(resp.Entries) < relayapi.MaxListedLimit {
			return out, nil
		}
		if after == from {
			return nil, c.malformed("the card listing", "a full page", "one that can be paged past: no entry's bundle parsed, so the next page would be this one again")
		}
	}
}

// ErrAmbiguousName is a name two or more listed identities claim.
var ErrAmbiguousName = errors.New("two listed identities claim the name")

// FindListed is one listed identity by the name on its card, byte for
// byte: nil and no error when nobody claims it, ErrAmbiguousName when
// more than one does, since names on a relay are not unique and a
// command that takes one must say to use the short id.
func (r *ListedResult) FindListed(name string) (*ListedPeer, error) {
	var found *ListedPeer
	for i := range r.Entries {
		if r.Entries[i].Card.Name != name {
			continue
		}
		if found != nil {
			return nil, ErrAmbiguousName
		}
		found = &r.Entries[i]
	}
	return found, nil
}
