package store

import (
	"errors"
	"strings"
	"testing"
)

// The address rule. A bang path names the relays a message goes by way of,
// nearest first, and the recipient at the end: "bar!baz!bob". Every name is
// relative to the relay reading it, so there is no global namespace and
// nothing here resolves anything — the rule is about the shape of an address
// and nothing else.
//
// It lives in this package because both ends run it: the relay on every
// forward request, `auu send` before anything is sealed. Two copies would be
// two rules, and the one that mattered would be whichever ran second.

func TestSplitAddressSeparatesTheRelaysFromTheRecipient(t *testing.T) {
	for _, tc := range []struct {
		address string
		path    []string
		peer    string
	}{
		{"bob", nil, "bob"},
		{"bar!bob", []string{"bar"}, "bob"},
		{"bar!baz!bob", []string{"bar", "baz"}, "bob"},
		// Nothing is validated here, so the shapes a person mistypes come
		// back as they are for the rule to refuse with a sentence about
		// names rather than about splitting.
		{"bar!!bob", []string{"bar", ""}, "bob"},
		{"!bob", []string{""}, "bob"},
		{"bar!", []string{"bar"}, ""},
		{"", nil, ""},
	} {
		path, peer := SplitAddress(tc.address)
		if peer != tc.peer {
			t.Errorf("%q: peer %q, want %q", tc.address, peer, tc.peer)
		}
		if strings.Join(path, "!") != strings.Join(tc.path, "!") || len(path) != len(tc.path) {
			t.Errorf("%q: path %q, want %q", tc.address, path, tc.path)
		}
		// And the two halves are one: what a path joins back to is what it
		// was, so a record that keeps the join says the address.
		if len(tc.path) > 0 && JoinAddress(path)+"!"+peer != tc.address {
			t.Errorf("%q does not survive a round trip: %q", tc.address, JoinAddress(path)+"!"+peer)
		}
	}
}

func TestAnAddressNamesEachRelayOnceAndNoMoreThanItsCeiling(t *testing.T) {
	for _, tc := range []struct {
		name string
		path []string
		via  []string
		hops int64
		want string
	}{
		{"an ordinary address", []string{"bar", "baz"}, nil, 8, ""},
		{"the hops so far count too", []string{"bar"}, []string{"one", "two"}, 8, ""},
		{"exactly at the ceiling", []string{"a", "b", "c", "d"}, nil, 4, ""},
		{"one over", []string{"a", "b", "c", "d", "e"}, nil, 4, "at most 4"},
		// The count is over both lists together, because what the ceiling
		// is about is how far one address reaches, not how far it has left.
		{"one over across the two", []string{"a", "b"}, []string{"c"}, 2, "names 3 relays"},
		{"a relay named twice", []string{"bar", "bar"}, nil, 8, "named once"},
		{"named twice, folded", []string{"bar", "BAR"}, nil, 8, "named once"},
		{"named twice across the two", []string{"bar"}, []string{"Bar"}, 8, "named once"},
		{"a name that is not one", []string{"b ar"}, nil, 8, "relay name"},
		{"an empty name", []string{""}, nil, 8, "relay name"},
		{"the reserved word", []string{"self"}, nil, 8, "relay name"},
		{"a device name on Windows", []string{"con"}, nil, 8, "device name"},
		{"nothing at all", nil, nil, 8, ""},
		// A ceiling of zero admits no relays, which is what a caller that
		// clamped a zero setting would pass; the rule says so rather than
		// admitting everything.
		{"a ceiling of none", []string{"bar"}, nil, 0, "at most 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAddress(tc.path, tc.via, tc.hops)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted; want a refusal with %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v; want a sentence with %q", err, tc.want)
			}
		})
	}
}

// TestOnlyTheCeilingsRefusalIsTheCallersToFinish: the caller names what set
// the ceiling, because the two callers set it differently — a relay from its
// own courier.max_hops, a terminal from the protocol's — and neither should
// print the other's reason.
func TestOnlyTheCeilingsRefusalIsTheCallersToFinish(t *testing.T) {
	err := CheckAddress([]string{"a", "b"}, nil, 1)
	if !errors.Is(err, ErrAddressHops) {
		t.Errorf("the ceiling's refusal is %v, which a caller cannot tell from the others", err)
	}
	// The sentence ends where the caller's begins: no full stop, no
	// bracket, nothing the caller would have to strip.
	if got := err.Error(); !strings.HasSuffix(got, "at most 1") {
		t.Errorf("%q does not end ready for the caller's clause", got)
	}
	for _, other := range []error{
		CheckAddress([]string{"bar", "bar"}, nil, 8),
		CheckAddress([]string{"self"}, nil, 8),
	} {
		if errors.Is(other, ErrAddressHops) {
			t.Errorf("%v is marked as the ceiling's refusal", other)
		}
	}
}
