package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// couriersFile records the relays whose couriers this machine admits as
// senders at one relay: the neighbours that may hand mail to it on somebody
// else's behalf.
//
// It is per relay and cannot be anything else. A courier is a relay's own
// identity enrolled as a user of its neighbour, so the fingerprint that
// carries mail to one of this identity's relays means nothing at another, and
// the name beside it is that relay's name for the neighbour and means nothing
// anywhere else either. Two relays in one home therefore have two of these
// files with nothing in common.
//
// A line is a fingerprint, a space, and the name the relay gave it, which is
// the form 'auu allow add --courier' writes. The name is there for the person:
// it is what they typed to admit the courier and what 'rm --courier' matches
// on, and it is kept beside the fingerprint so that 'allow show' can say which
// relay a fingerprint is rather than showing sixty-four characters nobody can
// place.
const couriersFile = "couriers"

const couriersAdvice = "fix it, or delete it and admit the couriers again with " +
	"'auu allow add --courier'; it records which relays may carry mail to you here"

// foldName is how a relay name is compared here, and it is the relay's own
// folding rather than a choice of this package's. The relay keys the home it
// dials from folded and refuses two entries in its couriers file whose names
// differ only in case; this home refuses two relays whose names differ only in
// case; and the reason is the same in all three places, that a name is a
// directory and two filesystems spell Bar and bar as one. One name, one rule,
// and the rule includes how two of them are told apart.
func foldName(name string) string { return strings.ToLower(name) }

// AdmittedCourier is one line of that file: the fingerprint this machine
// admits and the relay name it was admitted under.
type AdmittedCourier struct {
	FP   string
	Name string
}

// Couriers is the couriers this machine admits at that relay, in name order.
// A relay with no file admits none, which is not an error: it is what every
// relay looks like until somebody admits one.
//
// Every line is held to its rule here rather than where it is used, because
// this is the one place the file is read and a fingerprint that reached an
// allow list unchecked would be a document the relay refuses with a sentence
// about a file the person never edited. The fingerprint is held to
// ValidFingerprint and the name to ValidRelayName — the same rule the relay
// runs over the same name when it loads its own couriers file, and the same
// rule this home runs over a relay's name, since it is one name in both
// places. A bad line is refused by name and by line number.
func (s *Store) Couriers(relayName string) ([]AdmittedCourier, error) {
	if err := ValidRelayName(relayName); err != nil {
		return nil, err
	}
	path := filepath.Join(s.relayDir(relayName), couriersFile)
	data, err := regular.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []AdmittedCourier
	seenFP := map[string]bool{}
	seenName := map[string]bool{}
	for n, line := range strings.Split(string(data), "\n") {
		// The same cap the relay holds its own couriers file to and the same
		// one a client holds the route's answer to. This end had none, which
		// made it the only one of the three without a bound on the same list.
		if len(out) >= relayapi.MaxCouriers {
			return nil, damaged(path, fmt.Sprintf("has more than %d couriers, at line %d", relayapi.MaxCouriers, n+1),
				nil, couriersAdvice)
		}
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		fp, name, ok := strings.Cut(text, " ")
		if !ok {
			return nil, damaged(path, fmt.Sprintf("has %q on line %d, which is not a fingerprint and a name", text, n+1),
				nil, couriersAdvice)
		}
		name = strings.TrimSpace(name)
		if !identity.ValidFingerprint(fp) {
			return nil, damaged(path, fmt.Sprintf("has %q on line %d, which is not a fingerprint", fp, n+1),
				nil, couriersAdvice)
		}
		if err := ValidRelayName(name); err != nil {
			return nil, damaged(path, fmt.Sprintf("has %q on line %d, which is not a relay name", name, n+1),
				nil, couriersAdvice)
		}
		// One fingerprint once and one name once, for the reason the relay's
		// own file refuses both: a fingerprint under two names makes 'rm
		// --courier' ambiguous about what it removed, and two fingerprints
		// under one name make the name a person types ambiguous about which
		// relay they meant. Refused rather than resolved in favour of either.
		if seenFP[fp] {
			return nil, damaged(path, fmt.Sprintf("lists the courier %s twice, most recently on line %d", fp, n+1),
				nil, couriersAdvice)
		}
		// Folded, because the relay folds. Its own couriers file refuses two
		// neighbours whose names differ only in case, it keys the home it
		// dials from folded, and this home refuses two relays whose names
		// differ only in case for the same reason — a name is a directory and
		// two filesystems spell Bar and bar as one. Comparing exactly here
		// would let a file hold two names the relay's own loader would refuse,
		// and would leave 'rm --courier bar' removing one and silently leaving
		// the other admitted, which is the ambiguity this check exists to
		// prevent.
		if seenName[foldName(name)] {
			return nil, damaged(path, fmt.Sprintf("lists two couriers under the name %q, the second on line %d", name, n+1),
				nil, couriersAdvice)
		}
		seenFP[fp], seenName[foldName(name)] = true, true
		out = append(out, AdmittedCourier{FP: fp, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// AddCourier admits one more at that relay. Admitting a name already there
// under the same fingerprint is a no-op, so the command is safe to repeat.
//
// A line matching on *either* field is replaced, and both cases are real. The
// same name under a different fingerprint is the courier having been re-keyed;
// the same fingerprint under a different name is the operator having renamed
// that neighbour in their couriers file, which a person meets by admitting it
// again under the name the route now gives.
//
// Replacing on either is not a convenience: keeping both lines would write a
// file that Couriers then refuses to read, since it rejects one fingerprint
// under two names and two fingerprints under one name. So the alternative to
// replacing is a file the person has to repair by hand.
//
// What it costs is worth knowing: after a rename, 'rm --courier' by the old
// name finds nothing, because the old name is no longer in the file. The
// refusal names the name and points at the listing, which is the right place
// to look — the old name is not there either.
func (s *Store) AddCourier(relayName, fp, name string) error {
	if !identity.ValidFingerprint(fp) {
		return fmt.Errorf("courier fingerprint %q: is not a fingerprint", fp)
	}
	if err := ValidRelayName(name); err != nil {
		return err
	}
	have, err := s.Couriers(relayName)
	if err != nil {
		return err
	}
	out := make([]AdmittedCourier, 0, len(have)+1)
	for _, c := range have {
		if foldName(c.Name) == foldName(name) || c.FP == fp {
			continue
		}
		out = append(out, c)
	}
	return s.SetCouriers(relayName, append(out, AdmittedCourier{FP: fp, Name: name}))
}

// RemoveCourier withdraws one by name, and says whether it was there. By name
// and not by fingerprint because the name is what the person admitted it
// under and what they will type to withdraw it.
func (s *Store) RemoveCourier(relayName, name string) (bool, error) {
	have, err := s.Couriers(relayName)
	if err != nil {
		return false, err
	}
	out := make([]AdmittedCourier, 0, len(have))
	found := false
	for _, c := range have {
		if foldName(c.Name) == foldName(name) {
			found = true
			continue
		}
		out = append(out, c)
	}
	if !found {
		return false, nil
	}
	return true, s.SetCouriers(relayName, out)
}

// SetCouriers writes the list, whole, and removes the file when nothing is
// admitted: a relay with no couriers and a relay whose file says none are one
// state, and the absent file is the one that needs no explaining.
func (s *Store) SetCouriers(relayName string, list []AdmittedCourier) error {
	// The rule at the call, as SaveRelay and SetLeftBehind run it: the
	// store's exported edge is a boundary of its own.
	if err := ValidRelayName(relayName); err != nil {
		return err
	}
	path := filepath.Join(s.relayDir(relayName), couriersFile)
	if len(list) == 0 {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sorted := make([]AdmittedCourier, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	// Every rule Couriers reads by, enforced here before a byte is written.
	// This is the store's exported edge and the only door with no caller
	// inside it, and a writer that can produce a file its own reader refuses
	// is worse than an unchecked read: the file stops 'allow push', a knock
	// and the push offered after trusting a sender, all at once, and the
	// person has to repair by hand a file they never wrote. The model this was
	// built on, SetLeftBehind, dedupes for the same reason.
	seenFP := make(map[string]bool, len(sorted))
	seenName := make(map[string]bool, len(sorted))
	for _, c := range sorted {
		if !identity.ValidFingerprint(c.FP) {
			return fmt.Errorf("courier fingerprint %q: is not a fingerprint", c.FP)
		}
		if err := ValidRelayName(c.Name); err != nil {
			return err
		}
		if seenFP[c.FP] {
			return fmt.Errorf("courier %s is listed twice", c.FP)
		}
		if seenName[foldName(c.Name)] {
			return fmt.Errorf("two couriers under the name %q", c.Name)
		}
		seenFP[c.FP], seenName[foldName(c.Name)] = true, true
		fmt.Fprintf(&b, "%s %s\n", c.FP, c.Name)
	}
	if err := os.MkdirAll(s.relayDir(relayName), dirMode); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(b.String()), fileMode)
}
