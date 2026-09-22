package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/tropeforce7/agentuucp/internal/card"
)

// cardFile is this mailbox's card as the owner last pushed it: the truth
// the owner's machine holds, which 'auu card push' signs and pushes to
// every relay, as channels.json is for the directory. It is the card
// unsigned and whole, issued included: issued is the time this machine
// last signed it, which a push signs under again so a relay that already
// holds that issue says so and one holding a newer issue from another
// machine refuses rather than being overwritten. A home with no file has
// pushed no card and is not listed anywhere, taking no knocks.
const cardFile = "card.json"

// Card reads the local card. found is false for a home that has none. A
// file that is there and will not read, or reads to a card that breaks a
// rule, is damaged and names itself: the file is this machine's to fix,
// and a card nobody could sign must not be pushed halfway.
func (s *Store) Card() (d *card.Document, found bool, err error) {
	data, err := os.ReadFile(s.path(cardFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d = &card.Document{}
	if err := json.Unmarshal(data, d); err != nil {
		return nil, false, damaged(s.path(cardFile), "is not valid JSON", err, cardAdvice)
	}
	if err := d.Validate(); err != nil {
		return nil, false, damaged(s.path(cardFile), "holds a card no relay would take", err, cardAdvice)
	}
	return d, true, nil
}

const cardAdvice = "fix it, or delete it and push your card again with 'auu card push'; " +
	"the relays keep what was last pushed until then"

// SetCard writes the local card, whole. The caller has validated and
// signed it; a card that would not sign is not written, so the file never
// holds what the relays would refuse.
func (s *Store) SetCard(d *card.Document) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("card: %w", err)
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(cardFile), append(data, '\n'), fileMode)
}

// CardPath is where the local card lives, for the sentences that name it.
func (s *Store) CardPath() string { return s.path(cardFile) }
