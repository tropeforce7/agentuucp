package store

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/regular"
)

// cardPushedFile records, beside a relay's cursor, when this machine last
// pushed a signed card to it, as allow_pushed does for the allow list. It
// is what lets a fetch tell "the relay never had a card" from "the relay
// has lost the card I pushed": the relay says which state the card is in,
// and this file says whether one was ever pushed from here. One RFC 3339
// line; 'auu card clear' removes it, since a cleared card is one the owner
// meant to say nothing.
const cardPushedFile = "card_pushed"

// CardPushed is when this machine last pushed a signed card to one relay,
// and found false when it never has, or has cleared it since.
func (s *Store) CardPushed(r *Relay) (pushed time.Time, found bool, err error) {
	path := s.relayPath(r, cardPushedFile)
	data, err := regular.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	text := strings.TrimSpace(string(data))
	pushed, err = time.Parse(time.RFC3339, text)
	if err != nil {
		if len(text) > 40 {
			text = text[:40] + "…"
		}
		return time.Time{}, false, damaged(path, fmt.Sprintf("is not a time (%q)", text), nil,
			"delete it, or run 'auu card push', which writes it again; it records only when this machine last pushed its card")
	}
	return pushed, true, nil
}

// SetCardPushed records that a signed card was pushed to one relay now.
func (s *Store) SetCardPushed(r *Relay, at time.Time) error {
	if err := os.MkdirAll(s.relayDir(r.Name), dirMode); err != nil {
		return err
	}
	return writeFileAtomic(s.relayPath(r, cardPushedFile), []byte(at.UTC().Format(time.RFC3339)+"\n"), fileMode)
}

// ClearCardPushed forgets the push, for a card cleared on purpose.
func (s *Store) ClearCardPushed(r *Relay) error {
	err := os.Remove(s.relayPath(r, cardPushedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
