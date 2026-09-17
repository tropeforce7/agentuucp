package store

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// allowPushedFile records, beside a relay's cursor, when this machine last
// pushed a signed allow list to it. It is what lets a fetch tell "the relay
// never had a list" from "the relay has lost the list I pushed": the relay
// says which state the list is in, and this file says whether a list was
// ever pushed from here. One RFC 3339 line; 'auu allow clear' removes it,
// since a cleared list is one the owner meant to be empty.
const allowPushedFile = "allow_pushed"

// AllowPushed is when this machine last pushed a signed allow list to one
// relay, and found false when it never has, or has cleared it since.
func (s *Store) AllowPushed(r *Relay) (pushed time.Time, found bool, err error) {
	path := s.relayPath(r, allowPushedFile)
	data, err := os.ReadFile(path)
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
			"delete it, or run 'auu allow push', which writes it again; it records only when this machine last pushed its allow list")
	}
	return pushed, true, nil
}

// SetAllowPushed records that a signed allow list was pushed to one relay
// now.
func (s *Store) SetAllowPushed(r *Relay, at time.Time) error {
	if err := os.MkdirAll(s.relayDir(r.Name), dirMode); err != nil {
		return err
	}
	return writeFileAtomic(s.relayPath(r, allowPushedFile), []byte(at.UTC().Format(time.RFC3339)+"\n"), fileMode)
}

// ClearAllowPushed forgets the push, for a list cleared on purpose.
func (s *Store) ClearAllowPushed(r *Relay) error {
	err := os.Remove(s.relayPath(r, allowPushedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
