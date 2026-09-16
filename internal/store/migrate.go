package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tropeforce7/agentuucp/internal/token"
)

// Moving a home that knew one relay under relays/.
//
// Before this, a home held one relay's URL in config.json and its anchor,
// certificate and cursor loose in the root. The move happens once, the first
// time a build that knows about several relays opens such a home, and it is
// one way: nothing downgrades.
//
// The anchor and the certificate are moved, not rewritten. What was pinned is
// what is pinned, byte for byte, because a re-encoded anchor is a different
// file to reason about at exactly the moment somebody is least able to check
// it.
//
// The order is what makes a crash survivable. The directory and its files go
// first and config.json last, so an interrupted move leaves a home that still
// looks unmigrated and is finished on the next open. Every step is written to
// be safe to repeat.
func (s *Store) migrateRelays() error {
	old, err := s.legacyConfig()
	if err != nil {
		return err
	}
	if old.Relay == "" {
		return nil
	}
	url := token.NormaliseRelay(old.Relay)
	name := defaultRelayName(url, nil)
	dir := s.relayDir(name)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	for _, file := range []string{anchorFile, certFile, cursorFile} {
		if err := moveIfPresent(s.path(file), filepath.Join(dir, file)); err != nil {
			return err
		}
	}
	// A record already there is from an interrupted move, and it is the
	// record: rewriting it would change the date the relay was added for no
	// reason.
	if _, err := s.readRelay(name); errors.Is(err, os.ErrNotExist) {
		r := &Relay{
			Name:               name,
			URL:                url,
			Added:              addedFrom(s.path(configFile)),
			TrustAnchorSPKI:    old.TrustAnchorSPKI,
			ServerIntSPKI:      old.ServerIntSPKI,
			ServerIntNotBefore: old.ServerIntNotBefore,
		}
		if err := s.SaveRelay(r); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	// A home that had a relay configured had a mailbox on it: that is what
	// configuring one was for, and draining it is what the old cursor in the
	// root recorded. A home whose cursor had never been written — registered
	// but never fetched from — would otherwise arrive here looking like a
	// relay nobody has joined, and 'auu inbox' skips those.
	migrated := &Relay{Name: name}
	if err := s.MarkRegistered(migrated); err != nil {
		return err
	}

	// Config never had these fields, so loading and saving is what removes
	// them: what is written back is the new shape and only the new shape.
	// This is the last step, and until it lands the home still looks
	// unmigrated, which is what makes the whole move safe to repeat.
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.DefaultRelay = name
	return s.SaveConfig(cfg)
}

// legacyConfig is config.json as a home held it before it could know more
// than one relay. It exists only for the move above; nothing else may read
// it, and Config does not carry these fields, which is what makes writing
// Config back the thing that removes them.
type legacyConfig struct {
	Relay              string    `json:"relay"`
	TrustAnchorSPKI    string    `json:"trust_anchor_spki"`
	ServerIntSPKI      string    `json:"server_int_spki"`
	ServerIntNotBefore time.Time `json:"server_int_not_before"`
}

func (s *Store) legacyConfig() (legacyConfig, error) {
	var c legacyConfig
	data, err := os.ReadFile(s.path(configFile))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, s.configDamaged(err)
	}
	return c, nil
}

// moveIfPresent renames a file that may already have been moved, or may never
// have existed. Both are ordinary: a home with no pinned anchor has no anchor
// file, and a move that was interrupted has some of them already in place.
func moveIfPresent(from, to string) error {
	if _, err := os.Stat(to); err == nil {
		return nil
	}
	err := os.Rename(from, to)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// addedFrom dates a migrated relay from the configuration that named it,
// which is the closest thing the home records to when it was chosen. A file
// that cannot be stat'd falls back to now.
func addedFrom(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return info.ModTime().UTC().Truncate(time.Second)
}
