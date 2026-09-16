package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// channelsFile is this mailbox's channel directory as the owner defines it:
// the truth the owner's machine holds, which 'auu channel' commands sign and
// push to every relay, as authorized_peers is the truth behind 'auu allow
// push'. It is the directory unsigned and whole, issued included: issued is
// the time this machine last signed it, which 'auu channel push' signs
// under again so a relay that already holds that issue says so and one
// holding a newer issue from another machine refuses rather than being
// overwritten, and which 'auu channel ls' compares against what each relay
// holds. A home with no file has the one channel, default, and has pushed
// nothing.
const channelsFile = "channels.json"

// Directory reads the local channel directory. found is false for a home
// that has none. A file that is there and will not read, or reads to a
// directory that breaks a rule, is damaged and names itself: the file is
// this machine's to fix, and a directory nobody could sign must not be
// pushed halfway.
func (s *Store) Directory() (d *channels.Directory, found bool, err error) {
	data, err := os.ReadFile(s.path(channelsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d = &channels.Directory{}
	if err := json.Unmarshal(data, d); err != nil {
		return nil, false, damaged(s.path(channelsFile), "is not valid JSON", err, channelsAdvice)
	}
	if err := d.Validate(); err != nil {
		return nil, false, damaged(s.path(channelsFile), "holds a directory no relay would take", err, channelsAdvice)
	}
	return d, true, nil
}

const channelsAdvice = "fix it, or delete it and define your channels again with 'auu channel create NAME'; " +
	"the relays keep what was last pushed until then"

// SetDirectory writes the local channel directory, whole. The caller has
// validated and signed it; a directory that would not sign is not written,
// so the file never holds what the relays would refuse.
func (s *Store) SetDirectory(d *channels.Directory) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("channels: %w", err)
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(channelsFile), append(data, '\n'), fileMode)
}

// ChannelsPath is where the local directory lives, for the sentences that
// name it.
func (s *Store) ChannelsPath() string { return s.path(channelsFile) }
