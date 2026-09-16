package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// channelSettingsFile is this machine's own fetching policy, per channel:
// whether mail fetched from a channel is left on the relay afterwards. It
// is not the signed directory — a sender has no business knowing it, and a
// relay is never told — so it lives in a file of its own, which a copy of
// the home carries to a second machine and which 'auu channel pull' never
// touches. It may name a channel the directory does not list, since mail
// queued under a channel since deleted still arrives.
const channelSettingsFile = "channel-settings.json"

// ChannelSettings is the file as it is written: a version, and the
// channels that have been given a setting. A channel absent from it has the
// default, which is to keep.
type ChannelSettings struct {
	V        int                       `json:"v"`
	Channels map[string]ChannelSetting `json:"channels"`
}

// ChannelSetting is one channel's. Keep says mail fetched from it stays
// queued on the relay until it is removed.
type ChannelSetting struct {
	Keep bool `json:"keep"`
}

const channelSettingsV = 1

const channelSettingsAdvice = "fix it, or delete it and set the channels again with " +
	"'auu channel keep NAME on|off'; every channel keeps its mail on the relay until then"

// ChannelSettings reads the file. A home with none has the default for
// every channel. A file that is there and will not read, or names a channel
// no directory could hold, is damaged and names itself: it decides what
// this machine does with mail it has fetched, and guessing at it would
// silently acknowledge mail the owner meant to keep.
func (s *Store) ChannelSettings() (ChannelSettings, error) {
	set := ChannelSettings{V: channelSettingsV, Channels: map[string]ChannelSetting{}}
	data, err := os.ReadFile(s.path(channelSettingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return set, nil
	}
	if err != nil {
		return set, err
	}
	var read ChannelSettings
	if err := json.Unmarshal(data, &read); err != nil {
		return set, damaged(s.path(channelSettingsFile), "is not valid JSON", err, channelSettingsAdvice)
	}
	if read.V != channelSettingsV {
		return set, damaged(s.path(channelSettingsFile),
			fmt.Sprintf("is version %d, which this build does not know", read.V), nil, channelSettingsAdvice)
	}
	for name := range read.Channels {
		if err := channels.ValidName(name); err != nil {
			return set, damaged(s.path(channelSettingsFile),
				fmt.Sprintf("names a channel %q that no directory could hold", name), err, channelSettingsAdvice)
		}
	}
	if read.Channels != nil {
		set.Channels = read.Channels
	}
	return set, nil
}

// KeepOnRelay says whether mail fetched from a channel is left queued on
// the relay. A channel with no setting keeps, which is the default, and so
// does a channel named with the empty string, which is default's own name
// on the wire.
func (s *Store) KeepOnRelay(channel string) (bool, error) {
	set, err := s.ChannelSettings()
	if err != nil {
		return true, err
	}
	one, ok := set.Channels[channelOrDefault(channel)]
	if !ok {
		return true, nil
	}
	return one.Keep, nil
}

// SetKeep records one channel's setting, leaving the others as they are.
// The name is checked here as the directory checks it: a file of settings
// for channels that could not exist would be a puzzle later.
func (s *Store) SetKeep(channel string, keep bool) error {
	name := channelOrDefault(channel)
	if err := channels.ValidName(name); err != nil {
		return err
	}
	set, err := s.ChannelSettings()
	if err != nil {
		return err
	}
	set.V = channelSettingsV
	if set.Channels == nil {
		set.Channels = map[string]ChannelSetting{}
	}
	set.Channels[name] = ChannelSetting{Keep: keep}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(channelSettingsFile), append(data, '\n'), fileMode)
}

// ChannelSettingsPath is where the file lives, for the sentences that name
// it.
func (s *Store) ChannelSettingsPath() string { return s.path(channelSettingsFile) }

// channelOrDefault is the name a setting is filed under: the empty name a
// message carries when its sender named no channel is default's.
func channelOrDefault(channel string) string {
	if channel == "" {
		return channels.Default
	}
	return channel
}
