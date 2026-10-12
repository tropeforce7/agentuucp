package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/wire"
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
	// Read strictly (G17, R24): a key the file does not have, a key given
	// twice, and a channel whose keep is absent or null are damage, never
	// keep off, since keep off acknowledges on the relay mail the owner
	// meant to keep for another machine. The file is walked by
	// eachKeyExactly rather than read by wire.Decode (R24b): a channel's
	// name is case-sensitive, as the directory's is, so "Bugs" and "bugs"
	// are two channels and only the same name twice is refused, where
	// wire.Decode's scan refuses two keys alike under folding at any depth.
	// The file's own two keys are matched exactly and each taken once, and
	// every value is read by wire.Decode.
	var v int
	var chans json.RawMessage
	var seenV, seenChannels bool
	err = eachKeyExactly(data, "the file", true, func(key string, raw json.RawMessage) error {
		switch {
		case key == "v" && !seenV:
			seenV = true
			return wire.Decode(raw, &v)
		case key == "channels" && !seenChannels:
			seenChannels = true
			chans = raw
			return nil
		case key == "v" || key == "channels":
			return fmt.Errorf("key %q appears twice", key)
		}
		return fmt.Errorf("json: unknown field %q", key)
	})
	if err != nil {
		return set, damaged(s.path(channelSettingsFile), "will not read", err, channelSettingsAdvice)
	}
	if v != channelSettingsV {
		return set, damaged(s.path(channelSettingsFile),
			fmt.Sprintf("is version %d, which this build does not know", v), nil, channelSettingsAdvice)
	}
	if string(chans) == "null" {
		chans = nil
	}
	err = eachKeyExactly(chans, "channels", false, func(name string, raw json.RawMessage) error {
		if err := channels.ValidName(name); err != nil {
			return damaged(s.path(channelSettingsFile),
				fmt.Sprintf("names a channel %q that no directory could hold", name), err, channelSettingsAdvice)
		}
		if _, twice := set.Channels[name]; twice {
			return damaged(s.path(channelSettingsFile),
				fmt.Sprintf("names the channel %q twice", name), nil, channelSettingsAdvice)
		}
		var one struct {
			Keep *bool `json:"keep"`
		}
		if err := wire.Decode(raw, &one); err != nil {
			return damaged(s.path(channelSettingsFile),
				fmt.Sprintf("gives the channel %q a setting that will not read", name), err, channelSettingsAdvice)
		}
		if one.Keep == nil {
			return damaged(s.path(channelSettingsFile),
				fmt.Sprintf("gives the channel %q no keep", name), nil, channelSettingsAdvice)
		}
		set.Channels[name] = ChannelSetting{Keep: *one.Keep}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrDamaged) {
			return set, err
		}
		return set, damaged(s.path(channelSettingsFile), "will not read", err, channelSettingsAdvice)
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

// eachKeyExactly walks one JSON object key by key, handing each key and
// its value to fn in the file's order; its keys are matched exactly, which
// is why it is not wire.Decode's walk, and each value is fn's to read
// strictly. what names the object in a refusal. Nothing at all is no
// keys, unless whole says the object is the whole of data, when anything
// after it is refused too, as wire.Decode refuses it.
func eachKeyExactly(data []byte, what string, whole bool, fn func(key string, value json.RawMessage) error) error {
	if len(data) == 0 && !whole {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil {
		return err
	} else if tok != json.Delim('{') {
		return fmt.Errorf("%s is not an object", what)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("a key is not a string")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}
	if tok, err := dec.Token(); err != nil {
		return err
	} else if tok != json.Delim('}') {
		return fmt.Errorf("%s does not end", what)
	}
	if whole {
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("there is more after %s", what)
		}
	}
	return nil
}
